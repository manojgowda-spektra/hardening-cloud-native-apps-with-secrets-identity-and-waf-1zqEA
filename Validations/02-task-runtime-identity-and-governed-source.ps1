using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = "rg-zava-$DID"
# Fallback: CloudLabs names the resource group from the template Code (e.g. ODL-CNA-<DID>),
# not "rg-zava-<DID>". If the assumed name is absent, find the group whose name carries the
# deployment id. Without this every check below fails before it reads anything.
if (-not (Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue)) {
    $__match = @(Get-AzResourceGroup -ErrorAction SilentlyContinue |
                 Where-Object { $_.ResourceGroupName -like "*$DID*" })
    if ($__match.Count -ge 1) { $rg = $__match[0].ResourceGroupName }
}
$secretName = "ZavaAppConnectionString"
$count = 0
$found = $false
$finalFailure = "Runtime identity and governed source were not validated."

function Normalize-Scope {
    param([string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Scope)) { return "" }
    return $Scope.TrimEnd('/').ToLowerInvariant()
}

function Get-NameFromResourceId {
    param([string]$ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }
    return ($ResourceId -split '/')[-1]
}

function Get-ResourceGroupFromResourceId {
    param([string]$ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }
    $parts = $ResourceId -split '/'
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ieq 'resourceGroups' -and ($i + 1) -lt $parts.Count) {
            return $parts[$i + 1]
        }
    }
    return $null
}

function Get-PublicIpFromId {
    param([string]$PublicIpId)
    if ([string]::IsNullOrWhiteSpace($PublicIpId)) { return $null }
    $pip = Get-AzResource -ResourceId $PublicIpId -ErrorAction SilentlyContinue
    if ($null -ne $pip -and $null -ne $pip.Properties -and -not [string]::IsNullOrWhiteSpace($pip.Properties.ipAddress)) {
        return $pip.Properties.ipAddress
    }
    return $null
}

function Get-StorefrontBaseUri {
    param($Vm, [string]$ResourceGroupName)

    $candidateIps = New-Object System.Collections.Generic.List[string]

    $gateways = @(Get-AzApplicationGateway -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
    foreach ($gateway in $gateways) {
        foreach ($frontend in @($gateway.FrontendIPConfigurations)) {
            $publicIpId = $null
            if ($null -ne $frontend.PublicIPAddress -and -not [string]::IsNullOrWhiteSpace($frontend.PublicIPAddress.Id)) {
                $publicIpId = $frontend.PublicIPAddress.Id
            }
            elseif ($null -ne $frontend.PublicIpAddress -and -not [string]::IsNullOrWhiteSpace($frontend.PublicIpAddress.Id)) {
                $publicIpId = $frontend.PublicIpAddress.Id
            }

            $ip = Get-PublicIpFromId -PublicIpId $publicIpId
            if (-not [string]::IsNullOrWhiteSpace($ip)) { [void]$candidateIps.Add($ip) }
        }
    }

    foreach ($nicRef in @($Vm.NetworkProfile.NetworkInterfaces)) {
        if ([string]::IsNullOrWhiteSpace($nicRef.Id)) { continue }
        $nicName = Get-NameFromResourceId -ResourceId $nicRef.Id
        $nicRg = Get-ResourceGroupFromResourceId -ResourceId $nicRef.Id
        if ([string]::IsNullOrWhiteSpace($nicName) -or [string]::IsNullOrWhiteSpace($nicRg)) { continue }
        $nic = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $nicRg -ErrorAction SilentlyContinue
        foreach ($ipConfig in @($nic.IpConfigurations)) {
            $publicIpId = $null
            if ($null -ne $ipConfig.PublicIpAddress -and -not [string]::IsNullOrWhiteSpace($ipConfig.PublicIpAddress.Id)) {
                $publicIpId = $ipConfig.PublicIpAddress.Id
            }
            $ip = Get-PublicIpFromId -PublicIpId $publicIpId
            if (-not [string]::IsNullOrWhiteSpace($ip)) { [void]$candidateIps.Add($ip) }
        }
    }

    foreach ($ip in ($candidateIps | Select-Object -Unique)) {
        $baseUri = "http://$ip"
        try {
            $health = Invoke-WebRequest -Uri "$baseUri/health" -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            if ($health.StatusCode -ge 200 -and $health.StatusCode -lt 400) {
                return $baseUri
            }
        }
        catch {
            continue
        }
    }

    return $null
}

function Test-RoleDefinitionHasSecretWrite {
    param($Assignment)

    $roleDefId = $Assignment.RoleDefinitionId
    if ([string]::IsNullOrWhiteSpace($roleDefId)) { return $false }
    $roleDefId = ($roleDefId -split '/')[-1]

    $roleDefinition = Get-AzRoleDefinition -Id $roleDefId -ErrorAction SilentlyContinue
    if ($null -eq $roleDefinition) { return $false }

    foreach ($dataAction in @($roleDefinition.DataActions)) {
        if ([string]::IsNullOrWhiteSpace($dataAction)) { continue }
        $lowerAction = $dataAction.ToLowerInvariant()
        if ($lowerAction -eq '*' -or $lowerAction -like 'microsoft.keyvault/*' -or $lowerAction -like 'microsoft.keyvault/vaults/*') {
            return $true
        }
        if ($lowerAction -like '*microsoft.keyvault/vaults/secrets/*' -and (
            $lowerAction -like '*setsecret*' -or
            $lowerAction -like '*write*' -or
            $lowerAction -like '*delete*' -or
            $lowerAction -like '*purge*' -or
            $lowerAction -like '*recover*' -or
            $lowerAction -like '*restore*' -or
            $lowerAction -like '*backup*' -or
            $lowerAction -like '*/*')) {
            return $true
        }
    }

    return $false
}

function Test-ConfigBodyDoesNotLeakSecret {
    param([string]$Body)

    if ([string]::IsNullOrWhiteSpace($Body)) { return $true }

    $leakPatterns = @(
        'Server\s*=',
        'Data\s+Source\s*=',
        'Initial\s+Catalog\s*=',
        'Database\s*=',
        'User\s+ID\s*=',
        'User\s+Id\s*=',
        'UID\s*=',
        'Password\s*=',
        'Pwd\s*=',
        'AccountKey\s*=',
        'ZavaRetailDb'
    )

    foreach ($pattern in $leakPatterns) {
        if ($Body -match $pattern) { return $false }
    }

    return $true
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $resourceGroup = Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue
        if ($null -eq $resourceGroup) {
            $finalFailure = "Resource group '$rg' was not found."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        $vm = Get-AzVM -ResourceGroupName $rg -Name "zava-web-vm" -ErrorAction SilentlyContinue
        if ($null -eq $vm) {
            $vm = @(Get-AzVM -ResourceGroupName $rg -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'zava*' -or $_.Name -like '*web*' }) | Select-Object -First 1
        }
        if ($null -eq $vm) {
            $finalFailure = "Storefront VM 'zava-web-vm' was not found in RG '$rg'."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        $vmIdentityType = [string]$vm.Identity.Type
        $vmPrincipalId = [string]$vm.Identity.PrincipalId
        if ([string]::IsNullOrWhiteSpace($vmPrincipalId) -or $vmIdentityType -notmatch 'SystemAssigned') {
            $finalFailure = "VM '$($vm.Name)' does not have an enabled system-assigned managed identity."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        $vaults = @(Get-AzKeyVault -ResourceGroupName $rg -ErrorAction SilentlyContinue | Where-Object { $_.EnableRbacAuthorization -eq $true })
        if ($vaults.Count -eq 0) {
            $finalFailure = "No Azure RBAC-mode Key Vault was found in RG '$rg'."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        $selectedVault = $null
        $vaultRoleAssignment = $null
        foreach ($vault in $vaults) {
            $assignmentsAtVault = @(Get-AzRoleAssignment -ObjectId $vmPrincipalId -Scope $vault.ResourceId -ErrorAction SilentlyContinue)
            $exactSecretsUser = $assignmentsAtVault | Where-Object {
                $_.RoleDefinitionName -eq 'Key Vault Secrets User' -and
                (Normalize-Scope $_.Scope) -eq (Normalize-Scope $vault.ResourceId)
            } | Select-Object -First 1

            $secretResource = Get-AzResource -ResourceId "$($vault.ResourceId)/secrets/$secretName" -ErrorAction SilentlyContinue
            if ($null -ne $exactSecretsUser -and $null -ne $secretResource) {
                $selectedVault = $vault
                $vaultRoleAssignment = $exactSecretsUser
                break
            }
        }

        if ($null -eq $selectedVault) {
            $finalFailure = "VM system-assigned identity '$vmPrincipalId' does not have built-in 'Key Vault Secrets User' scoped exactly to an RBAC-mode vault that contains secret '$secretName'."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        $subscriptionScope = Normalize-Scope "/subscriptions/$sub"
        $resourceGroupScope = Normalize-Scope "/subscriptions/$sub/resourceGroups/$rg"
        $allVmAssignments = @(Get-AzRoleAssignment -ObjectId $vmPrincipalId -ErrorAction SilentlyContinue)
        $forbiddenBroadRoleNames = @(
            'Owner',
            'Contributor',
            'User Access Administrator',
            'Role Based Access Control Administrator',
            'Key Vault Administrator',
            'Key Vault Secrets Officer',
            'Key Vault Data Access Administrator',
            'Key Vault Secrets User'
        )

        $forbiddenFindings = New-Object System.Collections.Generic.List[string]
        foreach ($assignment in $allVmAssignments) {
            $assignmentScope = Normalize-Scope $assignment.Scope
            $isBroadScope = ($assignmentScope -eq $subscriptionScope -or $assignmentScope -eq $resourceGroupScope)
            if (-not $isBroadScope) { continue }

            if ($forbiddenBroadRoleNames -contains $assignment.RoleDefinitionName) {
                [void]$forbiddenFindings.Add("$($assignment.RoleDefinitionName) at $($assignment.Scope)")
                continue
            }

            if (Test-RoleDefinitionHasSecretWrite -Assignment $assignment) {
                [void]$forbiddenFindings.Add("custom or renamed secret-write role '$($assignment.RoleDefinitionName)' at $($assignment.Scope)")
            }
        }

        if ($forbiddenFindings.Count -gt 0) {
            $finalFailure = "VM identity '$vmPrincipalId' has forbidden broad assignment(s): $($forbiddenFindings -join '; '). It should use Key Vault Secrets User only at vault scope '$($selectedVault.ResourceId)'."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        $baseUri = Get-StorefrontBaseUri -Vm $vm -ResourceGroupName $rg
        if ([string]::IsNullOrWhiteSpace($baseUri)) {
            $finalFailure = "No reachable storefront public endpoint was found for VM '$($vm.Name)' or an Application Gateway in RG '$rg'."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        $healthResponse = Invoke-WebRequest -Uri "$baseUri/health" -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        if ($healthResponse.StatusCode -lt 200 -or $healthResponse.StatusCode -ge 400) {
            $finalFailure = "Storefront /health at '$baseUri/health' returned HTTP $($healthResponse.StatusCode)."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        $configResponse = Invoke-WebRequest -Uri "$baseUri/config-status" -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $configBody = [string]$configResponse.Content
        $reportsKeyVault = $configBody -match '(?i)\bKeyVault\b'
        $doesNotLeakSecret = Test-ConfigBodyDoesNotLeakSecret -Body $configBody

        if (-not $reportsKeyVault) {
            $finalFailure = "Storefront /config-status at '$baseUri/config-status' did not report 'KeyVault'. Response snippet: '$($configBody.Substring(0, [Math]::Min(160, $configBody.Length)))'."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        if (-not $doesNotLeakSecret) {
            $finalFailure = "Storefront /config-status reports KeyVault but appears to expose connection string material for '$secretName'."
            $message = @{ Status = "Failed"; Message = $finalFailure } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
            if ($count -lt 3) { Start-Sleep -Seconds 10 }
            continue
        }

        $found = $true
        $message = @{
            Status  = "Succeeded"
            Message = "VM '$($vm.Name)' system-assigned identity '$vmPrincipalId' has 'Key Vault Secrets User' at vault '$($selectedVault.VaultName)' scope for '$secretName', has no forbidden broad Owner/Contributor/secret-write assignments, and storefront '$baseUri' returns healthy with /config-status reporting KeyVault without connection string material."
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
    }
    catch {
        $finalFailure = "Error during check. Attempt $count of 3. Error: $($_.Exception.Message)"
        $message = @{
            Status  = "Failed"
            Message = $finalFailure
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

# Post-loop: if every attempt failed, emit a final failure JSON so CloudLabs always sees a structured result.
if (-not $found) {
    $message = @{
        Status  = "Failed"
        Message = "Runtime identity and governed source validation failed in RG '$rg' after 3 attempts. $finalFailure"
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
