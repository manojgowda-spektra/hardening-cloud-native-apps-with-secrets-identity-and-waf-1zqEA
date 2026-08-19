using namespace System.Net

# CloudLabs challenge validation metadata:
# Key Vault is intentionally NOT deployed by ARM in this lab. This validator checks learner-created outcomes:
# an Azure RBAC authorization-mode Key Vault, ARM-visible secret metadata for 'ZavaAppConnectionString', and VM system-assigned identity.
# This validator intentionally uses only ARM/control-plane reads. Microsoft Learn documents that Key Vault RBAC separates
# management-plane access from data-plane secret-value access and that ARM secret properties never return the secret value.
# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = "rg-zava-$DID"
$secretName = "ZavaAppConnectionString"
$secretApiVersion = "2023-07-01"
$expectedVmName = "zava-web-vm"
$legacyIdentityName = "zava-app-legacy-id"
$count = 0
$found = $false
$lastFailureMessage = "Learner-created RBAC-mode Key Vault, ARM-visible secret metadata '$secretName', and VM system-assigned identity were not validated."

function Resolve-ZavaResourceGroup {
    param(
        [Parameter(Mandatory = $true)][string]$InitialResourceGroupName,
        [Parameter(Mandatory = $true)][string]$DeploymentId,
        [Parameter(Mandatory = $true)][string]$VmName,
        [Parameter(Mandatory = $true)][string]$IdentityName
    )

    $resourceGroup = Get-AzResourceGroup -Name $InitialResourceGroupName -ErrorAction SilentlyContinue
    if ($resourceGroup) { return $resourceGroup.ResourceGroupName }

    $candidateGroups = @(Get-AzResourceGroup -ErrorAction Stop | Where-Object { $_.ResourceGroupName -like "*$DeploymentId*" })
    if (-not $candidateGroups -or $candidateGroups.Count -eq 0) {
        $candidateGroups = @(Get-AzResourceGroup -ErrorAction Stop)
    }

    foreach ($candidate in $candidateGroups) {
        $candidateVm = Get-AzVM -ResourceGroupName $candidate.ResourceGroupName -Name $VmName -ErrorAction SilentlyContinue
        if ($candidateVm) { return $candidate.ResourceGroupName }

        $candidateIdentity = Get-AzResource -ResourceGroupName $candidate.ResourceGroupName -ResourceType "Microsoft.ManagedIdentity/userAssignedIdentities" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $IdentityName } | Select-Object -First 1
        if ($candidateIdentity) { return $candidate.ResourceGroupName }
    }

    return $InitialResourceGroupName
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory = $false)]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($PropertyName)) {
        return $InputObject[$PropertyName]
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($property) { return $property.Value }

    return $null
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $rg = Resolve-ZavaResourceGroup -InitialResourceGroupName $rg -DeploymentId $DID -VmName $expectedVmName -IdentityName $legacyIdentityName
        $resourceGroup = Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue

        $vaultResources = @()
        if ($resourceGroup) {
            # -ExpandProperties on the list form throws inside Az.Resources and
            # SilentlyContinue turns that into an empty result, so list first and
            # expand each vault individually by resource id.
            $vaultResources = @(Get-AzResource -ResourceGroupName $rg -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue | ForEach-Object {
                $expanded = Get-AzResource -ResourceId $_.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                if ($expanded) { $expanded } else { $_ }
            })
        }

        $rbacVaults = @($vaultResources | Where-Object {
            $enableRbac = Get-PropertyValue -InputObject $_.Properties -PropertyName "enableRbacAuthorization"
            $enableRbac -eq $true
        })

        $matchingVault = $null
        $matchingSecretResource = $null
        $secretEnabledState = "not returned by ARM"
        $secretLookupFailures = New-Object System.Collections.Generic.List[string]

        foreach ($vault in $rbacVaults) {
            $vaultResourceId = if (-not [string]::IsNullOrWhiteSpace($vault.ResourceId)) { $vault.ResourceId } else { $vault.Id }
            if ([string]::IsNullOrWhiteSpace($vaultResourceId)) {
                $secretLookupFailures.Add("RBAC-mode Key Vault '$($vault.Name)' was found, but its ARM resourceId was not returned.")
                continue
            }

            $secretResourceId = "$($vaultResourceId)/secrets/$secretName"
            try {
                # ARM metadata lookup only. Do not use Key Vault data-plane cmdlets or read the secret value.
                $secretResource = Get-AzResource -ResourceId $secretResourceId -ApiVersion $secretApiVersion -ExpandProperties -ErrorAction Stop
                if ($null -ne $secretResource) {
                    $secretProperties = $secretResource.Properties
                    $secretAttributes = Get-PropertyValue -InputObject $secretProperties -PropertyName "attributes"
                    $enabledAttribute = Get-PropertyValue -InputObject $secretAttributes -PropertyName "enabled"

                    if ($null -ne $enabledAttribute -and $enabledAttribute -eq $false) {
                        $secretLookupFailures.Add("Secret ARM metadata '$secretName' exists in Key Vault '$($vault.Name)' but properties.attributes.enabled is false.")
                    }
                    else {
                        $matchingVault = $vault
                        $matchingSecretResource = $secretResource
                        if ($null -ne $enabledAttribute) {
                            $secretEnabledState = $enabledAttribute.ToString()
                        }
                        break
                    }
                }
            }
            catch {
                $secretLookupFailures.Add("Secret ARM metadata '$secretName' was not found under RBAC-mode Key Vault '$($vault.Name)' using resourceId '$secretResourceId' and API version '$secretApiVersion'. Error: $($_.Exception.Message)")
            }
        }

        $vm = $null
        if ($resourceGroup) {
            $vm = Get-AzVM -ResourceGroupName $rg -Name $expectedVmName -ErrorAction SilentlyContinue
            if ($null -eq $vm) {
                $vm = @(Get-AzVM -ResourceGroupName $rg -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "zava*" } | Select-Object -First 1)
            }
        }

        $vmIdentityType = $null
        $vmPrincipalId = $null
        $vmHasSystemAssignedIdentity = $false

        if ($null -ne $vm -and $null -ne $vm.Identity) {
            $vmIdentityType = $vm.Identity.Type.ToString()
            $vmPrincipalId = $vm.Identity.PrincipalId
            $vmHasSystemAssignedIdentity = (($vmIdentityType -match "SystemAssigned") -and -not [string]::IsNullOrWhiteSpace($vmPrincipalId))
        }

        $failureDetails = New-Object System.Collections.Generic.List[string]

        if (-not $resourceGroup) {
            $failureDetails.Add("Resource group 'rg-zava-$DID' was not found, and no deployment resource group containing VM '$expectedVmName' or identity '$legacyIdentityName' was discovered.")
        }
        elseif ($vaultResources.Count -eq 0) {
            $failureDetails.Add("No learner-created Key Vault ARM resource exists in resource group '$rg'. Key Vault is intentionally not created by ARM for this challenge.")
        }
        elseif ($rbacVaults.Count -eq 0) {
            $vaultNames = ($vaultResources | Select-Object -ExpandProperty Name) -join ", "
            $failureDetails.Add("Key Vault ARM resource(s) found ($vaultNames), but none has properties.enableRbacAuthorization set to true.")
        }
        elseif ($null -eq $matchingSecretResource) {
            $rbacVaultNames = ($rbacVaults | Select-Object -ExpandProperty Name) -join ", "
            $secretDetail = if ($secretLookupFailures.Count -gt 0) { " Details: $($secretLookupFailures -join ' ')" } else { "" }
            $failureDetails.Add("RBAC-mode Key Vault ARM resource(s) found ($rbacVaultNames), but enabled secret ARM metadata '$secretName' was not validated.$secretDetail")
        }

        if ($null -eq $vm) {
            $failureDetails.Add("VM '$expectedVmName' or another zava-named VM was not found in resource group '$rg'.")
        }
        elseif (-not $vmHasSystemAssignedIdentity) {
            $failureDetails.Add("VM '$($vm.Name)' does not have a system-assigned managed identity with a principalId. Current identity type: '$vmIdentityType'.")
        }

        if ($null -ne $matchingVault -and $null -ne $matchingSecretResource -and $vmHasSystemAssignedIdentity) {
            $found = $true
            $vaultResourceIdForMessage = if (-not [string]::IsNullOrWhiteSpace($matchingVault.ResourceId)) { $matchingVault.ResourceId } else { $matchingVault.Id }
            $secretResourceIdForMessage = if (-not [string]::IsNullOrWhiteSpace($matchingSecretResource.ResourceId)) { $matchingSecretResource.ResourceId } else { $matchingSecretResource.Id }
            $message = @{
                Status  = "Succeeded"
                Message = "Learner-created RBAC-mode Key Vault '$($matchingVault.Name)' exists in RG '$rg'; secret '$secretName' exists as ARM metadata resource '$secretResourceIdForMessage' using API version '$secretApiVersion' with enabled state '$secretEnabledState'; VM '$($vm.Name)' has system-assigned identity principalId '$vmPrincipalId'. No Key Vault data-plane secret read was performed. Vault resourceId: '$vaultResourceIdForMessage'."
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
        }
        else {
            $lastFailureMessage = "Validation attempt $count of 3 failed: $($failureDetails -join ' ')"
            $message = @{
                Status  = "Failed"
                Message = $lastFailureMessage
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
        }
    }
    catch {
        $lastFailureMessage = "Error during check. Attempt $count of 3. Error: $($_.Exception.Message)"
        $message = @{
            Status  = "Failed"
            Message = $lastFailureMessage
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
        Message = "Learner-created RBAC-mode Key Vault, secret ARM metadata '$secretName', and VM system-assigned identity were not all found in RG '$rg' after 3 attempts. Last result: $lastFailureMessage"
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
