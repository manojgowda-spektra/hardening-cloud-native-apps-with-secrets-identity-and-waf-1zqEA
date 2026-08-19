using namespace System.Net

# Challenge validation note: this validator runs server-side and intentionally uses
# Azure Resource Manager/control-plane checks for Key Vault evidence. Microsoft Learn
# documents that Key Vault control-plane access and Key Vault data-plane access are
# independently authorized, and that Key Vault Reader can read metadata but not secret
# values. Therefore this script validates the ARM vault resource, ARM child secret
# proxy metadata, and Azure RBAC assignments only; it does not read or list Key Vault
# secret values or versions through the validation identity.
# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = "rg-zava-$DID"
$count = 0
$found = $false
$lastFailure = "Legacy metadata-only access validation has not run."

$legacyIdentityName = "zava-app-legacy-id"
$secretName = "ZavaAppConnectionString"

# Built-in role definition IDs verified from Microsoft Learn Azure built-in roles.
$keyVaultReaderRoleId = "21090545-7ca7-4776-b22c-e363652d74d2"
$contributorRoleId = "b24988ac-6180-42a0-ab88-20f7382dd24c"
$ownerRoleId = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
$keyVaultAdministratorRoleId = "00482a5a-887f-4fb3-b363-3b7fe8e74483"
$keyVaultSecretsUserRoleId = "4633458b-17de-408a-b874-0445c86b69e6"
$keyVaultSecretsOfficerRoleId = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
$keyVaultDataAccessAdministratorRoleId = "8b54135c-b56d-4d72-a534-26097cfdc8d8"
$userAccessAdministratorRoleId = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
$roleBasedAccessControlAdministratorRoleId = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
$keyVaultContributorRoleId = "f25e0fa2-a7c8-4377-a976-54943a77a395"

function Normalize-RoleId {
    param([string]$RoleDefinitionId)
    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) { return "" }
    return (($RoleDefinitionId -split "/")[-1]).ToLowerInvariant()
}

function Normalize-Scope {
    param([string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Scope)) { return "" }
    $normalized = $Scope.TrimEnd('/')
    if ($normalized.Length -eq 0) { return "/" }
    return $normalized
}

function Test-ScopeEquals {
    param(
        [string]$Left,
        [string]$Right
    )
    return (Normalize-Scope $Left).Equals((Normalize-Scope $Right), [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-AssignmentScopeAppliesToResource {
    param(
        [string]$AssignmentScope,
        [string]$ResourceScope
    )

    $assignment = Normalize-Scope $AssignmentScope
    $resource = Normalize-Scope $ResourceScope
    if ([string]::IsNullOrWhiteSpace($assignment) -or [string]::IsNullOrWhiteSpace($resource)) { return $false }
    if ($assignment -eq "/") { return $true }
    if ($resource.Equals($assignment, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $resource.StartsWith("$assignment/", [System.StringComparison]::OrdinalIgnoreCase)
}

function Convert-WildcardPatternToRegex {
    param([string]$Pattern)
    $escaped = [System.Text.RegularExpressions.Regex]::Escape($Pattern.Trim())
    return "^" + $escaped.Replace("\*", ".*") + "$"
}

function Test-ActionPatternMatch {
    param(
        [string[]]$Patterns,
        [string]$Target
    )

    foreach ($pattern in @($Patterns)) {
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
        $p = $pattern.Trim()
        if ($p -eq "*" -or $p.Equals($Target, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        $regex = Convert-WildcardPatternToRegex -Pattern $p
        if ([System.Text.RegularExpressions.Regex]::IsMatch($Target, $regex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) { return $true }
    }

    return $false
}

function Test-RoleGrantsAction {
    param(
        [string[]]$AllowedPatterns,
        [string[]]$DeniedPatterns,
        [string[]]$Targets
    )

    foreach ($target in @($Targets)) {
        if ((Test-ActionPatternMatch -Patterns $AllowedPatterns -Target $target) -and -not (Test-ActionPatternMatch -Patterns $DeniedPatterns -Target $target)) {
            return $true
        }
    }

    return $false
}

function New-ZavaOperationName {
    param([Parameter(Mandatory = $true)][string[]]$Parts)
    return ($Parts -join "/")
}

function Get-ResourceNameFromId {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceId,
        [Parameter(Mandatory = $true)][string]$SegmentName
    )

    $parts = $ResourceId -split '/'
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ieq $SegmentName -and ($i + 1) -lt $parts.Count) {
            return $parts[$i + 1]
        }
    }
    return $null
}

function Get-ZavaPublicEndpoint {
    param([string]$ResourceGroupName)

    $gateway = Get-AzApplicationGateway -ResourceGroupName $ResourceGroupName -Name "agw-zava-waf" -ErrorAction SilentlyContinue
    if (-not $gateway) {
        $gateway = Get-AzApplicationGateway -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "zava|agw|gateway" } | Select-Object -First 1
    }

    if (-not $gateway) { return $null }

    foreach ($frontend in @($gateway.FrontendIPConfigurations)) {
        if ($frontend.PublicIPAddress -and $frontend.PublicIPAddress.Id) {
            $pipName = Get-ResourceNameFromId -ResourceId $frontend.PublicIPAddress.Id -SegmentName "publicIPAddresses"
            $pipRg = Get-ResourceNameFromId -ResourceId $frontend.PublicIPAddress.Id -SegmentName "resourceGroups"
            if ([string]::IsNullOrWhiteSpace($pipRg)) { $pipRg = $ResourceGroupName }
            if (-not [string]::IsNullOrWhiteSpace($pipName)) {
                $pip = Get-AzPublicIpAddress -ResourceGroupName $pipRg -Name $pipName -ErrorAction SilentlyContinue
                if ($pip) {
                    if ($pip.IpAddress -and $pip.IpAddress -ne "Not Assigned") { return "http://$($pip.IpAddress)" }
                    if ($pip.DnsSettings -and $pip.DnsSettings.Fqdn) { return "http://$($pip.DnsSettings.Fqdn)" }
                }
            }
        }
    }

    return $null
}

function Test-ZavaHttpEndpoint {
    param([Parameter(Mandatory = $true)][string]$Uri)

    try {
        $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 15 -Headers @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZavaLabValidator/1.0'; 'Accept' = '*/*' } -ErrorAction Stop
        return [pscustomobject]@{
            Succeeded  = ([int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 400)
            StatusCode = [int]$response.StatusCode
            Content    = [string]$response.Content
            Error      = $null
        }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
        }
        return [pscustomobject]@{
            Succeeded  = $false
            StatusCode = $statusCode
            Content    = ""
            Error      = $_.Exception.Message
        }
    }
}

function Get-ControlPlaneSecretResource {
    param(
        [Parameter(Mandatory = $true)][string]$VaultResourceId,
        [Parameter(Mandatory = $true)][string]$SecretName
    )

    $secretResourceId = "$(Normalize-Scope $VaultResourceId)/secrets/$SecretName"
    $apiVersion = "2023-07-01"
    $lastError = "No error captured."
    try {
        $secretResource = Get-AzResource -ResourceId $secretResourceId -ApiVersion $apiVersion -ErrorAction Stop
        if ($secretResource) {
            return [pscustomobject]@{
                Found      = $true
                Resource   = $secretResource
                ResourceId = $secretResourceId
                Detail     = "Secret proxy resource '$secretResourceId' was found as Microsoft.KeyVault/vaults/secrets through ARM with API version $apiVersion."
            }
        }
    }
    catch {
        $lastError = $_.Exception.Message
    }

    return [pscustomobject]@{
        Found      = $false
        Resource   = $null
        ResourceId = $secretResourceId
        Detail     = "Secret proxy resource '$secretResourceId' was not found through ARM with API version $apiVersion. Last error: $lastError"
    }
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $resourceGroup = Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue
        if (-not $resourceGroup) {
            $candidateGroups = @(Get-AzResourceGroup -ErrorAction Stop | Where-Object { $_.ResourceGroupName -like "*$DID*" })
            foreach ($candidate in $candidateGroups) {
                $candidateIdentity = Get-AzResource -ResourceGroupName $candidate.ResourceGroupName -ResourceType "Microsoft.ManagedIdentity/userAssignedIdentities" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $legacyIdentityName } | Select-Object -First 1
                if ($candidateIdentity) {
                    $resourceGroup = $candidate
                    $rg = $candidate.ResourceGroupName
                    break
                }
            }
        }

        if (-not $resourceGroup) {
            $lastFailure = "Resource group 'rg-zava-$DID' was not found, and no deployment resource group containing '$legacyIdentityName' was discovered."
        }
        else {
            $rgScope = "/subscriptions/$sub/resourceGroups/$($resourceGroup.ResourceGroupName)"

            $legacyIdentity = Get-AzResource -ResourceGroupName $resourceGroup.ResourceGroupName -ResourceType "Microsoft.ManagedIdentity/userAssignedIdentities" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $legacyIdentityName } | Select-Object -First 1
            if (-not $legacyIdentity) {
                $lastFailure = "User-assigned managed identity '$legacyIdentityName' was not found in RG '$($resourceGroup.ResourceGroupName)'."
            }
            else {
                $legacyIdentityDetail = Get-AzResource -ResourceId $legacyIdentity.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                if ($legacyIdentityDetail) { $legacyIdentity = $legacyIdentityDetail }
                $legacyPrincipalId = [string]$legacyIdentity.Properties.principalId
                if ([string]::IsNullOrWhiteSpace($legacyPrincipalId)) {
                    $lastFailure = "User-assigned managed identity '$legacyIdentityName' was found, but its principalId was not available."
                }
                else {
                    $vaults = @(Get-AzResource -ResourceGroupName $resourceGroup.ResourceGroupName -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue)
                    if (-not $vaults -or $vaults.Count -eq 0) {
                        $lastFailure = "No Key Vault ARM resource exists in RG '$($resourceGroup.ResourceGroupName)'. Create the learner vault before validating legacy metadata-only access."
                    }
                    else {
                        $allAssignments = @(Get-AzRoleAssignment -ObjectId $legacyPrincipalId -SkipClientSideScopeValidation -ErrorAction SilentlyContinue)
                        $rgContributorAssignments = @($allAssignments | Where-Object {
                            (Normalize-RoleId $_.RoleDefinitionId) -eq $contributorRoleId -and (Test-ScopeEquals -Left $_.Scope -Right $rgScope)
                        })

                        if ($rgContributorAssignments.Count -gt 0) {
                            $lastFailure = "'$legacyIdentityName' still has built-in Contributor at exact resource-group scope '$rgScope'. Remove that broad assignment."
                        }
                        else {
                            $candidateVaults = @($vaults | Sort-Object @{ Expression = { if ($_.Name -like "kv-zava-*" ) { 0 } else { 1 } } }, Name)
                            $bestVaultFailure = "No candidate vault was evaluated."

                            foreach ($vault in $candidateVaults) {
                                # The plain listing carries no Properties payload, so the
                                # RBAC flag below would always read false. Expand first.
                                $vaultDetail = Get-AzResource -ResourceId $vault.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                                if ($vaultDetail) { $vault = $vaultDetail }
                                $vaultScope = Normalize-Scope $vault.ResourceId
                                $secretControlPlane = Get-ControlPlaneSecretResource -VaultResourceId $vaultScope -SecretName $secretName

                                $rbacEnabled = $false
                                if ($vault.Properties -and $null -ne $vault.Properties.enableRbacAuthorization) {
                                    $rbacEnabled = [System.Convert]::ToBoolean($vault.Properties.enableRbacAuthorization)
                                }

                                if (-not $rbacEnabled) {
                                    $bestVaultFailure = "Key Vault '$($vault.Name)' is not using Azure RBAC authorization. The vault ARM property enableRbacAuthorization must be true for the required RBAC-mode vault."
                                    continue
                                }

                                if (-not $secretControlPlane.Found) {
                                    $bestVaultFailure = "Secret proxy resource '$secretName' was not found under RBAC-mode Key Vault '$($vault.Name)' by Azure Resource Manager. Detail: $($secretControlPlane.Detail)"
                                    continue
                                }

                                $secretScope = Normalize-Scope $secretControlPlane.ResourceId
                                $secretEnabledEvidence = "The secret proxy resource was found; the ARM response did not expose an enabled flag."
                                $secretEnabled = $true
                                if ($secretControlPlane.Resource.Properties -and $secretControlPlane.Resource.Properties.attributes -and $null -ne $secretControlPlane.Resource.Properties.attributes.enabled) {
                                    $secretEnabled = [System.Convert]::ToBoolean($secretControlPlane.Resource.Properties.attributes.enabled)
                                    $secretEnabledEvidence = "The secret proxy resource reports attributes.enabled=$secretEnabled."
                                }

                                $readerAssignments = @($allAssignments | Where-Object {
                                    (Normalize-RoleId $_.RoleDefinitionId) -eq $keyVaultReaderRoleId -and (Test-ScopeEquals -Left $_.Scope -Right $vaultScope)
                                })

                                $otherReaderAssignments = @($allAssignments | Where-Object {
                                    (Normalize-RoleId $_.RoleDefinitionId) -eq $keyVaultReaderRoleId -and
                                    -not (Test-ScopeEquals -Left $_.Scope -Right $vaultScope) -and
                                    ((Test-AssignmentScopeAppliesToResource -AssignmentScope $_.Scope -ResourceScope $vaultScope) -or (Test-AssignmentScopeAppliesToResource -AssignmentScope $_.Scope -ResourceScope $secretScope))
                                })

                                $relevantAssignments = @($allAssignments | Where-Object {
                                    (Test-AssignmentScopeAppliesToResource -AssignmentScope $_.Scope -ResourceScope $vaultScope) -or (Test-AssignmentScopeAppliesToResource -AssignmentScope $_.Scope -ResourceScope $secretScope)
                                })

                                $prohibitedRoleIds = @(
                                    $ownerRoleId,
                                    $contributorRoleId,
                                    $keyVaultAdministratorRoleId,
                                    $keyVaultSecretsUserRoleId,
                                    $keyVaultSecretsOfficerRoleId,
                                    $keyVaultDataAccessAdministratorRoleId,
                                    $userAccessAdministratorRoleId,
                                    $roleBasedAccessControlAdministratorRoleId,
                                    $keyVaultContributorRoleId
                                )

                                $prohibitedRoleNames = @(
                                    "Owner",
                                    "Contributor",
                                    "Key Vault Administrator",
                                    "Key Vault Secrets User",
                                    "Key Vault Secrets Officer",
                                    "Key Vault Data Access Administrator",
                                    "User Access Administrator",
                                    "Role Based Access Control Administrator",
                                    "Key Vault Contributor"
                                )

                                $kvProvider = ("Microsoft" + "." + "KeyVault")
                                $authProvider = ("Microsoft" + "." + "Authorization")
                                $sensitiveSecretDataOps = @(
                                    (New-ZavaOperationName -Parts @($kvProvider, "vaults", "secrets", "getSecret", "action")),
                                    (New-ZavaOperationName -Parts @($kvProvider, "vaults", "secrets", "setSecret", "action"))
                                )

                                $privilegeOrVaultWriteOps = @(
                                    (New-ZavaOperationName -Parts @($authProvider, "roleAssignments", "write")),
                                    (New-ZavaOperationName -Parts @($authProvider, "roleAssignments", "*")),
                                    (New-ZavaOperationName -Parts @($kvProvider, "vaults", "write")),
                                    (New-ZavaOperationName -Parts @($kvProvider, "vaults", "accessPolicies", "write"))
                                )

                                $dangerousAssignments = New-Object System.Collections.Generic.List[string]
                                $roleDefinitionCache = @{}

                                foreach ($assignment in $relevantAssignments) {
                                    $roleId = Normalize-RoleId $assignment.RoleDefinitionId
                                    $roleName = [string]$assignment.RoleDefinitionName

                                    if ($roleId -eq $keyVaultReaderRoleId -and (Test-ScopeEquals -Left $assignment.Scope -Right $vaultScope)) {
                                        continue
                                    }

                                    if (($prohibitedRoleIds -contains $roleId) -or ($prohibitedRoleNames -contains $roleName)) {
                                        $dangerousAssignments.Add("$roleName at $($assignment.Scope)")
                                        continue
                                    }

                                    $roleDefinition = $null
                                    if (-not [string]::IsNullOrWhiteSpace($roleId)) {
                                        if ($roleDefinitionCache.ContainsKey($roleId)) {
                                            $roleDefinition = $roleDefinitionCache[$roleId]
                                        }
                                        else {
                                            try { $roleDefinition = Get-AzRoleDefinition -Id $roleId -ErrorAction Stop } catch { $roleDefinition = $null }
                                            $roleDefinitionCache[$roleId] = $roleDefinition
                                        }
                                    }

                                    if ($roleDefinition) {
                                        # Az.Resources 10.x moved Actions/DataActions/NotActions/
                                        # NotDataActions from the top level into Permissions[n].
                                        # Reading the old flattened properties returns null, which
                                        # left both guards with empty allow-lists so neither could
                                        # ever match. Evaluate each permission entry on its own so a
                                        # NotDataActions in one entry is not applied to another's
                                        # DataActions. Falls back to the flattened form for older Az.
                                        $permissionSets = @($roleDefinition.Permissions | Where-Object { $_ })
                                        if (-not $permissionSets) {
                                            $permissionSets = @([pscustomobject]@{
                                                DataActions    = @($roleDefinition.DataActions)
                                                NotDataActions = @($roleDefinition.NotDataActions)
                                                Actions        = @($roleDefinition.Actions)
                                                NotActions     = @($roleDefinition.NotActions)
                                            })
                                        }

                                        $grantsSecretData = $false
                                        $grantsPrivilegeOrVaultWrite = $false
                                        foreach ($perm in $permissionSets) {
                                            if (Test-RoleGrantsAction -AllowedPatterns @($perm.DataActions) -DeniedPatterns @($perm.NotDataActions) -Targets $sensitiveSecretDataOps) {
                                                $grantsSecretData = $true
                                            }
                                            if (Test-RoleGrantsAction -AllowedPatterns @($perm.Actions) -DeniedPatterns @($perm.NotActions) -Targets $privilegeOrVaultWriteOps) {
                                                $grantsPrivilegeOrVaultWrite = $true
                                            }
                                        }

                                        if ($grantsSecretData) {
                                            $dangerousAssignments.Add("$roleName at $($assignment.Scope) grants getSecret or setSecret data permissions")
                                        }
                                        elseif ($grantsPrivilegeOrVaultWrite) {
                                            $customLabel = if ($roleDefinition.IsCustom -eq $true) { "custom role " } else { "" }
                                            $dangerousAssignments.Add("${customLabel}$roleName at $($assignment.Scope) grants privilege-management or vault-write permissions that can create a route to secret values")
                                        }
                                    }
                                }

                                $endpoint = Get-ZavaPublicEndpoint -ResourceGroupName $resourceGroup.ResourceGroupName
                                $healthOk = $false
                                $configUsesKeyVault = $false
                                $configDoesNotLeakSecret = $true
                                $healthDetail = "No Application Gateway public endpoint was discovered."
                                $configDetail = "No Application Gateway public endpoint was discovered."

                                if ($endpoint) {
                                    $healthResponse = Test-ZavaHttpEndpoint -Uri "$endpoint/health"
                                    $healthOk = $healthResponse.Succeeded
                                    $healthDetail = if ($healthResponse.Succeeded) { "HTTP $($healthResponse.StatusCode)" } else { "HTTP $($healthResponse.StatusCode): $($healthResponse.Error)" }

                                    $configResponse = Test-ZavaHttpEndpoint -Uri "$endpoint/config-status"
                                    $configContent = [string]$configResponse.Content
                                    $configUsesKeyVault = $configResponse.Succeeded -and ($configContent -match "KeyVault")
                                    $configDoesNotLeakSecret = -not ($configContent -match "(?i)(Server\s*=|Password\s*=|User\s+ID\s*=|Initial\s+Catalog\s*=|Data\s+Source\s*=)")
                                    $configDetail = if ($configResponse.Succeeded) { "HTTP $($configResponse.StatusCode): $configContent" } else { "HTTP $($configResponse.StatusCode): $($configResponse.Error)" }
                                }

                                if ($readerAssignments.Count -lt 1) {
                                    $bestVaultFailure = "'$legacyIdentityName' does not have the built-in Key Vault Reader role scoped exactly to learner vault '$($vault.Name)' ('$vaultScope')."
                                }
                                elseif ($otherReaderAssignments.Count -gt 0) {
                                    $bestVaultFailure = "'$legacyIdentityName' has Key Vault Reader at non-vault-exact scope(s) effective on '$($vault.Name)' or '$secretName': $((@($otherReaderAssignments | ForEach-Object { $_.Scope }) | Select-Object -Unique) -join ', '). Keep the replacement metadata role scoped exactly to the vault."
                                }
                                elseif ($dangerousAssignments.Count -gt 0) {
                                    $bestVaultFailure = "'$legacyIdentityName' has effective secret-value, secret-write, Secrets User, Secrets Officer, Administrator, Owner, Contributor, Key Vault Contributor, privilege-management, vault-write, or custom privilege route(s) for '$secretName': $($dangerousAssignments -join '; '). Remove all routes except built-in Key Vault Reader scoped exactly to the vault."
                                }
                                elseif (-not $secretEnabled) {
                                    $bestVaultFailure = "Secret proxy resource '$secretName' exists in Key Vault '$($vault.Name)', but ARM reports the current secret attributes.enabled value as false."
                                }
                                elseif (-not $healthOk) {
                                    $bestVaultFailure = "Storefront health check through Application Gateway endpoint '$endpoint/health' did not succeed. Result: $healthDetail"
                                }
                                elseif (-not $configUsesKeyVault) {
                                    $bestVaultFailure = "Storefront config source check through '$endpoint/config-status' did not report KeyVault. Result: $configDetail"
                                }
                                elseif (-not $configDoesNotLeakSecret) {
                                    $bestVaultFailure = "Storefront '$endpoint/config-status' reported KeyVault but appeared to expose connection-string material. Result: $configDetail"
                                }
                                else {
                                    $found = $true
                                    $message = @{
                                        Status  = "Succeeded"
                                        Message = "RBAC-mode Key Vault '$($vault.Name)' exists as an ARM resource, and secret proxy resource '$secretName' exists as Microsoft.KeyVault/vaults/secrets at '$secretScope' using ARM API 2023-07-01. '$legacyIdentityName' has no Contributor at exact RG scope '$rgScope', has built-in Key Vault Reader scoped exactly to the vault, and has no effective getSecret, setSecret, Secrets User, Secrets Officer, Administrator, Owner, Contributor, Key Vault Contributor, privilege-management, vault-write, or custom privilege route to '$secretName'. $secretEnabledEvidence Storefront /health and /config-status succeed and report a healthy KeyVault source through '$endpoint'. Secret rotation version-count evidence is learner-captured/solution evidence and is not evaluated by this validator because the validation runtime intentionally has no Key Vault data-plane rights."
                                    } | ConvertTo-Json
                                    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                                        StatusCode = [HttpStatusCode]::OK
                                        Body       = $message
                                    })
                                    break
                                }
                            }

                            if (-not $found) {
                                $lastFailure = $bestVaultFailure
                            }
                        }
                    }
                }
            }
        }

        if (-not $found) {
            $message = @{
                Status  = "Failed"
                Message = "$lastFailure Secret rotation version-count evidence is learner-captured/solution evidence and is not checked by this validator because the validation runtime intentionally has no Key Vault data-plane rights."
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            if ($count -lt 3) {
                Start-Sleep -Seconds 10
            }
        }
    }
    catch {
        $message = @{
            Status  = "Failed"
            Message = "Error during legacy metadata-only access check in RG '$rg'. Attempt $count of 3. Error: $($_.Exception.Message). Secret rotation version-count evidence is learner-captured/solution evidence and is not checked by this validator because the validation runtime intentionally has no Key Vault data-plane rights."
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
        Message = "Legacy metadata-only access validation did not pass in RG '$rg' after 3 attempts. Last result: $lastFailure. Secret rotation version-count evidence is learner-captured/solution evidence and is not checked by this validator because the validation runtime intentionally has no Key Vault data-plane rights."
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
