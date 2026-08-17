# Exercise 03: Remove Excessive Access and Rotate the Governed Secret

### Estimated Duration: 45 minutes

## Scenario

Zava Retail still has a legacy user-assigned managed identity named `zava-app-legacy-id` with **Contributor** at the resource-group scope. That assignment is broader than the identity needs and could allow unintended management-plane changes. In this exercise, you will replace that excessive access with metadata-only visibility to the Key Vault, then rotate `ZavaAppConnectionString` using your own lab account access from Exercise 1.

## Overview

You will locate the legacy identity, remove its resource-group Contributor assignment, assign the built-in **Key Vault Reader** role only at the vault scope, and prove that this replacement permits metadata visibility without secret-value read or secret write capability. After the access cleanup, you will create a new enabled version of `ZavaAppConnectionString` with your own **Key Vault Secrets Officer** access and confirm the storefront continues to resolve configuration from Key Vault through the VM managed identity.

## Objectives

- Task 1: Reconnect to the lab subscription and discover the working resources
- Task 2: Remove resource-group Contributor from `zava-app-legacy-id`
- Task 3: Grant only Key Vault Reader at the vault scope
- Task 4: Verify metadata-only least privilege
- Task 5: Rotate `ZavaAppConnectionString` using your own account
- Task 6: Refresh the storefront and validate the final state

## Task 1: Reconnect to the lab subscription and discover the working resources

In this task, you will reconnect to Azure, identify the lab resource group, and capture the names and IDs you need for the least-privilege change.

1. Sign in to the Azure portal at <https://portal.azure.com>.

   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>
   - Subscription: <inject key="SubscriptionID"></inject>
   - Tenant: <inject key="TenantID"></inject>

2. Open **Cloud Shell** from the Azure portal and choose **PowerShell**.

3. Keep your deployment marker available. Your lab deployment is **zava-<inject key="DeploymentID" enableCopy="false"/>**. If your resource group name differs, use the resource group that contains `zava-web-vm` and `zava-app-legacy-id`.

4. In Cloud Shell, run the following discovery script. When prompted, paste the subscription ID and deployment ID from the lab page.

   ```powershell
   $subscriptionId = Read-Host "Paste the lab Subscription ID"
   $deploymentId = Read-Host "Paste the lab Deployment ID"

   az account set --subscription $subscriptionId

   $vmId = az vm list --query "[?name=='zava-web-vm'].id | [0]" -o tsv
   if (-not $vmId) {
       throw "Could not find zava-web-vm. Confirm you are in the correct subscription."
   }

   $rg = ($vmId -split '/')[4]
   $rgScope = az group show --name $rg --query id -o tsv

   $vaultName = az keyvault list --resource-group $rg --query "[?properties.enableRbacAuthorization==``true``].name | [0]" -o tsv
   if (-not $vaultName) {
       throw "Could not find an RBAC-mode Key Vault in resource group $rg. Complete Exercise 1 first."
   }

   $vaultId = az keyvault show --name $vaultName --resource-group $rg --query id -o tsv
   $legacyPrincipalId = az identity show --name zava-app-legacy-id --resource-group $rg --query principalId -o tsv

   [pscustomobject]@{
       ResourceGroup = $rg
       ResourceGroupScope = $rgScope
       KeyVaultName = $vaultName
       KeyVaultScope = $vaultId
       LegacyIdentityPrincipalId = $legacyPrincipalId
   } | Format-List
   ```

5. Confirm that the output includes:

   - A resource group name.
   - A Key Vault name created in Exercise 1.
   - A Key Vault resource ID ending in `/providers/Microsoft.KeyVault/vaults/` followed by your vault name.
   - A principal ID for `zava-app-legacy-id`.

> [!Important]
> This exercise changes only the **legacy** user-assigned identity. Do not remove the VM system-assigned identity role assignment from Exercise 1. The storefront still needs the VM identity with **Key Vault Secrets User** at vault scope to resolve the secret at runtime.

## Task 2: Remove resource-group Contributor from `zava-app-legacy-id`

In this task, you will find the broad Contributor assignment and remove it at the resource-group scope.

1. List the current Contributor assignment for the legacy identity.

   ```powershell
   az role assignment list `
     --assignee-object-id $legacyPrincipalId `
     --role "Contributor" `
     --scope $rgScope `
     --query "[].{principalId:principalId, role:roleDefinitionName, scope:scope}" `
     -o table
   ```

2. If the table shows `Contributor` at the resource-group scope, remove that assignment.

   ```powershell
   az role assignment delete `
     --assignee-object-id $legacyPrincipalId `
     --role "Contributor" `
     --scope $rgScope
   ```

3. Run the list command again and confirm that no `Contributor` row remains for `zava-app-legacy-id` at the resource-group scope.

   ```powershell
   az role assignment list `
     --assignee-object-id $legacyPrincipalId `
     --role "Contributor" `
     --scope $rgScope `
     -o table
   ```

> [!Note]
> Azure RBAC removal can take a short time to appear consistently. If the assignment still appears immediately after deletion, wait a minute and run the list command again.

## Task 3: Grant only Key Vault Reader at the vault scope

In this task, you will grant the exact replacement role: built-in **Key Vault Reader**, scoped only to the learner-created vault.

1. Assign **Key Vault Reader** to the legacy identity at the Key Vault scope.

   ```powershell
   az role assignment create `
     --assignee-object-id $legacyPrincipalId `
     --assignee-principal-type ServicePrincipal `
     --role "Key Vault Reader" `
     --scope $vaultId
   ```

2. Confirm the assignment is scoped exactly to the vault and not to the resource group, subscription, or an individual secret.

   ```powershell
   az role assignment list `
     --assignee-object-id $legacyPrincipalId `
     --scope $vaultId `
     --include-inherited `
     --query "[].{role:roleDefinitionName, scope:scope}" `
     -o table
   ```

3. Verify that the expected row is:

   - `role`: `Key Vault Reader`
   - `scope`: the Key Vault resource ID stored in `$vaultId`

4. If you see `Key Vault Secrets User`, `Key Vault Secrets Officer`, `Key Vault Administrator`, `Contributor`, or `Owner` for `zava-app-legacy-id`, remove the incorrect assignment before continuing. The legacy identity must not have a secret-value read role or a secret-write role.

<question></question>

> [!Important]
> Do not assign **Key Vault Secrets User** to `zava-app-legacy-id`. That role reads secret contents. Do not assign **Key Vault Secrets Officer** or **Key Vault Administrator**; those roles can manage or modify secret values. The required replacement is metadata-only **Key Vault Reader** at vault scope.

## Task 4: Verify metadata-only least privilege

In this task, you will prove why Key Vault Reader is the correct least-privilege role for the legacy identity.

1. Inspect the built-in role definition for **Key Vault Reader**.

   ```powershell
   az role definition list `
     --name "Key Vault Reader" `
     --query "[0].{roleName:roleName, description:description, actions:permissions[0].actions, dataActions:permissions[0].dataActions}" `
     -o jsonc
   ```

2. In the output, verify that the description states that the role reads metadata and cannot read sensitive values such as secret contents or key material.

3. Confirm the role has metadata-oriented data actions only. It must not include either of these secret-value operations:

   - `Microsoft.KeyVault/vaults/secrets/getSecret/action`
   - `Microsoft.KeyVault/vaults/secrets/setSecret/action`

4. Check the legacy identity's effective assignments at the vault scope.

   ```powershell
   $legacyAssignments = az role assignment list `
     --assignee-object-id $legacyPrincipalId `
     --scope $vaultId `
     --include-inherited `
     --all `
     --query "[].{role:roleDefinitionName, scope:scope}" `
     -o json | ConvertFrom-Json

   $legacyAssignments | Format-Table -AutoSize

   $forbiddenRoles = @(
       "Owner",
       "Contributor",
       "Key Vault Administrator",
       "Key Vault Secrets Officer",
       "Key Vault Secrets User"
   )

   $badAssignments = $legacyAssignments | Where-Object { $forbiddenRoles -contains $_.role }
   if ($badAssignments) {
       Write-Warning "Remove these excessive assignments before continuing:"
       $badAssignments | Format-Table -AutoSize
   }
   else {
       Write-Host "PASS: zava-app-legacy-id has no secret-value read or secret-write role at or above the vault scope."
   }
   ```

5. Keep the assignment output for your final report in Exercise 4.

> [!Tip]
> **Key Vault Reader** can list or view vault, key, certificate, and secret metadata in an RBAC-mode vault. It cannot retrieve the value of `ZavaAppConnectionString`, cannot create a new version, and cannot rotate the secret.

## Task 5: Rotate `ZavaAppConnectionString` using your own account

In this task, you will use your own lab account's **Key Vault Secrets Officer** access from Exercise 1 to create a new enabled version of the exact secret `ZavaAppConnectionString`.

1. Confirm your signed-in user still has **Key Vault Secrets Officer** at the vault scope.

   ```powershell
   $signedInUserId = az ad signed-in-user show --query id -o tsv

   az role assignment list `
     --assignee-object-id $signedInUserId `
     --scope $vaultId `
     --include-inherited `
     --query "[?roleDefinitionName=='Key Vault Secrets Officer'].{role:roleDefinitionName, scope:scope}" `
     -o table
   ```

2. List existing versions of `ZavaAppConnectionString` without printing the secret value.

   ```powershell
   az keyvault secret list-versions `
     --vault-name $vaultName `
     --name ZavaAppConnectionString `
     --query "[].{id:id, enabled:attributes.enabled, created:attributes.created}" `
     -o table
   ```

3. Create a rotated value in memory. This keeps the connection string as a sample security artifact; there is no backing database and no database connection test is required.

   ```powershell
   $currentValue = az keyvault secret show `
     --vault-name $vaultName `
     --name ZavaAppConnectionString `
     --query value `
     -o tsv

   $rotationToken = [guid]::NewGuid().ToString("N").Substring(0,12)

   if ($currentValue -match "Password=") {
       $rotatedValue = $currentValue -replace "Password=[^;]*", "Password=Rotated-$rotationToken"
   }
   else {
       $rotatedValue = "$currentValue;RotationMarker=Rotated-$rotationToken"
   }
   ```

4. Set the secret again with the exact same name. In Key Vault, setting an existing secret name creates a new version.

   ```powershell
   az keyvault secret set `
     --vault-name $vaultName `
     --name ZavaAppConnectionString `
     --value $rotatedValue `
     --query "{name:name, id:id, enabled:attributes.enabled, created:attributes.created}" `
     -o table
   ```

5. List versions again and confirm there are now at least two enabled versions or, at minimum, a new latest enabled version after your rotation.

   ```powershell
   az keyvault secret list-versions `
     --vault-name $vaultName `
     --name ZavaAppConnectionString `
     --query "[].{id:id, enabled:attributes.enabled, created:attributes.created}" `
     -o table
   ```

> [!Important]
> The rotation is performed by **your signed-in lab account** because you assigned yourself **Key Vault Secrets Officer** in Exercise 1. `zava-app-legacy-id` is metadata-only and must not be able to read, write, or rotate `ZavaAppConnectionString`.

## Task 6: Refresh the storefront and validate the final state

In this task, you will refresh the storefront if needed and confirm it remains healthy using Key Vault as its configuration source.

1. Restart IIS on the VM by using Azure VM Run Command. This avoids relying on direct public VM HTTP access, which you removed or blocked in Exercise 2.

   ```powershell
   az vm run-command invoke `
     --resource-group $rg `
     --name zava-web-vm `
     --command-id RunPowerShellScript `
     --scripts "iisreset /restart" `
     --query "value[].message" `
     -o tsv
   ```

2. Discover the Application Gateway public IP created in Exercise 2.

   ```powershell
   $appGwName = "agw-zava-waf"
   $appGw = az network application-gateway show --resource-group $rg --name $appGwName -o json | ConvertFrom-Json
   $publicIpId = $appGw.frontendIPConfigurations[0].publicIPAddress.id
   $gatewayIp = az network public-ip show --ids $publicIpId --query ipAddress -o tsv

   Write-Host "Application Gateway public IP: $gatewayIp"
   ```

3. Confirm the storefront health endpoint succeeds through Application Gateway.

   ```powershell
   Invoke-WebRequest -Uri "http://$gatewayIp/health" -UseBasicParsing | Select-Object StatusCode, Content
   ```

4. Confirm the storefront reports Key Vault as the active source and does not expose the secret value.

   ```powershell
   Invoke-WebRequest -Uri "http://$gatewayIp/config-status" -UseBasicParsing | Select-Object StatusCode, Content
   ```

5. Your final evidence for this exercise should show:

   - No `Contributor` assignment for `zava-app-legacy-id` at the resource-group scope.
   - Exactly **Key Vault Reader** for `zava-app-legacy-id` at the vault scope.
   - No effective assignment for `zava-app-legacy-id` that grants secret-value read or secret write.
   - At least two versions of `ZavaAppConnectionString`, with the latest enabled.
   - `/health` succeeds through Application Gateway.
   - `/config-status` reports `KeyVault` and does not print the secret.

Run the canonical validation script `06-task-legacy-metadata-only-access-and-rotation.ps1` for legacy metadata-only access and rotation.

<validation step="06-task-legacy-metadata-only-access-and-rotation.ps1"/>

## Summary

You removed excessive resource-group Contributor access from `zava-app-legacy-id` and replaced it with the built-in **Key Vault Reader** role at the vault scope only. You verified that this role provides metadata visibility without `getSecret` or `setSecret`, then rotated `ZavaAppConnectionString` using your own **Key Vault Secrets Officer** access. The storefront remains healthy and continues to use Key Vault through the VM managed identity, while the legacy identity is constrained to metadata-only visibility.
