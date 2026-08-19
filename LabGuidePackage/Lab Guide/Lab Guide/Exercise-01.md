# Exercise 01: Create the vault and govern the secret with managed identity

### Estimated Duration: 75 Minutes

## Scenario

Zava Retail is running from a Windows VM, but its sample connection string is still stored as unmanaged plaintext application configuration. In this exercise, you will move that sample security artifact into a learner-created Azure Key Vault that uses Azure RBAC authorization, then configure the existing storefront to retrieve the secret by using the VM system-assigned managed identity. The connection string is only a sample artifact for governance practice; there is no backing database and no database connection test in this lab.

## Overview

You will inspect the insecure baseline, create a Key Vault, grant your own lab account the correct data-plane role before storing the secret, enable the VM system-assigned managed identity, grant that identity read-only secret access, and switch the storefront to use Key Vault as the authoritative configuration source.

## Objectives

- Task 1: Sign in, locate the lab resources, and inspect the plaintext baseline
- Task 2: Create an Azure RBAC-mode Key Vault and assign yourself Key Vault Secrets Officer
- Task 3: Store the exact secret `ZavaAppConnectionString`
- Task 4: Enable the VM system-assigned managed identity and grant Key Vault Secrets User
- Task 5: Switch the storefront to Key Vault and neutralize local plaintext authority
- Task 6: Verify health, source status, and least-privilege evidence

## Task 1: Sign in, locate the lab resources, and inspect the plaintext baseline

In this task, you will sign in to Azure, find the Zava Retail resource group for this deployment, confirm that the app currently uses local configuration, and inspect the sample plaintext connection string on the VM.

1. Open a browser and go to <https://portal.azure.com>.

2. Sign in with your lab credentials:

   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>

3. Confirm that you are working in the correct Azure context:

   - Subscription: <inject key="SubscriptionID"></inject>
   - Tenant: <inject key="TenantID"></inject>
   - Deployment ID: <inject key="DeploymentID" enableCopy="false"/>

4. Open **Cloud Shell** from the Azure portal toolbar. Choose **Bash** if prompted.

5. In Cloud Shell, set your subscription and locate the resource group. When prompted, paste the subscription ID and deployment ID shown in the previous step.

   ```bash
   read -p "Paste the subscription ID: " SUBSCRIPTION_ID
   az account set --subscription "$SUBSCRIPTION_ID"

   read -p "Paste the deployment ID: " DID
   RG=$(az group list --query "[?contains(name, '$DID')].name | [0]" -o tsv)

   if [ -z "$RG" ]; then
     echo "No resource group name contained the deployment ID. Listing resource groups so you can choose the Zava lab group."
     az group list --query "[].{name:name, location:location}" -o table
     read -p "Paste the Zava lab resource group name: " RG
   fi

   echo "Using resource group: $RG"
   ```

   In the portal, the lab resources are in the Zava deployment resource group associated with **zava-<inject key="DeploymentID" enableCopy="false"/>**.

6. Locate the storefront VM and its direct public endpoint.

   ```bash
   VM_NAME=$(az vm list -g "$RG" --query "[?name=='zava-web-vm'].name | [0]" -o tsv)

   if [ -z "$VM_NAME" ]; then
     VM_NAME=$(az vm list -g "$RG" --query "[?contains(name, 'zava') && contains(name, 'vm')].name | [0]" -o tsv)
   fi

   VM_PIP=$(az vm list-ip-addresses -g "$RG" -n "$VM_NAME" --query "[0].virtualMachine.network.publicIpAddresses[0].ipAddress" -o tsv)

   echo "VM name: $VM_NAME"
   echo "VM public IP: $VM_PIP"
   ```

7. Confirm the insecure starting state. The `/health` endpoint should succeed, and `/config-status` should report a local source.

   ```bash
   curl -iL "http://$VM_PIP/health"
   echo
   curl -iL "http://$VM_PIP/config-status"
   ```

8. Inspect the CSE-created local configuration files on the VM. This command reads the actual Zava Retail files created during deployment and prints only the evidence you need, without requiring Remote Desktop.

   ```bash
   az vm run-command invoke \
     --resource-group "$RG" \
     --name "$VM_NAME" \
     --command-id RunPowerShellScript \
     --scripts '
   $files = @(
     "C:\ZavaRetail\Config\plaintext-connection-string.txt",
     "C:\ZavaRetail\Config\zava-config.json"
   )

   foreach ($file in $files) {
     if (Test-Path $file) {
       Write-Host "Found file: $file"
       if ($file -like "*plaintext-connection-string.txt") {
         Get-Content -Path $file | Select-String -Pattern "ZavaAppConnectionString|Server=|Database=|ConnectionString"
       }
       else {
         Get-Content -Path $file | Select-String -Pattern "Source|Local|KeyVault|VaultName|SecretName|LastUpdated"
       }
     }
     else {
       Write-Host "Missing expected file: $file"
     }
   }
   ' \
     --query "value[].message" \
     -o tsv
   ```

   Successful output should show the sample connection string from `C:\ZavaRetail\Config\plaintext-connection-string.txt` and configuration metadata from `C:\ZavaRetail\Config\zava-config.json`, including `Source` set to `Local`.

9. Keep the sample connection string value in your terminal context so you can paste it directly into the later `read -s` prompt in Task 3. If you need a short-term holding place, store it only in a shell variable for the current Cloud Shell session. Do not include the value in screenshots, notes, transcripts, or final evidence.

> [!Important]
> Treat the connection string as a lab security artifact. Do not create a database, do not test database connectivity, and do not broaden permissions to make a database test work. The storefront never opens a database connection in this lab.

## Task 2: Create an Azure RBAC-mode Key Vault and assign yourself Key Vault Secrets Officer

In this task, you will create the vault yourself and explicitly grant your own signed-in lab account a Key Vault data-plane role. In an Azure RBAC-mode vault, management-plane permissions such as resource-group Owner or Contributor are not the same as permission to create or read secret values.

1. Create a globally unique Key Vault name, then create the vault in the lab resource group with Azure RBAC authorization enabled.

   ```bash
   LOCATION=$(az group show --name "$RG" --query location -o tsv)
   KV_NAME="kv-zava-${DID:0:8}-$RANDOM"
   KV_NAME=$(echo "$KV_NAME" | tr '[:upper:]' '[:lower:]' | cut -c1-24)

   echo "Creating Key Vault: $KV_NAME"
   az keyvault create \
     --name "$KV_NAME" \
     --resource-group "$RG" \
     --location "$LOCATION" \
     --enable-rbac-authorization true \
     --retention-days 7 \
     --output table
   ```

   If the vault name is already taken, choose a new name that starts with `kv-zava-`, uses only letters, numbers, and hyphens, and is no more than 24 characters long.

2. Verify that the vault uses Azure RBAC authorization.

   ```bash
   az keyvault show \
     --name "$KV_NAME" \
     --query "{name:name, enableRbacAuthorization:properties.enableRbacAuthorization}" \
     -o table
   ```

   The `enableRbacAuthorization` value must be `true`.

3. Get your signed-in user object ID and the vault resource ID.

   ```bash
   USER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)
   KV_ID=$(az keyvault show --name "$KV_NAME" --query id -o tsv)

   echo "Signed-in user object ID: $USER_OBJECT_ID"
   echo "Key Vault resource ID: $KV_ID"
   ```

4. Assign your own lab account the built-in **Key Vault Secrets Officer** role scoped to the vault.

   ```bash
   az role assignment create \
     --role "Key Vault Secrets Officer" \
     --assignee-object-id "$USER_OBJECT_ID" \
     --assignee-principal-type User \
     --scope "$KV_ID" \
     --output table
   ```

5. Wait for role propagation to the Key Vault data plane. Run the following loop until it can list secrets successfully.

   ```bash
   echo "Waiting for Key Vault data-plane RBAC propagation..."
   for i in {1..12}; do
     if az keyvault secret list --vault-name "$KV_NAME" --query "[].name" -o tsv >/dev/null 2>&1; then
       echo "Key Vault data-plane access is ready."
       break
     fi
     echo "Access is not ready yet. Waiting 30 seconds..."
     sleep 30
   done
   ```

> [!Important]
> A `Forbidden` response immediately after creating the role assignment usually means the Key Vault data-plane role has not propagated yet. Wait and retry. Do not assign yourself Owner, Contributor, Key Vault Administrator, or broad subscription-level permissions to bypass propagation.

<question></question>

## Task 3: Store the exact secret `ZavaAppConnectionString`

In this task, you will store the sample plaintext value from the VM as a governed Key Vault secret. The secret name must be exactly `ZavaAppConnectionString`, including capitalization.

1. Paste the sample connection string you copied in Task 1 when prompted. The `read -s` option prevents the value from being echoed to the Cloud Shell screen.

   ```bash
   read -s -p "Paste the sample Zava connection string: " ZAVA_CONN
   echo

   az keyvault secret set \
     --vault-name "$KV_NAME" \
     --name "ZavaAppConnectionString" \
     --value "$ZAVA_CONN" \
     --output table

   unset ZAVA_CONN
   ```

2. Verify that the secret exists and is enabled without printing the secret value.

   ```bash
   az keyvault secret show \
     --vault-name "$KV_NAME" \
     --name "ZavaAppConnectionString" \
     --query "{name:name, enabled:attributes.enabled, id:id}" \
     -o table
   ```

3. Record the vault name for later exercises.

   ```bash
   echo "$KV_NAME" > zava-keyvault-name.txt
   echo "Saved vault name to zava-keyvault-name.txt"
   ```

## Task 4: Enable the VM system-assigned managed identity and grant Key Vault Secrets User

In this task, you will enable the VM identity that the storefront will use at runtime. The VM identity receives only the built-in **Key Vault Secrets User** role at vault scope so it can read secret contents; it does not receive Contributor, Owner, Secrets Officer, or any secret-write role.

1. Enable the system-assigned managed identity on the existing VM.

   ```bash
   VM_PRINCIPAL_ID=$(az vm identity assign \
     --resource-group "$RG" \
     --name "$VM_NAME" \
     --query principalId \
     -o tsv)

   if [ -z "$VM_PRINCIPAL_ID" ]; then
     VM_PRINCIPAL_ID=$(az vm show -g "$RG" -n "$VM_NAME" --query identity.principalId -o tsv)
   fi

   echo "VM system-assigned managed identity principal ID: $VM_PRINCIPAL_ID"
   ```

2. Verify that the VM identity type includes `SystemAssigned`.

   ```bash
   az vm show \
     --resource-group "$RG" \
     --name "$VM_NAME" \
     --query "{name:name, identityType:identity.type, principalId:identity.principalId}" \
     -o table
   ```

3. Assign the VM system-assigned identity the built-in **Key Vault Secrets User** role at the vault scope.

   ```bash
   az role assignment create \
     --role "Key Vault Secrets User" \
     --assignee-object-id "$VM_PRINCIPAL_ID" \
     --assignee-principal-type ServicePrincipal \
     --scope "$KV_ID" \
     --output table
   ```

4. Confirm the VM identity role assignment at the vault scope.

   ```bash
   az role assignment list \
     --assignee "$VM_PRINCIPAL_ID" \
     --scope "$KV_ID" \
     --query "[].{principalId:principalId, role:roleDefinitionName, scope:scope}" \
     -o table
   ```

5. Wait several minutes for the role assignment to become effective for the VM identity.

   ```bash
   echo "Waiting 3 minutes for VM identity data-plane access to propagate..."
   sleep 180
   ```

> [!Tip]
> Key Vault Secrets User is the runtime read role. Your own account uses Key Vault Secrets Officer to administer and rotate the secret, but the VM identity should not be able to set, delete, or rotate secret values.

<validation step="Learner-created vault, secret, and VM identity"/>

## Task 5: Switch the storefront to Key Vault and neutralize local plaintext authority

In this task, you will use the prepared Zava Retail helper on the VM to change the existing application configuration source from local plaintext to Key Vault via the VM system-assigned managed identity.

1. Run the helper script on the VM. The helper configures the app to request `ZavaAppConnectionString` from your vault by using managed identity, removes the local plaintext value as the authoritative runtime source, and tests retrieval before reporting success.

   ```bash
   az vm run-command invoke \
     --resource-group "$RG" \
     --name "$VM_NAME" \
     --command-id RunPowerShellScript \
     --scripts "C:\ZavaRetail\Tools\Set-ZavaSecretSource.ps1 -Source KeyVault -VaultName '$KV_NAME' -RemoveLocalPlaintext -TestRetrieval" \
     --query "value[].message" \
     -o tsv
   ```

2. Restart IIS so the storefront reloads its configuration.

   ```bash
   az vm run-command invoke \
     --resource-group "$RG" \
     --name "$VM_NAME" \
     --command-id RunPowerShellScript \
     --scripts "iisreset" \
     --query "value[].message" \
     -o tsv
   ```

3. Inspect the app status through the direct VM endpoint. Direct VM HTTP is still intentionally open in Exercise 1; you will remove direct exposure after Application Gateway is deployed in a later exercise.

   ```bash
   curl -iL "http://$VM_PIP/health"
   echo
   curl -iL "http://$VM_PIP/config-status"
   ```

   The `/health` response should succeed. The `/config-status` response should report `KeyVault` and must not reveal the connection string value.

> [!Note]
> If `/config-status` still reports `Local`, wait another minute for identity or Key Vault RBAC propagation, rerun the helper, restart IIS, and test again. Do not create a database or add broad permissions.

## Task 6: Verify health, source status, and least-privilege evidence

In this task, you will gather the evidence required for the Exercise 1 validation checkpoint.

1. Confirm the vault, exact secret name, and enabled status.

   ```bash
   az keyvault show \
     --name "$KV_NAME" \
     --query "{name:name, resourceGroup:resourceGroup, rbac:properties.enableRbacAuthorization}" \
     -o table

   az keyvault secret show \
     --vault-name "$KV_NAME" \
     --name "ZavaAppConnectionString" \
     --query "{name:name, enabled:attributes.enabled}" \
     -o table
   ```

2. Confirm your own account has **Key Vault Secrets Officer** scoped to the vault.

   ```bash
   az role assignment list \
     --assignee "$USER_OBJECT_ID" \
     --scope "$KV_ID" \
     --query "[?roleDefinitionName=='Key Vault Secrets Officer'].{role:roleDefinitionName, scope:scope}" \
     -o table
   ```

3. Confirm the VM system-assigned identity has **Key Vault Secrets User** scoped to the vault.

   ```bash
   az role assignment list \
     --assignee "$VM_PRINCIPAL_ID" \
     --scope "$KV_ID" \
     --query "[?roleDefinitionName=='Key Vault Secrets User'].{role:roleDefinitionName, scope:scope}" \
     -o table
   ```

4. Confirm the VM identity does not have broad resource-group access in this exercise.

   ```bash
   RG_ID=$(az group show --name "$RG" --query id -o tsv)

   az role assignment list \
     --assignee "$VM_PRINCIPAL_ID" \
     --scope "$RG_ID" \
     --include-inherited \
     --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor' || roleDefinitionName=='Key Vault Secrets Officer'].{role:roleDefinitionName, scope:scope}" \
     -o table
   ```

   The output should be empty.

5. Confirm application health and source status one more time.

   ```bash
   curl -sL "http://$VM_PIP/health"
   echo
   curl -sL "http://$VM_PIP/config-status"
   echo
   ```

   Expected evidence:

   - `/health` succeeds.
   - `/config-status` reports `KeyVault`.
   - The response does not expose the secret value.

<validation step="Runtime identity and governed source"/>

## Summary

You created an Azure RBAC-mode Key Vault, assigned your own lab account Key Vault Secrets Officer before storing the exact `ZavaAppConnectionString` secret, enabled the VM system-assigned managed identity, granted that identity only Key Vault Secrets User at vault scope, and switched the existing Zava Retail storefront to use Key Vault as its runtime configuration source. The sample connection string is now governed by Key Vault and retrieved through managed identity, with no database created or tested.