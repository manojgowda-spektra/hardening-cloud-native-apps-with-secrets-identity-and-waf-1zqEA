# Exercise 04: Validate and report the defense-in-depth controls

### Estimated Duration: 25 Minutes

## Scenario

Zava Retail is no longer the same application posture you inherited at the start of the lab. The secret should be governed by Key Vault, the VM should use its system-assigned managed identity at runtime, Application Gateway WAF_v2 should be the only public entry point, WAF telemetry should prove the custom block, and the legacy identity should have metadata-only visibility. In this exercise, you will collect end-to-end evidence and turn it into a concise hardening report.

## Overview

You will verify each control from the prior exercises using Azure CLI, HTTP tests, Log Analytics, and Azure RBAC review. The final output is a short report that maps the implemented control to the security benefit and the evidence you captured.

## Objectives

- Task 1: Establish your validation workspace and discover lab resources
- Task 2: Validate the Key Vault source, exact secret, VM identity, and secret rotation
- Task 3: Validate Application Gateway-only access and WAF blocking
- Task 4: Validate Application Gateway diagnostics and Log Analytics evidence
- Task 5: Validate legacy identity least privilege
- Task 6: Write the final hardening report

## Task 1: Establish your validation workspace and discover lab resources

In this task, you will sign in, select the lab subscription, and discover the resource names you need for the final validation. Use the Azure portal or Cloud Shell. If you use Cloud Shell, choose **Bash** for the commands in this exercise.

1. Sign in to the Azure portal at <https://portal.azure.com> with the following lab credentials:

   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>

2. Confirm that you are working in subscription <inject key="SubscriptionID"></inject> and tenant <inject key="TenantID"></inject>.

3. Open the lab resource group for deployment **zava-<inject key="DeploymentID" enableCopy="false"/>**. If your lab environment adds a prefix or suffix to the resource group name, use the resource group that contains `zava-web-vm`, `zava-app-legacy-id`, and the Log Analytics workspace.

4. Open **Cloud Shell** from the Azure portal and run the following commands to discover the actual resource names. The discovery checks the VM `zava-web-vm` first, then the legacy identity `zava-app-legacy-id`. If both lookups fail, use deployment **zava-<inject key="DeploymentID" enableCopy="false"/>** in the portal to identify the lab resource group and paste the resource group name when prompted.

   ```bash
   az account set --subscription "$(az account show --query id -o tsv)"

   VM_NAME="zava-web-vm"
   APPGW_NAME="agw-zava-waf"
   WAF_POLICY_NAME="wafpol-zava"
   LEGACY_ID_NAME="zava-app-legacy-id"
   SECRET_NAME="ZavaAppConnectionString"

   RG="$(az resource list --name "$VM_NAME" --resource-type "Microsoft.Compute/virtualMachines" --query "[0].resourceGroup" -o tsv)"
   if [ -z "$RG" ]; then
     RG="$(az resource list --name "$LEGACY_ID_NAME" --resource-type "Microsoft.ManagedIdentity/userAssignedIdentities" --query "[0].resourceGroup" -o tsv)"
   fi
   if [ -z "$RG" ]; then
     echo "VM and legacy identity lookup did not find the lab resource group."
     echo "Enter the resource group that contains $VM_NAME and $LEGACY_ID_NAME:"
     read -r RG
   fi

   KV_NAME="$(az keyvault list -g "$RG" --query "[?properties.enableRbacAuthorization==\`true\`].name | [0]" -o tsv)"
   LAW_NAME="$(az monitor log-analytics workspace list -g "$RG" --query "[0].name" -o tsv)"

   echo "Resource group: $RG"
   echo "Key Vault:      $KV_NAME"
   echo "Workspace:      $LAW_NAME"
   echo "VM:             $VM_NAME"
   echo "App Gateway:    $APPGW_NAME"
   echo "WAF policy:     $WAF_POLICY_NAME"
   echo "Legacy ID:      $LEGACY_ID_NAME"
   ```

5. If the resource group discovery did not work, set it manually in Cloud Shell to the lab resource group name you opened in the portal, then rerun the variable discovery lines:

   ```bash
   RG="replace-with-your-lab-resource-group-name"
   KV_NAME="$(az keyvault list -g "$RG" --query "[?properties.enableRbacAuthorization==\`true\`].name | [0]" -o tsv)"
   LAW_NAME="$(az monitor log-analytics workspace list -g "$RG" --query "[0].name" -o tsv)"
   ```

> [!Tip]
> This exercise is evidence-focused. Save command output or screenshots as you go. Your final report only needs to be concise, but it must include proof from each control area.

## Task 2: Validate the Key Vault source, exact secret, VM identity, and secret rotation

In this task, you will prove that the application resolves `ZavaAppConnectionString` from Key Vault through the VM system-assigned managed identity and that the secret has been rotated.

1. Confirm the Key Vault uses Azure RBAC authorization and capture its resource ID.

   ```bash
   KV_ID="$(az keyvault show -g "$RG" -n "$KV_NAME" --query id -o tsv)"
   az keyvault show -g "$RG" -n "$KV_NAME" \
     --query "{name:name, enableRbacAuthorization:properties.enableRbacAuthorization, id:id}" \
     -o table
   ```

2. Confirm the exact secret name `ZavaAppConnectionString` exists and has at least two enabled versions. The value is intentionally not printed.

   ```bash
   az keyvault secret show --vault-name "$KV_NAME" --name "$SECRET_NAME" \
     --query "{name:name, enabled:attributes.enabled, id:id}" -o table

   az keyvault secret list-versions --vault-name "$KV_NAME" --name "$SECRET_NAME" \
     --query "[].{version:id, enabled:attributes.enabled, created:attributes.created}" \
     -o table
   ```

3. Confirm the VM has a system-assigned managed identity.

   ```bash
   VM_PRINCIPAL_ID="$(az vm show -g "$RG" -n "$VM_NAME" --query identity.principalId -o tsv)"
   az vm show -g "$RG" -n "$VM_NAME" \
     --query "{name:name, identityType:identity.type, principalId:identity.principalId}" \
     -o table
   ```

4. Confirm the VM system-assigned managed identity has **Key Vault Secrets User** scoped to the vault.

   ```bash
   az role assignment list --assignee-object-id "$VM_PRINCIPAL_ID" --scope "$KV_ID" \
     --query "[].{principalId:principalId, role:roleDefinitionName, scope:scope}" \
     -o table
   ```

5. Retrieve the Application Gateway public endpoint and validate the storefront reports Key Vault as its source.

   ```bash
   APPGW_PUBLIC_IP_ID="$(az network application-gateway show -g "$RG" -n "$APPGW_NAME" --query "frontendIPConfigurations[0].publicIPAddress.id" -o tsv)"
   APPGW_IP="$(az network public-ip show --ids "$APPGW_PUBLIC_IP_ID" --query ipAddress -o tsv)"

   curl -i -L "http://$APPGW_IP/health"
   curl -s -L "http://$APPGW_IP/config-status"
   ```

6. Confirm your `/config-status` response shows `KeyVault` and does not reveal the connection string value.

<validation step="Learner-created vault, secret, and VM identity"/>

<validation step="Runtime identity and governed source"/>

## Task 3: Validate Application Gateway-only access and WAF blocking

In this task, you will prove that normal public traffic works through Application Gateway, the custom WAF request is blocked in Prevention mode, and direct VM HTTP exposure has been removed.

1. Confirm the Application Gateway is WAF_v2 and has a WAF policy associated.

   ```bash
   APPGW_ID="$(az network application-gateway show -g "$RG" -n "$APPGW_NAME" --query id -o tsv)"
   az network application-gateway show -g "$RG" -n "$APPGW_NAME" \
     --query "{name:name, skuName:sku.name, tier:sku.tier, firewallPolicy:firewallPolicy.id}" \
     -o table
   ```

2. Confirm the WAF policy is in **Prevention** mode and contains the custom rule `Block-ZavaAttack-Header` with a **Block** action.

   ```bash
   WAF_POLICY_ID="$(az network application-gateway waf-policy show -g "$RG" -n "$WAF_POLICY_NAME" --query id -o tsv)"
   az network application-gateway waf-policy show -g "$RG" -n "$WAF_POLICY_NAME" \
     --query "{name:name, mode:policySettings.mode, customRules:customRules[].{name:name, action:action, priority:priority}}" \
     -o json
   ```

3. Send a normal request through Application Gateway and confirm the storefront returns successfully.

   ```bash
   curl -i "http://$APPGW_IP/"
   curl -i -L "http://$APPGW_IP/health"
   ```

4. Send the deterministic WAF test request through Application Gateway. The expected result is an HTTP 403 response because the request includes `X-Zava-Attack: true` and the WAF policy is in Prevention mode.

   ```bash
   curl -i -H "X-Zava-Attack: true" "http://$APPGW_IP/"
   ```

5. Discover the VM public IP, if one remains attached, and confirm direct HTTP is not reachable. A timeout, connection failure, or non-HTTP response is acceptable evidence. Do not remove the Application Gateway backend path.

   ```bash
   VM_PUBLIC_IP_ID="$(az vm list-ip-addresses -g "$RG" -n "$VM_NAME" --query "[0].virtualMachine.network.publicIpAddresses[0].id" -o tsv)"
   if [ -n "$VM_PUBLIC_IP_ID" ]; then
     VM_PUBLIC_IP="$(az network public-ip show --ids "$VM_PUBLIC_IP_ID" --query ipAddress -o tsv)"
     echo "Testing direct VM HTTP endpoint: $VM_PUBLIC_IP"
     timeout 15 curl -i "http://$VM_PUBLIC_IP/" || echo "Direct VM HTTP is not reachable, as expected."
   else
     echo "No VM public IP is attached. Direct VM HTTP exposure is removed."
   fi
   ```

<validation step="Application Gateway WAF_v2 and healthy routing"/>

<validation step="Direct VM exposure removed"/>

## Task 4: Validate Application Gateway diagnostics and Log Analytics evidence

In this task, you will prove that the block is visible in Application Gateway firewall telemetry and that the log record names `Block-ZavaAttack-Header` specifically.

1. Confirm diagnostic settings are attached to the **Application Gateway** resource and send both required categories to the lab Log Analytics workspace.

   ```bash
   LAW_ID="$(az monitor log-analytics workspace show -g "$RG" -n "$LAW_NAME" --query id -o tsv)"
   LAW_CUSTOMER_ID="$(az monitor log-analytics workspace show -g "$RG" -n "$LAW_NAME" --query customerId -o tsv)"

   az monitor diagnostic-settings list --resource "$APPGW_ID" \
     --query "[].{name:name, workspaceId:workspaceId, logs:logs[].{category:category, enabled:enabled}}" \
     -o json
   ```

2. Wait a few minutes if you generated the WAF request recently. Azure Monitor ingestion is not instantaneous, and firewall logs are collected after diagnostics are enabled.

3. Query resource-specific Application Gateway firewall logs first. This table is used when diagnostics are configured for resource-specific destination tables.

   ```bash
   az monitor log-analytics query --workspace "$LAW_CUSTOMER_ID" --timespan PT1H \
     --analytics-query "AGWFirewallLogs | extend RuleIdValue = tostring(column_ifexists(\"RuleId\", \"\")), MessageValue = tostring(column_ifexists(\"Message\", \"\")), DetailedMessageValue = tostring(column_ifexists(\"DetailedMessage\", \"\")), DetailedDataValue = tostring(column_ifexists(\"DetailedData\", \"\")), FileDetailsValue = tostring(column_ifexists(\"FileDetails\", \"\")), ActionValue = tostring(column_ifexists(\"Action\", \"\")), ClientIpValue = tostring(column_ifexists(\"ClientIp\", \"\")), RequestUriValue = tostring(column_ifexists(\"RequestUri\", \"\")), HostnameValue = tostring(column_ifexists(\"Hostname\", \"\")) | where ActionValue has 'Blocked' | where RuleIdValue == 'Block-ZavaAttack-Header' or MessageValue has 'Block-ZavaAttack-Header' or DetailedMessageValue has 'Block-ZavaAttack-Header' or DetailedDataValue has 'Block-ZavaAttack-Header' or FileDetailsValue has 'Block-ZavaAttack-Header' | project TimeGenerated, Action = ActionValue, RuleId = RuleIdValue, Message = MessageValue, DetailedMessage = DetailedMessageValue, DetailedData = DetailedDataValue, FileDetails = FileDetailsValue, ClientIp = ClientIpValue, RequestUri = RequestUriValue, Hostname = HostnameValue | order by TimeGenerated desc | take 10" \
     -o table
   ```

4. If the previous query returns no rows, query the classic `AzureDiagnostics` table. This table is used by many Application Gateway diagnostic settings and stores firewall fields with suffixes such as `ruleId_s` and `action_s`.

   ```bash
   az monitor log-analytics query --workspace "$LAW_CUSTOMER_ID" --timespan PT1H \
     --analytics-query "AzureDiagnostics | extend ResourceProviderValue = tostring(column_ifexists(\"ResourceProvider\", \"\")), CategoryValue = tostring(column_ifexists(\"Category\", \"\")), ActionValue = tostring(column_ifexists(\"action_s\", column_ifexists(\"Action\", \"\"))), RuleIdValue = tostring(column_ifexists(\"ruleId_s\", column_ifexists(\"RuleId\", \"\"))), MessageValue = tostring(column_ifexists(\"message_s\", column_ifexists(\"Message\", \"\"))), DetailedMessageValue = tostring(column_ifexists(\"details_message_s\", column_ifexists(\"DetailedMessage\", \"\"))), DetailedDataValue = tostring(column_ifexists(\"details_data_s\", column_ifexists(\"DetailedData\", \"\"))), FileDetailsValue = tostring(column_ifexists(\"details_file_s\", column_ifexists(\"FileDetails\", \"\"))), ClientIpValue = tostring(column_ifexists(\"clientIp_s\", column_ifexists(\"ClientIp\", \"\"))), RequestUriValue = tostring(column_ifexists(\"requestUri_s\", column_ifexists(\"RequestUri\", \"\"))), HostnameValue = tostring(column_ifexists(\"hostname_s\", column_ifexists(\"Hostname\", \"\"))) | where ResourceProviderValue =~ 'MICROSOFT.NETWORK' and CategoryValue == 'ApplicationGatewayFirewallLog' | where ActionValue has 'Blocked' | where RuleIdValue == 'Block-ZavaAttack-Header' or MessageValue has 'Block-ZavaAttack-Header' or DetailedMessageValue has 'Block-ZavaAttack-Header' or DetailedDataValue has 'Block-ZavaAttack-Header' or FileDetailsValue has 'Block-ZavaAttack-Header' | project TimeGenerated, Action = ActionValue, RuleId = RuleIdValue, Message = MessageValue, DetailedMessage = DetailedMessageValue, DetailedData = DetailedDataValue, FileDetails = FileDetailsValue, ClientIp = ClientIpValue, RequestUri = RequestUriValue, Hostname = HostnameValue | order by TimeGenerated desc | take 10" \
     -o table
   ```

5. Capture a row that shows a blocked action and names `Block-ZavaAttack-Header`. If neither query returns a row, repeat the WAF test request from Task 3, wait 5 to 10 minutes, and rerun both queries.

> [!Important]
> An HTTP 403 alone is not enough final evidence. You need a matching Application Gateway firewall log entry that identifies `Block-ZavaAttack-Header`; otherwise you have not proven which control blocked the request.

Run the canonical validation script `04-task-prevention-rule-diagnostics-and-logged-custom-rule-block.ps1` for Prevention mode, the custom WAF rule, Application Gateway diagnostics, and the logged block.

<validation step="04-task-prevention-rule-diagnostics-and-logged-custom-rule-block.ps1"/>

## Task 5: Validate legacy identity least privilege

In this task, you will prove that `zava-app-legacy-id` no longer has resource-group Contributor and has only **Key Vault Reader** scoped to the vault.

1. Resolve the legacy user-assigned managed identity principal ID.

   ```bash
   LEGACY_PRINCIPAL_ID="$(az identity show -g "$RG" -n "$LEGACY_ID_NAME" --query principalId -o tsv)"
   az identity show -g "$RG" -n "$LEGACY_ID_NAME" \
     --query "{name:name, principalId:principalId, clientId:clientId}" \
     -o table
   ```

2. Confirm there is no remaining **Contributor** assignment for the legacy identity at the resource group scope.

   ```bash
   RG_ID="$(az group show -n "$RG" --query id -o tsv)"
   az role assignment list --assignee-object-id "$LEGACY_PRINCIPAL_ID" --scope "$RG_ID" \
     --include-inherited \
     --query "[?roleDefinitionName=='Contributor'].{role:roleDefinitionName, scope:scope}" \
     -o table
   ```

   The expected output is an empty table.

3. Confirm the legacy identity has **Key Vault Reader** scoped exactly to the Key Vault.

   ```bash
   az role assignment list --assignee-object-id "$LEGACY_PRINCIPAL_ID" --scope "$KV_ID" \
     --query "[].{role:roleDefinitionName, scope:scope}" \
     -o table
   ```

4. Confirm the legacy identity does not have any known secret-value or secret-write role through inherited assignments.

   ```bash
   az role assignment list --assignee-object-id "$LEGACY_PRINCIPAL_ID" --scope "$KV_ID" \
     --include-inherited \
     --query "[?contains(roleDefinitionName, 'Secrets User') || contains(roleDefinitionName, 'Secrets Officer') || contains(roleDefinitionName, 'Key Vault Administrator') || roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].{role:roleDefinitionName, scope:scope}" \
     -o table
   ```

   The expected output is an empty table. **Key Vault Reader** can read vault and secret metadata, but it cannot retrieve sensitive secret values.

Run the canonical validation script `06-task-legacy-metadata-only-access-and-rotation.ps1` for legacy metadata-only access and secret rotation.

<validation step="06-task-legacy-metadata-only-access-and-rotation.ps1"/>

<question></question>

## Task 6: Write the final hardening report

In this task, you will produce a concise report that ties the technical evidence to the security benefit.

1. Create a short report named `zava-hardening-report.md` in Cloud Shell.

   ```bash
   cat > zava-hardening-report.md <<'EOF'
   # Zava Retail hardening report

   ## Environment
   - Resource group:
   - Key Vault:
   - Application Gateway:
   - WAF policy:
   - Log Analytics workspace:

   ## Evidence summary
   | Control | Evidence captured | Security benefit |
   | --- | --- | --- |
   | Key Vault source for ZavaAppConnectionString | /config-status reports KeyVault; secret exists in Key Vault | Removes unmanaged plaintext as the authoritative runtime source |
   | VM system-assigned identity | VM has a principal ID and Key Vault Secrets User at vault scope | Gives the app secret read access without embedded credentials |
   | Secret rotation | ZavaAppConnectionString has at least two enabled versions; app remains healthy | Proves rotation can occur without rebuilding the app |
   | Application Gateway WAF_v2 entry point | Normal gateway /health request succeeds | Places public ingress behind a managed edge control |
   | Custom WAF block | X-Zava-Attack: true returns blocked response in Prevention mode | Enforces deterministic application-specific blocking |
   | WAF telemetry | Log Analytics firewall row names Block-ZavaAttack-Header | Proves the edge control, not an unrelated component, blocked the request |
   | Direct VM exposure removed | Direct VM HTTP is unreachable or no VM public IP remains | Prevents bypass of Application Gateway and WAF |
   | Legacy identity least privilege | No RG Contributor; only Key Vault Reader at vault scope | Preserves metadata visibility without a route to secret values |

   ## Final posture statement
   Zava Retail now uses governed secret retrieval through managed identity, exposes public traffic through Application Gateway WAF_v2, records WAF enforcement in Log Analytics, blocks direct VM HTTP access, and limits the legacy identity to metadata-only Key Vault visibility.
   EOF
   ```

2. Edit the report and fill in the evidence you captured in Tasks 2 through 5.

   ```bash
   code zava-hardening-report.md
   ```

3. Use the report as your final submission artifact for the exercise. It should be brief, but every row must include evidence that you personally verified.

## Summary

You validated the final defense-in-depth posture for Zava Retail. You proved that the exact secret `ZavaAppConnectionString` is governed and rotated in Key Vault, the application uses VM managed identity, Application Gateway WAF_v2 is the public entry point, the custom `Block-ZavaAttack-Header` rule blocks in Prevention mode with Log Analytics evidence, direct VM HTTP access is removed, and `zava-app-legacy-id` has only metadata-only Key Vault Reader access.