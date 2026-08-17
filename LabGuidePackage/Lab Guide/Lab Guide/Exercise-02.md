# Exercise 02: Deploy WAF_v2, enable diagnostics, then prove the block

### Estimated Duration: 95 Minutes

## Scenario

Zava Retail is no longer relying on unmanaged local secret material, but the storefront is still exposed directly from the VM. In this exercise, you will place an Azure Application Gateway WAF_v2 in front of the existing Windows storefront, enforce a deterministic custom WAF rule, and capture the firewall evidence in the provided Log Analytics workspace.

## Overview

You will deploy the Application Gateway yourself into the empty `appgw-subnet`, configure it to route HTTP traffic to the VM private IP, associate a WAF policy in **Prevention** mode, and add a custom block rule named `Block-ZavaAttack-Header`. The sequence matters: first make normal traffic work through the gateway, then enable diagnostics on the **Application Gateway resource itself**, and only after diagnostics are saved generate the WAF block event.

## Objectives

- Task 1: Discover the baseline resources and deployment variables
- Task 2: Create the WAF policy and custom header block rule
- Task 3: Deploy Application Gateway WAF_v2 in `appgw-subnet`
- Task 4: Confirm normal storefront traffic through the gateway
- Task 5: Enable Application Gateway diagnostics before the block test
- Task 6: Generate the custom-rule block and query WAF evidence
- Task 7: Remove direct VM public HTTP exposure while preserving gateway access

## Task 1: Discover the baseline resources and deployment variables

In this task, you will sign in and collect the resource names, IP addresses, and workspace information needed for the gateway deployment.

1. Sign in to the Azure portal at <https://portal.azure.com> with the lab credentials:

   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>

2. Open **Cloud Shell** from the Azure portal toolbar, select **Bash**, and set the correct subscription. Your subscription is <inject key="SubscriptionID"></inject>.

   ```bash
   read -p "Paste the Subscription ID shown in the lab guide: " SUBSCRIPTION_ID
   az account set --subscription "$SUBSCRIPTION_ID"
   az account show --query "{subscription:id, tenant:tenantId, user:user.name}" -o table
   ```

3. Set a variable for your lab deployment marker. Your deployment ID is <inject key="DeploymentID" enableCopy="false"></inject>.

   ```bash
   read -p "Paste the Deployment ID shown in the lab guide: " DID
   echo "Deployment ID: $DID"
   ```

4. Discover the resource group that contains the existing storefront VM named **zava-web-vm**. The fallback query is included only in case the lab environment contains a variant name that starts with `zava-web-vm`.

   ```bash
   RG=$(az vm list --query "[?name=='zava-web-vm'].resourceGroup | [0]" -o tsv)
   if [ -z "$RG" ]; then
     RG=$(az vm list --query "[?starts_with(name, 'zava-web-vm')].resourceGroup | [0]" -o tsv)
   fi
   echo "Resource group: $RG"
   ```

   > [!Tip]
   > If the variable is empty, run `az vm list -o table` and copy the resource group for the Zava storefront VM into `RG` manually.

5. Discover the VM, virtual network, Application Gateway subnet, VM private IP, VM public IP, and Log Analytics workspace. The exact VM name is `zava-web-vm`; the fallback query is only for discovery resilience.

   ```bash
   VM_NAME=$(az vm list -g "$RG" --query "[?name=='zava-web-vm'].name | [0]" -o tsv)
   if [ -z "$VM_NAME" ]; then
     VM_NAME=$(az vm list -g "$RG" --query "[?starts_with(name, 'zava-web-vm')].name | [0]" -o tsv)
   fi
   VNET_NAME=$(az network vnet list -g "$RG" --query "[0].name" -o tsv)
   APPGW_SUBNET_ID=$(az network vnet subnet show -g "$RG" --vnet-name "$VNET_NAME" -n appgw-subnet --query id -o tsv)
   VM_PRIVATE_IP=$(az vm list-ip-addresses -g "$RG" -n "$VM_NAME" --query "[0].virtualMachine.network.privateIpAddresses[0]" -o tsv)
   VM_PUBLIC_IP=$(az vm list-ip-addresses -g "$RG" -n "$VM_NAME" --query "[0].virtualMachine.network.publicIpAddresses[0].ipAddress" -o tsv)
   LAW_NAME=$(az monitor log-analytics workspace list -g "$RG" --query "[?starts_with(name, 'law-zava')].name | [0]" -o tsv)
   LAW_ID=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW_NAME" --query id -o tsv)

   echo "VM: $VM_NAME"
   echo "VNet: $VNET_NAME"
   echo "App Gateway subnet ID: $APPGW_SUBNET_ID"
   echo "VM private IP: $VM_PRIVATE_IP"
   echo "VM public IP: $VM_PUBLIC_IP"
   echo "Log Analytics workspace: $LAW_NAME"
   ```

6. Confirm the VM private endpoint is serving the storefront from inside Azure. This validates the backend before you create the gateway.

   ```bash
   az vm run-command invoke \
     -g "$RG" \
     -n "$VM_NAME" \
     --command-id RunPowerShellScript \
     --scripts "Invoke-WebRequest -UseBasicParsing http://localhost/health | Select-Object -ExpandProperty Content" \
     --query "value[0].message" -o tsv
   ```

## Task 2: Create the WAF policy and custom header block rule

In this task, you will create the WAF policy in Prevention mode and configure the custom rule before associating it with Application Gateway.

1. Create the WAF policy named `wafpol-zava`.

   ```bash
   az network application-gateway waf-policy create \
     --resource-group "$RG" \
     --name wafpol-zava \
     --location "$(az group show -n "$RG" --query location -o tsv)" \
     --type OWASP \
     --version 3.2
   ```

2. Put the WAF policy in **Prevention** mode.

   ```bash
   az network application-gateway waf-policy policy-setting update \
     --resource-group "$RG" \
     --policy-name wafpol-zava \
     --mode Prevention \
     --state Enabled
   ```

3. Create the mandatory custom rule named `Block-ZavaAttack-Header`. It blocks requests when request header `X-Zava-Attack` equals `true`.

   ```bash
   az network application-gateway waf-policy custom-rule create \
     --resource-group "$RG" \
     --policy-name wafpol-zava \
     --name Block-ZavaAttack-Header \
     --priority 10 \
     --rule-type MatchRule \
     --action Block

   az network application-gateway waf-policy custom-rule match-condition add \
     --resource-group "$RG" \
     --policy-name wafpol-zava \
     --name Block-ZavaAttack-Header \
     --match-variables RequestHeaders \
     --selector X-Zava-Attack \
     --operator Equal \
     --values true
   ```

4. Verify the policy mode and custom rule.

   ```bash
   az network application-gateway waf-policy show \
     -g "$RG" \
     -n wafpol-zava \
     --query "{mode:policySettings.mode, customRules:customRules[].{name:name, action:action, priority:priority, selector:matchConditions[0].matchVariables[0].selector, operator:matchConditions[0].operator, values:matchConditions[0].matchValues}}" \
     -o jsonc
   ```

   > [!Important]
   > Do not send the `X-Zava-Attack: true` test yet. The block test must happen only after the gateway exists, normal traffic works, and Application Gateway diagnostics are saved.

## Task 3: Deploy Application Gateway WAF_v2 in `appgw-subnet`

In this task, you will deploy the learner-created gateway into the reserved `appgw-subnet`, connect it to the VM private IP, and associate the WAF policy.

1. Create a public IP address for the Application Gateway frontend.

   ```bash
   az network public-ip create \
     --resource-group "$RG" \
     --name pip-agw-zava-waf \
     --sku Standard \
     --allocation-method Static \
     --location "$(az group show -n "$RG" --query location -o tsv)"
   ```

2. Create Application Gateway `agw-zava-waf` using the WAF_v2 SKU and the reserved `appgw-subnet`. This command creates the initial listener, backend pool, backend HTTP settings, and routing rule.

   > [!Important]
   > `appgw-subnet` is dedicated to Application Gateway. Microsoft Learn states that an Application Gateway subnet can't contain other resource types, and Standard_v2/WAF_v2 deployments recommend at least a `/24` subnet for scale headroom. Do not place VMs, private endpoints, or other resources in this subnet. Also do not attach restrictive NSG or UDR rules to `appgw-subnet` unless the gateway-required management, health, logging, and backend traffic paths are preserved.

   > [!Important]
   > To control lab cost and quota usage, keep WAF_v2 at `--capacity 1`. Do not enable autoscale beyond the lab capacity, availability zones, HTTPS certificates, extra Application Gateways, or extra listeners unless the lab instructions explicitly tell you to do so.

   ```bash
   WAF_POLICY_ID=$(az network application-gateway waf-policy show -g "$RG" -n wafpol-zava --query id -o tsv)

   az network application-gateway create \
     --resource-group "$RG" \
     --name agw-zava-waf \
     --location "$(az group show -n "$RG" --query location -o tsv)" \
     --sku WAF_v2 \
     --capacity 1 \
     --vnet-name "$VNET_NAME" \
     --subnet appgw-subnet \
     --public-ip-address pip-agw-zava-waf \
     --frontend-port 80 \
     --http-settings-port 80 \
     --http-settings-protocol Http \
     --routing-rule-type Basic \
     --servers "$VM_PRIVATE_IP" \
     --waf-policy "$WAF_POLICY_ID" \
     --priority 100
   ```

   > [!Note]
   > Application Gateway v2 provisioning can take several minutes. Keep `--capacity 1` for this lab, and do not increase capacity or add extra listeners unless instructed.

3. Create a health probe for `/health`, then attach it to the backend HTTP settings.

   ```bash
   az network application-gateway probe create \
     --resource-group "$RG" \
     --gateway-name agw-zava-waf \
     --name probe-zava-health \
     --protocol Http \
     --host 127.0.0.1 \
     --path /health \
     --interval 30 \
     --timeout 30 \
     --threshold 3

   HTTP_SETTINGS_NAME=$(az network application-gateway http-settings list \
     -g "$RG" \
     --gateway-name agw-zava-waf \
     --query "[0].name" -o tsv)

   az network application-gateway http-settings update \
     --resource-group "$RG" \
     --gateway-name agw-zava-waf \
     --name "$HTTP_SETTINGS_NAME" \
     --probe probe-zava-health
   ```

4. Verify that the gateway uses WAF_v2 and is associated with `wafpol-zava`.

   ```bash
   az network application-gateway show \
     -g "$RG" \
     -n agw-zava-waf \
     --query "{sku:sku.name, tier:sku.tier, subnet:gatewayIPConfigurations[0].subnet.id, wafPolicy:firewallPolicy.id}" \
     -o jsonc
   ```

5. Check backend health.

   ```bash
   az network application-gateway show-backend-health \
     -g "$RG" \
     -n agw-zava-waf \
     -o jsonc
   ```

   > [!Tip]
   > If the backend is unhealthy, confirm that the VM is running and that the NSG still permits HTTP from the Application Gateway subnet to the VM. Do not remove direct VM exposure until the final task.

## Task 4: Confirm normal storefront traffic through the gateway

In this task, you will prove that ordinary HTTP traffic reaches the storefront through Application Gateway before configuring diagnostics and before generating any blocked request.

1. Capture the Application Gateway public IP address.

   ```bash
   AGW_PUBLIC_IP=$(az network public-ip show -g "$RG" -n pip-agw-zava-waf --query ipAddress -o tsv)
   echo "Application Gateway public IP: $AGW_PUBLIC_IP"
   ```

2. Confirm the health endpoint through the gateway.

   ```bash
   curl -i "http://$AGW_PUBLIC_IP/health"
   ```

3. Confirm the storefront root page or status page through the gateway.

   ```bash
   curl -i "http://$AGW_PUBLIC_IP/"
   curl -i "http://$AGW_PUBLIC_IP/config-status"
   ```

4. Run the validation for the healthy gateway before continuing.

   <validation step="Application Gateway WAF_v2 and healthy routing"/>

   > [!Important]
   > The next task must be completed before the first malicious-header test. Diagnostic logs are not retrospective; a request sent before the diagnostic setting exists is not available later in Log Analytics.

## Task 5: Enable Application Gateway diagnostics before the block test

In this task, you will configure the diagnostic setting on the **Application Gateway resource itself**. The setting must send both `ApplicationGatewayFirewallLog` and `ApplicationGatewayAccessLog` to the provided Log Analytics workspace.

1. Get the Application Gateway resource ID.

   ```bash
   AGW_ID=$(az network application-gateway show -g "$RG" -n agw-zava-waf --query id -o tsv)
   echo "$AGW_ID"
   ```

2. Create a diagnostic setting on `agw-zava-waf`, not on `wafpol-zava`. Use resource-specific destination tables so firewall records land in `AGWFirewallLogs` and access records land in `AGWAccessLogs`.

   ```bash
   az monitor diagnostic-settings create \
     --name diag-agw-zava \
     --resource "$AGW_ID" \
     --workspace "$LAW_ID" \
     --export-to-resource-specific true \
     --logs '[
       {"category":"ApplicationGatewayFirewallLog","enabled":true},
       {"category":"ApplicationGatewayAccessLog","enabled":true}
     ]'
   ```

   > [!Note]
   > Enable only the two required log categories for this lab: `ApplicationGatewayFirewallLog` and `ApplicationGatewayAccessLog`. Do not enable extra log categories unless instructed.

3. Verify that the diagnostic setting is attached to the Application Gateway and that both categories are enabled.

   ```bash
   az monitor diagnostic-settings show \
     --name diag-agw-zava \
     --resource "$AGW_ID" \
     --query "{workspaceId:workspaceId, logAnalyticsDestinationType:logAnalyticsDestinationType, logs:logs[].{category:category, enabled:enabled}}" \
     -o jsonc
   ```

4. Pause and answer the diagnostic sequencing question.

   <question></question>

## Task 6: Generate the custom-rule block and query WAF evidence

In this task, you will send the first malicious-header test after diagnostics are enabled, confirm the block, and query Log Analytics for a firewall record that names `Block-ZavaAttack-Header` specifically.

1. Send a normal request again to keep an access-log comparison point.

   ```bash
   curl -i "http://$AGW_PUBLIC_IP/health"
   ```

2. Send the WAF test request with the custom header `X-Zava-Attack: true`.

   ```bash
   curl -i -H "X-Zava-Attack: true" "http://$AGW_PUBLIC_IP/health"
   ```

   The expected result is an HTTP 403-style response from the WAF because the policy is in Prevention mode and the custom rule action is Block.

3. Wait for Azure Monitor ingestion. Application Gateway logs are collected periodically and commonly require several minutes before they appear in Log Analytics.

   ```bash
   echo "Waiting 8 minutes for Application Gateway firewall and access logs to reach Log Analytics..."
   sleep 480
   ```

4. Query the resource-specific firewall table for the custom rule. This is the preferred schema when the diagnostic setting uses resource-specific destination tables.

   ```bash
   WORKSPACE_CUSTOMER_ID=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW_NAME" --query customerId -o tsv)

   az monitor log-analytics query \
     --workspace "$WORKSPACE_CUSTOMER_ID" \
     --analytics-query "AGWFirewallLogs
       | where TimeGenerated > ago(1h)
       | extend RuleText=tostring(column_ifexists('RuleId', ''))
       | extend DetailText=strcat(tostring(column_ifexists('Message', '')), ' ', tostring(column_ifexists('DetailedMessage', '')), ' ', tostring(column_ifexists('DetailedData', '')), ' ', tostring(column_ifexists('FileDetails', '')))
       | where RuleText == 'Block-ZavaAttack-Header' or DetailText has 'Block-ZavaAttack-Header'
       | project TimeGenerated,
           Action=tostring(column_ifexists('Action', '')),
           RuleId=RuleText,
           Message=tostring(column_ifexists('Message', '')),
           DetailedMessage=tostring(column_ifexists('DetailedMessage', '')),
           DetailedData=tostring(column_ifexists('DetailedData', '')),
           FileDetails=tostring(column_ifexists('FileDetails', '')),
           ClientIp=tostring(column_ifexists('ClientIp', '')),
           RequestUri=tostring(column_ifexists('RequestUri', '')),
           Hostname=tostring(column_ifexists('Hostname', ''))
       | order by TimeGenerated desc" \
     -o table
   ```

5. If the table returns no rows, wait a few more minutes and run the query again. If you intentionally chose Azure Diagnostics mode instead of resource-specific tables, use this fallback query against `AzureDiagnostics`.

   ```bash
   az monitor log-analytics query \
     --workspace "$WORKSPACE_CUSTOMER_ID" \
     --analytics-query "AzureDiagnostics
       | where TimeGenerated > ago(1h)
       | where ResourceProvider == 'MICROSOFT.NETWORK'
       | where Category == 'ApplicationGatewayFirewallLog'
       | extend RuleText=tostring(column_ifexists('ruleId_s', ''))
       | extend DetailText=strcat(tostring(column_ifexists('message_s', '')), ' ', tostring(column_ifexists('details_message_s', '')), ' ', tostring(column_ifexists('details_data_s', '')), ' ', tostring(column_ifexists('details_file_s', '')))
       | where RuleText == 'Block-ZavaAttack-Header' or DetailText has 'Block-ZavaAttack-Header'
       | project TimeGenerated,
           Action=tostring(column_ifexists('action_s', '')),
           RuleId=RuleText,
           Message=tostring(column_ifexists('message_s', '')),
           DetailText,
           ClientIp=tostring(column_ifexists('clientIp_s', '')),
           RequestUri=tostring(column_ifexists('requestUri_s', '')),
           Hostname=tostring(column_ifexists('hostname_s', ''))
       | order by TimeGenerated desc" \
     -o table
   ```

6. Query the access log to confirm ordinary traffic and the blocked request are both represented at the gateway layer.

   ```bash
   az monitor log-analytics query \
     --workspace "$WORKSPACE_CUSTOMER_ID" \
     --analytics-query "AGWAccessLogs
       | where TimeGenerated > ago(1h)
       | project TimeGenerated, HttpStatus, RequestUri, ClientIp, Host, UserAgent
       | order by TimeGenerated desc
       | take 20" \
     -o table
   ```

7. Run the canonical validation script `04-task-prevention-rule-diagnostics-and-logged-custom-rule-block.ps1` for the WAF policy, diagnostic setting, and logged custom-rule block.

   <validation step="04-task-prevention-rule-diagnostics-and-logged-custom-rule-block.ps1"/>

   > [!Important]
   > An HTTP 403 alone is not sufficient evidence for this lab. You must also have a firewall log record that identifies `Block-ZavaAttack-Header` specifically.

## Task 7: Remove direct VM public HTTP exposure while preserving gateway access

In this task, you will stop internet users from bypassing the gateway and reaching the VM public IP directly. The NSG that controls this traffic may be attached to the VM network interface or to the VM subnet. You will discover the effective NSG location, remove the direct internet HTTP allow rule, and preserve Application Gateway access to the backend.

1. Identify the VM network interface, derive the VM subnet and VNet from the NIC subnet ID, and discover the NSG from the NIC first with a subnet fallback.

   ```bash
   NIC_ID=$(az vm show -g "$RG" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv)
   NIC_NAME=$(basename "$NIC_ID")
   NIC_SUBNET_ID=$(az network nic show -g "$RG" -n "$NIC_NAME" --query "ipConfigurations[0].subnet.id" -o tsv)
   APP_SUBNET_NAME=$(basename "$NIC_SUBNET_ID")
   VNET_NAME=$(echo "$NIC_SUBNET_ID" | sed -n 's#^.*/virtualNetworks/\([^/]*\)/subnets/.*#\1#p')

   NSG_ID=$(az network nic show -g "$RG" -n "$NIC_NAME" --query "networkSecurityGroup.id" -o tsv)
   NSG_SCOPE="NIC"
   if [ -z "$NSG_ID" ]; then
     NSG_ID=$(az network vnet subnet show --ids "$NIC_SUBNET_ID" --query "networkSecurityGroup.id" -o tsv)
     NSG_SCOPE="subnet"
   fi

   if [ -z "$NSG_ID" ]; then
     echo "No NSG found on NIC $NIC_NAME or subnet $APP_SUBNET_NAME. Stop and verify the lab deployment."
     exit 1
   fi

   NSG_NAME=$(basename "$NSG_ID")
   echo "NIC: $NIC_NAME"
   echo "VM subnet: $APP_SUBNET_NAME"
   echo "VNet: $VNET_NAME"
   echo "NSG scope: $NSG_SCOPE"
   echo "NSG: $NSG_NAME"
   ```

2. Review inbound NSG rules that allow HTTP from the internet.

   ```bash
   az network nsg rule list \
     -g "$RG" \
     --nsg-name "$NSG_NAME" \
     --query "[?direction=='Inbound'].{name:name, priority:priority, access:access, source:sourceAddressPrefix, destinationPort:destinationPortRange}" \
     -o table
   ```

3. Remove the direct inbound HTTP allow rule named `Allow-HTTP-Direct-Internet` from the discovered NSG.

   ```bash
   az network nsg rule delete \
     -g "$RG" \
     --nsg-name "$NSG_NAME" \
     -n Allow-HTTP-Direct-Internet
   ```

4. Add an explicit allow rule for HTTP from `appgw-subnet` to the VM, if a suitable rule does not already exist. This preserves gateway-to-backend traffic after direct internet access is removed.

   ```bash
   APPGW_SUBNET_PREFIX=$(az network vnet subnet show -g "$RG" --vnet-name "$VNET_NAME" -n appgw-subnet --query addressPrefix -o tsv)

   az network nsg rule create \
     --resource-group "$RG" \
     --nsg-name "$NSG_NAME" \
     --name Allow-AppGateway-HTTP \
     --priority 120 \
     --direction Inbound \
     --access Allow \
     --protocol Tcp \
     --source-address-prefixes "$APPGW_SUBNET_PREFIX" \
     --source-port-ranges '*' \
     --destination-address-prefixes "$VM_PRIVATE_IP" \
     --destination-port-ranges 80
   ```

5. Test that direct VM public HTTP no longer works.

   ```bash
   curl -i --max-time 15 "http://$VM_PUBLIC_IP/health" || echo "Direct VM HTTP is blocked or unreachable, as expected."
   ```

6. Confirm the gateway path still works.

   ```bash
   curl -i "http://$AGW_PUBLIC_IP/health"
   ```

   > [!Success]
   > The discovered NSG should no longer contain an inbound **Allow** rule from `Internet` or `Any` to destination port `80`. At the same time, the Application Gateway `/health` request must still succeed through `http://$AGW_PUBLIC_IP/health`.

7. Run the validation for direct exposure removal.

   <validation step="Direct VM exposure removed"/>

## Summary

You deployed Application Gateway WAF_v2 into `appgw-subnet`, associated a WAF policy in Prevention mode, created the deterministic `Block-ZavaAttack-Header` custom rule, confirmed normal gateway traffic, enabled `ApplicationGatewayFirewallLog` and `ApplicationGatewayAccessLog` on the Application Gateway resource before the block test, and proved the custom-rule block in Log Analytics. You also removed the direct VM public HTTP path so public storefront traffic now flows through the WAF-protected gateway.