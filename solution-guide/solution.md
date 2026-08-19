# Facilitator Solution Guide

# Hardening Cloud-Native Apps with Secrets, Identity, and WAF

Assess outcomes rather than command-line conformity. Resource names may vary except for `zava-web-vm`, `ZavaAppConnectionString`, `BlockZavaAttackHeader`, and `zava-app-legacy-id`. The connection string is a sample security artifact: **there is no database and no database test is valid**.

Set assessment variables to discovered resource names. Prefer locating the resource group from the known VM or legacy identity rather than by a broad name match:

```bash
RG=$(az vm list --query "[?name=='zava-web-vm'].resourceGroup | [0]" -o tsv)
[ -z "$RG" ] && RG=$(az identity list --query "[?name=='zava-app-legacy-id'].resourceGroup | [0]" -o tsv)
VM='zava-web-vm'
KV='set-learner-vault-name'
AGW='set-learner-gateway-name'
LAW='set-provided-workspace-name'
RG_ID=$(az group show -n "$RG" --query id -o tsv)
KV_ID=$(az keyvault show -g "$RG" -n "$KV" --query id -o tsv)
AGW_ID=$(az network application-gateway show -g "$RG" -n "$AGW" --query id -o tsv)
LAW_ID=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query id -o tsv)
```

Built-in role IDs: Secrets Officer `b86a8fe4-44ce-4948-aee5-eccb2c155cd7`; Secrets User `4633458b-17de-408a-b874-0445c86b69e6`; Key Vault Reader `21090545-7ca7-4776-b22c-e363652d74d2`; Contributor `b24988ac-6180-42a0-ab88-20f7382dd24c`.

## Exercise 1 — Create the vault and govern the secret

### Task 1.1 — Identify the plaintext sample

**Answer / expected end state:** Learner locates the deployed sample value at `C:\ZavaRetail\Config\plaintext-connection-string.txt` and the source metadata at `C:\ZavaRetail\Config\zava-config.json`, does not disclose the value in evidence, and recognizes that it has no backing database.

```powershell
Test-Path 'C:\ZavaRetail\Config\plaintext-connection-string.txt'
Get-Content 'C:\ZavaRetail\Config\zava-config.json' | ConvertFrom-Json |
  Select-Object Source, SecretName, VaultName, LocalPlaintextPath
```

**Rubric**
- **Full:** Correct files and setting identified and secret value redacted; no database is created or tested.
- **Partial:** Correct setting found but exposed in evidence.
- **No credit:** A different value is invented or a database is provisioned.

**Common pitfalls:** Printing `C:\ZavaRetail\Config\plaintext-connection-string.txt` to a transcript; overlooking `C:\ZavaRetail\Config\zava-config.json`; deleting the plaintext before vault retrieval works; attempting SQL connectivity.

### Task 1.2 — Create an RBAC-mode vault

**Answer / expected end state:** The learner—not ARM—creates a globally unique vault in the lab resource group with Azure RBAC authorization enabled.

```bash
az keyvault show -g "$RG" -n "$KV" \
  --query '{id:id,location:location,rbac:properties.enableRbacAuthorization}' -o json
```

**Rubric**
- **Full:** Learner-created vault, correct resource group, `rbac` is true.
- **Partial:** Wrong region/group is corrected.
- **No credit:** Access-policy vault or pre-provisioned vault.

**Common pitfalls:** Global name collision; soft-deleted vault blocks recreation; wrong region. Recover/purge only when lab permissions permit.

### Task 1.3 — Assign learner Secrets Officer and create the exact secret

**Answer / expected end state:** The signed-in learner has **Key Vault Secrets Officer** at vault scope. After propagation, that learner creates enabled secret `ZavaAppConnectionString` containing the original sample value.

```bash
ME=$(az ad signed-in-user show --query id -o tsv)
az role assignment list --assignee "$ME" --scope "$KV_ID" --include-inherited \
  --query "[?roleDefinitionName=='Key Vault Secrets Officer'].{role:roleDefinitionName,scope:scope}" -o table
az keyvault secret show --vault-name "$KV" --name ZavaAppConnectionString \
  --query '{id:id,enabled:attributes.enabled}' -o json
```

**Rubric**
- **Full:** Correct user, role, vault scope, exact secret name, and enabled version.
- **Partial:** Correct role was initially over-scoped then narrowed, or data-plane propagation is pending.
- **No credit:** Role assigned to the legacy identity/VM instead, broader control-plane role substituted, or wrong secret name.

**Common pitfalls:** Resource-group Owner/Contributor does not grant RBAC-mode secret data actions. A temporary `Forbidden` after assignment normally requires waiting several minutes, not granting broader access. Never display the secret's `value` field.

### Task 1.4 — Enable and authorize the VM identity

**Answer / expected end state:** Existing VM has a system-assigned identity. Its principal has only **Key Vault Secrets User** at exact vault scope for runtime retrieval.

```bash
VM_PID=$(az vm show -g "$RG" -n "$VM" --query identity.principalId -o tsv)
az vm show -g "$RG" -n "$VM" --query '{type:identity.type,principalId:identity.principalId}' -o json
az role assignment list --assignee-object-id "$VM_PID" --all \
  --query '[].{role:roleDefinitionName,scope:scope}' -o table
```

**Rubric**
- **Full:** System identity enabled; vault-scoped Secrets User; no Owner, Contributor, Officer, or write role.
- **Partial:** Correct role initially at resource-group scope then narrowed.
- **No credit:** User-assigned/legacy identity used at runtime or VM receives write/admin rights.

**Common pitfalls:** Confusing principal ID, client ID, and resource ID; omitting principal type during directory replication; assuming ARM initially enabled the identity.

### Task 1.5 — Switch runtime source

**Answer / expected end state:** The deployed helper retrieves the exact secret with the VM identity, without rebuilding the app. Local plaintext is removed or non-authoritative. `/health` succeeds and `/config-status` reports `KeyVault` without a value.

```bash
az vm run-command invoke -g "$RG" -n "$VM" --command-id RunPowerShellScript \
  --scripts "C:\ZavaRetail\Tools\Set-ZavaSecretSource.ps1 -Source KeyVault -VaultName '$KV' -RemoveLocalPlaintext -TestRetrieval" \
  --query value[].message -o tsv
az vm run-command invoke -g "$RG" -n "$VM" --command-id RunPowerShellScript \
  --scripts "(Invoke-WebRequest -UseBasicParsing http://localhost/health).Content; (Invoke-WebRequest -UseBasicParsing http://localhost/config-status).Content" \
  --query value[].message -o tsv
```

**Rubric**
- **Full:** Key Vault is authoritative through system identity; both endpoint results are correct.
- **Partial:** Retrieval works but stale plaintext fallback remains, or refresh is pending.
- **No credit:** Secret is hard-coded elsewhere or legacy identity is used.

**Common pitfalls:** Version-pinning prevents later rotation; IIS caches old configuration; immediate RBAC 403; helper receives the wrong vault name. The deployed helper supports only `-Source`, `-VaultName`, `-RemoveLocalPlaintext`, and `-TestRetrieval`.

## Exercise 2 — Deploy WAF_v2, enable diagnostics, then test

### Task 2.1 — Deploy healthy Application Gateway WAF_v2 routing

**Answer / expected end state:** Learner-created gateway uses `WAF_v2` in dedicated `appgw-subnet`; backend is VM private IP; listener, HTTP settings, probe, and rule produce a healthy normal response. Per Microsoft Learn, the Application Gateway subnet must be dedicated to Application Gateway resources; a `/24` is recommended for WAF_v2 to provide sufficient scale-out capacity.

```bash
az network application-gateway show -g "$RG" -n "$AGW" --query \
  '{tier:sku.tier,state:operationalState,subnet:gatewayIPConfigurations[0].subnet.id,policy:firewallPolicy.id}' -o json
az network application-gateway show-backend-health -g "$RG" -n "$AGW" -o json
```

**Rubric**
- **Full:** WAF_v2, correct dedicated subnet/private backend, healthy routing, normal storefront response.
- **Partial:** Gateway exists but probe/host/NSG error is corrected.
- **No credit:** Standard_v2, VM public-IP backend, or gateway assumed to exist initially.

**Common pitfalls:** Long deployment time leads to overlapping retries; unsupported region/zone/capacity; probe host mismatch; other resource types placed in the dedicated gateway subnet; undersized subnet; NSG blocks the gateway subnet; public IP SKU incompatibility.

### Task 2.2 — Configure Prevention and the exact custom rule

**Answer / expected end state:** Associated policy is in Prevention mode. `BlockZavaAttackHeader` has Block action and matches request header `X-Zava-Attack` equal to `true`.

```bash
POLICY_ID=$(az network application-gateway show -g "$RG" -n "$AGW" --query firewallPolicy.id -o tsv)
az network application-gateway waf-policy show --ids "$POLICY_ID" \
  --query '{mode:policySettings.mode,state:policySettings.state,rules:customRules}' -o json
```

**Rubric**
- **Full:** Association, mode, exact rule/header/value, and action are correct.
- **Partial:** Correct rule left in Detection, then corrected before accepted test.
- **No credit:** Policy unassociated or managed-rule result substituted.

**Common pitfalls:** Rule created but policy not associated; header selector/value mismatch; Detection mode does not enforce.

### Task 2.3 — Enable diagnostics before block traffic

**Answer / expected end state:** Before the accepted malicious request, a diagnostic setting on the **Application Gateway resource** targets the supplied workspace and enables `ApplicationGatewayFirewallLog` and `ApplicationGatewayAccessLog`.

```bash
az monitor diagnostic-settings list --resource "$AGW_ID" \
  --query '[].{name:name,workspace:workspaceId,logs:logs[].{category:category,enabled:enabled}}' -o json
```

**Rubric**
- **Full:** Correct resource, workspace, both categories, and sequencing.
- **Partial:** First test preceded diagnostics, but learner saves setting and generates a new accepted test.
- **No credit:** Setting on WAF policy, wrong workspace, metrics only, or missing firewall/access category.

**Common pitfalls:** Logs are not retrospective; category group evidence must prove both required categories; setting the policy as target is invalid.

### Task 2.4 — Prove enforcement and telemetry

**Answer / expected end state:** A post-diagnostic request through the gateway with `X-Zava-Attack: true` is blocked, normally HTTP 403. After ingestion latency, a firewall event names `BlockZavaAttackHeader`.

```bash
AGW_PIP_ID=$(az network application-gateway show -g "$RG" -n "$AGW" --query 'frontendIPConfigurations[0].publicIPAddress.id' -o tsv)
AGW_PIP=$(az network public-ip show --ids "$AGW_PIP_ID" --query ipAddress -o tsv)
curl -iL "http://$AGW_PIP/health"
curl -i -H 'X-Zava-Attack: true' "http://$AGW_PIP/"
WORKSPACE_ID=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query customerId -o tsv)
az monitor log-analytics query -w "$WORKSPACE_ID" --analytics-query "
union isfuzzy=true
 (AGWFirewallLogs
  | project TimeGenerated,
      Action=tostring(column_ifexists('Action', '')),
      RuleId=tostring(column_ifexists('RuleId', '')),
      Message=tostring(column_ifexists('Message', ''))),
 (AzureDiagnostics | where Category == 'ApplicationGatewayFirewallLog'
  | project TimeGenerated, Action=action_s, RuleId=ruleId_s, Message=message_s)
| where TimeGenerated > ago(30m)
| where RuleId == 'BlockZavaAttackHeader' or Message has 'BlockZavaAttackHeader'
| order by TimeGenerated desc" -o table
```

**Rubric**
- **Full:** Normal request works; malicious request is blocked; corresponding firewall record names exact custom rule.
- **Partial:** HTTP evidence exists while telemetry is within normal ingestion delay; facilitator later reproduces it.
- **No credit:** 403 only, access log only, wrong endpoint, or unrelated managed rule.

**Common pitfalls:** Querying immediately; resource-specific versus `AzureDiagnostics` schema variation; testing VM IP; backend-generated generic 403. Inspect `getschema` when columns differ.

### Task 2.5 — Remove direct VM exposure

**Answer / expected end state:** Internet HTTP to the VM is unavailable. The baseline NSG rule `Allow-HTTP-Direct-Internet` is deleted from the effective NSG; the public IP may also be detached. Gateway-subnet-to-backend traffic remains allowed and healthy. The baseline ARM deployment associates `zava-app-nsg` with `app-subnet`, not the NIC, so discovery must check the NIC first and then fall back to its subnet.

```bash
NIC_ID=$(az vm show -g "$RG" -n "$VM" --query 'networkProfile.networkInterfaces[0].id' -o tsv)
NSG_ID=$(az network nic show --ids "$NIC_ID" --query networkSecurityGroup.id -o tsv)
if [ -z "$NSG_ID" ]; then
  SUBNET_ID=$(az network nic show --ids "$NIC_ID" --query 'ipConfigurations[0].subnet.id' -o tsv)
  NSG_ID=$(az network vnet subnet show --ids "$SUBNET_ID" --query networkSecurityGroup.id -o tsv)
fi
if [ -z "$NSG_ID" ]; then
  echo 'No NSG is associated with the NIC or its subnet' >&2
  exit 1
fi
az network nsg rule delete --ids "$NSG_ID/securityRules/Allow-HTTP-Direct-Internet"
az network nsg rule show --ids "$NSG_ID/securityRules/Allow-HTTP-Direct-Internet" 2>/dev/null || echo 'Baseline direct HTTP rule deleted'
az network nic show --ids "$NIC_ID" --query 'ipConfigurations[].publicIPAddress.id' -o json
az network application-gateway show-backend-health -g "$RG" -n "$AGW" -o json
```

**Rubric**
- **Full:** `Allow-HTTP-Direct-Internet` is deleted, direct public HTTP fails, and gateway still works.
- **Partial:** Baseline rule is deleted and public IP remains, but effective NSG denies Internet HTTP and permits only gateway backend flow.
- **No credit:** Baseline rule remains, direct path works, or lockdown breaks gateway.

**Common pitfalls:** Assuming the NSG is attached to the NIC when it is attached to `app-subnet`; deleting a similarly named rule but leaving `Allow-HTTP-Direct-Internet`; higher-priority broad allow; denying gateway subnet too; relying only on configured rules rather than reachability test.

## Exercise 3 — Remove excess access and rotate

### Task 3.1 — Make legacy identity metadata-only

**Answer / expected end state:** `zava-app-legacy-id` has no Contributor at resource-group scope. It has built-in **Key Vault Reader** scoped exactly to the vault, and no inherited/direct route granting `getSecret`, `setSecret`, Secrets User/Officer/Administrator, Owner, Contributor, or equivalent custom data actions.

```bash
LEGACY_PID=$(az identity show -g "$RG" -n zava-app-legacy-id --query principalId -o tsv)
az role assignment list --assignee-object-id "$LEGACY_PID" --all \
  --query '[].{role:roleDefinitionName,scope:scope}' -o table
az role definition list --name 'Key Vault Reader' \
  --query '[0].{actions:permissions[0].actions,dataActions:permissions[0].dataActions}' -o json
```

**Rubric**
- **Full:** Contributor gone; exact vault-scoped Reader; effective-role review proves no value/read-write path.
- **Partial:** Reader was over-scoped and then narrowed.
- **No credit:** Contributor retained or any secret-value/admin role granted.

**Common pitfalls:** Confusing Key Vault Reader metadata rights with Secrets User value rights; checking only direct assignments; deleting another principal's assignment.

### Task 3.2 — Rotate using the learner account

**Answer / expected end state:** Learner uses their own Secrets Officer access to create a new enabled version of `ZavaAppConnectionString`. App resolves latest through VM identity and remains healthy.

```bash
az keyvault secret list-versions --vault-name "$KV" --name ZavaAppConnectionString \
  --query '[].{id:id,enabled:attributes.enabled,created:attributes.created}' -o table
```

**Rubric**
- **Full:** At least two versions; latest enabled; learner performed rotation; health and `KeyVault` source remain valid.
- **Partial:** New version exists but app cache/restart is pending and then corrected.
- **No credit:** New secret name, legacy identity rotates, or local file is changed instead.

**Common pitfalls:** Version-pinned URI; disabling all usable versions; treating sample rotation as database credential rotation.

## Exercise 4 — Validate and report

### Task 4.1 — Evidence bundle

**Answer / expected end state:** Evidence includes: RBAC-mode vault; exact enabled/rotated secret metadata; learner Officer; VM system identity and vault-scoped Secrets User; healthy `KeyVault` runtime source; WAF_v2 healthy normal routing; Prevention/custom rule; gateway diagnostic setting with both categories; named firewall block; failed direct VM HTTP; and legacy identity's exact Reader-only effective access.

**Rubric**
- **Full:** Every item is reproducible, scoped, timestamped, and does not disclose the secret.
- **Partial:** One noncritical capture is absent but facilitator can reproduce the correct state.
- **No credit:** Missing named WAF event, effective-RBAC proof, direct-exposure result, or runtime-source proof.

**Common pitfalls:** Scope-free screenshots; a 403 presented as complete proof; inherited roles omitted; secret value leaked.

### Task 4.2 — Hardening report

**Answer / expected end state:** Concise report maps each change to benefit and evidence:

| Change | Benefit | Evidence |
|---|---|---|
| RBAC vault and learner Officer | Governed administration/rotation | Vault mode, user role, secret versions |
| VM system identity and Secrets User | Credentialless read-only runtime | Principal, exact scope, `KeyVault` status |
| WAF_v2 Prevention | Edge enforcement | Normal and blocked responses, exact rule |
| Gateway diagnostics before test | Auditable enforcement | Both categories and named firewall event |
| Direct VM HTTP removed | Prevents WAF bypass | Failed direct and successful gateway tests |
| Legacy Reader only | Metadata without value/write | Contributor removal and effective roles |
| Same secret rotated | Lifecycle continuity | Two versions and healthy app |

**Rubric**
- **Full:** Accurate control-benefit-evidence mapping and explicit statement that no database exists.
- **Partial:** One mapping omitted.
- **No credit:** Claims database validation, legacy rotation, Reader value access, or retrospective diagnostics.

**Common pitfalls:** Conflating control and data planes; claiming HTTP status alone proves WAF; omitting identity scopes.

## Final decision

Award completion only if the vault and gateway were learner-created; diagnostics preceded the accepted block test; the firewall event names `BlockZavaAttackHeader`; `Allow-HTTP-Direct-Internet` is deleted and direct VM HTTP is unavailable; and identities have exactly these vault-scoped responsibilities:

- Learner: **Key Vault Secrets Officer**.
- VM system-assigned identity: **Key Vault Secrets User**.
- `zava-app-legacy-id`: **Key Vault Reader**, with no secret-value route.

The storefront on `zava-web-vm` must remain healthy using the latest `ZavaAppConnectionString` version, without a database.

## Microsoft Learn grounding

- [Azure Key Vault RBAC guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- [Configure managed identities on Azure VMs](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/how-to-configure-managed-identities)
- [Application Gateway infrastructure configuration](https://learn.microsoft.com/azure/application-gateway/configuration-infrastructure)
- [Application Gateway diagnostics](https://learn.microsoft.com/azure/application-gateway/application-gateway-diagnostics)
- [Application Gateway WAF monitoring and logging](https://learn.microsoft.com/azure/web-application-firewall/ag/web-application-firewall-logs)
- [AGWFirewallLogs table reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/agwfirewalllogs)
- [Application Gateway supported logs](https://learn.microsoft.com/azure/azure-monitor/reference/supported-logs/microsoft-network-applicationgateways-logs)

Portal labels and log columns can change. Use the gateway diagnostic category list and workspace table schema as authoritative while retaining the required outcomes and exact names above.
