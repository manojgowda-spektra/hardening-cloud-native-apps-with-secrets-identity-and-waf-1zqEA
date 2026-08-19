# Hardening Cloud-Native Apps with Secrets, Identity, and WAF

## Package summary

This CloudLabs package provides an Azure challenge lab for hardening the intentionally weak Zava Retail storefront. The starting environment is a working IIS storefront on a Windows virtual machine with direct public HTTP exposure, a local plaintext sample connection string, a legacy user-assigned managed identity with excessive Contributor access at the resource-group scope, and no Key Vault, VM system-assigned managed identity, Application Gateway, WAF policy, gateway diagnostic setting, or database.

Learners improve the security posture without rebuilding the app. They create an Azure RBAC-mode Key Vault, store and rotate the exact secret `ZavaAppConnectionString`, enable the VM system-assigned managed identity for runtime secret retrieval, deploy an Application Gateway WAF_v2 in front of the VM, enable Application Gateway access and firewall diagnostics to Log Analytics, remove or block direct VM HTTP exposure, and replace the legacy identity's broad Contributor assignment with metadata-only Key Vault Reader access.

## Lab scope

- Cloud: Azure
- Duration: 240 minutes
- Lab type: Challenge lab
- Level: Advanced
- Exercises: 4
- Inline questions: 4
- Validations: 6

## Exercises

1. Create the vault and govern the secret with managed identity
2. Deploy WAF_v2, enable diagnostics, then prove the block
3. Remove excessive access and rotate the governed secret
4. Validate and report the defense-in-depth controls

## Initial deployment state

The ARM deployment and Custom Script Extension create only the insecure baseline and lab prerequisites:

- Virtual network with `app-subnet` and an empty `appgw-subnet`
- Windows Server VM running IIS and the lightweight Zava Retail storefront
- VM public IP and NSG rule allowing direct inbound HTTP at lab start
- Local plaintext sample connection string configuration
- User-assigned managed identity `zava-app-legacy-id`
- Contributor role assignment for `zava-app-legacy-id` at resource-group scope
- Log Analytics workspace for learner-created Application Gateway diagnostics

The deployment intentionally does not create:

- Key Vault or any Key Vault secret
- VM system-assigned managed identity or its role assignment
- Application Gateway
- WAF policy
- Application Gateway diagnostic setting
- Database of any kind

These omissions are intentional challenge outcomes, not deployment defects. Validators that check for a Key Vault, VM system identity, Application Gateway, WAF policy, diagnostics, or rotated secret are expected to fail against the baseline until learners create and configure those resources.

The sample connection string is a security-governance artifact only. There is no backing database, and the storefront never opens a database connection.

## Target learner outcomes

By the end of the lab, learners must demonstrate that:

- A learner-created Key Vault uses Azure RBAC authorization.
- The exact secret `ZavaAppConnectionString` exists and contains the sample connection string.
- The learner's own signed-in lab account has the built-in Key Vault Secrets Officer role scoped to the vault for secret creation and rotation.
- The VM system-assigned managed identity is enabled and has only the built-in Key Vault Secrets User role scoped to the vault.
- The storefront resolves the secret through the VM managed identity and reports `KeyVault` on `/config-status` without exposing the secret value.
- A learner-created Application Gateway WAF_v2 fronts the storefront from `appgw-subnet`.
- A WAF policy is associated, set to Prevention mode, and includes custom rule `BlockZavaAttackHeader` to block `X-Zava-Attack: true`.
- Diagnostic settings are configured on the Application Gateway resource and send `ApplicationGatewayFirewallLog` and `ApplicationGatewayAccessLog` to the provided Log Analytics workspace.
- Log Analytics contains a blocked-request record identifying `BlockZavaAttackHeader`.
- Direct public HTTP access to the VM is removed or blocked while gateway-to-backend connectivity remains functional.
- `zava-app-legacy-id` no longer has Contributor at resource-group scope and has only built-in Key Vault Reader scoped to the vault.
- The secret is rotated by the learner's own Secrets Officer access and the storefront remains healthy.

## Built-in role model

This lab uses Azure built-in roles only. No custom RBAC role is required.

- Learner account: Key Vault Secrets Officer at the learner-created vault scope
- VM system-assigned managed identity: Key Vault Secrets User at the learner-created vault scope
- Legacy user-assigned managed identity `zava-app-legacy-id`: Key Vault Reader at the learner-created vault scope

This role separation reflects Azure Key Vault RBAC behavior: management-plane roles such as Owner or Contributor do not by themselves grant permission to create, read, or rotate secret values in an RBAC-mode vault. Key Vault Reader provides metadata visibility only and does not permit secret-value retrieval or rotation.

## Application Gateway and WAF requirements

Application Gateway is absent at lab start and is created by the learner. The required gateway posture is:

- SKU/tier: Application Gateway WAF_v2
- Subnet: `appgw-subnet`
- Backend: storefront VM private IP
- WAF policy mode: Prevention
- Custom rule: `BlockZavaAttackHeader`
- Rule match: request header `X-Zava-Attack` equals `true`
- Rule action: Block

Diagnostics must be enabled on the Application Gateway resource before generating the WAF block test. Gateway diagnostic logs are not retrospective, and the required firewall and access log categories are emitted from the Application Gateway diagnostic setting rather than from the WAF policy resource.

## Direct VM exposure requirement

Learners must prevent internet-origin HTTP traffic from reaching the VM directly while preserving Application Gateway-to-backend connectivity. NSG blocking is sufficient for this requirement and supports trainer/RDP access patterns. Detaching the VM public IP is optional only when the lab access model still preserves required trainer or operational access.

## Validation launcher aliases

Some `source_file` validation stubs are intentional CloudLabs launcher aliases. They delegate to the canonical numbered validation scripts and should remain unless the CloudLabs validation launcher no longer requires aliases.

## Azure Policy artifact note

The audit-only Azure Policy artifact intentionally uses the bare CloudLabs `{ if, then }` policy-rule shape and is not wrapped in `properties.policyRule`. Before publishing, verify the Application Gateway and WAF policy aliases against current Microsoft Learn/Azure Policy alias documentation for the target Azure API version.

## Cost note

Application Gateway WAF_v2 is the primary cost driver for this challenge environment. The package keeps one deployment stage, avoids database resources entirely, and uses the Log Analytics workspace only for the required short-lived Application Gateway access and firewall logs.

## Included package artifacts

- ARM template and parameter file
- Custom Script Extension bootstrap script
- Lab guide and exercises
- Inline assessment questions
- PowerShell validations
- Solution guide
- Audit-only Azure Policy artifact for Application Gateway WAF posture
- Spec sheet
- README summary

## Explicit exclusions

- No database resource or local database component
- No Key Vault created by deployment
- No secret created by deployment
- No VM system-assigned managed identity created by deployment
- No Application Gateway or WAF policy created by deployment
- No Application Gateway diagnostic setting created by deployment
- No custom RBAC role artifact

## Microsoft Learn grounding

The package follows the current documented Azure behavior for managed identities on existing VMs, Azure RBAC-mode Key Vault data-plane authorization, Key Vault built-in roles, Application Gateway WAF_v2, Application Gateway diagnostic settings, and WAF firewall logging. The lab guide and validations account for role propagation delays and Azure Monitor log-ingestion latency.