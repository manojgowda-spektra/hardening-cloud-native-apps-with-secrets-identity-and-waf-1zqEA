Hardening Cloud-Native Apps with Secrets, Identity, and WAF

Lab Overview
• Cloud: Azure
• Duration: 240 minutes
• Exercises: 4 (Create the vault and govern the secret with managed identity, Deploy WAF_v2, enable diagnostics, then prove the block, Remove excessive access and rotate the governed secret, Validate and report the defense-in-depth controls)
• Validations: 6
• Deployed services: Azure Virtual Network with app and Application Gateway subnets, Network Security Group, Public IP address, Network Interface, Windows Server Virtual Machine with IIS storefront, User-assigned Managed Identity, Azure RBAC role assignment, Log Analytics workspace
• Scenario: Zava Retail begins as a working but intentionally insecure storefront on one Windows VM, with a plaintext sample connection string, direct public HTTP exposure, and a legacy user-assigned identity holding Contributor at resource-group scope. Learners harden the app by creating an RBAC-mode Key Vault, enabling the VM system-assigned managed identity, deploying Application Gateway WAF_v2 with custom-rule logging to Log Analytics, removing or blocking direct VM HTTP exposure, rotating the governed secret, and replacing excessive legacy access with built-in Key Vault Reader metadata-only visibility. The sample connection string is a security artifact only; no database is deployed or used, and Application Gateway WAF_v2 is the primary cost driver.

This Package Includes

Deliverables Included in the Package
• Lab Guide
• Master Document
• Inline Validations
• Inline Questions / Assessments

Inline Validations
Pre-configured inline validations enabled

Inline Assessment Questions
Single-choice questions (Simple question types only)

Lab Guide Preview
Preview link for the lab guide documentation:
[[CloudLabs LabGuide Preview]](https://experience.cloudlabs.ai/#labguidepreview/<GUID>/1)

Lab Environment Setup & Deployment
Lab provisioning and setup include one or more of the following components:
• ARM template deployment
• Custom Script Extension (CSE)
• Custom image-based environment setup
• Supporting deployment configurations as required

Exclusions
This package does not include:
• Scoring or grading mechanisms for inline validations
• Complex or advanced inline question types
