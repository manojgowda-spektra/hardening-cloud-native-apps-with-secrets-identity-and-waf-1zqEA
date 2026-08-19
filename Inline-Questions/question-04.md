## MetaData
Question Type : Single Choice

## Question
Why are HTTP status, WAF log, secret-source, and effective-RBAC evidence all needed to establish Zava Retail's final defense-in-depth posture?

## Options
Option 1 : Each proves a different control: HTTP results prove request behavior, the WAF log attributes the block to `BlockZavaAttackHeader`, secret-source evidence proves runtime use of Key Vault, and effective-RBAC evidence proves no broader assignment still grants the legacy identity secret-value access.
Option 2 : HTTP results and the WAF log are sufficient because successful edge enforcement automatically proves that the application uses Key Vault and that all identities have least-privilege access.
Option 3 : Secret-source evidence alone is sufficient because a `KeyVault` response proves the WAF is in Prevention mode, direct VM access is blocked, and inherited RBAC assignments cannot expose the secret.
Option 4 : The configured WAF policy and visible Key Vault role assignments are sufficient because Azure configuration always proves the observed request outcome, log attribution, runtime secret source, and effective inherited access.

## Answers
Option 1

## Correct Answer Feedback
Option 1 is correct answer, the evidence is complementary rather than interchangeable. HTTP status demonstrates observed request behavior but does not identify which WAF rule acted. The Application Gateway firewall record ties the block to `BlockZavaAttackHeader`. The application's secret-source result confirms runtime retrieval from Key Vault without exposing the value. Effective-RBAC review accounts for assignments at the vault, resource group, subscription, and other applicable scopes, proving that `zava-app-legacy-id` has metadata-only Key Vault Reader access and no remaining route to retrieve or modify secret values.

## Incorrect Answer Feedback
Selected Option is not correct Option 1 is the correct answer

## Number of Retries
1
