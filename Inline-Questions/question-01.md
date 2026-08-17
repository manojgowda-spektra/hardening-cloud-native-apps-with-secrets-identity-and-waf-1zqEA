## MetaData
Question Type : Single Choice

## Question
Why must a resource-group Owner assign their own signed-in account the Key Vault Secrets Officer role at vault scope before creating `ZavaAppConnectionString` in an Azure RBAC-mode vault?

## Options
Option 1 : Owner can create secrets only after converting the vault from Azure RBAC to the access-policy permission model.
Option 2 : Owner already grants secret-value access, but Key Vault Secrets Officer is required only to enable secret versioning.
Option 3 : Owner provides management-plane authority, including the ability to assign roles, but does not grant Key Vault secret data-plane operations; Key Vault Secrets Officer grants the account permission to create and manage secret values.
Option 4 : Key Vault Secrets Officer allows the account to enable the VM system-assigned identity, which is required before any secret can exist.

## Answers
Option 3

## Correct Answer Feedback
Option 3 is correct answer, Azure Key Vault separates management-plane access from data-plane access when using Azure RBAC. Resource-group Owner can manage resources and role assignments, but it does not by itself authorize secret operations. Assigning Key Vault Secrets Officer at vault scope grants the signed-in learner the secret data-plane permissions needed to create and later rotate `ZavaAppConnectionString`; role propagation can take several minutes.

## Incorrect Answer Feedback
Selected Option is not correct Option 3 is the correct answer

## Number of Retries
1