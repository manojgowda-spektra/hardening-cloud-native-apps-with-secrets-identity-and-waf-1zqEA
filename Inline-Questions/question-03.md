## MetaData
Question Type : Single Choice

## Question
Why does the built-in Key Vault Reader role satisfy the metadata requirement for `zava-app-legacy-id` while preventing it from retrieving or rotating `ZavaAppConnectionString`?

## Options
Option 1 : It can retrieve the current secret value but cannot list previous versions, so it cannot perform a complete rotation.
Option 2 : It can read vault and secret metadata, but it has no data actions to read secret values or create new secret versions; rotation must be performed by an identity with secret-write permission.
Option 3 : It can rotate the secret only when assigned at resource-group scope, while vault scope limits it to retrieving the current value.
Option 4 : It inherits secret-value retrieval from Azure Resource Manager but blocks rotation because the identity is user-assigned.

## Answers
Option 2

## Correct Answer Feedback
Option 2 is correct answer, Microsoft Learn defines Key Vault Reader as a metadata-reading role that cannot read sensitive values. It does not grant the secret-value read or secret-write data actions needed to retrieve `ZavaAppConnectionString` or create a rotated version. The learner's Key Vault Secrets Officer access performs rotation instead.

## Incorrect Answer Feedback
Selected Option is not correct Option 2 is the correct answer

## Number of Retries
1
