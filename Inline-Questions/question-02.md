## MetaData
Question Type : Single Choice

## Question
Why must Application Gateway diagnostics be enabled before generating the test block, and why is the diagnostic setting placed on the Application Gateway rather than the WAF policy?

## Options
Option 1 : Enabling diagnostics activates Prevention mode, and only Application Gateway can change a WAF policy from Detection to Prevention.
Option 2 : Diagnostic logs are not retrospective, so the block test must occur after logging is enabled; the Application Gateway resource exposes the access and firewall log categories, whereas the WAF policy does not.
Option 3 : Log Analytics rejects events generated before the workspace is linked to the WAF policy, and the gateway setting is needed only to record backend health.
Option 4 : The WAF policy records blocked requests locally until gateway diagnostics are enabled, after which Azure Monitor automatically imports the earlier records.

## Answers
Option 2

## Correct Answer Feedback
Option 2 is correct answer, Azure Monitor diagnostic settings collect events only after they are configured, so an earlier block test cannot provide retrospective firewall evidence. The diagnostic setting belongs on the Application Gateway because that resource exposes ApplicationGatewayFirewallLog and ApplicationGatewayAccessLog; the associated WAF policy does not expose those diagnostic log categories.

## Incorrect Answer Feedback
Selected Option is not correct Option 2 is the correct answer

## Number of Retries
1
