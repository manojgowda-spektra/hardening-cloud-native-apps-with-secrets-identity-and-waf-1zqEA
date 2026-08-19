using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = "rg-zava-$DID"
# Fallback: CloudLabs names the resource group from the template Code (e.g. ODL-CNA-<DID>),
# not "rg-zava-<DID>". If the assumed name is absent, find the group whose name carries the
# deployment id. Without this every check below fails before it reads anything.
if (-not (Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue)) {
    $__match = @(Get-AzResourceGroup -ErrorAction SilentlyContinue |
                 Where-Object { $_.ResourceGroupName -like "*$DID*" })
    if ($__match.Count -ge 1) { $rg = $__match[0].ResourceGroupName }
}
$count = 0
$found = $false
$lastFailure = "Prevention-mode WAF policy, custom rule, diagnostics, blocked request, and Log Analytics evidence were not fully validated."

function Get-ZavaResourceById {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ResourceId
    )

    try {
        return Get-AzResource -ResourceId $ResourceId -ExpandProperties -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Get-ZavaResourceNameFromId {
    param([string] $ResourceId)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }
    return ($ResourceId.TrimEnd('/') -split '/')[-1]
}

function Get-ZavaResourceGroupNameFromId {
    param([string] $ResourceId)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }
    $parts = $ResourceId -split '/'
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ieq 'resourceGroups' -and ($i + 1) -lt $parts.Count) {
            return $parts[$i + 1]
        }
    }
    return $null
}

function Get-ZavaDiagnosticLogSettings {
    param(
        [Parameter(Mandatory = $true)]
        [object] $DiagnosticSetting
    )

    $logs = @()
    if ($DiagnosticSetting.Log) { $logs += @($DiagnosticSetting.Log) }
    if ($DiagnosticSetting.Logs) { $logs += @($DiagnosticSetting.Logs) }
    if ($DiagnosticSetting.Properties -and $DiagnosticSetting.Properties.logs) { $logs += @($DiagnosticSetting.Properties.logs) }
    return $logs
}

function Test-ZavaLogCategoryEnabled {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Logs,
        [Parameter(Mandatory = $true)]
        [string] $CategoryName
    )

    foreach ($log in @($Logs)) {
        $category = [string]$log.Category
        $categoryGroup = [string]$log.CategoryGroup
        $enabledText = [string]$log.Enabled
        $enabled = ($log.Enabled -eq $true -or $enabledText -ieq "true")

        if ($enabled -and (($category -ieq $CategoryName) -or ($categoryGroup -ieq "allLogs"))) {
            return $true
        }
    }

    return $false
}

function Get-ZavaPublicIpFromFrontend {
    param(
        [Parameter(Mandatory = $true)]
        [object] $ApplicationGateway,
        [object] $Listener
    )

    $frontendIpConfigName = $null
    if ($Listener -and $Listener.FrontendIpConfiguration -and $Listener.FrontendIpConfiguration.Id) {
        $frontendIpConfigName = Get-ZavaResourceNameFromId -ResourceId $Listener.FrontendIpConfiguration.Id
    }

    $frontendCandidates = @($ApplicationGateway.FrontendIPConfigurations)
    if (-not [string]::IsNullOrWhiteSpace($frontendIpConfigName)) {
        $frontendCandidates = @($frontendCandidates | Where-Object { $_.Name -eq $frontendIpConfigName }) + @($ApplicationGateway.FrontendIPConfigurations | Where-Object { $_.Name -ne $frontendIpConfigName })
    }

    foreach ($frontend in @($frontendCandidates)) {
        $pipId = $null
        if ($frontend.PublicIpAddress -and $frontend.PublicIpAddress.Id) { $pipId = $frontend.PublicIpAddress.Id }
        if (-not $pipId -and $frontend.PublicIPAddress -and $frontend.PublicIPAddress.Id) { $pipId = $frontend.PublicIPAddress.Id }
        if (-not $pipId -and $frontend.Properties -and $frontend.Properties.publicIPAddress -and $frontend.Properties.publicIPAddress.id) { $pipId = $frontend.Properties.publicIPAddress.id }

        if ($pipId) {
            $pipName = Get-ZavaResourceNameFromId -ResourceId $pipId
            $pipRg = Get-ZavaResourceGroupNameFromId -ResourceId $pipId
            if ($pipName -and $pipRg) {
                $pip = Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $pipRg -ErrorAction SilentlyContinue
                if ($pip) {
                    if (-not [string]::IsNullOrWhiteSpace($pip.DnsSettings.Fqdn)) {
                        return [string]$pip.DnsSettings.Fqdn
                    }
                    if (-not [string]::IsNullOrWhiteSpace($pip.IpAddress)) {
                        return [string]$pip.IpAddress
                    }
                }
            }

            $pipResource = Get-ZavaResourceById -ResourceId $pipId
            if ($pipResource -and $pipResource.Properties -and $pipResource.Properties.ipAddress) {
                return [string]$pipResource.Properties.ipAddress
            }
        }
    }

    return $null
}

function Get-ZavaGatewayProbeTarget {
    param(
        [Parameter(Mandatory = $true)]
        [object] $ApplicationGateway
    )

    $listener = @($ApplicationGateway.HttpListeners | Where-Object { $_.Protocol -eq 'Http' } | Select-Object -First 1)
    if (-not $listener) {
        $listener = @($ApplicationGateway.HttpListeners | Select-Object -First 1)
    }

    if (-not $listener) {
        return [PSCustomObject]@{ Uri = $null; HostHeader = $null; Detail = "no HTTP listener exists" }
    }

    $gatewayHost = Get-ZavaPublicIpFromFrontend -ApplicationGateway $ApplicationGateway -Listener $listener
    if ([string]::IsNullOrWhiteSpace($gatewayHost)) {
        return [PSCustomObject]@{ Uri = $null; HostHeader = $null; Detail = "no public frontend IP address or DNS name is allocated" }
    }

    $port = 80
    if ($listener.FrontendPort -and $listener.FrontendPort.Id) {
        $frontendPortName = Get-ZavaResourceNameFromId -ResourceId $listener.FrontendPort.Id
        $frontendPort = @($ApplicationGateway.FrontendPorts | Where-Object { $_.Name -eq $frontendPortName } | Select-Object -First 1)
        if ($frontendPort -and $frontendPort.Port) { $port = [int]$frontendPort.Port }
    }

    $scheme = if ($listener.Protocol -eq 'Https') { 'https' } else { 'http' }
    $uri = if (($scheme -eq 'http' -and $port -eq 80) -or ($scheme -eq 'https' -and $port -eq 443)) {
        "${scheme}://$gatewayHost/"
    }
    else {
        "${scheme}://$gatewayHost`:$port/"
    }

    $hostHeader = $null
    if (-not [string]::IsNullOrWhiteSpace($listener.HostName)) {
        $hostHeader = [string]$listener.HostName
    }
    elseif ($listener.HostNames -and @($listener.HostNames).Count -gt 0) {
        $hostHeader = [string]@($listener.HostNames)[0]
    }

    return [PSCustomObject]@{ Uri = $uri; HostHeader = $hostHeader; Detail = "listener '$($listener.Name)' on $scheme/$port" }
}

function Invoke-ZavaWafProbe {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Uri,
        [string] $HostHeader
    )

    $result = [PSCustomObject]@{
        StatusCode = 0
        Error      = $null
    }

    try {
        $request = [System.Net.HttpWebRequest]::Create($Uri)
        $request.Method = "GET"
        $request.Timeout = 30000
        $request.AllowAutoRedirect = $false
        $request.UserAgent = "CloudLabs-Zava-WAF-Validator"
        $request.Accept = "*/*"
        $request.Headers.Add("X-Zava-Attack", "true")
        if (-not [string]::IsNullOrWhiteSpace($HostHeader)) {
            $request.Host = $HostHeader
        }

        $response = $request.GetResponse()
        $result.StatusCode = [int]$response.StatusCode
        $response.Close()
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
            $result.StatusCode = [int]$response.StatusCode
            $response.Close()
        }
        else {
            $result.Error = $_.Exception.Message
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Test-ZavaCustomRule {
    param(
        [Parameter(Mandatory = $true)]
        [object] $PolicyResource
    )

    $result = [PSCustomObject]@{
        FoundRule     = $false
        BlockAction   = $false
        HeaderMatch   = $false
        Enabled       = $false
        FailureDetail = "Custom rule 'BlockZavaAttackHeader' was not found."
    }

    $customRules = @()
    if ($PolicyResource.Properties -and $PolicyResource.Properties.customRules) {
        $customRules = @($PolicyResource.Properties.customRules)
    }

    $rule = $customRules | Where-Object { $_.name -eq "BlockZavaAttackHeader" } | Select-Object -First 1
    if (-not $rule) { return $result }

    $result.FoundRule = $true
    $result.BlockAction = ([string]$rule.action -ieq "Block")
    $state = [string]$rule.state
    $result.Enabled = ([string]::IsNullOrWhiteSpace($state) -or $state -ieq "Enabled")

    foreach ($condition in @($rule.matchConditions)) {
        $operatorOk = ([string]$condition.operator -ieq "Equal" -or [string]$condition.operator -ieq "Equals")
        $negationOk = -not ($condition.negationCondition -eq $true -or [string]$condition.negationCondition -ieq "true")
        $valueOk = $false
        foreach ($value in @($condition.matchValues)) {
            if ([string]$value -ieq "true") { $valueOk = $true }
        }

        $headerOk = $false
        foreach ($matchVariable in @($condition.matchVariables)) {
            $variableName = [string]$matchVariable.variableName
            $selector = [string]$matchVariable.selector
            if (($variableName -ieq "RequestHeaders" -or $variableName -ieq "RequestHeader") -and $selector -ieq "X-Zava-Attack") {
                $headerOk = $true
            }
        }

        if ($operatorOk -and $valueOk -and $headerOk -and $negationOk) {
            $result.HeaderMatch = $true
        }
    }

    if (-not $result.BlockAction) {
        $result.FailureDetail = "Custom rule 'BlockZavaAttackHeader' exists but its action is not Block."
    }
    elseif (-not $result.Enabled) {
        $result.FailureDetail = "Custom rule 'BlockZavaAttackHeader' exists but is disabled."
    }
    elseif (-not $result.HeaderMatch) {
        $result.FailureDetail = "Custom rule 'BlockZavaAttackHeader' does not match request header X-Zava-Attack equal to true with a non-negated Equal condition."
    }
    else {
        $result.FailureDetail = $null
    }

    return $result
}

function Invoke-ZavaWafLogQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string] $WorkspaceCustomerId,
        [Parameter(Mandatory = $true)]
        [string] $ApplicationGatewayId
    )

    $escapedAppGwId = $ApplicationGatewayId.Replace('\\', '\\\\').Replace('"', '\"')
    $query = @"
let appGwId = tolower("$escapedAppGwId");
let ruleName = "BlockZavaAttackHeader";
let Empty = datatable(TimeGenerated:datetime, Schema:string, ActionText:string, RuleText:string, DetailText:string)[];
union isfuzzy=true
Empty,
(
    AGWFirewallLogs
    | where TimeGenerated > ago(6h)
    | where tolower(tostring(column_ifexists("_ResourceId", ""))) == appGwId
    | extend ActionText = tostring(column_ifexists("Action", ""))
    | extend RuleText = tostring(column_ifexists("RuleId", ""))
    | extend DetailText = strcat(
        tostring(column_ifexists("Message", "")), " ",
        tostring(column_ifexists("DetailedMessage", "")), " ",
        tostring(column_ifexists("DetailedData", "")), " ",
        tostring(column_ifexists("FileDetails", "")), " ",
        tostring(column_ifexists("PolicyId", "")))
    | where RuleText =~ ruleName or DetailText has ruleName
    | project TimeGenerated, Schema = "AGWFirewallLogs", ActionText, RuleText, DetailText
),
(
    AzureDiagnostics
    | where TimeGenerated > ago(6h)
    | where tostring(column_ifexists("ResourceProvider", "")) =~ "MICROSOFT.NETWORK"
    | where tostring(column_ifexists("Category", "")) == "ApplicationGatewayFirewallLog"
    | where tolower(tostring(column_ifexists("_ResourceId", ""))) == appGwId or tolower(tostring(column_ifexists("ResourceId", ""))) == appGwId
    | extend AdditionalText = tostring(column_ifexists("AdditionalFields", dynamic({})))
    | extend ActionText = tostring(column_ifexists("action_s", ""))
    | extend RuleText = tostring(column_ifexists("ruleId_s", ""))
    | extend DetailText = strcat(
        tostring(column_ifexists("Message", "")), " ",
        tostring(column_ifexists("details_message_s", "")), " ",
        tostring(column_ifexists("details_data_s", "")), " ",
        tostring(column_ifexists("details_file_s", "")), " ",
        AdditionalText)
    | where RuleText =~ ruleName or DetailText has ruleName
    | project TimeGenerated, Schema = "AzureDiagnostics", ActionText, RuleText, DetailText
)
| where ActionText =~ "Blocked" or ActionText =~ "Block" or DetailText has "Blocked" or DetailText has "block"
| top 1 by TimeGenerated desc
"@

    $queryResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceCustomerId -Query $query -Timespan (New-TimeSpan -Hours 6) -Wait 120 -ErrorAction Stop
    if ($queryResult -and $queryResult.Results) {
        return @([System.Linq.Enumerable]::ToArray($queryResult.Results))
    }

    return @()
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $applicationGateways = @(Get-AzApplicationGateway -ResourceGroupName $rg -ErrorAction SilentlyContinue)
        $appGw = $applicationGateways | Where-Object { $_.Name -eq "agw-zava-waf" } | Select-Object -First 1
        if (-not $appGw) {
            $appGw = $applicationGateways | Where-Object { $_.Sku -and $_.Sku.Tier -eq "WAF_v2" } | Select-Object -First 1
        }

        if (-not $appGw) {
            $lastFailure = "Application Gateway 'agw-zava-waf' or another WAF_v2 gateway was not found in RG '$rg'."
        }
        else {
            $policyIds = @()
            if ($appGw.FirewallPolicy -and $appGw.FirewallPolicy.Id) { $policyIds += [string]$appGw.FirewallPolicy.Id }
            foreach ($listener in @($appGw.HttpListeners)) {
                if ($listener.FirewallPolicy -and $listener.FirewallPolicy.Id) { $policyIds += [string]$listener.FirewallPolicy.Id }
            }
            foreach ($urlPathMap in @($appGw.UrlPathMaps)) {
                if ($urlPathMap.FirewallPolicy -and $urlPathMap.FirewallPolicy.Id) { $policyIds += [string]$urlPathMap.FirewallPolicy.Id }
                foreach ($pathRule in @($urlPathMap.PathRules)) {
                    if ($pathRule.FirewallPolicy -and $pathRule.FirewallPolicy.Id) { $policyIds += [string]$pathRule.FirewallPolicy.Id }
                }
            }
            $policyIds = @($policyIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

            if ($policyIds.Count -eq 0) {
                $lastFailure = "Application Gateway '$($appGw.Name)' does not have an associated WAF policy."
            }
            else {
                $policyResource = $null
                foreach ($policyId in $policyIds) {
                    $candidatePolicy = Get-ZavaResourceById -ResourceId $policyId
                    if ($candidatePolicy -and $candidatePolicy.Name -eq "wafpol-zava") {
                        $policyResource = $candidatePolicy
                        break
                    }
                    elseif (-not $policyResource -and $candidatePolicy) {
                        $policyResource = $candidatePolicy
                    }
                }

                if (-not $policyResource) {
                    $lastFailure = "The associated WAF policy resource could not be read from Application Gateway '$($appGw.Name)'."
                }
                else {
                    $mode = [string]$policyResource.Properties.policySettings.mode
                    $policyState = [string]$policyResource.Properties.policySettings.state
                    if ($mode -ne "Prevention") {
                        $lastFailure = "Associated WAF policy '$($policyResource.Name)' is in mode '$mode' instead of Prevention."
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($policyState) -and $policyState -ieq "Disabled") {
                        $lastFailure = "Associated WAF policy '$($policyResource.Name)' is disabled."
                    }
                    else {
                        $customRuleResult = Test-ZavaCustomRule -PolicyResource $policyResource
                        if (-not ($customRuleResult.FoundRule -and $customRuleResult.BlockAction -and $customRuleResult.HeaderMatch -and $customRuleResult.Enabled)) {
                            $lastFailure = $customRuleResult.FailureDetail
                        }
                        else {
                            $workspaces = @(Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -ErrorAction SilentlyContinue)
                            $workspace = $workspaces | Where-Object { $_.Name -like "law-zava*" } | Select-Object -First 1
                            if (-not $workspace) { $workspace = $workspaces | Select-Object -First 1 }

                            if (-not $workspace) {
                                $lastFailure = "No Log Analytics workspace was found in RG '$rg'."
                            }
                            else {
                                $workspaceResourceId = [string]$workspace.ResourceId
                                $diagnosticSettings = @(Get-AzDiagnosticSetting -ResourceId $appGw.Id -ErrorAction SilentlyContinue)
                                $matchingDiagnostic = $null

                                foreach ($setting in $diagnosticSettings) {
                                    $settingWorkspaceId = [string]$setting.WorkspaceId
                                    if ([string]::IsNullOrWhiteSpace($settingWorkspaceId) -and $setting.Properties -and $setting.Properties.workspaceId) {
                                        $settingWorkspaceId = [string]$setting.Properties.workspaceId
                                    }

                                    $logs = @(Get-ZavaDiagnosticLogSettings -DiagnosticSetting $setting)
                                    $workspaceOk = ($settingWorkspaceId -ieq $workspaceResourceId)
                                    $firewallLogOk = Test-ZavaLogCategoryEnabled -Logs $logs -CategoryName "ApplicationGatewayFirewallLog"
                                    $accessLogOk = Test-ZavaLogCategoryEnabled -Logs $logs -CategoryName "ApplicationGatewayAccessLog"

                                    if ($workspaceOk -and $firewallLogOk -and $accessLogOk) {
                                        $matchingDiagnostic = $setting
                                        break
                                    }
                                }

                                if (-not $matchingDiagnostic) {
                                    $lastFailure = "No diagnostic setting on Application Gateway '$($appGw.Name)' targets workspace '$($workspace.Name)' with both ApplicationGatewayFirewallLog and ApplicationGatewayAccessLog enabled. The setting must be on the Application Gateway resource, not on the WAF policy."
                                }
                                else {
                                    $probeTarget = Get-ZavaGatewayProbeTarget -ApplicationGateway $appGw
                                    if ([string]::IsNullOrWhiteSpace($probeTarget.Uri)) {
                                        $lastFailure = "Application Gateway '$($appGw.Name)' cannot be probed because $($probeTarget.Detail)."
                                    }
                                    else {
                                        $probeResult = Invoke-ZavaWafProbe -Uri $probeTarget.Uri -HostHeader $probeTarget.HostHeader
                                        if ($probeResult.StatusCode -ne 403) {
                                            if ($probeResult.Error) {
                                                $lastFailure = "WAF probe through Application Gateway '$($appGw.Name)' to '$($probeTarget.Uri)' with header X-Zava-Attack=true did not return HTTP 403. Error: $($probeResult.Error)"
                                            }
                                            else {
                                                $lastFailure = "WAF probe through Application Gateway '$($appGw.Name)' to '$($probeTarget.Uri)' with header X-Zava-Attack=true returned HTTP $($probeResult.StatusCode) instead of 403."
                                            }
                                        }
                                        else {
                                            $workspaceCustomerId = [string]$workspace.CustomerId
                                            if ($workspace.CustomerId -and $workspace.CustomerId.Guid) { $workspaceCustomerId = [string]$workspace.CustomerId.Guid }

                                            $logRows = @()
                                            $queryError = $null
                                            try {
                                                $logRows = @(Invoke-ZavaWafLogQuery -WorkspaceCustomerId $workspaceCustomerId -ApplicationGatewayId $appGw.Id)
                                            }
                                            catch {
                                                $queryError = $_.Exception.Message
                                            }

                                            if ($logRows.Count -gt 0) {
                                                $found = $true
                                                $row = $logRows | Select-Object -First 1
                                                $ruleText = if ([string]::IsNullOrWhiteSpace([string]$row.RuleText)) { "BlockZavaAttackHeader" } else { [string]$row.RuleText }
                                                $messageDetail = "WAF policy '$($policyResource.Name)' is associated with Application Gateway '$($appGw.Name)' and is in Prevention mode; custom rule 'BlockZavaAttackHeader' is enabled with Block action for request header X-Zava-Attack equal to true; diagnostic setting '$($matchingDiagnostic.Name)' is attached to the Application Gateway resource and sends ApplicationGatewayFirewallLog and ApplicationGatewayAccessLog to workspace '$($workspace.Name)'; the gateway probe returned HTTP 403; Log Analytics table '$($row.Schema)' contains a blocked firewall event naming custom rule '$ruleText'."
                                            }
                                            else {
                                                if ($queryError) {
                                                    $lastFailure = "WAF probe returned HTTP 403, but the Log Analytics query for 'BlockZavaAttackHeader' failed. This can occur while Application Gateway WAF logs are still being ingested. Query error: $queryError"
                                                }
                                                else {
                                                    $lastFailure = "WAF probe returned HTTP 403, but no ApplicationGatewayFirewallLog event naming 'BlockZavaAttackHeader' was found in workspace '$($workspace.Name)' in the last 6 hours. Application Gateway logs can be delayed by Azure Monitor ingestion; confirm diagnostics were enabled before the block test, wait a few minutes, and retry."
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if ($found) {
            $message = @{
                Status  = "Succeeded"
                Message = $messageDetail
            } | ConvertTo-Json -Compress
        }
        else {
            $message = @{
                Status  = "Failed"
                Message = "Attempt $count of 3: $lastFailure"
            } | ConvertTo-Json -Compress
        }
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })

        if (-not $found -and $count -lt 3) {
            Start-Sleep -Seconds 10
        }
    }
    catch {
        $lastFailure = "Error during WAF prevention, diagnostics, and logged custom-rule block check. Attempt $count of 3. Error: $($_.Exception.Message)"
        $message = @{
            Status  = "Failed"
            Message = $lastFailure
        } | ConvertTo-Json -Compress
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

# Post-loop: if every attempt failed, emit a final failure JSON so CloudLabs
# always sees a structured result.
if (-not $found) {
    $message = @{
        Status  = "Failed"
        Message = "Prevention rule, Application Gateway diagnostics, and logged custom-rule block validation did not succeed in RG '$rg' after 3 attempts. Last result: $lastFailure"
    } | ConvertTo-Json -Compress
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
