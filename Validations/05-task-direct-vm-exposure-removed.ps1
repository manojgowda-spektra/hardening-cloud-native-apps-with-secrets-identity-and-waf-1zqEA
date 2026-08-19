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

function Get-ResourceNameFromId {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceId,
        [Parameter(Mandatory = $true)][string]$SegmentName
    )

    $parts = $ResourceId -split '/'
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ieq $SegmentName -and ($i + 1) -lt $parts.Count) {
            return $parts[$i + 1]
        }
    }
    return $null
}

function Get-RuleValues {
    param(
        [Parameter(Mandatory = $true)]$Rule,
        [Parameter(Mandatory = $true)][string]$SingleName,
        [Parameter(Mandatory = $true)][string]$PluralName
    )

    $values = @()
    $single = $Rule.PSObject.Properties[$SingleName]
    $plural = $Rule.PSObject.Properties[$PluralName]

    if ($single -and $null -ne $single.Value) {
        $values += $single.Value
    }

    if ($plural -and $null -ne $plural.Value) {
        $values += $plural.Value
    }

    $values = @($values | Where-Object { $null -ne $_ -and $_.ToString().Trim().Length -gt 0 })
    if ($values.Count -eq 0) {
        return @('*')
    }

    return $values
}

function Test-Port80Match {
    param([string[]]$Ports)

    foreach ($port in $Ports) {
        $p = $port.ToString().Trim()
        if ($p -eq '*' -or $p -ieq 'Any' -or $p -eq '80') {
            return $true
        }
        if ($p -match '^(\d+)\s*-\s*(\d+)$') {
            if ([int]$Matches[1] -le 80 -and 80 -le [int]$Matches[2]) {
                return $true
            }
        }
    }

    return $false
}

function Test-ProtocolMatch {
    param([string]$Protocol)

    return ([string]::IsNullOrWhiteSpace($Protocol) -or $Protocol -eq '*' -or $Protocol -ieq 'Any' -or $Protocol -ieq 'Tcp')
}

function Test-InternetSourceMatch {
    param([string[]]$Sources)

    foreach ($source in $Sources) {
        $s = $source.ToString().Trim()
        if ($s -eq '*' -or $s -ieq 'Any' -or $s -ieq 'Internet' -or $s -eq '0.0.0.0/0' -or $s -eq '::/0') {
            return $true
        }
    }

    return $false
}

function Test-DestinationMatch {
    param(
        [string[]]$Destinations,
        [string]$PrivateIp
    )

    foreach ($destination in $Destinations) {
        $d = $destination.ToString().Trim()
        if ($d -eq '*' -or $d -ieq 'Any' -or $d -ieq 'VirtualNetwork' -or $d -eq '0.0.0.0/0' -or $d -eq $PrivateIp) {
            return $true
        }
    }

    return $false
}

function Test-HttpEndpoint {
    param([Parameter(Mandatory = $true)][string]$Uri)

    try {
        $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 10 -Headers @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZavaLabValidator/1.0'; 'Accept' = '*/*' } -ErrorAction Stop
        return [pscustomobject]@{
            Reachable  = $true
            StatusCode = [int]$response.StatusCode
            Content    = [string]$response.Content
            Error      = $null
        }
    }
    catch {
        $statusCode = $null
        $content = ''
        if ($_.Exception.Response) {
            try {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            catch {
                $statusCode = $null
            }

            return [pscustomobject]@{
                Reachable  = $true
                StatusCode = $statusCode
                Content    = $content
                Error      = $_.Exception.Message
            }
        }

        return [pscustomobject]@{
            Reachable  = $false
            StatusCode = $null
            Content    = $content
            Error      = $_.Exception.Message
        }
    }
}

function Get-HealthyBackendCount {
    param($Object)

    $healthyCount = 0

    if ($null -eq $Object) {
        return 0
    }

    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
        foreach ($item in $Object) {
            $healthyCount += Get-HealthyBackendCount -Object $item
        }
        return $healthyCount
    }

    foreach ($property in $Object.PSObject.Properties) {
        if ($property.Name -eq 'Health' -and [string]$property.Value -eq 'Healthy') {
            $healthyCount++
        }
        elseif ($null -ne $property.Value -and -not ($property.Value -is [string]) -and -not ($property.Value.GetType().IsPrimitive)) {
            $healthyCount += Get-HealthyBackendCount -Object $property.Value
        }
    }

    return $healthyCount
}

function Get-Http80InternetRuleDecision {
    param(
        [string[]]$NsgIds,
        [string]$PrivateIp
    )

    $matchingRules = @()

    foreach ($nsgId in @($NsgIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        $nsgName = Get-ResourceNameFromId -ResourceId $nsgId -SegmentName 'networkSecurityGroups'
        $nsgRg = Get-ResourceNameFromId -ResourceId $nsgId -SegmentName 'resourceGroups'
        if ([string]::IsNullOrWhiteSpace($nsgName) -or [string]::IsNullOrWhiteSpace($nsgRg)) {
            continue
        }

        $nsg = Get-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $nsgRg -ErrorAction Stop
        foreach ($rule in @($nsg.SecurityRules | Sort-Object Priority)) {
            $sourceValues = Get-RuleValues -Rule $rule -SingleName 'SourceAddressPrefix' -PluralName 'SourceAddressPrefixes'
            $destinationValues = Get-RuleValues -Rule $rule -SingleName 'DestinationAddressPrefix' -PluralName 'DestinationAddressPrefixes'
            $portValues = Get-RuleValues -Rule $rule -SingleName 'DestinationPortRange' -PluralName 'DestinationPortRanges'

            if ($rule.Direction -ieq 'Inbound' -and
                (Test-ProtocolMatch -Protocol $rule.Protocol) -and
                (Test-InternetSourceMatch -Sources $sourceValues) -and
                (Test-DestinationMatch -Destinations $destinationValues -PrivateIp $PrivateIp) -and
                (Test-Port80Match -Ports $portValues)) {
                $matchingRules += [pscustomobject]@{
                    NsgName  = $nsg.Name
                    RuleName = $rule.Name
                    Access   = $rule.Access
                    Priority = [int]$rule.Priority
                }
            }
        }
    }

    $firstRule = $matchingRules | Sort-Object Priority | Select-Object -First 1
    return [pscustomobject]@{
        HasExplicitInternetAllow = [bool]($firstRule -and $firstRule.Access -ieq 'Allow')
        FirstMatchingRule        = $firstRule
        MatchingRuleCount        = @($matchingRules).Count
    }
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop

        $resourceGroup = Get-AzResourceGroup -Name $rg -ErrorAction Stop

        $vm = Get-AzVM -ResourceGroupName $resourceGroup.ResourceGroupName -Name "labvm-$DID" -ErrorAction SilentlyContinue
        if (-not $vm) {
            $vm = Get-AzVM -ResourceGroupName $resourceGroup.ResourceGroupName -ErrorAction Stop | Where-Object { $_.Name -match 'zava.*web|web.*zava' } | Select-Object -First 1
        }

        if (-not $vm) {
            throw "Storefront VM 'labvm-$DID' was not found in resource group '$rg'."
        }

        $nicId = $vm.NetworkProfile.NetworkInterfaces[0].Id
        $nicName = Get-ResourceNameFromId -ResourceId $nicId -SegmentName 'networkInterfaces'
        $nicRg = Get-ResourceNameFromId -ResourceId $nicId -SegmentName 'resourceGroups'
        $nic = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $nicRg -ErrorAction Stop
        $privateIp = $nic.IpConfigurations[0].PrivateIpAddress

        $publicIpAddress = $null
        $publicIpName = $null
        $publicIpConfig = $nic.IpConfigurations | Where-Object { $_.PublicIpAddress -and $_.PublicIpAddress.Id } | Select-Object -First 1
        if ($publicIpConfig) {
            $publicIpName = Get-ResourceNameFromId -ResourceId $publicIpConfig.PublicIpAddress.Id -SegmentName 'publicIPAddresses'
            $publicIpRg = Get-ResourceNameFromId -ResourceId $publicIpConfig.PublicIpAddress.Id -SegmentName 'resourceGroups'
            $pip = Get-AzPublicIpAddress -Name $publicIpName -ResourceGroupName $publicIpRg -ErrorAction SilentlyContinue
            if ($pip) {
                $publicIpAddress = $pip.IpAddress
            }
        }

        $nsgIds = @()
        if ($nic.NetworkSecurityGroup -and $nic.NetworkSecurityGroup.Id) {
            $nsgIds += $nic.NetworkSecurityGroup.Id
        }

        $subnetId = $nic.IpConfigurations[0].Subnet.Id
        $vnetName = Get-ResourceNameFromId -ResourceId $subnetId -SegmentName 'virtualNetworks'
        $vnetRg = Get-ResourceNameFromId -ResourceId $subnetId -SegmentName 'resourceGroups'
        $subnetName = Get-ResourceNameFromId -ResourceId $subnetId -SegmentName 'subnets'
        $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $vnetRg -ErrorAction Stop
        $subnet = Get-AzVirtualNetworkSubnetConfig -Name $subnetName -VirtualNetwork $vnet -ErrorAction Stop
        if ($subnet.NetworkSecurityGroup -and $subnet.NetworkSecurityGroup.Id) {
            $nsgIds += $subnet.NetworkSecurityGroup.Id
        }

        $nsgDecision = Get-Http80InternetRuleDecision -NsgIds $nsgIds -PrivateIp $privateIp
        $nsgBlocksDirectInternetHttp = -not $nsgDecision.HasExplicitInternetAllow

        $directBlocked = $false
        $directDetail = "No public IP is associated with VM '$($vm.Name)'; direct VM HTTP cannot be reached from the internet."
        if (-not [string]::IsNullOrWhiteSpace($publicIpAddress)) {
            $directTest = Test-HttpEndpoint -Uri "http://$publicIpAddress/health"
            if (-not $directTest.Reachable) {
                $directBlocked = $true
                $directDetail = "VM public IP '$publicIpAddress' did not return an HTTP response on /health ($($directTest.Error))."
            }
            else {
                $directBlocked = $false
                $directDetail = "VM public IP '$publicIpAddress' still returned an HTTP response on /health with status '$($directTest.StatusCode)'."
            }
        }
        else {
            $directBlocked = $true
        }

        $appGw = Get-AzApplicationGateway -Name 'agw-zava-waf' -ResourceGroupName $resourceGroup.ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $appGw) {
            $appGw = Get-AzApplicationGateway -ResourceGroupName $resourceGroup.ResourceGroupName -ErrorAction Stop | Where-Object { $_.Name -match 'agw|gateway' } | Select-Object -First 1
        }

        if (-not $appGw) {
            throw "Application Gateway 'agw-zava-waf' was not found in resource group '$rg'."
        }

        $appGwPublicIpId = ($appGw.FrontendIpConfigurations | Where-Object { $_.PublicIpAddress -and $_.PublicIpAddress.Id } | Select-Object -First 1).PublicIpAddress.Id
        if ([string]::IsNullOrWhiteSpace($appGwPublicIpId)) {
            throw "Application Gateway '$($appGw.Name)' does not have a public frontend IP configuration."
        }

        $appGwPublicIpName = Get-ResourceNameFromId -ResourceId $appGwPublicIpId -SegmentName 'publicIPAddresses'
        $appGwPublicIpRg = Get-ResourceNameFromId -ResourceId $appGwPublicIpId -SegmentName 'resourceGroups'
        $appGwPublicIp = Get-AzPublicIpAddress -Name $appGwPublicIpName -ResourceGroupName $appGwPublicIpRg -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($appGwPublicIp.IpAddress)) {
            throw "Application Gateway public IP '$appGwPublicIpName' does not have an allocated IP address."
        }

        $gatewayHealth = Test-HttpEndpoint -Uri "http://$($appGwPublicIp.IpAddress)/health"
        $gatewayRoot = Test-HttpEndpoint -Uri "http://$($appGwPublicIp.IpAddress)/"
        $gatewayHealthOk = $gatewayHealth.Reachable -and $gatewayHealth.StatusCode -ge 200 -and $gatewayHealth.StatusCode -lt 400
        $gatewayStorefrontOk = $gatewayRoot.Reachable -and $gatewayRoot.StatusCode -ge 200 -and $gatewayRoot.StatusCode -lt 400

        $backendHealth = Get-AzApplicationGatewayBackendHealth -Name $appGw.Name -ResourceGroupName $resourceGroup.ResourceGroupName -ErrorAction Stop
        $healthyBackendCount = Get-HealthyBackendCount -Object $backendHealth
        $gatewayBackendAllowed = $healthyBackendCount -gt 0

        $directExposureRemoved = $nsgBlocksDirectInternetHttp -or $directBlocked

        if ($directExposureRemoved -and $gatewayBackendAllowed -and $gatewayHealthOk -and $gatewayStorefrontOk) {
            $found = $true
            $ruleDetail = if ($nsgDecision.FirstMatchingRule) { "first internet-to-HTTP NSG match is '$($nsgDecision.FirstMatchingRule.NsgName)/$($nsgDecision.FirstMatchingRule.RuleName)' with access '$($nsgDecision.FirstMatchingRule.Access)' at priority $($nsgDecision.FirstMatchingRule.Priority)" } else { "no custom NSG rule allows Internet-origin inbound HTTP to the VM" }
            $message = @{
                Status  = "Succeeded"
                Message = "Direct VM HTTP exposure is removed for VM '$($vm.Name)' ($ruleDetail; $directDetail). Application Gateway '$($appGw.Name)' frontend '$($appGwPublicIp.IpAddress)' returns HTTP $($gatewayRoot.StatusCode) for the storefront and HTTP $($gatewayHealth.StatusCode) for /health, with $healthyBackendCount healthy backend target(s)."
            } | ConvertTo-Json
        }
        else {
            $failures = @()
            if (-not $directExposureRemoved) { $failures += "direct VM HTTP is still reachable and an Internet-origin HTTP allow rule remains effective in the checked NSG configuration" }
            if (-not $gatewayBackendAllowed) { $failures += "Application Gateway backend health has no Healthy server entries" }
            if (-not $gatewayHealthOk) { $failures += "gateway /health did not return a 2xx/3xx response" }
            if (-not $gatewayStorefrontOk) { $failures += "gateway storefront root path did not return a 2xx/3xx response" }
            $ruleDetail = if ($nsgDecision.FirstMatchingRule) { "first internet-to-HTTP NSG match: '$($nsgDecision.FirstMatchingRule.NsgName)/$($nsgDecision.FirstMatchingRule.RuleName)' access '$($nsgDecision.FirstMatchingRule.Access)' priority $($nsgDecision.FirstMatchingRule.Priority)" } else { "no matching custom Internet-to-HTTP NSG allow rule found" }
            $message = @{
                Status  = "Failed"
                Message = "Validation 5 failed: $($failures -join '; '). Direct endpoint detail: $directDetail. NSG detail: $ruleDetail. Gateway root status: $($gatewayRoot.StatusCode); gateway /health status: $($gatewayHealth.StatusCode); healthy backend count: $healthyBackendCount."
            } | ConvertTo-Json
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
        $message = @{
            Status  = "Failed"
            Message = "Error during direct VM exposure check in RG '$rg'. Attempt $count of 3. Error: $($_.Exception.Message)"
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

# Post-loop: if every attempt failed, emit a final failure JSON so CloudLabs always sees a structured result.
if (-not $found) {
    $message = @{
        Status  = "Failed"
        Message = "Direct VM exposure removal was not verified in RG '$rg' after 3 attempts. Confirm Internet-origin HTTP to the VM is blocked or unreachable, Application Gateway backend health is Healthy, and the storefront is reachable through Application Gateway."
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
