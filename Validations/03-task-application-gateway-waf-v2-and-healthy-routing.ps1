using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = "rg-zava-$DID"
$count = 0
$found = $false
$lastFailure = "Application Gateway validation has not run."

function Get-ResourceNameFromId {
    param([string]$ResourceId)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        return $null
    }

    return ($ResourceId.TrimEnd('/') -split '/')[-1]
}

function Get-ResourceGroupNameFromId {
    param([string]$ResourceId)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        return $null
    }

    $parts = $ResourceId -split '/'
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ieq 'resourceGroups' -and ($i + 1) -lt $parts.Count) {
            return $parts[$i + 1]
        }
    }

    return $null
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $failureDetails = New-Object System.Collections.Generic.List[string]

        $resourceGroup = Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue
        if (-not $resourceGroup) {
            $candidateResourceGroups = @(Get-AzResourceGroup -ErrorAction Stop | Where-Object { $_.ResourceGroupName -like "*$DID*" })
            if ($candidateResourceGroups.Count -ge 1) {
                $rg = $candidateResourceGroups[0].ResourceGroupName
                $resourceGroup = $candidateResourceGroups[0]
            }
        }

        if (-not $resourceGroup) {
            $failureDetails.Add("Resource group '$rg' was not found.")
        }

        $appGw = $null
        if ($resourceGroup) {
            $appGw = Get-AzApplicationGateway -Name "agw-zava-waf" -ResourceGroupName $rg -ErrorAction SilentlyContinue
            if (-not $appGw) {
                $allGateways = @(Get-AzApplicationGateway -ResourceGroupName $rg -ErrorAction SilentlyContinue)
                if ($allGateways.Count -eq 1) {
                    $appGw = $allGateways[0]
                }
                elseif ($allGateways.Count -gt 1) {
                    $appGw = $allGateways | Where-Object {
                        $_.GatewayIPConfigurations.Subnet.Id -match '/subnets/appgw-subnet$' -and $_.Sku.Name -eq 'WAF_v2' -and $_.Sku.Tier -eq 'WAF_v2'
                    } | Select-Object -First 1
                }
            }
        }

        if (-not $appGw) {
            $failureDetails.Add("Application Gateway 'agw-zava-waf' was not found in resource group '$rg'.")
        }
        else {
            if (-not ($appGw.Sku.Name -eq 'WAF_v2' -and $appGw.Sku.Tier -eq 'WAF_v2')) {
                $failureDetails.Add("Application Gateway '$($appGw.Name)' is SKU name '$($appGw.Sku.Name)' and tier '$($appGw.Sku.Tier)', not WAF_v2/WAF_v2.")
            }

            $gatewaySubnetIds = @($appGw.GatewayIPConfigurations | ForEach-Object { $_.Subnet.Id } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $usesAppGwSubnet = @($gatewaySubnetIds | Where-Object { $_ -match '/subnets/appgw-subnet$' }).Count -gt 0
            if (-not $usesAppGwSubnet) {
                $subnetSummary = if ($gatewaySubnetIds.Count -gt 0) { $gatewaySubnetIds -join '; ' } else { 'no gateway subnet configuration found' }
                $failureDetails.Add("Application Gateway '$($appGw.Name)' is not deployed in subnet 'appgw-subnet'. Current subnet reference(s): $subnetSummary.")
            }

            $listeners = @($appGw.HttpListeners)
            if ($listeners.Count -lt 1) {
                $failureDetails.Add("Application Gateway '$($appGw.Name)' has no HTTP listeners configured.")
            }

            $routingRules = @($appGw.RequestRoutingRules)
            $usableRules = @($routingRules | Where-Object {
                $_.HttpListener -and (($_.BackendAddressPool -and ($_.BackendHttpSettings -or $_.BackendSettings)) -or $_.UrlPathMap)
            })
            if ($usableRules.Count -lt 1) {
                $failureDetails.Add("Application Gateway '$($appGw.Name)' has no request routing rule that binds a listener to a backend target.")
            }

            $vm = Get-AzVM -Name "zava-web-vm" -ResourceGroupName $rg -ErrorAction SilentlyContinue
            $vmPrivateIps = New-Object System.Collections.Generic.List[string]
            $vmNicIds = New-Object System.Collections.Generic.List[string]
            if ($vm) {
                foreach ($nicRef in @($vm.NetworkProfile.NetworkInterfaces)) {
                    if ($nicRef.Id) {
                        $vmNicIds.Add($nicRef.Id)
                        $nicName = Get-ResourceNameFromId -ResourceId $nicRef.Id
                        $nicRg = Get-ResourceGroupNameFromId -ResourceId $nicRef.Id
                        if ($nicName -and $nicRg) {
                            $nic = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $nicRg -ErrorAction SilentlyContinue
                            foreach ($ipConfig in @($nic.IpConfigurations)) {
                                if (-not [string]::IsNullOrWhiteSpace($ipConfig.PrivateIpAddress)) {
                                    $vmPrivateIps.Add($ipConfig.PrivateIpAddress)
                                }
                            }
                        }
                    }
                }
            }
            else {
                $failureDetails.Add("Storefront VM 'zava-web-vm' was not found in resource group '$rg'.")
            }

            $backendTargets = New-Object System.Collections.Generic.List[string]
            foreach ($pool in @($appGw.BackendAddressPools)) {
                foreach ($backendAddress in @($pool.BackendAddresses)) {
                    if (-not [string]::IsNullOrWhiteSpace($backendAddress.IpAddress)) {
                        $backendTargets.Add($backendAddress.IpAddress)
                    }
                    if (-not [string]::IsNullOrWhiteSpace($backendAddress.Fqdn)) {
                        $backendTargets.Add($backendAddress.Fqdn)
                    }
                }
                foreach ($backendIpConfig in @($pool.BackendIPConfigurations)) {
                    if (-not [string]::IsNullOrWhiteSpace($backendIpConfig.Id)) {
                        $backendTargets.Add($backendIpConfig.Id)
                    }
                }
            }

            $targetsStorefront = $false
            foreach ($privateIp in @($vmPrivateIps)) {
                if ($backendTargets -contains $privateIp) {
                    $targetsStorefront = $true
                }
            }
            foreach ($nicId in @($vmNicIds)) {
                if (@($backendTargets | Where-Object { $_ -like "$nicId*" }).Count -gt 0) {
                    $targetsStorefront = $true
                }
            }

            if (-not $targetsStorefront) {
                $targetSummary = if ($backendTargets.Count -gt 0) { $backendTargets -join '; ' } else { 'no backend targets found' }
                $expectedSummary = if ($vmPrivateIps.Count -gt 0) { $vmPrivateIps -join ', ' } else { 'no VM private IP discovered' }
                $failureDetails.Add("Application Gateway '$($appGw.Name)' backend pool does not target storefront VM 'zava-web-vm'. Expected private IP(s): $expectedSummary. Backend target(s): $targetSummary.")
            }

            $backendHealth = $null
            try {
                $backendHealth = Get-AzApplicationGatewayBackendHealth -Name $appGw.Name -ResourceGroupName $rg -ExpandResource "backendhealth/applicationgatewayresource" -ErrorAction Stop
            }
            catch {
                $failureDetails.Add("Could not read backend health for Application Gateway '$($appGw.Name)': $($_.Exception.Message)")
            }

            $healthRecords = New-Object System.Collections.Generic.List[object]
            if ($backendHealth) {
                $poolHealthObjects = @()
                if ($backendHealth.BackendAddressPools) {
                    $poolHealthObjects = @($backendHealth.BackendAddressPools)
                }
                elseif ($backendHealth.BackendAddressPool) {
                    $poolHealthObjects = @($backendHealth)
                }

                foreach ($poolHealth in $poolHealthObjects) {
                    $poolName = if ($poolHealth.BackendAddressPool.Id) { Get-ResourceNameFromId -ResourceId $poolHealth.BackendAddressPool.Id } else { 'unknown-pool' }
                    foreach ($settingsHealth in @($poolHealth.BackendHttpSettingsCollection)) {
                        $settingsName = if ($settingsHealth.BackendHttpSettings.Id) { Get-ResourceNameFromId -ResourceId $settingsHealth.BackendHttpSettings.Id } else { 'unknown-settings' }
                        foreach ($server in @($settingsHealth.Servers)) {
                            $healthRecords.Add([pscustomobject]@{
                                Pool     = $poolName
                                Settings = $settingsName
                                Address  = $server.Address
                                Health   = $server.Health
                            })
                        }
                    }
                }
            }

            $healthyRecords = @($healthRecords | Where-Object { $_.Health -eq 'Healthy' })
            if ($healthyRecords.Count -lt 1) {
                $healthSummary = if ($healthRecords.Count -gt 0) {
                    @($healthRecords | ForEach-Object { "$($_.Address)=$($_.Health)" }) -join '; '
                }
                else {
                    'no backend health server records returned'
                }
                $failureDetails.Add("Application Gateway '$($appGw.Name)' has no Healthy backend server. Backend health: $healthSummary.")
            }

            $frontendPublicIpId = @($appGw.FrontendIPConfigurations | Where-Object { $_.PublicIpAddress -and $_.PublicIpAddress.Id } | Select-Object -First 1).PublicIpAddress.Id
            $gatewayHost = $null
            if ($frontendPublicIpId) {
                $pipName = Get-ResourceNameFromId -ResourceId $frontendPublicIpId
                $pipRg = Get-ResourceGroupNameFromId -ResourceId $frontendPublicIpId
                $pip = Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $pipRg -ErrorAction SilentlyContinue
                if ($pip) {
                    if (-not [string]::IsNullOrWhiteSpace($pip.DnsSettings.Fqdn)) {
                        $gatewayHost = $pip.DnsSettings.Fqdn
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($pip.IpAddress)) {
                        $gatewayHost = $pip.IpAddress
                    }
                }
            }

            if ([string]::IsNullOrWhiteSpace($gatewayHost)) {
                $failureDetails.Add("Application Gateway '$($appGw.Name)' does not have an allocated public frontend IP address or DNS name for internet storefront testing.")
            }
            else {
                $selectedListener = @($listeners | Where-Object { $_.Protocol -eq 'Http' } | Select-Object -First 1)
                if (-not $selectedListener) {
                    $selectedListener = @($listeners | Select-Object -First 1)
                }

                $frontendPort = 80
                if ($selectedListener -and $selectedListener.FrontendPort.Id) {
                    $selectedPortName = Get-ResourceNameFromId -ResourceId $selectedListener.FrontendPort.Id
                    $portObject = @($appGw.FrontendPorts | Where-Object { $_.Name -eq $selectedPortName } | Select-Object -First 1)
                    if ($portObject -and $portObject.Port) {
                        $frontendPort = [int]$portObject.Port
                    }
                }

                $scheme = if ($selectedListener -and $selectedListener.Protocol -eq 'Https') { 'https' } else { 'http' }
                $uri = if (($scheme -eq 'http' -and $frontendPort -eq 80) -or ($scheme -eq 'https' -and $frontendPort -eq 443)) {
                    "${scheme}://$gatewayHost/"
                }
                else {
                    "${scheme}://$gatewayHost`:$frontendPort/"
                }

                try {
                    $webRequestParams = @{
                        Uri             = $uri
                        UseBasicParsing = $true
                        TimeoutSec      = 30
                        ErrorAction     = 'Stop'
                    }
                    if ($selectedListener -and -not [string]::IsNullOrWhiteSpace($selectedListener.HostName)) {
                        $webRequestParams.Headers = @{ Host = $selectedListener.HostName }
                    }
                    if ($scheme -eq 'https') {
                        $webRequestParams.SkipCertificateCheck = $true
                    }

                    $response = Invoke-WebRequest @webRequestParams
                    $content = [string]$response.Content
                    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
                        $failureDetails.Add("Normal request to Application Gateway '$($appGw.Name)' at '$uri' returned HTTP $($response.StatusCode), not a 2xx success.")
                    }
                    elseif ($content -notmatch 'Zava\s*Retail|Zava|Retail|storefront') {
                        $failureDetails.Add("Normal request to Application Gateway '$($appGw.Name)' at '$uri' returned HTTP $($response.StatusCode) but did not contain expected Zava Retail storefront content.")
                    }
                }
                catch {
                    $failureDetails.Add("Normal request to Application Gateway '$($appGw.Name)' at '$uri' did not return the storefront: $($_.Exception.Message)")
                }
            }
        }

        if ($failureDetails.Count -eq 0) {
            $found = $true
            $healthySummary = @($healthyRecords | ForEach-Object { "$($_.Address)=$($_.Health)" }) -join '; '
            $message = @{
                Status  = "Succeeded"
                Message = "Application Gateway '$($appGw.Name)' in RG '$rg' is deployed in 'appgw-subnet' with WAF_v2 SKU, has listener/routing rule configuration, targets storefront VM 'zava-web-vm', reports healthy backend(s) [$healthySummary], and normal gateway traffic returns Zava Retail storefront content."
            } | ConvertTo-Json -Compress
        }
        else {
            $lastFailure = $failureDetails -join ' '
            $message = @{
                Status  = "Failed"
                Message = "Application Gateway WAF_v2 and routing check failed in RG '$rg'. $lastFailure"
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
        $lastFailure = "Error during check. Attempt $count of 3. Error: $($_.Exception.Message)"
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
        Message = "Application Gateway WAF_v2 and healthy routing validation did not succeed in RG '$rg' after 3 attempts. $lastFailure"
    } | ConvertTo-Json -Compress
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
