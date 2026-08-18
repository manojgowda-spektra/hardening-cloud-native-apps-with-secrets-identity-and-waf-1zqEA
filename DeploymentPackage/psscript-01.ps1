Param(
    [string] $AzureUserName,
    [string] $AzurePassword,
    [string] $AzureTenantID,
    [string] $AzureSubscriptionID,
    [string] $ODLID,
    [string] $InstallCloudLabsShadow,
    [string] $DeploymentID,
    [string] $vmAdminUsername,
    [string] $vmAdminPassword,
    [string] $trainerUserName,
    [string] $trainerUserPassword
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$logPath = 'C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt'
New-Item -ItemType Directory -Path (Split-Path $logPath) -Force | Out-Null
Start-Transcript -Path $logPath -Append -Force

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    function Write-Log {
        param([string]$Message)
        Write-Host "[$(Get-Date -Format o)] $Message"
    }

    function Invoke-DownloadFile {
        param(
            [Parameter(Mandatory = $true)][string]$Uri,
            [Parameter(Mandatory = $true)][string]$OutFile
        )
        New-Item -ItemType Directory -Path (Split-Path $OutFile) -Force | Out-Null
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    }

    function Update-TokenizedFile {
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [hashtable]$Tokens
        )
        if (-not (Test-Path $Path)) { return }
        $content = Get-Content -Path $Path -Raw
        foreach ($key in $Tokens.Keys) {
            $value = [string]$Tokens[$key]
            $patterns = @(
                "<$key>",
                "[$key]",
                "{$key}",
                "__${key}__",
                "#${key}#",
                "`${$key}"
            )
            foreach ($pattern in $patterns) {
                $content = $content.Replace($pattern, $value)
            }
            # The undelimited token name is replaced only where it stands on its own and is not
            # part of a variable name. A plain substring replace collides twice: TenantID matches
            # inside AzureTenantID, so the tenant ID comes out prefixed with the text Azure, and
            # the variable name in $AzureTenantID = 'AzureTenantID' is overwritten along with the
            # value, which leaves AzureCreds.ps1 invalid PowerShell.
            $bareToken = '(?<![\w$])' + [regex]::Escape($key) + '(?!\w)'
            $content = [regex]::Replace($content, $bareToken, $value.Replace('$', '$$'))
        }
        Set-Content -Path $Path -Value $content -Encoding UTF8 -Force
    }

    function CreateCredFile {
        Write-Log 'Creating CloudLabs credential files.'
        $commonBase = 'https://experienceazure.blob.core.windows.net/templates/cloudlabs-common'
        $labFiles = 'C:\LabFiles'
        $desktop = 'C:\Users\Public\Desktop'
        New-Item -ItemType Directory -Path $labFiles -Force | Out-Null
        New-Item -ItemType Directory -Path $desktop -Force | Out-Null

        $downloadTargets = @(
            @{ Uri = "$commonBase/AzureCreds.txt"; Path = Join-Path $labFiles 'AzureCreds.txt' },
            @{ Uri = "$commonBase/AzureCreds.ps1"; Path = Join-Path $labFiles 'AzureCreds.ps1' }
        )

        foreach ($target in $downloadTargets) {
            try {
                Invoke-DownloadFile -Uri $target.Uri -OutFile $target.Path
            }
            catch {
                Write-Log "Common credential artifact $($target.Uri) was not downloaded: $($_.Exception.Message)"
                if ($target.Path.EndsWith('.txt')) {
                    @"
Azure User Name: AzureUserName
Azure Password: AzurePassword
Azure Tenant ID: AzureTenantID
Azure Subscription ID: AzureSubscriptionID
Deployment ID: DeploymentID
ODL ID: ODLID
"@ | Set-Content -Path $target.Path -Encoding UTF8 -Force
                }
                else {
                    @"
`$AzureUserName = 'AzureUserName'
`$AzurePassword = 'AzurePassword'
`$AzureTenantID = 'AzureTenantID'
`$AzureSubscriptionID = 'AzureSubscriptionID'
`$DeploymentID = 'DeploymentID'
`$ODLID = 'ODLID'
"@ | Set-Content -Path $target.Path -Encoding UTF8 -Force
                }
            }
        }

        $tokens = @{
            'AzureUserName'       = $AzureUserName
            'AzurePassword'       = $AzurePassword
            'AzureTenantID'       = $AzureTenantID
            'AzureSubscriptionID' = $AzureSubscriptionID
            'SubscriptionID'      = $AzureSubscriptionID
            'TenantID'            = $AzureTenantID
            'DeploymentID'        = $DeploymentID
            'ODLID'               = $ODLID
            'vmAdminUsername'     = $vmAdminUsername
            'vmAdminPassword'     = $vmAdminPassword
        }

        foreach ($file in @((Join-Path $labFiles 'AzureCreds.txt'), (Join-Path $labFiles 'AzureCreds.ps1'))) {
            Update-TokenizedFile -Path $file -Tokens $tokens
            Copy-Item -Path $file -Destination (Join-Path $desktop (Split-Path $file -Leaf)) -Force
        }
    }

    function Enable-TrainerShadowAccount {
        $shadowRequested = $true
        if (-not [string]::IsNullOrWhiteSpace($InstallCloudLabsShadow)) {
            $shadowRequested = ($InstallCloudLabsShadow -notmatch '^(false|0|no)$')
        }

        if (-not $shadowRequested) {
            Write-Log 'InstallCloudLabsShadow is explicitly false. Skipping trainer local account creation.'
            return
        }
        if ([string]::IsNullOrWhiteSpace($trainerUserName) -or [string]::IsNullOrWhiteSpace($trainerUserPassword)) {
            Write-Log 'Trainer credentials were not provided. Skipping trainer local account creation.'
            return
        }

        Write-Log 'Creating or updating trainer local account for VM Shadow/RDP support.'
        $securePassword = ConvertTo-SecureString $trainerUserPassword -AsPlainText -Force
        $existing = Get-LocalUser -Name $trainerUserName -ErrorAction SilentlyContinue
        if ($existing) {
            Set-LocalUser -Name $trainerUserName -Password $securePassword -PasswordNeverExpires $true
            Enable-LocalUser -Name $trainerUserName
        }
        else {
            New-LocalUser -Name $trainerUserName -Password $securePassword -PasswordNeverExpires -AccountNeverExpires | Out-Null
        }

        foreach ($group in @('Remote Desktop Users', 'Administrators')) {
            try {
                Add-LocalGroupMember -Group $group -Member $trainerUserName -ErrorAction Stop
            }
            catch {
                if ($_.Exception.Message -notmatch 'already.*member') {
                    Write-Log "Unable to add $trainerUserName to ${group}: $($_.Exception.Message)"
                }
            }
        }
    }

    function Install-ProductivityTools {
        Write-Log 'Installing productivity tools for the lab VM.'
        try {
            $azExists = Get-Command az.cmd -ErrorAction SilentlyContinue
            if (-not $azExists) {
                $azMsi = Join-Path $env:TEMP 'AzureCLI.msi'
                Invoke-DownloadFile -Uri 'https://aka.ms/installazurecliwindows' -OutFile $azMsi
                Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $azMsi, '/quiet', '/norestart') -Wait
                $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')
            }
        }
        catch {
            Write-Log "Azure CLI installation was skipped or failed non-fatally: $($_.Exception.Message)"
        }

        try {
            $portalShortcut = 'C:\Users\Public\Desktop\Azure Portal.url'
            "[InternetShortcut]`r`nURL=https://portal.azure.com/`r`n" | Set-Content -Path $portalShortcut -Encoding ASCII -Force
        }
        catch {
            Write-Log "Unable to create Azure Portal shortcut: $($_.Exception.Message)"
        }
    }

    function Install-ZavaRetailStorefront {
        Write-Log 'Installing IIS and the Zava Retail storefront.'
        Install-WindowsFeature -Name Web-Server, Web-Common-Http, Web-Default-Doc, Web-Static-Content, Web-Http-Errors, Web-Http-Logging, Web-Asp-Net45, Web-Net-Ext45, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Mgmt-Console -IncludeManagementTools | Out-Null

        Import-Module WebAdministration

        $zavaRoot = 'C:\ZavaRetail'
        $siteRoot = Join-Path $zavaRoot 'wwwroot'
        $configRoot = Join-Path $zavaRoot 'Config'
        $toolsRoot = Join-Path $zavaRoot 'Tools'
        New-Item -ItemType Directory -Path $siteRoot, $configRoot, $toolsRoot -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $siteRoot 'health'), (Join-Path $siteRoot 'config-status') -Force | Out-Null

        $sampleConnectionString = 'Server=tcp:zava-sample.database.windows.net,1433;Initial Catalog=ZavaRetailSample;User ID=zava_app;Password=PlaintextSampleOnly!2026;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;'
        $plainTextPath = Join-Path $configRoot 'plaintext-connection-string.txt'
        Set-Content -Path $plainTextPath -Value $sampleConnectionString -Encoding UTF8 -Force

        $configPath = Join-Path $configRoot 'zava-config.json'
        $config = [ordered]@{
            Source = 'Local'
            SecretName = 'ZavaAppConnectionString'
            VaultName = ''
            LocalPlaintextPath = $plainTextPath
            LastUpdatedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Notes = 'Initial insecure lab baseline. The connection string is a sample security artifact only; there is no backing database and the app never opens a database connection.'
        }
        $config | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding UTF8 -Force

        $commonCode = @'
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>
<script runat="server">
    const string ConfigPath = @"C:\ZavaRetail\Config\zava-config.json";
    const string RequiredSecretName = "ZavaAppConnectionString";

    Dictionary<string, object> ReadConfig()
    {
        var serializer = new JavaScriptSerializer();
        var text = File.ReadAllText(ConfigPath);
        return serializer.Deserialize<Dictionary<string, object>>(text);
    }

    string ConfigValue(Dictionary<string, object> config, string key)
    {
        if (config != null && config.ContainsKey(key) && config[key] != null) { return config[key].ToString(); }
        return String.Empty;
    }

    string ToJson(object value)
    {
        return new JavaScriptSerializer().Serialize(value);
    }

    string GetManagedIdentityTokenForKeyVault()
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        var tokenUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net";
        var request = (HttpWebRequest)WebRequest.Create(tokenUri);
        request.Method = "GET";
        request.Headers.Add("Metadata", "true");
        request.Proxy = null;
        using (var response = (HttpWebResponse)request.GetResponse())
        using (var stream = response.GetResponseStream())
        using (var reader = new StreamReader(stream))
        {
            var payload = reader.ReadToEnd();
            var serializer = new JavaScriptSerializer();
            var result = serializer.Deserialize<Dictionary<string, object>>(payload);
            if (!result.ContainsKey("access_token")) { throw new ApplicationException("Managed identity token response did not include an access_token."); }
            return result["access_token"].ToString();
        }
    }

    string GetSecretFromKeyVault(string vaultName)
    {
        if (String.IsNullOrWhiteSpace(vaultName)) { throw new ApplicationException("VaultName is not configured."); }
        var token = GetManagedIdentityTokenForKeyVault();
        var secretUri = String.Format("https://{0}.vault.azure.net/secrets/{1}?api-version=7.4", vaultName, RequiredSecretName);
        var request = (HttpWebRequest)WebRequest.Create(secretUri);
        request.Method = "GET";
        request.Headers.Add("Authorization", "Bearer " + token);
        request.Proxy = null;
        using (var response = (HttpWebResponse)request.GetResponse())
        using (var stream = response.GetResponseStream())
        using (var reader = new StreamReader(stream))
        {
            var payload = reader.ReadToEnd();
            var serializer = new JavaScriptSerializer();
            var result = serializer.Deserialize<Dictionary<string, object>>(payload);
            if (!result.ContainsKey("value")) { throw new ApplicationException("Key Vault secret response did not include a value."); }
            return result["value"].ToString();
        }
    }
</script>
'@

        $rootPage = @'
<%@ Page Language="C#" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Zava Retail</title>
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #f5f7fb; color: #1f2937; }
        header { background: #111827; color: white; padding: 28px 40px; }
        main { padding: 32px 40px; }
        .card { background: white; border-radius: 10px; padding: 24px; max-width: 900px; box-shadow: 0 6px 18px rgba(0,0,0,.08); }
        code { background: #eef2ff; padding: 2px 6px; border-radius: 4px; }
        .badge { display: inline-block; background: #fee2e2; color: #991b1b; border-radius: 999px; padding: 6px 12px; font-weight: 600; }
    </style>
</head>
<body>
    <header><h1>Zava Retail Storefront</h1><p>Working storefront baseline for identity, secrets, and WAF hardening.</p></header>
    <main>
        <section class="card">
            <span class="badge">Initial posture: direct VM + local plaintext sample secret</span>
            <h2>Welcome to Zava Retail</h2>
            <p>This lightweight storefront is intentionally deployed on a single IIS VM so you can harden it without rebuilding it.</p>
            <ul>
                <li>Health endpoint: <code>/health</code></li>
                <li>Configuration source endpoint: <code>/config-status</code></li>
                <li>Switch helper: <code>C:\ZavaRetail\Tools\Set-ZavaSecretSource.ps1</code></li>
                <li>Required Key Vault secret name: <code>ZavaAppConnectionString</code></li>
            </ul>
            <p>The connection string used in this lab is a sample security artifact only. The storefront never opens a database connection.</p>
        </section>
    </main>
</body>
</html>
'@
        Set-Content -Path (Join-Path $siteRoot 'default.aspx') -Value $rootPage -Encoding UTF8 -Force

        $healthPage = @"
<%@ Page Language="C#" %>
$commonCode
<script runat="server">
    void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        var output = new Dictionary<string, object>();
        output["service"] = "ZavaRetail";
        output["secretName"] = RequiredSecretName;
        output["databaseConnectionAttempted"] = false;
        try
        {
            var config = ReadConfig();
            var source = ConfigValue(config, "Source");
            output["source"] = source;
            if (String.Equals(source, "KeyVault", StringComparison.OrdinalIgnoreCase))
            {
                var secret = GetSecretFromKeyVault(ConfigValue(config, "VaultName"));
                if (String.IsNullOrWhiteSpace(secret)) { throw new ApplicationException("The Key Vault secret was empty."); }
                output["status"] = "Healthy";
                output["resolvedBy"] = "VM system-assigned managed identity";
            }
            else
            {
                var localPath = ConfigValue(config, "LocalPlaintextPath");
                var localSecret = File.Exists(localPath) ? File.ReadAllText(localPath) : String.Empty;
                if (String.IsNullOrWhiteSpace(localSecret)) { throw new ApplicationException("The local plaintext sample connection string was missing or empty."); }
                output["status"] = "Healthy";
                output["resolvedBy"] = "Local plaintext configuration";
            }
            output["checkedUtc"] = DateTime.UtcNow.ToString("o");
            Response.StatusCode = 200;
        }
        catch (Exception ex)
        {
            Response.StatusCode = 503;
            output["status"] = "Unhealthy";
            output["error"] = ex.Message;
            output["checkedUtc"] = DateTime.UtcNow.ToString("o");
        }
        Response.Write(ToJson(output));
    }
</script>
"@
        Set-Content -Path (Join-Path $siteRoot 'health\default.aspx') -Value $healthPage -Encoding UTF8 -Force

        $configStatusPage = @"
<%@ Page Language="C#" %>
$commonCode
<script runat="server">
    void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        var output = new Dictionary<string, object>();
        try
        {
            var config = ReadConfig();
            var source = ConfigValue(config, "Source");
            var localPath = ConfigValue(config, "LocalPlaintextPath");
            output["status"] = "OK";
            output["source"] = source;
            output["activeSource"] = source;
            output["secretName"] = RequiredSecretName;
            output["vaultNameConfigured"] = !String.IsNullOrWhiteSpace(ConfigValue(config, "VaultName"));
            output["localPlaintextPathExists"] = File.Exists(localPath);
            output["secretValueExposed"] = false;
            output["databaseConnectionAttempted"] = false;
            output["checkedUtc"] = DateTime.UtcNow.ToString("o");
            Response.StatusCode = 200;
        }
        catch (Exception ex)
        {
            Response.StatusCode = 500;
            output["status"] = "Error";
            output["error"] = ex.Message;
            output["secretValueExposed"] = false;
        }
        Response.Write(ToJson(output));
    }
</script>
"@
        Set-Content -Path (Join-Path $siteRoot 'config-status\default.aspx') -Value $configStatusPage -Encoding UTF8 -Force

        $webConfig = @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.web>
    <compilation targetFramework="4.8" />
    <httpRuntime targetFramework="4.8" />
    <customErrors mode="Off" />
  </system.web>
  <system.webServer>
    <defaultDocument enabled="true">
      <files>
        <clear />
        <add value="default.aspx" />
      </files>
    </defaultDocument>
    <httpProtocol>
      <customHeaders>
        <add name="X-Zava-Lab" value="Secrets-Identity-WAF" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
'@
        Set-Content -Path (Join-Path $siteRoot 'web.config') -Value $webConfig -Encoding UTF8 -Force

        $helper = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Local', 'KeyVault')]
    [string]$Source,

    [Parameter(Mandatory = $false)]
    [string]$VaultName,

    [switch]$RemoveLocalPlaintext,
    [switch]$TestRetrieval
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ConfigPath = 'C:\ZavaRetail\Config\zava-config.json'
$PlaintextPath = 'C:\ZavaRetail\Config\plaintext-connection-string.txt'
$RequiredSecretName = 'ZavaAppConnectionString'
$SampleConnectionString = 'Server=tcp:zava-sample.database.windows.net,1433;Initial Catalog=ZavaRetailSample;User ID=zava_app;Password=PlaintextSampleOnly!2026;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;'

function Get-ZavaManagedIdentityTokenForKeyVault {
    # Microsoft Learn documents VM managed identity token acquisition through IMDS at 169.254.169.254.
    # The Metadata=true header is required. The resource value requests a Key Vault token.
    $metadataUri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net'
    try { [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy } catch { }
    $response = Invoke-RestMethod -Method GET -Uri $metadataUri -Headers @{ Metadata = 'true' } -TimeoutSec 10
    if (-not $response.access_token) { throw 'Managed identity token response did not include an access_token.' }
    return $response.access_token
}

function Test-ZavaSecretRetrieval {
    param([Parameter(Mandatory = $true)][string]$VaultNameToTest)
    $token = Get-ZavaManagedIdentityTokenForKeyVault
    $secretUri = "https://$VaultNameToTest.vault.azure.net/secrets/$RequiredSecretName`?api-version=7.4"
    $secret = Invoke-RestMethod -Method GET -Uri $secretUri -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 15
    if (-not $secret.value) { throw "Secret $RequiredSecretName was returned without a value." }
    [pscustomobject]@{
        VaultName = $VaultNameToTest
        SecretName = $RequiredSecretName
        RetrievedWith = 'VM system-assigned managed identity'
        SecretValueDisplayed = $false
        Result = 'Success'
    }
}

if ($Source -eq 'KeyVault' -and [string]::IsNullOrWhiteSpace($VaultName)) {
    throw 'VaultName is required when Source is KeyVault. Example: .\Set-ZavaSecretSource.ps1 -Source KeyVault -VaultName kv-zava-12345 -RemoveLocalPlaintext -TestRetrieval'
}

if (-not (Test-Path $PlaintextPath) -and $Source -eq 'Local') {
    Set-Content -Path $PlaintextPath -Value $SampleConnectionString -Encoding UTF8 -Force
}

if ($Source -eq 'KeyVault' -and $RemoveLocalPlaintext) {
    'NON_AUTHORITATIVE_MOVED_TO_KEY_VAULT' | Set-Content -Path $PlaintextPath -Encoding UTF8 -Force
}

$config = [ordered]@{
    Source = $Source
    SecretName = $RequiredSecretName
    VaultName = $(if ($Source -eq 'KeyVault') { $VaultName } else { '' })
    LocalPlaintextPath = $PlaintextPath
    LastUpdatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Notes = $(if ($Source -eq 'KeyVault') { 'Runtime source is Key Vault. The app retrieves the latest enabled ZavaAppConnectionString value with the VM system-assigned managed identity.' } else { 'Runtime source is the initial local plaintext sample configuration.' })
}

$config | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigPath -Encoding UTF8 -Force

if ($TestRetrieval -and $Source -eq 'KeyVault') {
    Test-ZavaSecretRetrieval -VaultNameToTest $VaultName | Format-List
}

Write-Host "Zava Retail secret source is now set to $Source."
Write-Host "The configured secret name is $RequiredSecretName."
Write-Host 'The application reads this configuration at request time; no rebuild is required.'
'@
        Set-Content -Path (Join-Path $toolsRoot 'Set-ZavaSecretSource.ps1') -Value $helper -Encoding UTF8 -Force

        $labInfo = @"
Zava Retail Lab VM
==================

Storefront root: http://localhost/
Health endpoint: http://localhost/health
Configuration status endpoint: http://localhost/config-status
Local plaintext sample: C:\ZavaRetail\Config\plaintext-connection-string.txt
Source switch helper: C:\ZavaRetail\Tools\Set-ZavaSecretSource.ps1
Required Key Vault secret name: ZavaAppConnectionString

The sample connection string is a training artifact only. There is no database and the application never opens a database connection.
"@
        New-Item -ItemType Directory -Path 'C:\LabFiles' -Force | Out-Null
        Set-Content -Path 'C:\LabFiles\ZavaRetail-ReadMe.txt' -Value $labInfo -Encoding UTF8 -Force

        $envFile = @"
AZURE_SUBSCRIPTION_ID=$AzureSubscriptionID
AZURE_TENANT_ID=$AzureTenantID
DEPLOYMENT_ID=$DeploymentID
ODL_ID=$ODLID
ZAVA_SECRET_NAME=ZavaAppConnectionString
ZAVA_STORE_FRONT_URL=http://localhost/
ZAVA_HEALTH_URL=http://localhost/health
ZAVA_CONFIG_STATUS_URL=http://localhost/config-status
ZAVA_HELPER_PATH=C:\ZavaRetail\Tools\Set-ZavaSecretSource.ps1
"@
        Set-Content -Path 'C:\LabFiles\.env' -Value $envFile -Encoding UTF8 -Force

        # IIS application pool and site wiring.
        if (-not (Test-Path 'IIS:\AppPools\ZavaRetailAppPool')) {
            New-WebAppPool -Name 'ZavaRetailAppPool' | Out-Null
        }
        Set-ItemProperty 'IIS:\AppPools\ZavaRetailAppPool' -Name managedRuntimeVersion -Value 'v4.0'
        Set-ItemProperty 'IIS:\AppPools\ZavaRetailAppPool' -Name managedPipelineMode -Value 'Integrated'

        if (Test-Path 'IIS:\Sites\Default Web Site') {
            Set-ItemProperty 'IIS:\Sites\Default Web Site' -Name physicalPath -Value $siteRoot
            Set-ItemProperty 'IIS:\Sites\Default Web Site' -Name applicationPool -Value 'ZavaRetailAppPool'
        }
        else {
            New-Website -Name 'Default Web Site' -PhysicalPath $siteRoot -Port 80 -ApplicationPool 'ZavaRetailAppPool' -Force | Out-Null
        }

        icacls $zavaRoot /grant 'IIS_IUSRS:(OI)(CI)(RX)' /T | Out-Null
        icacls $configRoot /grant 'IIS_IUSRS:(OI)(CI)(RX)' /T | Out-Null
        icacls $siteRoot /grant 'IIS_IUSRS:(OI)(CI)(RX)' /T | Out-Null

        try {
            New-NetFirewallRule -DisplayName 'Zava Retail HTTP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Any -ErrorAction Stop | Out-Null
        }
        catch {
            if ($_.Exception.Message -notmatch 'already') { Write-Log "Firewall rule creation warning: $($_.Exception.Message)" }
        }

        Restart-Service W3SVC -Force

        # Warm up endpoints. The health path may redirect to the directory default document; Invoke-WebRequest follows redirects by default.
        # The first request to each page triggers ASP.NET compilation and is the slowest request this
        # VM ever serves, so the warm-up is given a long timeout and is never allowed to fail the
        # deployment. The site is already installed; the pages compile on the first real request.
        Start-Sleep -Seconds 5
        foreach ($warmUpUri in @('http://localhost/health', 'http://localhost/config-status')) {
            try {
                Invoke-WebRequest -Uri $warmUpUri -UseBasicParsing -TimeoutSec 120 | Out-Null
                Write-Log "Warm-up request to $warmUpUri completed."
            }
            catch {
                Write-Log "Warm-up request to $warmUpUri did not succeed and was ignored: $($_.Exception.Message)"
            }
        }
    }

    CreateCredFile
    Enable-TrainerShadowAccount
    Install-ProductivityTools
    Install-ZavaRetailStorefront

    Write-Log 'CloudLabs Stage 1 CSE bootstrap completed successfully.'
}
catch {
    Write-Error "CloudLabs Stage 1 CSE bootstrap failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    throw
}
finally {
    Stop-Transcript | Out-Null
}
