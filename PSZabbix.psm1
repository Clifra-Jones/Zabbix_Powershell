# Powershell module for the Zabbix 5.0 API.
using namespace System.Management.Automation

$Uri = "zabbix.balfourbeattyus.com/api_jsonrpc.php"
$configPath = "$home/.zabbix"
$configFile = "$configPath/auth.json"

# private functions

function Get-AuthCode() {
    $config = Get-Content $configFile | ConvertFrom-Json
    return $config.authcode
}

function Set-AuthCode() {
    [CmdletBinding()]
    Param(
        [string]$Username,
        [securestring]$Password        
    )

    if (-not $Username) {
        $Creds = Get-Credential
    } else { 
        If (-not $Password) {
            $Creds = Get-Credential -UserName $Username
        } 
    }

    $Username = $Creds.UserName
    $Passwd = ConvertFrom-SecureString -SecureString $creds.Password -AsPlainText

    $hashbody = @{
        jsonrpc = "2.0"
        method = "user.login"
        params = @{
            user = $UserName
            password = $Passwd
        }
        id = 1
    }

    $body = $hashbody | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Method GET -Uri $Uri -ContentType "application/json" -Body $body
        $authcode = $response.result
        $auth = @{
            authcode = $authcode
        }
        if (-not (Test-Path -Path $configPath)) {
            [void](New-Item -ItemType Directory -Path "$home/.zabbix")            
        }
        $Auth | ConvertTo-Json | Out-File $configFile
    } catch {
        Throw $_
    }
}

# Media Types
function Get-MediaTypes() {

    $authcode = Get-AuthCode
    $hashBody = @{
        jsonrpc = "2.0"
        method = "mediatype.get"
        params = @{
            output = "extend"
            SelectMessageTemplates = "extend"
        }
        auth = $authcode
        id = 1
    }
    $body = $hashBody | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Method GET -Uri $Uri -ContentType 'application/json' -Body $body
        return $response.result
    } catch {
        throw $_
    }
}

function Set-MediaType() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [int]$mediaTypeId,
        [string]$name,
        [string]$execPath,
        [string]$gsmModem,
        [string]$passwd,
        [string]$smtpEmail,
        [string]$smtpHelo,
        [string]$smtpServer,
        [int]$smtpPort,
        [ValidatePattern('None','STARTTLS','SSL/TLS')]
        [string]$smtpSecurity,
        [switch]$smtpVerifyHost,
        [switch]$smtpVerifyPeer,
        [switch]$smtpAuthentication,
        [switch]$disable,
        [string]$execParams,
        [int]$maxSessions,
        [int]$maxAttempts,
        [string]$attemptInterval,
        [switch]$html,
        [string]$script,
        [string]$timeout,
        [switch]$webhookTags,
        [switch]$showEventMenu,
        [string]$eventMenuUrl,
        [string]$eventMenuName,
        [hashtable]$webhookParameters,
        [string]$description
    )

    $auth = Get-AuthCode

    $hashBody = @{
        jsonrpc = "2.0"
        method = "mediatype.update"
        params = @{
            mediatypeid = $mediaTypeId
        }
        auth = $auth
        id = 1
    }
    if ($name) { $hashBody.Add("name",$name) }
    if ($execPath) { $hashBody.Add("name",$execPath) }
    if ($gsmModem) { $hashBody.Add("gms_modem", $gsmModem) }
    if ($passwd) { $hashBody.Add("passwd", $passwd) }
    if ($smtpEmail) { $hashBody.Add("smtp_email", $smtpEmail) }
    if ($smtpHelo) { $hashBody.Add("smtp_help", $smtpHelo) }
    if ($smtpServer) {$hashBody.Add("smtp_server", $smtpServer) }
    if ($smtpPort) { $hashBody.Add("smtp_port", $smtpPort) }
    if ($smtpSecurity) {
        switch ($smtpSecurity) {
            "None" {
                $hashBody.Add("smtp_security", 0)
            }
            "STARTTLS" {
                $hashBody.Add("smtp_securoty", 1)
            }
            "SSL/TLS" {
                $hashBody.Add("smtp_security", 2)
            }
        }
        if ($smtpVerifyHost) { $hashBody.Add("smtp_verifu_host", 1) }
        if ($smtpVerifyPeer) { $hashBody.Add("smtp_verify_peer", 1) }
        if ($smtpAuthentication) {$hashBody.Add("smtp_authentication", 1) }
        if ($disable) { $hashBody.Add("status", 1) }
        if ($execParams) { $hashBody.Add("exec_params", $execParams) }
        if ($maxSessions) { $hashBody.Add("maxsessions", $maxSessions) }
        if ($maxAttempts) {$hashBody.Add("maxattempts", $maxAttempts) }
        if ($attemptInterval) { $hashBody.Add("attempt_interval", $attemptInterval) }
        if($html) { $hashBody.Add("content_type", "1") }
        if ($script) { $hashBody.Add("script", $script) }
        if ($timeout) { $hashBody.Add("timeout", $timeout) }
        if ($webhookTags) { $hashBody.Add("process_tags", 1) }
        if ($showEventMenu) { $hashBody.Add("show_event_menu", 1) }
        if ($eventMenuUrl) { $hashBody.Add("event_menu_url", $eventMenuUrl) }
        if ($eventMenuName) { $hashBody.Add("event_menu_name", $eventMenuName) }
        if ($webhookParameters) { $hashBody.Add("parameters", $webhookParameters) }
        if ($description) { $hashBody.Add("description", $description) }

        $body = $hashBody | ConvertTo-Json -Compress

        try {
            $response = Invoke-RestMethod -Method Post -Uri $Uri, -ContentType 'application/json' -Body $body
            return $response.result
        } catch {
            throw $_
        }
    }


}