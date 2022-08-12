# Media Types
function Get-ZabbixMediaTypes() {
    Param(
        [string]$authcode
    )

    if (-not $authcode) {
        $authcode = Read-ZabbixConfig
    }
    
    $payload = Get-Payload

    $payload.method = "mediatype.get"
    $payload.params = @{
        output = "extend"
        selectMessageTemplates = "extend"
    }
    $payload.Add("auth", $authcode)

    $body = $payload | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Method GET -Uri $Uri -ContentType 'application/json' -Body $body
        return $response.result
    } catch {
        throw $_
    }
}

function Set-ZabbixMediaType() {
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
        [string]$username,
        [string]$passwd,
        [string]$smtpEmail,
        [string]$smtpHelo,
        [string]$smtpServer,
        [int]$smtpPort,
        [ValidateSet('None','STARTTLS','SSL/TLS')]
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
        [string]$description,
        [string]$authcode
    )
    if (-not $authcode) {
        $authcode = Read-ZabbixConfig
    }

    $payload = Get-Payload

    $payload.method = "mediatype.update"
    $payload.params = @{
        mediatypeid = $mediaTypeId
    }
    $payload.Add("auth", $authcode)

    if ($name) { $payload.params.Add("name",$name) }
    if ($execPath) { $payload.params.Add("name",$execPath) }
    if ($gsmModem) { $payload.params.Add("gms_modem", $gsmModem) }
    if ($passwd) { $payload.params.Add("passwd", $passwd) }
    if ($username) { $payload.params.Add("username", $username)}
    if ($smtpEmail) { $payload.params.Add("smtp_email", $smtpEmail) }
    if ($smtpHelo) { $payload.params.Add("smtp_help", $smtpHelo) }
    if ($smtpServer) {$payload.params.Add("smtp_server", $smtpServer) }
    if ($smtpPort) { $payload.params.Add("smtp_port", $smtpPort) }
    if ($smtpSecurity) {
        switch ($smtpSecurity) {
            "None" {
                $payload.params.Add("smtp_security", 0)
            }
            "STARTTLS" {
                $payload.params.Add("smtp_securoty", 1)
            }
            "SSL/TLS" {
                $payload.params.Add("smtp_security", 2)
            }
        }
    }
    if ($smtpVerifyHost) { $payload.params.Add("smtp_verifu_host", 1) }
    if ($smtpVerifyPeer) { $payload.params.Add("smtp_verify_peer", 1) }
    if ($smtpAuthentication) {$payload.params.Add("smtp_authentication", 1) }
    if ($disable) { $payload.params.Add("status", 1) }
    if ($execParams) { $payload.params.Add("exec_params", $execParams) }
    if ($maxSessions) { $payload.params.Add("maxsessions", $maxSessions) }
    if ($maxAttempts) {$payload.params.Add("maxattempts", $maxAttempts) }
    if ($attemptInterval) { $payload.params.Add("attempt_interval", $attemptInterval) }
    if  ($html) { $payload.params.Add("content_type", "1") }
    if ($script) { $payload.params.Add("script", $script) }
    if ($timeout) { $payload.params.Add("timeout", $timeout) }
    if ($webhookTags) { $payload.params.Add("process_tags", 1) }
    if ($showEventMenu) { $payload.params.Add("show_event_menu", 1) }
    if ($eventMenuUrl) { $payload.params.Add("event_menu_url", $eventMenuUrl) }
    if ($eventMenuName) { $payload.params.Add("event_menu_name", $eventMenuName) }
    if ($webhookParameters) { $payload.params.Add("parameters", $webhookParameters) }
    if ($description) { $payload.params.Add("description", $description) }

    $body = $payload | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Method Post -Uri $Uri -ContentType 'application/json' -Body $body
        return $response.result
    } catch {
        throw $_
    }
}
