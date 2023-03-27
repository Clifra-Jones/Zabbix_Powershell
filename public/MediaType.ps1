# Media Types
function Get-ZabbixMediaType() {
    Param(
        [string]$MediaTypeId,
        [ValidateSet('email','script','SMS','Webhook')]
        [string]$Media,
        [string]$UserId,
        [switch]$includeUsers,
        [switch]$includeMessageTemplates,
        [string]$authcode
    )

    if (-not $authcode) {
        $authcode = Read-ZabbixConfig
    }
    
    $payload = Get-Payload

    $payload.method = "mediatype.get"

    if ($includeMessageTemplates) {
        $payload.params = @{
            output = "extend"
            selectMessageTemplates = "extend"
        }
    }

    if ($MediaTypeId) {$payload.params.Add("mediatypeids", $MediaTypeId)}
    if ($Media) {
        $media = @('email','script','SMS','Webhook')
        $mediaIndex = $media.IndexOf($Media)
        $payload.params.Add("mediaids", $MediaIndex)
    }
    if ($UserId) {$payload.params.Add("userids", $UserId)}

    $payload.Add("auth", $authcode)

    $body = $payload | ConvertTo-Json 

    try {
        $response = Invoke-RestMethod -Method GET -Uri $Uri -ContentType 'application/json' -Body $body
        if ($response.error) {
            throw $response.error.data
        }
        return $response.result
    } catch {
        throw $_
    }

    <#
    .SYNOPSIS
    Return media types.
    .PARAMETER MediaTypeId
    Return only media types with the given ID.
    .PARAMETER Media
    Return only media types used by the given media.
    .PARAMETER UserId
    Return only media types used by the given users.
    .PARAMETER includeUsers
    Return a users property with the users that use the media type.
    .PARAMETER includeMessageTemplates
    Return a message_templates property with an array of media type messages.
    .OUTPUTS
    An array of media Type objects.
    #>
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
        [ValidateSet('email','script','SMS','Webhook')]
        [string]$Media,
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
        [psobject]$messageTemplates,
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
    if ($Media) {
        $media = @('email','script','SMS','Webhook')
        $mediaIndex = $media.IndexOf($Media)
        $payload.params.Add("type", $MediaIndex)
    }
    if ($execPath) {
        if ($media -ne 'script') {
            throw "Parameter execPath only valid for script media types!"
        }
        $payload.params.Add("name",$execPath) 
    }
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
    if ($html) { $payload.params.Add("content_type", "1") }
    if ($script) {
        if ($media -ne "Webhook") {
            throw "Parameter script only valid with media type Webhook"
        }
        $payload.params.Add("script", $script)
    }
    if ($timeout) {
        if ($media -ne "Webhook") {
            throw "Parameter timeout only valid with media type Webhook"
        }
        $payload.params.Add("timeout", $timeout) 
    }
    if ($webhookTags) {
        if ($media -ne "Webhook") {
            throw "Parameter webhookTags only valid with media type Webhook"
        }
        $payload.params.Add("process_tags", 1) 
    }
    if ($showEventMenu) { $payload.params.Add("show_event_menu", 1) }
    if ($eventMenuUrl) { $payload.params.Add("event_menu_url", $eventMenuUrl) }
    if ($eventMenuName) { $payload.params.Add("event_menu_name", $eventMenuName) }
    if ($webhookParameters) { $payload.params.Add("parameters", $webhookParameters) }
    if ($description) { $payload.params.Add("description", $description) }

    $body = $payload | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Method Post -Uri $Uri -ContentType 'application/json' -Body $body
        If ($response.error) {
            throw $response.error.data
        } else {
            return $response.result
        }
    } catch {
        throw $_
    }
    <#
    .SYNOPSIS
    Modify a media type.
    .DESCRIPTION
    Modify an existing media type.
    .PARAMETER mediaTypeId
    Media type to be modified.
    .PARAMETER name
    Name of the media type.
    .PARAMETER Media
    The type of media transport.
    .PARAMETER execPath
    For script media types exec_path contains the name of the executed script.
    .PARAMETER gsmModem
    Serial device name of the GSM modem.
    .PARAMETER username
    Username for media connection
    .PARAMETER passwd
    Password for media connections.
    .PARAMETER smtpEmail
    Email address from which notifications will be sent.
    .PARAMETER smtpHelo
    SMTP HELO
    .PARAMETER smtpServer
    SMTP Server
    .PARAMETER smtpPort
    SMTP Port
    .PARAMETER smtpSecurity
    MTP connection security level to use.
    .PARAMETER smtpVerifyHost
    SSL verify host for SMTP.
    .PARAMETER smtpVerifyPeer
    SSL verify peer for SMTP.
    .PARAMETER smtpAuthentication
    SMTP authentication method to use.
    .PARAMETER disable
    Disable this media type.
    .PARAMETER execParams
    Script parameters
    .PARAMETER maxSessions
    The maximum number of alerts that can be processed in parallel. Default = 1, MAX = 100.
    .PARAMETER maxAttempts
    The maximum number of attempts to send an alert. Default = 3, Max = 100.
    .PARAMETER attemptInterval
    The interval between retry attempts. Accepts seconds and time unit with suffix. Default = 10s.
    .PARAMETER html
    Content-Type = HTML, otherwise plain text.
    .PARAMETER script
    Media type webhook script javascript body.
    .PARAMETER timeout
    The interval between retry attempts. Accepts seconds and time unit with suffix. Default = 10s.
    .PARAMETER webhookTags
    Defines should the webhook script response to be interpreted as tags and these tags should be added to associated event.
    .PARAMETER showEventMenu
    Show media type entry in problem.get and event.get property urls.
    .PARAMETER eventMenuUrl
    Define url property of media type entry in urls property of problem.get and event.get.
    .PARAMETER eventMenuName
    Define name property of media type entry in urls property of problem.get and event.get.
    .PARAMETER webhookParameters
    Array of webhook input parameters.
    .PARAMETER description
    Media type description.
    .PARAMETER messageTemplates
    An array of message template properties.
    .PARAMETER authcode
    Authorization code to use for the API call. If omitted read the authcode from the local configuration file.
    #>
}
