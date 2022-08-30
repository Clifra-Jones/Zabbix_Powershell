using namespace System.Management
function Get-ZabbixAuthCode() {
    [CmdletBinding()]
    Param(
        [string]$Username,
        [securestring]$Password,
        [switch]$storeToProfile        
    )

    [Automation.pscredential] $zabbixCreds
    if (-not $Username) {
        $zabbixCreds = Get-Credential
    } elseIf (-not $Password) {
            $zabbixCreds = Get-Credential -UserName $Username
    } else {
            $zabbixCreds = [Automation.pscredential]::new($Username, $Password)
    } 

    $Username = $zabbixCreds.UserName
    $Passwd = ConvertFrom-SecureString -SecureString $zabbixcreds.Password -AsPlainText

    $payload = Get-Payload

    $payload.method = "user.login"
    $payload.params = @{
        user = $UserName
        password = $Passwd
    }

    $body = $payload | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Method GET -Uri $Uri -ContentType $contentType -Body $body
        if ($response.error) {
            Write-Host $response.error.data -ForegroundColor Red
            exit
        }
        $authcode = $response.result
        if ($storeToProfile) {
            $auth = @{
                authcode = $authcode
            }
            if (-not (Test-Path -Path $configPath)) {
                [void](New-Item -ItemType Directory -Path "$home/.zabbix")            
            }
            $Auth | ConvertTo-Json | Out-File $configFile
        } else {
            return $authcode
        }
    } catch {
        Throw $_
    }

    <#
    .SYNOPSIS
    Authorize use of the API.
    .DESCRIPTION
    Login and receive an authorization token. 
    User must have a Zabbix logon. 
    If security settings for the user have changed, a new authorization token will be required.
    .PARAMETER Username
    Username to log in with.
    .PARAMETER Password
    Password tl log in with. This MUST be a secure string.
    .PARAMETER storeToProfile
    Stores the authorization token in a configuration file in the directory .zabbix in the user's profile.
    .OUTPUTS
    The authorization token as a string.
    #>
}