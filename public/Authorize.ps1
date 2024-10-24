using namespace System.Management
function Get-ZabbixAuthCode() {
    [CmdletBinding()]
    Param(        
        [string]$Uri,
        [string]$Username,
        [SecureString]$Password,
        [string]$ProfileName,
        [switch]$StoreToProfile
    )

    [Automation.PsCredential] $zabbixCreds
    if (-not $Username) {
        $zabbixCreds = Get-Credential
    } elseIf (-not $Password) {
            $zabbixCreds = Get-Credential -UserName $Username
    } else {
            $zabbixCreds = [Automation.PsCredential]::new($Username, $Password)
    } 

    $Username = $zabbixCreds.UserName
    $Passwd = ConvertFrom-SecureString -SecureString $zabbixCreds.Password -AsPlainText

    $payload = @{
        jsonrpc = "2.0"
    }

    $payload['method'] = "user.login"
    $payload['params'] = @{
        username = $UserName
        password = $Passwd
    }
    $payload['id'] = 1


    $body = $payload | ConvertTo-Json #-Compress

    try {
        $response = Invoke-RestMethod -Method GET -Uri $Uri -ContentType $contentType -Body $body
        
        if ($response.error) {
            Write-Host $response.error.data -ForegroundColor Red
            exit
        }
        $authcode = $response.result

        if ($storeToProfile) {
            if (-not $ProfileName) {
                $ProfileName = 'default'
            }
            if (-not (Test-Path -Path $configPath)) {
                [void](New-Item -ItemType Directory -Path "$home/.zabbix")
            }
            if (-not (Test-Path -Path $configFile)) {
                $Profiles = @{
                    $ProfileName = @{
                        Uri = $Uri
                        authcode = $authcode
                    }
                }                
            } else {
                $Profiles = Get-Content -Path $configFile | ConvertFrom-Json
                if ($Profiles.$ProfileName) {
                    $Profiles.$ProfileName.Uri = $Uri
                    $Profiles.$ProfileName.authcode = $authcode
                } else {
                    $NewProfile = @{
                        Uri = $Uri
                        authcode = $authcode
                    }
                   $Profiles | Add-Member -MemberType NoteProperty -Name $ProfileName -Value $NewProfile -Force
                }
            }
            ConvertTo-Json $Profiles | Out-File $configFile             
        }
        
        $CurrentProfile = @{
            Uri = $Uri 
            authcode = $authcode
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
    If username and password are omitted they will be prompted for.
    .PARAMETER Uri
    The Zabbix API Uri for you primary Zabbix Server.
    .PARAMETER Username
    Username to log in with.
    .PARAMETER Password
    Password to log in with. This MUST be a secure string.
    .PARAMETER storeToProfile
    Stores the authorization token in a configuration file in the directory .zabbix in the user's profile.
    .PARAMETER ProfileName
    The name to store the profile in. Must be used with the StoreToProfile Parameter.
    If omitted the profile is stored as the default profile.
    .OUTPUTS
    The authorization token as a string.
    .NOTES
    This command has the alias Connect-ZabbixUser. Eventually the Get-ZabbixAuthcode command will be depreciated 
    in favor of Connect-ZabbixUser.

    The authcode will remain active until you log out with the Disconnect-ZabbixUser function (alias: Remove-ZabbixAuthCode)
    unless the user has the autologoff property set.

    If your authcode is saved in a profile and still active DO NOT execute this command again. Use the stored profile. This will
    prevent multiple user sessions from being created.

    If you execute this command without the StoreToProfile and ProfileName parameters the auth token will only be retained for the current session.
    You may want to use this if you are using a SuperAdmin account to perform some functions and don't want
    that authcode stored in you profile file.
    Failing to disconnect in this situation will leave the session active if the user account does not have an autologoff property set.
    Closing the powershell window WILL NOT log the user off. Neither will executing a Remove-Module command.
    #>
}

Set-Alias -Name Connect-ZabbixUser -Value Get-ZabbixAuthCode -Option ReadOnly

function Remove-ZabbixAuthCode() {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [string]$ProfileName
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    #     $fromConfig = $true
    # }

    # $payload = Get-Payload

    # $payload.method = 'user.logout'

    # $payload.Add("auth", $authcode)

    $Parameters = @{
        method = 'user.logoff'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    }

    $Parameters.Add("params", @())

    #$body = $payload | ConvertTo-Json -Depth 5 -Compress

    if ($ProfileName) {
        $response = $(Write-host "Warning! You are about to deactivate an authorization code from your profile. Continue? [N/y]" -ForegroundColor Yellow -NoNewline); `
        Read-Host
        if ($response -eq "y") {
            write-host "Operation canceled"
            exit
        }
    }

    if ($PSCmdlet.ShouldProcess("Deactivate","Authorization code ending in $(-join $authcode[-4..-1])")) {
        try {
            #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            $response = Invoke-ZabbixAPI @Parameters
            
            if ($response.error) {
                throw $response.error.data
            }
            if ($ProfileName) {
                $Profiles = Get-Content $configFile | ConvertFrom-Json
                $Profiles.PSObject.Properties.Remove($ProfileName)
                ConvertTo-Json $Profiles |Out-File $configFile
            }
        } catch {
            $_
        }
    }
    <#
    .SYNOPSIS
    Deactivate the current authcode.
    .DESCRIPTION
    Logs the user off and deactivates the API authorization code.
    .PARAMETER ProfileName
    The profile to log off. If the profile is not currently logged on an error will occur.
    The profile entry will be removed from the profiles file.
    This command wil not remove the default profile entry even of if the default profile is logged off!
    If you are changing you default profile authorization code you should re-connect to save your default profile.
    #>
}

Set-Alias -Name Disconnect-ZabbixUser -Value Remove-ZabbixAuthCode -Option ReadOnly

function Save-ZabbixAuthCode () {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [string]$AuthCode,
        [string]$ProfileName
    )

    if (-not $ProfileName) {
        $ProfileName = 'default'
    }

    if (-not (Test-Path -Path $configPath)) {
        [void](New-Item -ItemType Directory -Path "$home/.zabbix")
    }
    if (-not (Test-Path -Path $configFile)) {
        $Profiles = @{
            $ProfileName = @{
                Uri = $Uri
                authcode = $AuthCode
            }
        }
    } else {
        $Profiles = Get-Content -Path $configFile | ConvertFrom-Json
        if ($Profiles.ProfileName) {
            $Profiles.ProfileName.Uri = $Uri
            $Profiles.ProfileName.authCode = $AuthCode        
        } else {
            $NewProfile = @{
                Uri = $Uri
                authcode = $AuthCode
            }
            $Profiles | Add-Member -MemberType NoteProperty -Name $ProfileName -Value $NewProfile -Force
        }
    }

    ConvertTo-Json $Profiles | Out-File $configFile
}

function Set-ZabbixProfile() {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )

    $CurrentProfile = (Read-ZabbixConfig -ProfileName $ProfileName)

    <#
    .SYNOPSIS
    Sets the current active profile.
    .DESCRIPTION
    Sets the current active authentication code and URI to the saved profile name.
    This DOES NOT issue a logon. The authorization code MUST be active.
    #>
}