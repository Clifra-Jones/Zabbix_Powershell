using namespace System.Management
function Get-ZabbixAuthCode() {
    [CmdletBinding()]
    Param(        
        [string]$Uri,
        [string]$Username,
        [securestring]$Password,
        [ValidateScript(
            {
                if ($_ -and $StoreToProfile) {
                    $true
                } else {
                    throw "Parameter StoreToProfile is required with the parameter ProfileName."
                }
            }
        )]
        [string]$ProfileName,
        [ValidateSet(
            {
                if ($_ -and $ProfileName) {
                    $true
                } else {
                    throw "Parameter ProfileName is required with parameter StoreToProfile."
                }
            }
        )]
        [switch]$StoreToProfile
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
                    $Profiles.Add($ProfileName, $Profile)
                }
            }
            $Profiles | ConvertTo-Json | Out-File $configFile 
        }
        $CurrentCredentials.Uri = $Uri
        $CurrentCredentials.authcode = $authcode
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

    if ($fromConfig) {
        $response = $(Write-host "Warning! You are about to deactivate the authroization code from your profile. Continue? [N/y]" -ForegroundColor Yellow -NoNewline); `
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
        } catch {
            $_
        }
    }
}

Set-Alias -Name Disconnect-ZabbixUser -Value Remove-ZabbixAuthCode -Option ReadOnly

function Set-ZabbixProfile() {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )

    $config = Get-Content -Path $configFile | ConvertFrom-Json
    $CurrentCredentials.Uri = $config.$Uri
    $CurrentCredentials.authcode = $Config.authcode
}