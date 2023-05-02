# Powershell module for the Zabbix 5.0 API.
using namespace System.Management.Automation

# Private Variables
#$Uri = "https://zabbix.balfourbeattyus.com/api_jsonrpc.php"

#$DefaultProfile = Read-ZabbixConfig 
<# Set-Variable -Name "CurrentProfile" -Value (Read-ZabbixConfig) -Scope Script

$configPath = "$home/.zabbix"
$configFile = "$configPath/auth.json" #>

function Get-Payload() { 
    return [ordered]@{
        jsonrpc = "2.0"
        method = ""
        params = @{
        }
        id = 1
    }
}

Set-Variable contentType -Option Constant -Value "application/json"

# private functions

function Read-ZabbixConfig() {    
    Param(
        [string]$ProfileName
    )

    If (-not $ProfileName) {
        $ProfileName = 'default'
    }

    if (Test-Path $configFile) {
        $config = Get-Content $configFile | ConvertFrom-Json
    
        return $config.$ProfileName
    } else {
        return $null
    }
}

. $PSScriptRoot/public/Authorize.ps1
. $PSScriptRoot/public/MediaType.ps1
. $PSScriptRoot/public/Hosts.ps1
. $PSScriptRoot/public/Items.ps1
. $PSScriptRoot/public/History.ps1
. $PSScriptRoot/public/Trends.ps1
. $PSScriptRoot/public/Templates.ps1
. $PSScriptRoot/public/Discovery.ps1
. $PSScriptRoot/public/Users.ps1



function Invoke-ZabbixAPI() {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [psobject]$params,
        [string]$ProfileName
    )

    if ($ProfileName) {
        $AuthProfile = Read-ZabbixConfig $ProfileName
    } else {
        $AuthProfile = $CurrentProfile
    }

    $Uri = $AuthProfile.Uri

    $payload = Get-Payload

    $payload.method = $Method

    $payload.params = $params

    $payload.Add("auth", $AuthProfile.authcode)

    $body = $payload | ConvertTo-Json -Depth 10 -Compress

    try {
        $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
        return $response

    } catch {
        throw $_
    }
    <#
    .SYNOPSIS
    Make a custom call to the zabbix API.
    .DESCRIPTION
    This method allows you to make a customized call to the API. 
    There are many parameters for the API calls. Not all of them are in the module functons. This is for simplicity sake.
    .PARAMETER Method
    This is the method to call. i.e. 'host.get'
    .PARAMETER params
    This is an object containing the parameters to use.
    .OUTPUTS
    Return the result of the call. This is the complete response. It is up to you to display or use the data.
    .EXAMPLE
    This example calls the hostgroup.get method and returns groups with a hosts property containing hostid and name.
    $params = @{
        selectHosts = @(
            "hostid",
            "name"
        )
    }
    $response  = Invoke-ZabbixAPI -Method "hostgroup.get" -params $params
    .EXAMPLE
    This example shows how to search hosts by host tags. Only output hostid and host name.
    $params = @{
        output = @(
            "hostid",
            "name"
        )
        selectTags = "extend"
        tags = @(
            @{
                tag = "Host name"
                value = "Linux server"
                "operator" = 1
            }
        )
    }
    $response = Invoke-ZabbixAPI -Method "host.get" -params $params    
    #>
}

