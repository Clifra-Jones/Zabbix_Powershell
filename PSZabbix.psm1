# Powershell module for the Zabbix 5.0 API.
using namespace System.Management.Automation

# Private Variables
$Uri = "https://zabbix.balfourbeattyus.com/api_jsonrpc.php"
$configPath = "$home/.zabbix"
$configFile = "$configPath/auth.json"
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
    $config = Get-Content $configFile | ConvertFrom-Json
    return $config.authcode
}

. $PSScriptRoot/public/Authorize.ps1
. $PSScriptRoot/public/MediaType.ps1
. $PSScriptRoot/public/Hosts.ps1
. $PSScriptRoot/public/Items.ps1
. $PSScriptRoot/public/History.ps1
. $PSScriptRoot/public/Trends.ps1

