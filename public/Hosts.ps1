using namespace System.Collections.Generic
function Get-ZabbixHostGroups() {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [string[]]$hostId,
        [string]$groupId,
        [switch]$includeHosts,
        [string]$authCode
    )

    Begin {
        if (-not $authcode) {
            $authcode = Read-ZabbixConfig
        }
        #$inputType = ""
        $payload = Get-Payload
        $payload.method = 'hostgroup.get'
        if ($groupId) {$payload.params.Add("groupids", $groupId)}
        if ($includeHosts) {           
                $payload.params.Add("selectHosts",@("hostid","name"))
        } else {
            $payload.params.Add("selectHosts", "count")
        }
    }

    Process {
        if ($hostid) {
            $payload.params.Add("hostids", $hostId)
        }

        $payload.Add("auth", $authcode)

        $body = $payload | ConvertTo-Json -Compress

        Try {
            $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            if ($response.error) {
                throw $response.error.data
            }
            return $response.result

        } catch {
            throw $_
        }
    }
    <#
    .SYNOPSIS
    Returns Zabbix host groups.
    .PARAMETER hostId
    Returns groups the host is a member of.
    .PARAMETER groupId
    Returns the group with the group id.
    .PARAMETER includeHosts
    Return a hosts property that includes all host members of the group.
    .PARAMETER authCode
    Authorization code to use for the API call. If omitted read the authcode from the local configuration file.
    #>
}

function Get-ZabbixHosts() {
    [CmdletBinding()]
    Param(   
        [string]$hostid,
        [string]$groupid,
        [string]$itemid,
        [string]$templateid,
        [switch]$includeItems,
        [switch]$includeGroups,
        [switch]$includeInterfaces,
        [switch]$includeParentTemplates,
        [switch]$excludeDisabled,
        [string]$authcode
    )

    $authcode = Read-ZabbixConfig
    $payload = Get-Payload
    $payload.method = 'host.get'
    if ($hostid) {$payload.params.Add("hostids", $hostId)}
    if ($groupid) {$payload.params.Add("groupids", $groupId)}
    if ($itemid) {$payload.params.Add("itemids", $itemId)}
    if ($templateid) {$payload.params.Add("templateids", $templateid)}
    if ($excludeDisabled) {
        $payload.params.Add("filter", @{
            status = 0
        })
    }
    if ($includeItems) {$payload.params.Add("selectItems", @("itemid", "name", "key_"))}
    if ($includeGroups) {$payload.params.Add("selectGroups",@("groupid", "name"))}
    if ($includeInterfaces) {$payload.params.Add("selectInterfaces", "extend")}
    if ($includeParentTemplates) {$payload.params.Add("selectParentTemplates", @("templateid", "name"))}

    $payload.Add("auth", $authcode)

    $body = $payload | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
        if ($response.error) {
            throw $response.error.data
        }
        return $response.result        
    } catch {
        throw $_
    }
    <#
    .SYNOPSIS 
    Returns Zabbix hosts.
    .DESCRIPTION
    Returns Zabbix hosts based oin the supplied parameters.
    .PARAMETER hostid
    Return the host with this host id.
    .PARAMETER groupid
    Return the hosts that are a member of this group.
    .PARAMETER itemid
    Returns hosts that with this item id.
    .PARAMETER templateid
    Returns hosts that have this template applied.
    .PARAMETER includeItems
    Return an items property with host items.
    .PARAMETER includeGroups
    Return a groups property with host groups data that the host belongs to.
    .PARAMETER includeInterfaces
    Return an interfaces property with host interfaces.
    .PARAMETER includeParentTemplates
    Return a parentTemplates property with templates that the host is linked to.
    .PARAMETER excludeDisabled
    Exclude disabled hosts.
    .PARAMETER authcode
    Authorization code to use for the API call. If omitted read the authcode from the local configuration file.
    #>
}

function Get-HostInterfaces() {
    [CmdletBinding()]
    Param(
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$hostId,
        [string]$InterfaceId,
        [string]$authcode
    )

    Begin {
        If (-not $authcode) {
            $authcode = Read-ZabbixConfig
        }
        $payload = Get-Payload
        $payload.Method = "hostinterface.get"
        $payload.params.Add("output", "extend")
        $payload.Add("auth", $authcode)
    }

    Process {
        If ($hostid) {
            $payload.params.Add("hostids", $hostId)
        }
        if ($InterfaceId) {
            $payload.params.Add("interfaceIds",$InterfaceId)
        }

        $body = $payload | ConvertTo-Json -Compress -Depth 5

        try {
            $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            if ($response.error) {
                throw $response.error.data
            }
            return $response.result
        } catch {
            throw $_
        }
    }
}

function Add-HostInterface() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$hostId,
        [switch]$primaryInterface,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Agent','SNMP','IPMI','JMX')]
        [string]$interfaceType,
        [switch]$useIP,
        [string]$IPAddress,
        [string]$dnsName,
        [int]$port=10050,
        [string]$authcode
    )

    Begin {
        if (-not $authcode) {
            $authcode = Read-ZabbixConfig
        }
        $payload = Get-Payload
        $payload.Method = 'hostinterface.create'      
        $payload.Add("auth", $authcode)  
    }

    Process {
        $payload.params.Add("hostid",$hostId)
        if ($interfaceType) {
            $types = @('Agent','SNMP','IPMI','JMX')
            $typeIndex = $types.IndexOf($interfaceType)
            $payload.params.Add("type", $typeIndex)
        }
        if ($primaryInterface.IsPresent) {
            $payload.params.Add("main", "1")            
        } else {
            $payload.params.Add("main", "0")
        }
        if ($useIP.IsPresent) {
            $payload.params.Add("useip", "1")
        } else {
            $payload.params.Add("useip", "0")
        }
        if ($IPAddress) {
            $payload.params.Add("ip", $IPAddress)
        }
        if ($dnsName) {
            $payload.params.Add("dns", $dnsName)
        }
        $payload.params.Add("port", $port)

        $body = $payload | ConvertTo-Json -Compress -Depth 5

        try {
            $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            if ($response.error) {
                throw $response.error.data
            }
            return $response.result
        } catch {
            throw $_
        }
    }
}

function Set-HostInterface() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$InterfaceId,
        [switch]$primaryInterface,
        [ValidateSet('Agent','SNMP','IPMI','JMX')]
        [string]$interfaceType,
        [switch]$useIP,
        [string]$IPAddress,
        [string]$dnsName,
        [int]$port=10050,
        [string]$authcode
    )

    Begin {
        if (-not $authcode) {
            $authcode = Read-ZabbixConfig
        }

        $payload = Get-Payload
        $payload.method = 'hostinterface.update'
        $payload.Add("auth", $authcode)
    }

    Process{
        $payload.params.Add("interfaceid", $InterfaceId)
        if ($primaryInterface.IsPresent) {
            $payload.params.Add("main", "1")
        } else {
            $payload.params.Add("main". "0")
        }
        if ($interfaceType) {
            $types = @('Agent','SNMP','IPMI','JMX')
            $typeIndex = $types.IndexOf($interfaceType)
            $payload.params.Add("type", $typeIndex)
        }
        if ($useIP.IsPresent) {
            $payload.params.Add("useip", "1")
        } else {
            $payload.params.Add("useip", "0")
        }
        if ($IPAddress) {
            $payload.params.ADD("ip", $IPAddress)
        }
        if ($dnsName) {
            $payload.params.Add("dns", $dnsName)
        }
        $payload.params.Add("port", $port)

        try {
            $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            if ($response.error) {
                throw $response.error.data
            }
            return $response.result
        } catch {
            throw $_
        }
    }
}
