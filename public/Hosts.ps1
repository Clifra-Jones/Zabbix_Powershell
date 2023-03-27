using namespace System.Collections.Generic
function Get-ZabbixHostGroups() {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [string]$hostId,
        [string]$groupId,
        [switch]$includeHosts,
        [string]$ProfileName
    )

    Begin {
        # if (-not $authcode) {
        #     $authcode = Read-ZabbixConfig
        # }
        # #$inputType = ""
        # $payload = Get-Payload
        # $payload.method = 'hostgroup.get'

        $Parameters = @{
            method = 'hostgroup.get'
        }

        if ($ProfileName) {
            $Parameters.Add("ProfileName", $ProfileName)
        }

        $params = @{}

        if ($groupId) {$params.Add("groupids", $groupId)}
        if ($includeHosts) {           
                $params.Add("selectHosts",@("hostid","name"))
        } else {
            $params.Add("selectHosts", "count")
        }
    }

    Process {
        if ($hostid) {
            $payload.params.Add("hostids", $hostId)
        }

        #$payload.Add("auth", $authcode)

        #$body = $payload | ConvertTo-Json -Compress

        $Parameters.Add("params", $params)

        Try {
            #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            $response = Invoke-ZabbixAPI @Parameters

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
    .PARAMETER ProfileName
    Name of the saved profile to use.
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
        [string]$ProfileName
    )

    # $authcode = Read-ZabbixConfig
    # $payload = Get-Payload
    # $payload.method = 'host.get'

    $Parameters = @{
        method = 'host.get'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    }

    $params = @{}

    if ($hostid) {
        $params.Add("hostids", $hostId)
    }
    if ($groupid) {
        $params.Add("groupids", $groupId)
    }
    if ($itemid) {
        $params.Add("itemids", $itemId
        )}
    if ($templateid) {
        $params.Add("templateids", $templateid)
    }
    if ($excludeDisabled) {
        $params.Add("filter", @{
            status = 0
        })
    }
    if ($includeItems) {
        $.params.Add("selectItems", "extend")
    }
    if ($includeGroups) {
        $params.Add("selectGroups","extend")
    }
    if ($includeInterfaces) {
        $params.Add("selectInterfaces", "extend")
    }
    if ($includeParentTemplates) {
        $params.Add("selectParentTemplates", "extend")
    }

    #$payload.Add("auth", $authcode)

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Compress

    try {
        #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
        $response = Invoke-ZabbixAPI @Parameters

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
    .PARAMETER ProfileName
    The name of rhe saved profile to use.
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
        [string]$ProfileName
    )

    Begin {
        # If (-not $authcode) {
        #     $authcode = Read-ZabbixConfig
        # }
        # $payload = Get-Payload
        # $payload.Method = "hostinterface.get"

        $Parameters = @{
            method = 'hostinterface.get'
        }

        if ($ProfileName) {
            $Parameters.Add("ProfileName", $ProfileName)
        }

        #$params.Add("output", "extend")
        #$payload.Add("auth", $authcode)
    }

    Process {
        $params = @{}

        If ($hostid) {
            $params.Add("hostids", $hostId)
        }
        if ($InterfaceId) {
            $params.Add("interfaceIds",$InterfaceId)
        }

        $Params.Add("params", $params)

        #$body = $payload | ConvertTo-Json -Compress -Depth 5

        try {
            #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            $response = Invoke-ZabbixAPI @Parameters
            
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
        [string]$ProfileName
    )

    Begin {
        # if (-not $authcode) {
        #     $authcode = Read-ZabbixConfig
        # }
        # $payload = Get-Payload
        # $payload.Method = 'hostinterface.create'      
        # $payload.Add("auth", $authcode)  

        $Parameters = @{
            method = 'hostinterface.create'
        }

        if ($ProfileName) {
            $Parameters.Add("ProfileName", $ProfileName)
        }
    }

    Process {
        $params = @{}

        $params.Add("hostid",$hostId)
        if ($interfaceType) {
            $types = @{
                Agent = 1
                SNMP = 2
                IPMI = 3
                JMX = 4
            }
            #$typeIndex = $types.IndexOf($interfaceType)
            $params.Add("type", $types[$interfaceType])
        }
        if ($primaryInterface.IsPresent) {
            $params.Add("main", "1")            
        } else {
            $params.Add("main", "0")
        }
        if ($useIP.IsPresent) {
            $params.Add("useip", "1")
        } else {
            $params.Add("useip", "0")
        }
        if ($IPAddress) {
            $params.Add("ip", $IPAddress)
        }
        if ($dnsName) {
            $params.Add("dns", $dnsName)
        }
        $params.Add("port", $port)

        $Parameters.Add("params", $params)

        #$body = $payload | ConvertTo-Json -Compress -Depth 5

        try {
            #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            $response = Invoke-ZabbixAPI @Parameters

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
        [string]$ProfileName
    )

    Begin {
        # if (-not $authcode) {
        #     $authcode = Read-ZabbixConfig
        # }

        # $payload = Get-Payload
        # $payload.method = 'hostinterface.update'
        # $payload.Add("auth", $authcode)

        $Parameters = @{
            method = 'hostinterface.update'
        }

        if ($ProfileName) {
            $Parameters.Add("ProfileName", $ProfileName)
        }
    }

    Process{
        $params = @{}

        $params.Add("interfaceid", $InterfaceId)
        if ($primaryInterface.IsPresent) {
            $params.Add("main", "1")
        } else {
            $params.Add("main". "0")
        }
        if ($interfaceType) {
            $types = @{
                Agent = 1
                SNMP = 2
                IPMI = 3
                JMX = 4
            }
            #$typeIndex = $types.IndexOf($interfaceType)
            $params.Add("type", $types[$interfaceType])
        }
        if ($useIP.IsPresent) {
            $params.Add("useip", "1")
        } else {
            $params.Add("useip", "0")
        }
        if ($IPAddress) {
            $params.ADD("ip", $IPAddress)
        }
        if ($dnsName) {
            $params.Add("dns", $dnsName)
        }
        $params.Add("port", $port)

        $Parameters.Add("params", $params)

        try {
            #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            $response = Invoke-ZabbixAPI @Parameters
            
            if ($response.error) {
                throw $response.error.data
            }
            return $response.result
        } catch {
            throw $_
        }
    }
}
