using namespace System.Collections.Generic

function Get-ZabbixHostGroup() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [string]$HostId,
        [string]$GroupId,
        [switch]$IncludeHosts,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    Begin {
        $Parameters = @{
            method = 'hostgroup.get'
        }

        if ($ProfileName) {
            $Parameters.Add("ProfileName", $ProfileName)
        } elseif ($AuthCode) {
            if ($Uri) {
                $Parameters.Add("AuthCode", $AuthCode)
                $Parameters.Add("Uri", $Uri)
            } else {
                throw "Uri is required when providing an AuthCode."
            }
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

function Add-ZabbixHostGroup() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = "hostgroup.create"        
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    } elseif ($AuthCode) {
        if ($Uri) {
            $Parameters.Add("AuthCode", $AuthCode)
            $Parameters.Add("Uri", $Uri)
        } else {
            throw "Uri is required when providing an AuthCode."
        }
    }

    $params = @{
        name = $Name
    }

    $Parameters.Add("params", $params)

    try {
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
    Add a host group.
    .DESCRIPTION
    Add a new zabbix host group.
    .PARAMETER Name
    The name of the group
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Set-ZabbixHostGroup() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = "hostgroup.update"
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    } elseif ($AuthCode) {
        if ($Uri) {
            $Parameters.Add("AuthCode", $AuthCode)
            $Parameters.Add("Uri", $Uri)
        } else {
            throw "Uri is required when providing an AuthCode."
        }
    }

    $params = @{
        groupid = $GroupId
        name = $Name
    }

    $Parameters.Add("params", $params)

    try {
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
    Update a host group
    .DESCRIPTION
    Update the properties of a host group.
    .PARAMETER GroupId
    ID of the host group.
    .PARAMETER Name
    Name of the host group.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Remove-ZabbixHostGroup() {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = 'hostgroup.delete'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    } elseif ($AuthCode) {
        if ($Uri) {
            $Parameters.Add("AuthCode", $AuthCode)
            $Parameters.Add("Uri", $Uri)
        } else {
            throw "Uri is required when providing an AuthCode."
        }
    }

    $params = @(
        $GroupId
    )

    $Parameters.Add("params", $params)

    $HostGroup = Get-ZabbixHostGroup -groupId $GroupId

    if ($PSCmdlet.ShouldProcess("Delete", "Host group: $($HostGroup.Name)")) {
        try {
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
    Remove a host group.
    .DESCRIPTION
    Remove the specified host group.
    .PARAMETER GroupId
    ID of the host group.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Add-ZabbixHostGroupMembers() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$GroupId,
        [Parameter(Mandatory, ParameterSetName = 'hosts')]
        [Parameter(Mandatory, ParameterSetName = 'both')]
        [string[]]$HostIds,
        [Parameter(Mandatory, ParameterSetName = 'templates')]
        [Parameter(Mandatory, ParameterSetName = 'both')]
        [string[]]$TemplateIds,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri

    )

    $Parameters = @{
        method = "hostgroup.massadd"
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    }

    $params = @{
        groups = @(
            @{
                groupId = $GroupId
            }
        )
    }

    if ($HostIds) {
        $Hosts = [List[psobject]]::New()
        foreach ($HostId in $HostIds) { 
            $HostIds.Add(
                @{
                    hostid = $HostId}
            )
        }
        $params.Add(
            "hosts", ($Hosts.ToArray())
        )
    }

    if ($TemplateIds) {
        $Templates = [List[PSObject]]::New()
        foreach($TemplateId in $TemplateIds) {
            $Templates.Add(
                @{
                    templateId = $TemplateId
                }
            )
        }
        $Params.Add(
            "templates", ($templates.ToArray())
        )
    }

    $Parameters.Add("params", $params)

    try {
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
    Add Host group members.
    .DESCRIPTION
    Add hosts or templates to a Zabbix host group.
    .PARAMETER GroupId
    The ID of the group.
    .PARAMETER HostIds
    An array of host IDs to add to the group.
    .PARAMETER TemplateIds
    An array of template IDs to add to the group.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Get-ZabbixHost() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(   
        [string]$HostId,
        [string]$HostName,
        [string]$groupid,
        [string]$itemid,
        [string]$templateid,
        [switch]$includeItems,
        [switch]$includeGroups,
        [switch]$includeInterfaces,
        [switch]$includeParentTemplates,
        [switch]$excludeDisabled,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    # $authcode = Read-ZabbixConfig
    # $payload = Get-Payload
    # $payload.method = 'host.get'

    $Parameters = @{
        method = 'host.get'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    } elseif ($AuthCode) {
        if ($Uri) {
            $Parameters.Add("AuthCode", $AuthCode)
            $Parameters.Add("Uri", $Uri)
        } else {
            throw "Uri is required when providing an AuthCode."
        }
    }

    $params = @{}

    if ($hostid) {
        $params.Add("hostids", $hostId)
    }
    if ($groupid) {
        $params.Add("groupids", $groupId)
    }
    if ($itemid) {
        $params.Add("itemids", $itemId)
    }
    if ($templateid) {
        $params.Add("templateids", $templateid)
    }

    if ($excludeDisabled) {
        $params.Add("filter", @{
            status = 0
        })
    }
    if ($includeItems) {
        $params.Add("selectItems", "extend")
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

    if ($HostName) {
        $params.Add("filter", @{
            "host" = @($HostName)
        })
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
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Add-ZabbixHost() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword','')]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [Alias('host')]        
        [string]$HostName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,
        [Parameter(ValueFromPipelineByPropertyName)]        
        [InventoryModes]$Inventory_Mode = -1,
        [Parameter(ValueFromPipelineByPropertyName)]
        [IpmiAuthTypes]$Ipmi_AuthType = -1,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$IPMI_Password,
        [IPMIPrivileges]$Ipmi_Privilege = 2,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Ipmi_Username,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Proxy_HostId,
        [Parameter(ValueFromPipelineByPropertyName)]
        [HostStatus]$Status = 0,
        [Parameter(ValueFromPipelineByPropertyName)]        
        [TlsConnections]$Tls_Connect = 1,
        [Parameter(ValueFromPipelineByPropertyName)]
        [TlsConnections]$Tls_Accept = 1,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Tls_Issuer,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Tls_Subject, 
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({(-not $_) -and ($Tls_Connect -eq 2 -or $Tls_Accept -eq 2)}, 
            ErrorMessage = "Parameter 'Tls_Psk_Identity is required if Parameters 'Tls_Connect' is set to PSK (2).")]
        [string]$Tls_Psk_Identity,
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({(-not $_) -and ($Tls_Connect -eq 2 -or $Tls_Accept -eq 2)}, 
            ErrorMessage = "Parameter 'Tls_Psk is required if Parameters 'Tls_Connect' is set to PSK (2).")]
        [string]$Tls_Psk,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = 'host.create'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    } elseif ($AuthCode) {
        if ($Uri) {
            $Parameters.Add("AuthCode", $AuthCode)
            $Parameters.Add("Uri", $Uri)
        } else {
            throw "Uri is required when providing an AuthCode."
        }
    }

    $params = @{
        "Name" = $HostName
    }

    if ($Description) {
        $params.Add("description", $Description)
    }

    if ($Inventory_Mode) {
        $params.Add("inventory_mode", $Inventory_Mode)
    }

    if ($Ipmi_AuthType) {
        $params.Add("ipmi_authtype", $Ipmi_AuthType)
    }
    
    if ($IPMI_Password) {
        $params.Add("ipmi_password", $IPMI_Password)
    }

    if ($Ipmi_Username) {
        $params.Add("ipmi_username", $Ipmi_Username)
    }

    if ($Proxy_HostId) {
        $params.Add("proxy_hostid", $Proxy_HostId)
    }

    if ($Status) {
        $param.Add("status", $Status)
    }

    if ($Tls_Connect) {
        $params.Add("tls_connect", $Tls_Connect)
    }

    if ($Tls_Accept) {
        $params.Add("tls_accpt", $Tls_Accept)
    }

    if ($Tls_Issuer) {
        $params.Add("tls_issuer", $Tls_Issuer)
    }

    if ($Tls_Subject) {
        $params.Add("tls_subject", $tls_subject)
    }

    if ($Tls_Psk_Identity) {
        $params.Add("tls_psk_identity", $Tls_Psk_Identity)
    }

    if ($Tls_Psk) {
        $params.Add("tls_psk", $Tls_Psk)
    }

    $Parameters.Add("params", $params)

    try {
        $response = Invoke-ZabbixAPI @Parameters

        If ($response.error) {
            throw $response.error.data
        }
        return $response.result
    } catch {
        throw $_
    }

    <#
    .SYNOPSIS
    Add a host.
    .DESCRIPTION
    Add a Zabbix host to the configuration.
    .PARAMETER HostName
    The name of the host
    .PARAMETER Name
    The display name of the host
    .PARAMETER Description
    A description of the host
    .PARAMETER Inventory_Mode
    Host inventory population mode.
    .PARAMETER Ipmi_AuthType
    IPMI authentication algorithm.
    .PARAMETER IPMI_Password
    IPMI password.
    .PARAMETER Ipmi_Privilege
    IPMI privilege level.
    .PARAMETER Ipmi_Username
    IPMI username.
    .PARAMETER Proxy_HostId
    ID of the proxy that is used to monitor the host.
    .PARAMETER Status
    Status and function of the host.(0 = monitored host (enabled), 1 = unmonitored host (disabled))
    .PARAMETER Tls_Connect
    TLS connection to host
    .PARAMETER Tls_Accept
    TLS Connection from host.
    .PARAMETER Tls_Issuer
    Certificate issuer.
    .PARAMETER Tls_Subject
    Certificate subject.
    .PARAMETER Tls_Psk_Identity
    PSK identity. Required if either tls_connect or tls_accept has PSK enabled.
    Do not put sensitive information in the PSK identity, it is transmitted unencrypted over the network to inform a receiver which PSK to use.
    .PARAMETER Tls_Psk
    The preshared key, at least 32 hex digits. Required if either tls_connect or tls_accept has PSK enabled.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Get-ZabbixHostInterface() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$hostId,
        [string]$InterfaceId,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
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
        } elseif ($AuthCode) {
            if ($Uri) {
                $Parameters.Add("AuthCode", $AuthCode)
                $Parameters.Add("Uri", $Uri)
            } else {
                throw "Uri is required when providing an AuthCode."
            }
        }    
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
    <#
    .SYNOPSIS
    Retrieve host interface(s).
    .DESCRIPTION
    Retrieve the interfaces assigned to the host. You can also provide the Interface ID top retrieve one interface.
    .PARAMETER hostId
    The ID of the host.
    .PARAMETER InterfaceId
    The Interface Id.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Add-ZabbixHostInterface() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
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
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    Begin {

        $Parameters = @{
            method = 'hostinterface.create'
        }

        if ($ProfileName) {
            $Parameters.Add("ProfileName", $ProfileName)
        } elseif ($AuthCode) {
            if ($Uri) {
                $Parameters.Add("AuthCode", $AuthCode)
                $Parameters.Add("Uri", $Uri)
            } else {
                throw "Uri is required when providing an AuthCode."
            }
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
    <#
    .SYNOPSIS
    Add (create) a Host interface.
    .DESCRIPTION
    Create an interface and assign it to a Host.
    .PARAMETER hostId
    The ID of the host to create the interface on.
    .PARAMETER primaryInterface
    Whether the interface is used as default on the host. Only one interface of some type can be set as default on a host.
    .PARAMETER interfaceType
    The type of Interface.
    .PARAMETER useIP
    Whether the connection should be made via IP.
    .PARAMETER IPAddress
    IP address used by the interface. (Can be empty if the connection is made via DNS)
    .PARAMETER dnsName
    DNS name used by the interface. (Can be empty if the connection is made via IP.)
    .PARAMETER port
    Port number used by the interface. Can contain user macros.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Set-ZabbixHost() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword','')]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$HostId,
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('host')]        
        [string]$HostName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,
        [Parameter(ValueFromPipelineByPropertyName)]
        [InventoryModes]$Inventory_Mode = -1,
        [Parameter(ValueFromPipelineByPropertyName)]
        [IpmiAuthTypes]$Ipmi_AuthType = -1,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$IPMI_Password,
        [IPMIPrivileges]$Ipmi_Privilege = 2,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Ipmi_Username,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Proxy_HostId,
        [Parameter(ValueFromPipelineByPropertyName)]
        [HostStatus]$Status = 0,
        [Parameter(ValueFromPipelineByPropertyName)]        
        [TlsConnections]$Tls_Connect = 1,
        [Parameter(ValueFromPipelineByPropertyName)]
        [TlsConnections]$Tls_Accept = 1,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Tls_Issuer,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Tls_Subject, 
        [Parameter(
            ParameterSetName = 'psk',
            ValueFromPipelineByPropertyName
        )]
        [string]$Tls_Psk_Identity,
        [Parameter(
            ParameterSetName = 'psk',
            ValueFromPipelineByPropertyName)]
        [string]$Tls_Psk,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = 'host.update'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    } elseif ($AuthCode) {
        if ($Uri) {
            $Parameters.Add("AuthCode", $AuthCode)
            $Parameters.Add("Uri", $Uri)
        } else {
            throw "Uri is required when providing an AuthCode."
        }
    }

    $params = @{
        hostid = $HostId
    }

    if ($Description) {
        $params.Add("description", $Description)
    }

    if ($Inventory_Mode) {
        $params.Add("inventory_mode", $Inventory_Mode)
    }

    if ($Ipmi_AuthType) {
        $params.Add("ipmi_authtype", $Ipmi_AuthType)
    }
    
    if ($IPMI_Password) {
        $params.Add("ipmi_password", $IPMI_Password)
    }

    if ($Ipmi_Username) {
        $params.Add("ipmi_username", $Ipmi_Username)
    }

    if ($Proxy_HostId) {
        $params.Add("proxy_hostid", $Proxy_HostId)
    }

    if ($Status) {
        $param.Add("status", $Status)
    }

    if ($Tls_Connect) {
        $params.Add("tls_connect", $Tls_Connect)
    }

    if ($Tls_Accept) {
        $params.Add("tls_accpt", $Tls_Accept)
    }

    if ($Tls_Issuer) {
        $params.Add("tls_issuer", $Tls_Issuer)
    }

    if ($Tls_Subject) {
        $params.Add("tls_subject", $tls_subject)
    }

    if ($Tls_Psk_Identity) {
        $params.Add("tls_psk_identity", $Tls_Psk_Identity)
    }

    if ($Tls_Psk) {
        $params.Add("tls_psk", $Tls_Psk)
    }

    $Parameters.Add("params", $params)

    try {
        $response = Invoke-ZabbixAPI @Parameters

        If ($response.error) {
            throw $response.error.data
        }
        return $response.result
    } catch {
        throw $_
    }
    <#
    .SYNOPSIS
    Update a Zabbix Host.
    .DESCRIPTION
    Update the properties of a Zabbix Host.
    .PARAMETER HostId
    The ID of the host.
    .PARAMETER HostName
    The host (DNS) name of the host.
    .PARAMETER Name
    The visible name of the host.
    .PARAMETER Description
    Description of the host.
    .PARAMETER Inventory_Mode
    Host inventory population mode.
    .PARAMETER Ipmi_AuthType
    IPMI authentication algorithm.
    .PARAMETER IPMI_Password
    IPMI password.
    .PARAMETER Ipmi_Privilege
    IPMI privilege level.
    .PARAMETER Ipmi_Username
    IPMI username.
    .PARAMETER Proxy_HostId
    ID of the proxy that is used to monitor the host.
    .PARAMETER Status
    Status and function of the host. Possible values are: 0 - (default) monitored host; 1 - unmonitored host.
    .PARAMETER Tls_Connect
    Connections to host. Possible values are: 1 - (default) No encryption; 2 - PSK; 4 - certificate.
    .PARAMETER Tls_Accept
    Connections from host. Possible bitmap values are: 1 - (default) No encryption; 2 - PSK; 4 - certificate.
    .PARAMETER Tls_Issuer
    Certificate issuer.
    .PARAMETER Tls_Subject
    Certificate subject.
    .PARAMETER Tls_Psk_Identity
    PSK identity. Required if either tls_connect or tls_accept has PSK enabled. Do not put sensitive information in the PSK identity, it is transmitted unencrypted over the network to inform a receiver which PSK to use.
    .PARAMETER Tls_Psk
    The preshared key, at least 32 hex digits. Required if either tls_connect or tls_accept has PSK enabled.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}



function Set-ZabbixHostInterface() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
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
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    Begin {

        $Parameters = @{
            method = 'hostinterface.update'
        }

        if ($ProfileName) {
            $Parameters.Add("ProfileName", $ProfileName)
        } elseif ($AuthCode) {
            if ($Uri) {
                $Parameters.Add("AuthCode", $AuthCode)
                $Parameters.Add("Uri", $Uri)
            } else {
                throw "Uri is required when providing an AuthCode."
            }
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
    <#
    .SYNOPSIS 
    Update a Host interface.
    .DESCRIPTION
    Update an existing host interface.
    .PARAMETER InterfaceId
    The ID of the interface
    .PARAMETER primaryInterface
    Whether the interface is used as default on the host. Only one interface of some type can be set as default on a host.
    .PARAMETER interfaceType
    The Interface type.
    .PARAMETER useIP
    Whether the connection should be made via IP.
    .PARAMETER IPAddress
    IP address used by the interface. Can be omitted if the connection is made via DNS.
    .PARAMETER dnsName
    DNS name used by the interface. Can be omitted if the connection is made via IP.
    .PARAMETER port
    Port number used by the interface. Can contain user macros.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Remove-ZabbixHostInterface() {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'default')]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]$InterfaceId,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = "hostinterface.delete"
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    } elseif ($AuthCode) {
        if ($Uri) {
            $Parameters.Add("AuthCode", $AuthCode)
            $Parameters.Add("Uri", $Uri)
        } else {
            throw "Uri is required when providing an AuthCode."
        }
    }

    $params = @($InterfaceId)

    $Parameters.Add("params", $params)

    $Interface = Get-ZabbixHostInterface -InterfaceId $InterfaceId

    if ($PSCmdlet.ShouldProcess("Delete", "Host Interface: $($Interface.Name)")) {
        try {
            Invoke-ZabbixAPI @Parameters
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
    Delete a Zabbix Host Interface
    .DESCRIPTION 
    Delete an interface from a host.
    .PARAMETER InterfaceId
    The ID of the interface.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}
