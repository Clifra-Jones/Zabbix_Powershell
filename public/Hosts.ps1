using namespace System.Collections.Generic

#region HostGroups
function Get-ZabbixHostGroup() {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [string]$hostId,
        [string]$groupId,
        [switch]$includeHosts,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$ProfileName,
        [string]$AuthCode,
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
}

function Set-ZabbixHostGroup() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$ProfileName,
        [string]$AuthCode,
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
}

function Remove-ZabbixHostGroup() {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        [string]$ProfileName,
        [string]$AuthCode,
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
}

function Add-ZabbixHostGroupMembers() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$GroupId,
        [string[]]$HostIds,
        [ValidateScript({$_ -or $HostsIds}, ErrorMessage = "One or both of HostIds or TemplateIds must be specified." )]
        [string[]]$TemplateIds,
        [string]$ProfileName,
        [string]$AuthCode,
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
}
#endregion

#region Hosts
function Get-ZabbixHost() {
    [CmdletBinding()]
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
        [string]$ProfileName,
        [string]$AuthCode,
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
    The name of rhe saved profile to use.
    #>
}

function Add-ZabbixHost() {
    [CmdletBinding()]
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
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    # Validate Parameters

<#     If ($Tls_Connect -eq 2 -or $Tls_Accept -eq 2) {
        If (-not $Tls_Psk_Identity) {
            Write-Host "Add-ZabbixHost: Cannot validate argument on parameter 'Tls_Psk_Identity'. Parameter 'Tls_Psk_Identity is required if Parameters 'Tls_Connect' is set to PSK (2)." `
                -ForegroundColor Red
            exit
        }
        if (-not $Tls_Psk) {
            Write-Host "Add-ZabbixHost: Cannot validate argument on parameter 'Tls_Psk'. Parameter 'Tls_Psk is required if Parameters 'Tls_Accept is set to PSK (2)." `
                -ForegroundColor Red
            exit
        }
    }
 #>
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
}

function Get-HostInterface() {
    [CmdletBinding()]
    Param(
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$hostId,
        [string]$InterfaceId,
        [string]$ProfileName,
        [string]$AuthCode,
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
#endregion

#region Interfaces
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
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
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
}

function Set-ZabbixHost() {
    [CmdletBinding()]
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
        [string]$ProfileName,
        [string]$AuthCode,
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
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
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
}
