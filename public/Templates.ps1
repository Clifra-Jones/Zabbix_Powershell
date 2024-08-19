function Get-ZabbixTemplate() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [string]$TemplateId,
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [switch]$IncludeHosts,
        [switch]$IncludeGroups,
        [switch]$IncludeTags,
        [switch]$IncludeTemplates,
        [switch]$IncludeParentTemplates,
        [switch]$IncludeHttpTests,
        [switch]$IncludeItems,
        [switch]$IncludeDiscoveries,
        [switch]$IncludeTriggers,
        [switch]$IncludeGraphs,
        [switch]$IncludeMacros,
        [switch]$IncludeDashboards,
        [switch]$IncludeValueMaps,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    Begin {
        # if (-not $authcode) {
        #     $authcode = Read-ZabbixConfig
        # }
        # $payload = Get-Payload
        # $payload.method = "template.get"

        $Parameters = @{
            method = 'template.get'
        }
        #$payload.Add("auth", $authcode)

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
        if ($TemplateId) {
            $params.add("templateIds", $TemplateId)
        }

        if ($includeHosts) {
            $Params.Add("selectHosts", "extend")
        }

        if ($includeGroups) {
            $params.Add("selectGroups", "extend")
        }

        if ($IncludeTags) {
            $params.Add("selectTags", "extend")
        }

        if ($includeTemplates) {
            $params.Add("selectTemplates", "extend")
        }

        if ($IncludeParentTemplates) {
            $params.Add("selectParentTemplates", "extend")
        }

        if ($IncludeHttpTests) {
            $params.Add("selectHttpTests", "extend")
        }

        if ($IncludeItems) {
            $params.Add("selectItems", "extend")
        }

        if ($IncludeDiscoveries) {
            $params.Add("selectDiscoveries", "extend")
        }

        if ($IncludeTriggers) {
            $params.Add("selectTriggers", "extend")
        }

        if ($IncludeGraphs) {
            $params.Add("selectGraphs", "extend")
        }

        if ($IncludeMacros) {
            $params.Add("selectMacros", "extend")
        }

        if ($IncludeDashboards) {
            $params.Add("selectDashboards". "extend") 
        }

        if ($IncludeValueMaps) {
            $Params.Add("selectValueMaps", "extend")
        }

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
    Retrieves Zabbix Template(s)
    .DESCRIPTION 
    Retrieves Zabbix Template(s)
    .PARAMETER TemplateId
    The ID of the Template tpo receive. If omitted all templates are returned.
    .PARAMETER IncludeHosts
    Return the hosts that are linked to the template in the hosts property.
    .PARAMETER IncludeGroups
    Return the host groups that the template belongs to in the groups property.
    .PARAMETER IncludeTags
    Return template tags in the tags property.
    .PARAMETER IncludeParentTemplates
    Return templates to which the template is a parent, in the parentTemplates property.
    .PARAMETER IncludeTemplates
    Return templates to which the template is a child, in the templates property.
    .PARAMETER IncludeHttpTests
    Return the web scenarios from the template in the httpTests property.
    .PARAMETER IncludeItems
    Return items from the template in the items property.
    .PARAMETER IncludeDiscoveries
    Return low-level discoveries from the template in the discoveries property.
    .PARAMETER IncludeTriggers
    Return triggers from the template in the triggers property.
    .PARAMETER IncludeGraphs
    Return graphs from the template in the graphs property.
    .PARAMETER IncludeMacros
    Return the macros from the template in the macros property..
    .PARAMETER IncludeDashboards
    Return dashboards from the template in the dashboards property.
    .PARAMETER IncludeValueMaps
    Return a valuemaps property with template value maps.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)

    #>
}

function Add-ZabbixTemplate() {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$VisibleName,
        [string]$Description,
        [Parameter(Mandatory)]
        [PsObject[]]$Groups,
        [PsObject[]]$Tags,
        [PsObject[]]$Templates,
        [PsObject[]]$Macros,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = "template.create"
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
        host = $Name
    }

    if ($VisibleName) {
        $params.Add("name", $VisibleName)
    }

    if ($Description) {
        $params.Add("description", $Description)
    }

    if ($Groups) {
        $params.Add("groups", $groups)
    }

    if ($Tags) {
        $params.Add("tags", $Tags)
    }

    if ($Templates) {
        $params.Add("templates", $Templates)
    }

    if ($Macros) {
        $params.Add("macros", $Macros)
    }

    $Parameters.Add("params", $params)

    try {
        $response = Invoke-ZabbixAPI @Parameters

        if ($response.error) {
            throw $response.error.data
        }
        return $response.result
    } catch {
        $_
    }

    <#
    .SYNOPSIS
    Creates a Zabbix Template.
    .DESCRIPTION
    Creates a Zabbix Template.
    .PARAMETER Name
    Name of the Template
    .PARAMETER VisibleName
    The visible name of the template.
    .PARAMETER Description
    The description of the template
    .PARAMETER Groups
    An array of host groups to add to the template. The only required property is GroupId.
    .PARAMETER Tags
    An array of Tag objects to add to the template. The Tag object requires the property "tag" and "value".
    .PARAMETER Templates
    An array of Template objects to add to the template. The only required property is the TemplateId.
    .PARAMETER Macros
    An array of Macros to add to the template. Macro objects must define the macro, value properties. The type and description properties are optional.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Set-ZabbixTemplate() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateId,
        [string]$Name,
        [string]$VisibleName,
        [string]$Description,
        [PsObject[]]$Groups,
        [PsObject[]]$Tags,
        [PsObject[]]$Templates,
        [PsObject[]]$ClearTemplates,
        [PsObject[]]$Macros,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = "template.update"
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

    if ($name) {
        $params.Add("host", $name)
    }

    if ($VisibleName) {
        $params.Add("name", $VisibleName)
    }

    if ($Description) {
        $params.Add("description", $Description)
    }

    if ($Groups) {
        $params.Add("groups", $groups)
    }

    if ($Tags) {
        $params.Add("tags", $Tags)
    }

    if ($Templates) {
        $params.Add("templates", $Templates)
    }

    if ($ClearTemplates) {
        $param.Add("templates_clear", $ClearTemplates)
    }

    if ($Macros) {
        $params.Add("macros", $Macros)
    }

    $Parameters.Add("params", $params)

    try {
        $response = Invoke-ZabbixAPI @Parameters

        if ($response.error) {
            throw $response.error.data
        }

        return $response
    } catch {
        throw $_
    }    

    <#
    .SYNOPSIS
    Update a Zabbix Template
    .DESCRIPTION
    Update an existing Zabbix Template.
    .PARAMETER TemplateId
    The ID of the template.
    .PARAMETER Name
    The Name of the template.
    .PARAMETER VisibleName
    The visible name.
    .PARAMETER Description
    The description.
    .PARAMETER Groups
    An array of Host group object to replace the current host groups the templates belong to. Objects must define the GroupId property.
    .PARAMETER Tags
    An array of tags objects to replace the current template tags. Tag object must define the tag and value properties.
    .PARAMETER Macros
    An array of macro objects to replace the current user macros on the given templates. Macro objects must define the macro, value properties. The type and description properties are optional.
    .PARAMETER Templates
    An array of template objects to replace the currently linked templates. Templates that are not passed are only unlinked. Objects must define the TemplateId property.
    .PARAMETER ClearTemplates
    An array of template objects to unlink and clear from the given templates. Objects must define the TemplateId property.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>

}

function Remove-ZabbixTemplate() {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateId,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = "template.delete"
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

    $Params = @(
        $TemplateId
    )

    $Parameters.Add("params", $params)

    $template = Get-ZabbixTemplate -TemplateId $TemplateId

    if ($PSCmdlet.ShouldProcess("Delete", "Template: $($Template.host) ($($template.Name))")) {
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
    Remove a Zabbix Template
    .DESCRIPTION
    Remove the template specified by the template ID.
    .PARAMETER TemplateId
    The ID of the template.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)

    #>
}