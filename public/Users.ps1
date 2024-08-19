using namespace System.Generic.Collections
function Get-ZabbixUserGroup() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [string]$GroupId,
        [switch]$IncludeUsers,
        [switch]$IncludeRights,
        [switch]$IncludeTags,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{}

    $Parameters.Add("method", "usergroup.get")

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

    if ($GroupId) {
        $params.Add("usrgrpids", $GroupId)
    }

    if ($IncludeUsers.IsPresent) {
        $params.Add("selectUsers","extend")
    }
    if ($IncludeRights.IsPresent) {
        $params.Add("selectRights", "extend")
    }
    if ($IncludeTags.IsPresent) {
        $param.Add("selectTagFilters", "extend")
    }

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Depth 5 -Compress

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
    Retrieve Zabbix User Groups
    .DESCRIPTION
    Retrieve Zabbix User Groups
    .PARAMETER GroupId
    The ID of the group
    .PARAMETER IncludeUsers
    Return the users from the user group in the users property.
    .PARAMETER IncludeRights
    Return user group rights in the rights property. It has the following properties: permission - (integer) access level to the host group; id - (string) ID of the host group.
    .PARAMETER IncludeTags
    Return user group tag based permissions in the tag_filters property. It has the following properties: groupid - (string) ID of the host group; tag - (string) tag name; value - (string) tag value.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    .OUTPUTS
    An array of trend objects.


    #>
}

function Import-UserGroups() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [psObject]$UserGroup,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    Begin {
        # if (-not $authcode) {
        #     $authcode = Read-ZabbixConfig
        # }

        # $payload = Get-Payload

        # $payload.Method = "usergroup.create"

        # $payload.Add("auth", $authcode)

        $Parameters = @{
            method = 'usergroup.create'
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

        $params.Add("name", $UserGroup.name)

        if ($UserGroup.rights) {
            $param.Add("rights", $UserGroup.rights)
        } 

        If ($UserGroup.Users) {
            $params.Add("users", $UserGroup.users)
        }

        #$body = $payload | ConvertTo-Json -Depth 5 -Compress

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

function Add-ZabbixUserGroup() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [FrontendAccess]$FrontEndAccess = 'default',
        [switch]$Disabled,
        [switch]$DebugMode,
        [psobject[]]$Rights,
        [psobject[]]$Users,
        [psobject[]]$Tag,
        [Parameter(Mandatory, ParameterSetName = 'profile')]        
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig        
    # }

    # $payload.method = 'usergroup.create'
    
    # $payload.Add('auth', $authcode)

    $Parameters = @{
        method = 'usergroup.create'
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

    $params.Add("name", $Name)

    $params.Add("gui_access", $FrontEndAccess.value__)

    if ($Disabled.IsPresent) {
        $params.Add("users_status", "1")
    }

    if ($DebugMode.IsPresent) {
        $params.Add("debug_mode", "1")
    }

    if ($Rights) {
        $params.Add("rights", $Rights)
    }

    if ($Users) {
        $params.Add("users", $Users) 
    }

    if ($Tag) {
        $params.Add("tag_filters", $Tag)
    }

    #$body = $payload | ConvertTo-Json -Depth 5 -Compress
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

    <#
    .SYNOPSIS
    Creates a user group.
    .DESCRIPTION
    Creates a new Users Group.
    .PARAMETER Name
    The name of the group
    .PARAMETER FrontEndAccess
    Frontend authentication method of the users in the group. 
    Possible values: 
    0 - (default) use the system default authentication method;
    1 - use internal authentication;
    2 - use LDAP authentication;
    3 - disable access to the frontend.
    .PARAMETER Disabled
    Create the group disabled.
    .PARAMETER DebugMode
    Create the group with debug mode enabled.
    .PARAMETER Rights
    An array of user rights objects
    .PARAMETER Users
    An array of user objects. Must define the userid property
    .PARAMETER Tag
    an array of Tag based permissions to assign to the group.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Set-ZabbixUserGroup() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        [string]$Name,
        [FrontendAccess]$FrontEndAccess = 'default',
        [switch]$Disabled,
        [switch]$DebugMode,
        [psobject[]]$Rights,
        [psobject[]]$Users,
        [psobject[]]$Tags,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    # }

    # $payload = Get-Payload

    # $payload.method = 'usergroup.update'

    # $payload.Add("auth", $authcode)

    $Parameters = @{
        method = 'usergroup.update'
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

    if ($Name) {
        $params.Add("name", $Name)
    }

    if ($FrontEndAccess) {
        $params.Add("gui_access", $FrontEndAccess.value__)
    }

    if ($Disabled.IsPresent) {
        $params.Add("user_status", "1")
    }

    if ($DebugMode) {
        $params.Add("debug_mode", "1")
    }

    if ($Rights) {
        $params.Add("rights", $Rights)
    }

    if ($Users) {
        $params.Add("users", $Users)
    }

    if ($Tags) {
        $params.Add("tag_filters", $Tags)
    }

    #$body = $payload | ConvertTo-Json -Depth 5 -Compress

    $Parameters.Add("params", $params)

    try {
        #$response = Invoke-RestMethod -Method POST -URI $Uri -ContentType $contentType -Body $body
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
    Updates a Users Groups.
    .DESCRIPTION
    Update Zabbix users group.
    .PARAMETER GroupId
    The Group ID to update.
    .PARAMETER Name
    The name of the group.
    .PARAMETER FrontEndAccess
    Frontend authentication method of the users in the group.
    Possible values:
    0 - (default) use the system default authentication method;
    1 - use internal authentication;
    2 - use LDAP authentication;
    3 - disable access to the frontend.
    .PARAMETER Disabled
    Disable the group
    .PARAMETER DebugMode
    Set the group to debug mode
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    .OUTPUTS
    An array of trend objects.

    #>
}

function Add-ZabbixUserGroupMembers() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        [string[]]$Members,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = "usergroup.update"
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
        usrgrpid = $GroupId
    }
    $currentUsers = (Get-ZabbixUserGroup -GroupId -IncludeUsers).Users

    $users = [List[string]]$currentUsers.userIds

    foreach ($member in $members) {
        if ($member -is [psobject]) {
            $users.Add($Member.userId)
        } else {
            try {
                $userId = (Get-ZabbixUser -UserId $member).Userid
                $users.Add($userId)
            } catch {
                try {
                    $userid = (Get-ZabbixUser -Username $member).UserId
                    $users.Add($userId)
                } catch {
                    throw "Invalid Member: Member must be valid user object, UserId, or username or an array of the same."
                }
            }
        }        
    }

    $params.Add(
        "userIds", ($users.ToArray())
    )

    $Parameters.Add("params", $params)

    try {
        #$response = Invoke-RestMethod -Method POST -URI $Uri -ContentType $contentType -Body $body
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
    Add members ro a group
    .DESCRIPTION
    Add the specified users to a Zabbix Users Group
    .PARAMETER GroupId
    ID of the group.
    .PARAMETER Members
    An array of user objects. Objects must define the userid property.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)    #>
}

function Get-ZabbixUsersGroupMembership() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]$UserId,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri        
    )

    Begin {
        $Parameters = @{
            method = "usergroup.get"
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
        $params = @{
            userids = @($UserId)
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
    <#
    .SYNOPSIS
    Return a users group membership.
    .DESCRIPTION
    Return the group membership for the given user.
    .PARAMETER UserId
    The User Id.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)    
    .OUTPUTS
    An array of trend objects.
    
    #>
}

function Remove-ZabbixUserGroup() {
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
        method = 'usergroup.delete'
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
    
    $params = @($GroupId)
    
    #$payload.params = @($GroupId)

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Depth 5 -Compress

    $UserGroup = Get-ZabbixUserGroup -GroupId $GroupId

    if ($PSCmdlet.ShouldProcess("Delete", "User Group: $($UserGroup.Name)") ) {
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
    Remove a Users Group
    .DESCRIPTION
    Remove the given users group.
    .PARAMETER GroupId
    The ID of the group.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

Function Add-ZabbixUserGroupPermission() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$GroupId,
        [Parameter(Mandatory)]
        [string]$HostGroupid,
        [Parameter(Mandatory)]
        [HostAccessLevel]$Permission,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{}

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

    $rights = (Get-ZabbixUserGroup -GroupId $GroupId -IncludeRights @Parameters).rights
    $right = @{
        id = $HostGroupid
        permission = $Permission.value__
    }
    $rights += $right

    $Group = Set-ZabbixUserGroup -GroupId $GroupId -Rights $right @Parameters

    return $group    

    <#
    .SYNOPSIS
    Adds a User group permission
    .DESCRIPTION
    Add a permission to the permissions collection for this group.
    .PARAMETER GroupId
    The group Id.
    .PARAMETER HostGroupid
    The ID of the host group to add the permissions to.
    .PARAMETER Permission
    Access level to the host group.

    Possible values:
    0 - access denied;
    2 - read-only access;
    3 - read-write access.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Add-ZabbixUserGroupTag() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$Groupid,
        [Parameter(Mandatory)]
        [string]$HostGroupId,
        [Parameter(Mandatory)]
        [string]$TagName,
        [Parameter(Mandatory)]
        [string]$TagValue,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{}
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

    $Tags = (Get-ZabbixUserGroup -GroupId $Groupid -IncludeTags @Parameters).tag_filters

    $Tag = @{
        groupid = $HostGroupId
        tag = $TagName
        value = $TagValue
    }

    $Tags += $tag

    $Group = Set-ZabbixUserGroup -GroupId $Groupid -TagPermissions $Tags @Parameters

    return $Group

    <#
    .SYNOPSIS
    Add tag based permissions.
    .DESCRIPTION 
    Add tag based permissions to a group.
    .PARAMETER Groupid
    The group id.
    .PARAMETER HostGroupId
    ID of the host group to add permission to.
    .PARAMETER TagName
    The tag name
    .PARAMETER TagValue
    The tag value
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)    
    #>


}

function Get-ZabbixUser() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory, ParameterSetName = 'userid')]
        [string]$UserId,
        [Parameter(Mandatory, ParameterSetName = 'username')]
        [string]$Username,
        [switch]$includeMedias,
        [switch]$IncludeMediaTypes,
        [switch]$IncludeUserGroups,
        [ValidateScript({$env:ZABBIXVersion -gt 5}, ErrorMessage = "IncludeRoles can only be used with Zabbix 6 and above.")]
        [switch]$IncludeRoles,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = "user.get"
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
    if ($UserId) {
        $params.Add("userIds", $UserId)
    }

    if ($Username) {
        if ($env:ZABBIXVersion -eq "5") {
            $filter = @{
                alias = $Username
            }
        } else {
            $filter = @{
                username = $Username
            }
        }
        $params.Add("filter", $filter)
    }

    if ($IncludeMediaTypes) {
        $params.Add("selectMediatypes", "extend")
    }

    if ($includeMedias) {
        $params.Add("selectMedias","extend")
    }

    if ($IncludeUserGroups) {
        $params.Add("selectUsrgrps", "extend") 
    }
    if ($IncludeRoles) {
        $params.Add("selectRoles", "extend")        
    }

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Depth 5 -Compress

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
    .DESCRIPTION
    Retrieve a Zabbix user.
    .PARAMETER UserId
    The user Id. If omitted retrieve all users. (Cannot be used with username)
    .PARAMETER Username
    The username. if omitted retrieve all users. (Cannot be used with userid)
    .PARAMETER includeMedias
    Return media used by the user in the medias property.
    .PARAMETER IncludeMediaTypes
    Return media types used by the user in the mediatypes property.
    .PARAMETER IncludeUserGroups
    Return user groups that the user belongs to in the usrgrps property.
    .PARAMETER IncludeRoles
    Return user role in the role property.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Add-ZabbixUser() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [Alias('Alias')]
        [string]$Username,
        [string]$RoleId,
        [string]$GivenName,
        [string]$Surname,
        [switch]$AutoLogon,
        [string]$AutoLogout,
        [string]$Language,
        [string]$Refresh,
        [int]$RowsPerPage,
        [ValidateSet('default','blue','dark')]
        [string]$Theme,
        [string]$Url,
        [string]$timezone,
        [Parameter(Mandatory)]
        [PSObject[]]$UserGroups,
        [PSObject[]]$Medias,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = 'user.create'
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

    if ($env:ZABBIXVersion -eq '5') {
        $params.Add("alias", $Username)
    } else {
        $params.Add("username", $Username)
    }

    if ($RoleId) {
        $params.Add("roleid", $RoleId)
    }

    if ($GivenName) {
        $params.Add("name", $GivenName)
    }

    if ($Surname) {
        $params.Add("surname", $Surname)
    }

    if ($AutoLogon) {
        $params.Add("autologon", 1)
    }

    if ($AutoLogout) {
        $params.Add("autologout", $AutoLogout)
    }

    if($Language) {
        $params.Add("lang", $Language)
    }

    if ($Refresh) {
        $params.Add("refresh", $Refresh)
    }

    If ($RowsPerPage) {
        $params.Add("rows_per_page", $RowsPerPage)
    }

    if ($Theme) {
        $params.Add("theme", $Theme)
    }

    if ($Url) {
        $params.Add("url", $Url)
    }

    if ($timezone) {
        $params.Add("timezone", $timezone)
    }

    If ($UserGroups) {
        $params.Add("usrgrps", $UserGroups)
    }

    if ($Medias) {
        if ($env:ZABBIXVersion -eq '5') {
            $params.Add("user_medias", $Medias)
        } else {
            $params.Add("medias", $Medias)
        }
    }

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Depth 10 -Compress

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
    .DESCRIPTION
    Create a new Zabbix User.
    .PARAMETER Username
    The users name.
    .PARAMETER RoleId
    Role Id for this user
    .PARAMETER GivenName
    The users given name
    .PARAMETER Surname
    The users surname.
    .PARAMETER AutoLogon
    Set the user to auto logon
    .PARAMETER AutoLogout
    The time interval for auto logout.
    .PARAMETER Language
    The users language. If omitted the system default is used.
    .PARAMETER Refresh
    The refresh interval. Default is 30 seconds.
    .PARAMETER RowsPerPage
    Amount of object rows to show per page.
    .PARAMETER Theme
    The users theme. 
    .PARAMETER Url
    URL of the page to redirect the user to after logging in.
    .PARAMETER timezone
    User's time zone, for example, Europe/London, UTC.
    .PARAMETER UserGroups
    An array of user groups object. Object must define the usrgrpid property
    .PARAMETER Medias
    An array if user media to be created
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    
    #>
}

function Set-ZabbixUser() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]        
        [string]$UserId,
        [string]$UserName,
        [string]$RoleId,
        [string]$Language,
        [string]$GivenName,
        [string]$Surname,
        [string]$Refresh,
        [int]$RowsPerPage,
        [ValidateSet('default','dark-theme','blue-theme')]
        [string]$Theme,
        [string]$Url,
        [string]$TimeZone,
        [switch]$AutoLogon,
        [string]$SessionLifeTime,
        [psobject[]]$Medias,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName = 'default',
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = 'user,update'
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

    $params.Add("userid", $UserId)

    if ($UserName) {
        $params.Add("username", $UserId)
    }

    if ($RoleId) {
        $params.Add("roleid", $RoleId)
    }

    if ($Language) {
        $params.Add("lang", $Language)
    }

    if ($GivenName) {
        $params.Add("name", $GivenName)
    }

    if ($Surname) {
        $params.Add("surname",$Surname)
    }

    if ($Refresh) {
        $params.Add("refresh", $Refresh)
    }

    if ($RowsPerPage) {
        $params.Add("rows_per_page", $RowsPerPage)
    }

    if ($Theme) {
        $params.Add("theme", $Theme)
    }

    if ($Url) {
        $params.Add("Url", $Url)
    }

    if ($TimeZone) {
        $params.Add("timezone", $TimeZone)
    }

    if ($AutoLogon.IsPresent) {
        $params.Add("autologin", 1)
    }

    if ($SessionLifeTime) {
        $params.Add("autologout", $SessionLifeTime)
    }

    if ($Medias) {
        $params.Add("medias", $Medias)
    }

    $Parameters.Add("Params", $params)
    
    #$body = $payload | ConvertTo-Json -Depth 5 -Compress
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
    .DESCRIPTION
    Update a Zabbix User.
    .PARAMETER UserId
    The ID of the user
    .PARAMETER Username
    The users name.
    .PARAMETER RoleId
    Role Id for this user
    .PARAMETER GivenName
    The users given name
    .PARAMETER Surname
    The users surname.
    .PARAMETER AutoLogon
    Set the user to auto logon
    .PARAMETER AutoLogout
    The time interval for auto logout.
    .PARAMETER Language
    The users language. If omitted the system default is used.
    .PARAMETER Refresh
    The refresh interval. Default is 30 seconds.
    .PARAMETER RowsPerPage
    Amount of object rows to show per page.
    .PARAMETER Theme
    The users theme. 
    .PARAMETER Url
    URL of the page to redirect the user to after logging in.
    .PARAMETER timezone
    User's time zone, for example, Europe/London, UTC.
    .PARAMETER UserGroups
    An array of user groups object. Object must define the usrgrpid property
    .PARAMETER Medias
    An array if user media to be created
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Remove-ZabbixUser() {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = 'user.delete'
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

    $params.Add("userids", $UserId)

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Depth 4 -Compress

    $user = Get-ZabbixUser -UserId $UserId
    if ($env:ZABBIXVersion -eq '5') {
        $alias = $user.alias
    } else {
        $alias = $user.username
    }

    $msg = "User: {0} ({1} {2})" -f $alias, $user.name, $user.surname

    if ($PSCmdlet.ShouldProcess("Delete", "$msg")) {
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
    .DESCRIPTION
    Remove a Zabbix user.
    .PARAMETER UserId
    The users Id.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)    
    #>
}

function Add-ZabbixUserMedia() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$UserId,
        [Parameter(Mandatory)]
        [string]$MediaTypeId,
        [Parameter(Mandatory)]
        [switch]$Active,
        [string[]]$SendTo,
        [ValidateSet('NotClassified','Information','Warning','Average','High','Disaster')]
        [string]$Severity,
        [string]$Period,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{}
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

    $mediaType = Get-ZabbixMediaType -MediaTypeId $MediaTypeId @Parameters

    if ($Sendto -is [array] -and $MediaType.Type -ne [MediaType]::Email) {
        throw "Parameter SendTo can only be an array with a Media Type of 'Email'"
    }

    $Medias = (Get-ZabbixUser -UserId $UserId -includeMedias).medias

    $Media = @{
        mediatypeId = $MediaTypeId
        sendto = $SendTo
    }

    if ($Active.IsPresent) {
        $Media.Add("active", 1)
    }

    if ($Severities) {
        $Int_Severity = ConvertSeverityTo-Integer -Severity $Severity
        $Media.Add("severity", $Int_Severity)
    }

    if ($Period) {
        $Media.Add("period", $Period)
    }

    $Medias += $Media

    $User = Set-ZabbixUser -UserId $UserId -Medias $Medias @Parameters

    return $User

    <#
    .DESCRIPTION
    Add media to a Zabbix User
    .PARAMETER UserId
    The User Id.
    .PARAMETER MediaTypeId
    ID of the media type used by the media.
    .PARAMETER Active
    Set the media to active.
    .PARAMETER SendTo
    Address, user name or other identifier of the recipient.
    If type of Media type is e-mail, values are represented as array. For other types of Media types, value is represented as a string.
    .PARAMETER Severity
    Highest severity to alert on.
    .PARAMETER Period
    Time when the notifications can be sent as a time period or user macros separated by a semicolon. Default: 1-7,00:00-24:00
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}