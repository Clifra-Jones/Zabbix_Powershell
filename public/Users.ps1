using namespace System.Generic.Collections
function Get-ZabbixUserGroup() {
    [CmdletBinding()]
    Param(
        [string]$GroupId,
        [string]$UserId,
        [switch]$IncludeUsers,
        [switch]$IncludeRights,
        [switch]$IncludeTags,
        [string]$authcode
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    # }

    # $payload = Get-Payload

    # $payload.method = "usergroup.get"

    # $payload.Add("auth", $authcode)

    $Parameters = @{}
    if ($profilename) {
        $Parameters.Add("ProfileName", $profilename)
    }

    $Parameters.Add("method", "usergroup.get")

    $params = @{}

    if ($GroupId) {
        $params.Add("usrgrpids", $GroupId)
    }
    if ($UserId) {
        $params.Add("userIds", $UserId)
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
}

function Import-UserGroups() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [psObject]$UserGroup,
        [string]$ProfileName
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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [FrontendAccess]$FrontEndAccess = 'default',
        [switch]$Disabled,
        [switch]$DebugMode,
        [psobject]$Rights,
        [psobject]$Users,
        [psobject]$TagPermissions,
        [string]$ProfileName
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
    }

    $params = @{}

    $params.Add("name", $Name)

    $params.Add("gui_access", $FrontEndAccess.value__)

    if ($Disabled.IsPresent) {
        $params.Add("userss.status", "1")
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

    if ($TagPermissions) {
        $params.Add("tag_filters", $TagPermissions)
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

function Set-ZabbixUserGroup() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        [string]$Name,
        [FrontendAccess]$FrontEndAccess = 'default',
        [switch]$Disabled,
        [switch]$DebugMode,
        [psobject]$Rights,
        [psobject]$Users,
        [psobject]$TagPermissions,
        [string]$ProfileName
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

    if ($TagPermissions) {
        $params.Add("tag_filters", $TagPermissions)
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
}

function Add-ZabbixUserGroupMembers() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        [string[]]$Members,
        [string]$ProfileName
    )

    $Parameters = @{
        method = "usergroup.update"
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
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
}

function Remove-ZabbixUserGroup() {
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        [string]$ProfileName
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    # }

    # $payload = Get-Payload

    # $payload.method = 'usergroup.delete'

    $Parameters = @{
        method = 'usergroup.delete'
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
}

Function Add-ZabbixUserGroupPermission() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$GroupId,
        [Parameter(Mandatory)]
        [string]$HostGroupid,
        [Parameter(Mandatory)]
        [HostAccessLevel]$Permission
    )

    $rights = (Get-ZabbixUserGroup -GroupId $GroupId -IncludeRights).rights
    $right = @{
        id = $HostGroupid
        permission = $Permission.value__
    }
    $rights += $right

    $Group = Set-ZabbixUserGroup -GroupId $GroupId -Rights $right

    return $group    
}

function Add-ZabbixUserGroupTag() {
    [CmdletBinding()]
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
        [string]$TagValue
    )

    $Tags = (Get-ZabbixUserGroup -GroupId $Groupid -IncludeTags).tag_filters

    $Tag = @{
        groupid = $HostGroupId
        tag = $TagName
        value = $TagValue
    }

    $Tags += $tag

    $Group = Set-ZabbixUserGroup -GroupId $Groupid -TagPermissions $Tags

    return $Group
}

function Get-ZabbixUser() {
    [CmdletBinding()]
    Param(
        [string]$UserId,
        [ValidateScript({$_ -and $UserId}, ErrorMessage = "Parameter Username cannot be used with parameter UserId.")]
        [string]$Username,
        [switch]$includeMedias,
        [switch]$IncludeMediaTypes,
        [switch]$IncludeUserGroups,
        [string]$ProfileName
    )

    #if (-not $authcode) {
    #    $authcode = Read-ZabbixConfig
    #}

    #$payload = Get-Payload

    #$payload.method = 'user.get'

    #$payload.Add("auth", $authcode)

    $Parameters = @{}

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    }

    $Parameters.Add("Method", "user.get")

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
}

function Add-ZabbixUser() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Alias('Alias')]
        [string]$Username,
        [string]$RoleId,
        [string]$GivenName,
        [string]$Surname,
        [Parameter(Mandatory)]
        [PSObject]$UserGroups,
        [PSObject]$Medias,
        [string]$ProfileName        
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    # }

    # $payload = Get-Payload
    
    # $payload.method = "user.create"
    
    # $payload.Add("auth", $authcode)

    $Parameters = @{
        method = 'user.create'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
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
}

function Set-ZabbixUser() {
    [CmdletBinding()]
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
        [string]$ProfileName
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    # }

    # $payload = Get-Payload

    # $payload.method = 'user.update'

    # $payload.Add("auth", $authcode)

    $Parameters = @{
        method = 'user,update'
    }

    if ($profilename) {
        $Parameters.Add("ProfileName", $profilename)
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
}

function Remove-ZabbixUser() {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        [string]$ProfileName
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    # }

    # $payload = Get-Payload

    # $payload.method = 'user.delete'
    # $payload.Add("auth", $authcode)

    $Parameters = @{
        method = 'user.delete'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
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


}