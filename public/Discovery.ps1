function Get-ZabbixDiscoveryRule() {
    [CmdletBinding()]
    Param(
        [string]$DRuleId,
        [switch]$IncludeChecks,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    # }

    # $payload = Get-Payload

    # $Payload.method = 'drule.get'

    # $Payload.Add("auth", $authcode)

    $Parameters = @{
        method = 'drule.get'
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

    if ($DRuleId) {
        $params.Add("druleids", $DRuleId)
    }

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Depth 4 -Compress

    try {
        # $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
        $response = Invoke-ZabbixAPI @Parameters

        if ($response.error) {
            throw $response.error.data
        } else {
            if ($IncludeChecks.IsPresent) {
                $response.result | ForEach-Object {
                    $dCheck = $_ | Get-ZabbixDiscoveryRuleCheck
                    $_ | Add-Member -MemberType NoteProperty -Name "Checks" -Value $dCheck
                }
            }
            return $response.result
        }
    } catch {
        throw $_
    }

    <#
    .SYNOPSIS
    Retrieve Zabbix Discovery Rule(s).
    .DESCRIPTION
    Retrieve Zabbix Discovery Rule(s) from the Zabbix configuration.
    .PARAMETER DRuleId
    The Discovery Rule Id. If omitted all rules will be returned.
    .PARAMETER IncludeChecks
    Include the checks in the output.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Get-ZabbixDiscoveryRuleCheck() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$dRuleId,
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

        $CheckType = @{
            '0' = 'SSH'
            '1' = 'LDAP'
            '2' = 'SMTP'
            '3' = 'FTP'
            '4' = 'HTTP'
            '5' = 'POP'
            '6' = 'NNTP'
            '7' = 'IMAP'
            '8' = 'TCP'
            '9' = 'Zabbix agent'
            '10' = 'SNMPv1 agent'
            '11' = 'SNMPv2 agent'
            '12' = 'ICMP ping'
            '13' = 'SNMPv3 agent'
            '14' = 'HTTPS'
            '15' = 'Telnet'
        }

        $HostSource = @{
            '1' = 'DNS'
            '2' = 'IP'
        }

        $NameSource = @{
            '1' = 'DNS'
            '2' = 'IP'
        }

        # $payload = Get-Payload

        # $payload.method = "dcheck.get"        

        $Parameters = @{
            method = 'dcheck.get'
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

        $params.Add("druleids", $druleId)

        #$Body = $payload | ConvertTo-Json -Depth 4

        $Parameters.Add("params", $params)

        try {
            #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $Body
            $response = Invoke-ZabbixAPI @Parameters

            if ($response.error) {
                throw $response.error.data
            } else {                
                $response.result | ForEach-Object{
                    $_ | Add-Member -MemberType NoteProperty -Name "type_name" -Value ($CheckType[$_.type])
                    $_ | Add-Member -MemberType NoteProperty -Name "host_name" -Value ($HostSource[$_.host_source])
                    $_ | Add-Member -MemberType NoteProperty -Name "visible_name" -Value ($NameSource[$_.name_source])
                }
                return $response.result
            }
        } catch {
            throw $_
        }
    }
    <#
    .SYNOPSIS
    Retrieve the checks associated with a discovery rule.
    .DESCRIPTION
    Retrieve the Discovery Checks associated with a discovery rule.
    .PARAMETER dRuleId
    The Discovery Rule ID to retrieve the check for.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Add-ZabbixDiscoveryRule() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$IpRange,
        [string]$Delay,
        [string]$ProxyHostId,
        [switch]$Disabled,
        [Parameter(Mandatory)]
        [PsObject[]]$Checks,
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

    # $Payload.method = 'drule.create'
    # $Payload.Add("auth", $authcode)        
    $Parameters = @{
        method = 'drule.create'
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

    $Params = @{}

    $params.Add("name", $DRule.Name)
    $params.Add("iprange", $DRule.iprange)

    $params.Add("dchecks", $Checks)

    #$body = $payload | ConvertTo-Json -Depth 10 #-Compress

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
    Add a Discovery Rule
    .DESCRIPTION
    Add a discovery rule to the zabbix configuration.
    .PARAMETER Name
    The Name of the discovery rule.
    .PARAMETER IpRange
    The IP Range of the discovery rule.
    .PARAMETER Delay
    Execution interval of the discovery rule. Accepts seconds, time unit with suffix and user macro.
    .PARAMETER ProxyHostId
    ID of the Proxy host.
    .PARAMETER Disabled
    Create the rul in the disabled state.
    .PARAMETER Checks
    An array of check objects to apply to this rule.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}


function Set-ZabbixDiscoveryRule() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword','')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$DruleId,        
        [String]$Name,
        [string]$IpRange,
        [string]$Delay,
        [string]$ProxyHost,
        [switch]$Disabled,
        [PsObject]$Checks,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$Uri
    )

    $Parameters = @{
        method = 'drule.update'
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
        $Parameters.Add("name", $Name)
    }

    if ($IpRange) {
        $params.Add("iprange", $IpRange)
    }

    if ($Delay) {
        $params.Add("delay", $Delay)
    }

    if ($Disabled) {
        $params.Add("status", 1)
    }

    if ($Checks) {
        $params.Add("checks", $Checkds)
    }

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-JSON -Depth 10 -Compress

    try {
        #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
        $response = Invoke-ZabbixAPI @Parameters

        if ($response.error) {
            throw $response.err.data
        }
        return $response.result
    } catch {
        throw $_
    }

    <#
    .SYNOPSIS 
    Updates a Discovery Rule
    .DESCRIPTION
    Updates the properties and checks of a Discovery Rule.
    .PARAMETER DruleId
    The ID of the discovery Rule.
    .PARAMETER Name
    The new name of the rule.
    .PARAMETER IpRange
    One or several IP ranges to check separated by commas.
    .PARAMETER Delay
    Execution interval of the discovery rule. Accepts seconds, time unit with suffix and user macro. Default: 1h.
    .PARAMETER ProxyHost
    ID of the proxy used for discovery.
    .PARAMETER Disabled
    Set the rul to Disabled.
    .PARAMETER Checks
    An array of discovery checks.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}


function Remove-ZabbixDiscoveryRule() {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$DRuleId,
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

    # $payload.method = 'drule.delete'

    $Parameters = @{
        method = 'drule.delete'
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

    $params = @($DRuleId)

    #$payload.Add("auth", $authcode)

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Depth 5 -Compress
    
    $drule = Get-ZabbixDiscoveryRules -DRuleId $DRuleId

    if ($PSCmdlet.ShouldProcess("Delete", "Discovery rule: $($drule.name)?") ) {
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
    Remove a Discovery Rule.
    .DESCRIPTION
    Remove the specified discovery rule from the configuration
    .PARAMETER DRuleId
    ID of the discovery rule.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}