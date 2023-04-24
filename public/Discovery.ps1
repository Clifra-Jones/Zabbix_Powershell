function Get-ZabbixDiscoveryRule() {
    [CmdletBinding()]
    Param(
        [string]$DRuleId,
        [switch]$IncludeChecks,
        [string]$ProfileName
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
}

function Get-ZabbixDiscoveryRuleCheck() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$druleid,
        [string]$ProfileName
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
}

function Add-ZabbixDiscoveryRule() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [psobject]$DRuleId,
        [Parameter(Mandatory = $true)]
        [string]$IpRange,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$Delay,
        [string]$ProxyHostId,
        [switch]$Disabled,
        [psobject]$Checks,
        [string]$ProfileName
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
    }

    $Params = @{}

    $params.Add("name", $DRule.Name)
    $params.Add("iprange", $DRule.iprange)

    if ($Checks) {
        $dchecks= @()
        foreach ($dcheck in $checks) {
            switch ($dcheck.dcheckid) {
                "10" {
                    $check = @{
                        type = $dcheck.type
                        ports = $dcheck.ports
                        key_ = $dcheck.key_
                        snmp_community = $dcheck.snmp_community
                        uniq = $dcheck.uniq
                    }
                }
                "11" {
                    $check = @{
                        type = $dcheck.type
                        ports = $dcheck.ports
                        key_ = $dcheck.key_
                        snmp_community = $dcheck.snmp_community
                        uniq = $dcheck.uniq
                    }
                }
                "13" {
                    $check = @{
                        type = $dcheck.type
                        ports= $dcheck.ports
                        key_ = $dcheck.key_
                        snmpv3_contextname = $dcjeck.snmpv3_contextname
                        snmpv3_securityname = $dcheck.snmpv3_securityname                            
                        uniq = $dcheck.uniq
                    }
                    switch ($dcheck.snmpv3_securitylevel) {
                        "1" {                                    
                            $check.Add("snmpv3_authprotocol", $dcheck.snmpv3_authprotocol)
                            $check.Add("snmpv3_authpassphrase", $dcheck.snmpv3_authpassphrase)
                        }
                        "2" {
                            $check.Add("snmpv3_authprotocol", $dcheck.snmpv3_authprotocol)
                            $check.Add("snmpv3_authpassphrase", $dcheck.snmpv3_authpassphrase)
                            $check.Add("snmpv3_privprotocol", $dcheck.snmpv3_privprotocol)
                            $check.Add("snmpv3_privpassphrase", $dcheck.snmpv3_privpassphrase)
                        }
                    }
                }
                "9" {
                    $check = @{
                        type = $dcheck.type
                        port = $dcheck.port
                        key_ = $dcheck.Key_
                        uniq = $dcheck.uniq
                    }
                }
                default {
                    $check = @{
                        type = $dcheck.type
                        port = $dcheck.port
                    }
                }
            }
            $dchecks += $check
        }
    }

    $params.Add("dchecks", $dchecks)

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
}


function Set-ZabbixDiscoveryRule() {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword','')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$DruleId,        
        [CheckType]$Type,
        [string]$IpRange,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Key,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Ports,
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript(
            {$_ -and ($type -in 10,7,11,13)}, 
            ErrorMessage = "Parameter Snmp_Community can only be used with Parameter Type as 'SNMPv1 agent', 'IMAP,SNMPv2 agent', or 'SNMPv3 agent'"
        )]
        [string]$Snmp_Community,
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({$_ -and $type -eq ([CheckType]::SNMPv3_agent)}, ErrorMessage = "Parameter Snmpv3_Securitylevel can only be used when parameter Type is set to 'SNMPv3 agent'.")]
        [string]$Snmpv3_Securitylevel,
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({$_ -and ($type -eq ([CheckType]::SNMPv3_agent) -and ($Snmpv3_Securitylevel -in 'authNoPriv','authPriv'))}
        )]
        [string]$Snmpv3_Authpassphrase,
        [Parameter(ValueFromPipelineByPropertyName)]        
        [ValidateScript({$_ -and $type -eq ([CheckType]::SNMPv3_agent)}, ErrorMessage = "Parameter Snmpv3_Authprotocol can only be used when parameter Type is set to 'SNMPv3 agent'.")]
        [AuthProtocol]$Snmpv3_Authprotocol,
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({$_ -and $type -eq ([CheckType]::SNMPv3_agent)}, ErrorMessage = "Parameter Snmpv3_Contextname can only be used when parameter Type is set to 'SNMPv3 agent'.")]
        [string]$Snmpv3_Contextname,
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({$_ -and $type -eq ([CheckType]::SNMPv3_agent)}, ErrorMessage = "Parameter Snmpv3_Privpassphrase can only be used when parameter Type is set to 'SNMPv3 agent'.")]
        [securestring]$Snmpv3_Privpassphrase,
        [Parameter(ValueFromPipelineByPropertyName)]        
        [ValidateScript({$_ -and $type -eq ([CheckType]::SNMPv3_agent)}, ErrorMessage = "Parameter Snmpv3_Protocol can only be used when parameter Type is set to 'SNMPv3 agent'.")]
        [PrivProtocol]$Snmpv3_PrivProtocol,
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({$_ -and $type -eq ([CheckType]::SNMPv3_agent)}, ErrorMessage = "Parameter Snmpv3_Securityname can only be used when parameter Type is set to 'SNMPv3 agent'.")]
        [SecurityLevel]$Snmpv3_Securityname,
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$Unique,
        [Parameter(ValueFromPipelineByPropertyName)]
        [HostSource]$HostNameSource,
        [Parameter(ValueFromPipeline)]
        [VisibleNameSource]$VisibleNameSource,
        [string]$ProfileName
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    # }

<#     $CheckTypes = @{
        'SNMPv1 agent' = '10'
        'IMAP' = '7'
        'SNMPv2 agent' = '11'
        'ICMP ping' = '12'
        'SMTP' = '2'
        'LDAP' = '1'
        'FTP' = '3'
        'NNTP' = '6'
        'HTTP' = '4'
        'POP' = '5'
        'TCP' = '8'
        'Telnet' = '15'
        'Zabbix agent' = '9'
        'HTTPS' = '14'
        'SSH' = '0'
        'SNMPv3 agent' = '13'
    } 
    $PrivProtocols = @{
        AES128 = '1'
        AES192 = '2'
        AES256 = '3'
        AES192C = '4'
        AES256C = '5'
    } 
    $SecurityLevels = @{
        noAuthNoPriv = '1'
        authNoPriv = '2'
        authPriv = '3'
    }
    $AuthProtocols = @{
        SHA1 = '1'
        SHA224 = '2'
        SHA256 = '3'
        SHA384 = '4'
        SHA512 = '5'
    }
    #>

    # $payload.method = "drule.update"
    # $payload.Add("auth", $authcode)

    Begin {
        $Parameters = @{
            method = 'drule.update'
        }

        if ($ProfileName) {
            $Parameters.Add("ProfileName", $ProfileName)
        }

        $params = @{}

        if ($Type) {
            $_type = $CheckTypes[$type]
            $params.Add("type", $_type)
        }
        if ($IpRange) {
            $params.Add("iprange", $IpRange)
        }
    }
    
    Process {
        if ($Key) {
            $params.Add("Key_", $Key)
        }
        if ($Ports) {
            $params.Add("ports", $Ports)
        }
        if ($Snmp_Community) {
            $params.Add("snmp_community", $Snmp_Community)
        }
        if ($Snmpv3_Authpassphrase) {            
            $params.Add("snmpv3_authpassphrase", $PassPhrase)
        }
        if ($Snmpv3_Authprotocol) {
            $params.Add("snmpv3_authprotocol", $AuthProtocol.value__)
        }
        if ($Snmpv3_Contextname) {
            $params.Add("snmpv3_contextname", $Snmpv3_Contextname)
        }
        if ($Snmpv3_Privpassphrase) {            
            $params.Add("snmpv3_privpassphrase", $PrivPassPhrase)
        }
        if ($Snmpv3_PrivProtocol) {
            $PrivProtocol = $PrivProtocols[$Snmpv3_PrivProtocol]
            $params.Add("snmpv3_privprotocol", $PrivProtocol.value__)
        }
        if ($Snmpv3_Securitylevel) {
            $SecLevel = $SecurityLevels[$Snmpv3_Securitylevel]
            $params.Add("snmpv3_securitylevel", $SecLevel)
        }
        if ($Snmpv3_Securityname) {
            $Params.Add("snmpv3_securityname", $Snmpv3_Securityname)
        }
        if ($Unique.IsPresent) {
            $params.Add("uniq", '1')
        }
        if ($HostNameSource) {
                $params.Add("host_source", $HostNameSource.value__)                
        }                    
        if ($VisibleNameSource) {
            $params.Add("name_source", $VisibleNameSource.value__)
        }
    }

    End{
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
    }
}


function Remove-ZabbixDiscoveryRule() {
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$DRuleId,
        [string]$ProfileName
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
}