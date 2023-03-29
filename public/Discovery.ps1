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
    Param(
        [Parameter(Mandatory = $true)]
        [string]$DruleId,
        [ValidateSet('SNMPv1 agent','IMAP,SNMPv2 agent','ICMP ping','SMTP','LDAP','FTP','NNTP','HTTP','POP','TCP','Telnet','Zabbix agent','HTTPS','SSH','SNMPv3 agent')]   
        [int]$Type,
        [string]$IpRange,
        [ValidateScript(
            {
                if ($_) {
                    if ($Key -or $Ports -or $Snmp_Community -or $Snmpv3_Authpassphrase -or $Snmpv3_Authprotocol `
                        -or $Snmpv3_Contextname -or $Snmpv3_Privpassphrase -or $Snmpv3_Securitylevel -or $Snmpv3_Securityname `
                        -or $type -or $Unique -or $HostNameSource -or $VisableNameSource) {
                            throw "Parameter Checks canno tbe used with other check Parameters"
                        }
                } else {
                    $true
                }
            }
        )]
        [PSObject]$Checks,
        [string]$Key,
        [string]$Ports,
        [ValidateScript(
            {
                if ($_ -and ($type -in 'SNMPv1 agent','IMAP,SNMPv2 agent','SNMPv3 agent')) {
                    $true
                } else {
                    throw "Parameter Snmp_Community can only be used with Type 'SNMPv1 agent','IMAP,SNMPv2 agent', and 'SNMPv3 agent'"
                }
            }
        )]
        [string]$Snmp_Community,
        [ValidateScript(
            {
                if ($_ -and ($type -eq 'SNMPv3 agent' -and ($Snmpv3_Securitylevel -in 'authNoPriv','authPriv') ) ) {
                    $true
                } else {
                    throw "Parameter can only be used with Parameter type set to 'SNMPv3 agent' and parameter Snmpv3_Securitylevel set to 'authNoPriv' or'authPriv'"
                }
            }
        )]
        [securestring]$Snmpv3_Authpassphrase,
        [ValidateSet('SHA1','SHA224','SHA256','SHA384','SHA512')]
        [ValidateScript(
            {
                if ($_ -and $type -eq 'SNMPv3 agent') {
                    $true
                } else {
                    throw "Parameter Snmpv3_Authprotocol can only be used when parameter Type is set to 'SNMPv3 agent'."
                }
            }
        )]
        [string]$Snmpv3_Authprotocol,
        [ValidateScript(
            {
                if ($_ -and $type -eq 'SNMPv3 agent') {
                    $true
                } else {
                    throw "Parameter Snmpv3_Contextname can only be used when parameter Type is set to 'SNMPv3 agent'."
                }
            }
        )]
        [string]$Snmpv3_Contextname,
        [ValidateScript(
            {
                if ($_ -and $type -eq 'SNMPv3 agent') {
                    $true
                } else {
                    throw "Parameter Snmpv3_Privpassphrase can only be used when parameter Type is set to 'SNMPv3 agent'."
                }
            }
        )]
        [securestring]$Snmpv3_Privpassphrase,
        [ValidateSet('Aes128','AES192','AES256','AES192C','AES256C')]
        [ValidateScript(
            {
                if ($_ -and $type -eq 'SNMPv3 agent') {
                    $true
                } else {
                    throw "Parameter Snmpv3_Protocol can only be used when parameter Type is set to 'SNMPv3 agent'."
                }
            }
        )]
        [string]$Snmpv3_PrivProtocol,
        [ValidateSet('noAuthNoPriv','authNoPriv','authPriv')]
        [ValidateScript(
            {
                if ($_ -and $type -eq 'SNMPv3 agent') {
                    $true
                } else {
                    throw "Parameter Snmpv3_Securitylevel can only be used when parameter Type is set to 'SNMPv3 agent'."
                }
            }
        )]
        [string]$Snmpv3_Securitylevel,
        [ValidateScript(
            {
                if ($_ -and $type -eq 'SNMPv3 agent') {
                    $true
                } else {
                    throw "Parameter Snmpv3_Securityname can only be used when parameter Type is set to 'SNMPv3 agent'."
                }
            }
        )]
        [string]$Snmpv3_Securityname,
        [switch]$Unique,
        [ValidateSet('DNS','IP')]
        [string]$HostNameSource,
        [ValidateSet('DNS','IP')]
        [string]$VisibleNameSource,
        [string]$ProfileName
    )

    # if (-not $authcode) {
    #     $authcode = Read-ZabbixConfig
    # }

    $CheckTypes = @{
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


    # $payload.method = "drule.update"
    # $payload.Add("auth", $authcode)

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
    if ($Checks) {
        $params.Add("dchecks", $Checks)
    } else {
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
            $PassPhrase = ConvertFrom-SecureString -SecureString $Snmpv3_Authpassphrase -AsPlainText
            $params.Add("snmpv3_authpassphrase", $PassPhrase)
        }
        if ($Snmpv3_Authprotocol) {
            $Protocol = $AuthProtocols[$Snmpv3_Authprotocol]
            $params.Add("snmpv3_authprotocol", $Protocol)
        }
        if ($Snmpv3_Contextname) {
            $params.Add("snmpv3_contextname", $Snmpv3_Contextname)
        }
        if ($Snmpv3_Privpassphrase) {
            $PrivPassPhrase = ConvertFrom-SecureString -SecureString $Snmpv3_Privpassphrase -AsPlainText
            $params.Add("snmpv3_privpassphrase", $PrivPassPhrase)
        }
        if ($Snmpv3_PrivProtocol) {
            $PrivProtocol = $PrivProtocols[$Snmpv3_PrivProtocol]
            $params.Add("snmpv3_privprotocol", $PrivProtocol)
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
            switch($HostNameSource) {
                'DNS' {
                    $params.Add("host_source", "1")
                }
                'IP' {
                    $params.Add("host_source", "2")
                }
            }            
        }
        if ($VisibleNameSource) {
            switch ($VisibleNameSource) {
                'DNS' {
                    $params.Add("name_source", "1")
                }
                'IP' {
                    $params.Add("name_source", '2')
                }                
            }
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