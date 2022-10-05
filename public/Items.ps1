function Get-ZabbixItems() {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$hostId,
        [string]$itemId,
        [string]$groupid,
        [string]$templateId,
        [switch]$includeHosts,
        [psObject]$filter,
        [psobject]$search,
        [switch]$searchByAny,
        [switch]$searchWildcardsEnabled,
        [switch]$searchFromStart,
        [switch]$NoProgress,
        [string]$authCode
    )

    Begin {
        if (-not $authCode) {
            $authCode = Read-ZabbixConfig
        }

        
    }

    Process {
        if (-not $NoProgress.IsPresent) {
            if ($hostId) { 
                $percentComplete = 100
                $status = "{0}: {1}" -f $hostId, $psItem.Name
                Write-Progress -Activity "Getting Items for host:" -Status $Status -PercentComplete $percentComplete
            }
        }

        $payload = Get-Payload
        $payload.method = 'item.get'

        if ($itemId) {$payload.params.Add("itemids", $itemid)}
        if ($groupid) {$payload.params.Add("groupids", $groupid)}
        if ($templateId) {$payload.params.Add("templateids", $templateId)}
        if ($includeHosts) {$payload.params.Add("selectHosts", @("hostId","name"))}
        if ($filter) {$payload.params.Add("filter", $filter)}
        if ($search) {$payload.params.Add("search", $search)}
        if ($searchByAny.IsPresent) {$payload.params.Add("searchByAny", $searchByAny.IsPresent)}
        if ($searchWildcardsEnabled.IsPresent) {$payload.params.Add("searchWildcardsEnabled", $searchWildcardsEnabled.IsPresent)}
        if ($searchFromStart) {$payload.params.Add("startSearch", $searchFromStart.IsPresent)}

        if ($payload.params.count -eq 0) {
            $payload.params.Add("limit", 50)
        }        if ($hostId) {$payload.params.Add("hostids", $hostId)}

        $payload.Add("auth", $authCode)

        $body = $payload | ConvertTo-Json -Depth 10 -Compress

        try {
            $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            if ($response.error) {
                throw $response.error.data
            }
            $results = $response.result
            foreach ($result in $results) {
                    
                [datetime]$_lastclock = ([System.DateTimeOffset]::FromUnixTimeSeconds($result.lastclock).DateTime).ToLocalTime()
                $result | Add-Member -NotePropertyName "lastupdate" -NotePropertyValue $_lastclock
                switch ($result.units) {
                    'B' {
                        # Bytes
                        # display the value in KBs
                        if ($result.lastvalue -lt 1Kb) {
                            $_LastValue = "{0} Bytes" -f $result.lastvalue
                        } elseif ($result.lastvalue -lt 1Mb) {
                            $_LastValue = "{0} KB" -f ($result.lastvalue / 1Kb)
                        } elseif ($result.lastvalue -lt 1GB) {
                            $_LastValue = "{0} MB" -f ($result.lastvalue / 1MB)
                        } else {
                            $_LastValue = "{0} GB" -f ($result.lastvalue / 1GB)
                        }                
                    }
                    'Bps' {
                                # Bytes
                        # display the value in KBs
                        if ($result.lastvalue -lt 1Kb) {
                            $_LastValue = "{0} Bps" -f $result.lastvalue
                        } elseif ($result.lastvalue -lt 1Mb) {
                            $_LastValue = "{0} KBps" -f ($result.lastvalue / 1Kb)
                        } elseif ($result.lastvalue -lt 1GB) {
                            $_LastValue = "{0} MBps" -f ($result.lastvalue / 1MB)
                        } else {
                            $_LastValue = "{0} GBps" -f ($result.lastvalue / 1GB)
                        }     
                    }
                    'unixtime' {
                        $_LastValue = [System.DateTimeOffset]::FromUnixTimeSeconds($result.lastvalue).DateTime.ToString("yyyy/MM/dd HH:mm:ss")
                    }
                    'uptime' {
                        $_lastValue = [TimeSpan]::FromSeconds($result.lastvalue).ToString()
                    }
                    's' {
                        $_LastValue = [timespan]::FromSeconds($result.lastvalue).ToString()
                    }
                    default {
                        $_LastValue = $result.lastvalue
                    }            
                }
                $result | Add-Member -MemberType NoteProperty -Name "lastData" -Value $_LastValue
            }
            return $results
        } catch {
            throw $_
        }
    }
    <#
    .SYNOPSIS
    Returns Zabbix items.
    .DESCRIPTION
    Returns Zabbix items based on the supplied parameters.
    .PARAMETER hostId
    Return only items that belong to the given hosts.
    .PARAMETER itemId
    Return only items with the given IDs.
    .PARAMETER groupid
    Return only items that belong to the hosts from the given groups.
    .PARAMETER templateId
    Return only items that belong to the given templates.
    .PARAMETER includeHosts
    Return a hosts property with an array of hosts that the item belongs to.
    .PARAMETER filter
    Filter the response by the supplied criteria.
    Example -filter @{key_ = 'system.uptime'}
    .PARAMETER search
    Search results by the supplied criteria.
    Example -search @{key_ = @("system.uptime","system.cpu")}
    .PARAMETER searchByAny
    Return results that match any of the criteria given in the filter or search parameter instead of all of them.
    .PARAMETER searchWildcardsEnabled
    If set to true enables the use of "*" as a wildcard character in the search parameter.
    .PARAMETER searchFromStart
    The search parameter will compare the beginning of fields.
    .PARAMETER NoProgress
    Do not show progress. If passing in an array of objects progress is show. Supply thi sto supress the progress indicator.
    .PARAMETER authCode
    Authorization code to use for the API call. If omitted read the authcode from the local configuration file.
    #>
}

function Set-ZabbixItem() {
    [CmdletBinding(DefaultParameterSetName = 'props')]
    Param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'props'
        )]
        [string]$itemid,
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ParameterSetName = 'item'
        )]
        [psobject]$item,
        [Parameter(ParameterSetName = 'props')]
        [string]$name,
        [string]$delay,
        [Parameter(ParameterSetName = 'props')]        
        [switch]$Disabled,
        [Parameter(ParameterSetName = 'props')]
        [string]$key,
        [Parameter(ParameterSetName = 'props')]
        [ValidateSet(
            'ZabbixAgent','ZabbixTrapper','SimpleCheck','ZabbixInternal','WebItem','ExternalCheck','DatabaseMonitor','IPMIAgent','SSHAgent','TelnetAgent', `
            'Calculation','JMXAgent','SNMPTrap','DependentItem','HTTPAgent','SNMPAgent','Script'
        )]
        [string]$type,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    Throw "Parameter URL only valid for HTTPAgent Item type."
                }
            }
        )]
        [string]$Url,
        [ValidateSet('NumericFloat','Character','Log','NumericUnsigned','Text')]
        [string]$valueType,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter allowTraps only valid for HTTPAgent Item index."
                }
            }
        )]
        [switch]$allowTraps,
        [ValidateSet('none','Basic','NTLM','Kerberos','Password','PublicKey')]
        [ValidateScript(
            {
                if ($type -ne "SSHAgent" -and $type -ne "HTTPAgent") {
                    throw "Parameter AuthType is only valid for SSHAGent and HTTPAgent Item types."
                } elseif ($AuthType -in "Password","PublicKey") {
                    if ($type -ne "SSHAGent") {
                        throw "AuthType Password amd PublicKey are only valid for SSHAgent Item types."
                    }                    
                } else {
                    if ($type -ne "HTTPAgent") {
                        throw "AuthType none, Basic, NTLM and Kerberos are only valid for HTTPAgent Item types."
                    }
                }
            }
        )]
        [string]$AuthType,
        [string]$Description,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter followRedirects is only valid for HTTPAgent Item type."
                }
            }
        )]
        [switch]$followRedirects,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter httpHeaders is only valid for HTTPAgent Item type."
                }
            }
        )]
        [psobject]$httpHeaders,
        [string]$History,
        [string]$httpProxyString,
        [int]$inventoryLink,
        [ValidateScript(
            {
                if ($type -ne "IPMIAgent") {
                    throw "Parameter ipmiSensor is only valid for IPMIAgent Item type."
                }
            }
        )]
        [string]$ipmiSensor,
        [ValidateScript(
            {
                if ($type -ne "JMXAgent") {
                    throw "Parameter JMXEndpoint is only valid for JMXAgent Item type."
                }
            }
        )]
        [string]$JMXEndpoint,
        [int]$MasterItemId,
        [ValidateScript(
            {
                if ($type -notin 'SSHAgent','TelnetAgent','DatabaseMonitor','Script') {
                    throw "Parameter additionalParams onlu valid for SSHAgent, TelnetAgent, DatabaseMonitor and Script Item types."
                }
            }
        )]
        [psObject]$additionalParams,
        [ValidateScript(
            {
                if ($type -ne "Script") {
                    throw "Parameter scriptParams is only valid got Script Item type."
                }
            }
        )]
        [psobject]$scriptParams,
        [ValidateSet('Raw','JSON','XML')]
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter postType is only valid for HTTPAgent Item type."
                }
            }
        )]
        [string]$postType,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter posts is only valid for HTTPAgent Item type."
                }
            }
        )]
        [psobject]$posts,
        [string]$privateKey,
        [string]$publicKey,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter queryFields is only valid for HTTPAgent Item type."
                }
            }
        )]
        [psobject]$queryFields,
        [ValidateSet('GET','POST','PUT','HEAD')]
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter requestMethod is only valid for HTTPAgent Item type."
                }
            }
        )]
        [string]$requestMethod,
        [ValidateScript(
            {
                if ($type -ne "HttpAgent") {
                    throw "Parameter retrieveMOde is only valid for HTTPAgent Item type."
                }
            }
        )]
        [ValidateSet('Body','Headers','Both')]
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter retrieveMode is only valid for HTTPAgent item type."
                }
            }
        )]
        [string]$retrieveMode,
        [ValidateScript(
            {
                if ($type -ne "SNMPAgent") {
                    throw "Parameter snmpOID os only valid for SNMPAgent item type"
                }
            }
        )]
        [string]$snmpOID,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter retrieveMode is only valid for HTTPAgent item type."
                }
            }
        )]
        [string]$sslCertFile,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter retrieveMode is only valid for HTTPAgent item type."
                }
            }
        )]
        [string]$sslKeyFile,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter retrieveMode is only valid for HTTPAgent item type."
                }
            }
        )]
        [securestring]$sslKeyPassword,
        [string[]]$httpStatusCodes,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter retrieveMode is only valid for HTTPAgent item type."
                }
            }
        )]
        [string]$Timeout,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter retrieveMode is only valid for HTTPAgent item type."
                }
            }
        )]
        [string]$trapperHost,
        [string]$Trends,
        [string]$Units,
        [string]$valueMapId,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter retrieveMode is only valid for HTTPAgent item type."
                }
            }
        )]
        [switch]$verifyHost,
        [ValidateScript(
            {
                if ($type -ne "HTTPAgent") {
                    throw "Parameter retrieveMode is only valid for HTTPAgent item type."
                }
            }
        )]
        [switch]$verifyPeer,
        [switch]$NoProgress,
        [string]$authcode
    )


    if (-not $autocode) {
        $authcode = Read-ZabbixConfig
    }

    $payload = Get-Payload
    $payload.method = 'item.update'


    if (-not $NoProgress.IsPresent) {
        $percentComplete = 100
        Write-Progress -Activity "Updating Item:" -Status $ItemId -PercentComplete $percentComplete
    }
    if ($item) {
        $properties = $Item.psObject.Properties | Select-Object Name, value
        $properties | ForEach-Object {
            $payload.params.Add($_.name, $_.value)
        }
    } else {
        $payload.params.Add("itemid", $itemId)
        if ($name) {$payload.params.Add("name", $name)}
        if ($delay) {$payload.params.Add("delay", $delay)}
        if($Disabled.IsPresent) {$payload.params.Add("status", 1)}
        if ($key) {$payload.params.Add("key_", $key)}
        if ($type) {
            $types= @('ZabbixAgent','ZabbixTrapper','SimpleCheck','ZabbixInternal','WebItem','ExternalCheck','DatabaseMonitor','IPMIAgent','SSHAgent','TelnetAgent', `
            'Calculation','JMXAgent','SNMPTrap','DependentItem','HTTPAgent','SNMPAgent','Script')
            $typeIndex = $types.IndexOf($type)
            $payload.params.Add("type", $typeIndex)
        }
        if ($Url) {
            $payload.params.Add("url", $url)
        }
        if ($valueType) {
            $valueTypes = @('NumericFloat','Character','Log','NumericUnsigned','Text')
            $valueTypeIndex = $valueTypes.IndexOf($valueType)
            $payload.params.Add("value_type", $valueTypeIndex)
        }
        if ($allowTraps) {
            $payload.params.Add("allow_traps", 1)
        }
        if ($AuthType) {
            if ($AuthType -in "Password","PublicKey") {
                If ($AuthType -eq "Password") {
                    $authIndex = 0
                } else {
                    $authIndex = 1
                }
                $payload.params.Add("authtype", $authIndex)
            } else {
                $authIndex = @('none','Basic','NTLM','Kerberos').IndexOf($AuthType)
                $payload.params.Add("authtype", $authIndex)
            }
        }
        if ($Description) {$payload.params.Add("description", $Description)}
        if ($followRedirects) {$payload.params.Add("follow_redirects", 1)}
        if ($httpHeaders) {$payload.params.Add("headers", $httpHeaders)}
        if ($inventoryLink) {$payload.params.Add("inventory_link", $inventoryLink)}
        if ($ipmiSensor) {$payload.params.Add("ipmi_sensor", $ipmiSensor)}
        if ($JMXEndpoint) {$payload.params.Add("jmx_endpoint",$JMXEndpoint)}
        if ($additionalParams) {$payload.params.Add("params", $additionalParams)}
        if ($scriptParams) {$payload.params.Add("parameters", $scriptParams)}
        if ($postType) {
            $postTypeIndex = @('Raw','JSON','XML').IndexOf($postType)
            $payload.params.Add("post_type", $postTypeIndex)
        }
        if ($posts) {$payload.params.Add("posts", ($posts | ConvertTo-Json -Depth 10 -Compress))}
        if ($queryFields) {$payload.params.Add("query_fields", $queryFields)}
        if ($requestMethod) {
            $requestMethidIndex = @('GET','POST','PUT','HEAD').IndexOf($requestMethod)
            $payload.params.Add("request_method", $requestMethidIndex)
        }
        if ($retrieveMode) {
            $retrieveModeIndex = @('Body','Headers','Both').IndexOf($retrieveMode)
            $payload.params.Add("retrieve_mode",$retrieveModeIndex)
        }
    }   

    payload.Add("auth", $authcode)

    $body = $payload | ConvertTo-Json -Depth 10 -Compress
    try {
        $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
        if ($response.error) {
            throw $response.error.data
        } else {
            return $response.result
        }           
    } catch {
        throw $_
    }
    <#
    .SYNOPSIS
    Set-Item configuration
    .DESCRIPTION
    The itemid property must be defined for each item, all other properties are optional. 
    Only the passed properties will be updated, all others will remain unchanged.
    .PARAMETER itemid
    Id of the item to be updated.
    .PARAMETER item
    An item object containing the properties to update. It mist include item Id.
    Cannot be combined with other properties.
    .PARAMETER name
    The Item Name.
    .PARAMETER delay
    Update interval of the item. Accepts seconds or a time unit with suffix (30s,1m,2h,1d).
    Optionally one or more custom intervals can be specified either as flexible intervals or scheduling.
    Multiple intervals are separated by a semicolon.
    User macros may be used. A single macro has to fill the whole field. Multiple macros in a field or macros mixed with text are not supported.
    Flexible intervals may be written as two macros separated by a forward slash (e.g. {$FLEX_INTERVAL}/{$FLEX_PERIOD}).

    Optional for Zabbix trapper, dependent items and for Zabbix agent (active) with mqtt.get key.
    .PARAMETER Disabled
    Disable this item.
    .PARAMETER key
    Item Key.
    .PARAMETER type
    Item type. Values can be 'ZabbixAgent','ZabbixTrapper','SimpleCheck','ZabbixInternal','WebItem','ExternalCheck','DatabaseMonitor','IPMIAgent','SSHAgent','TelnetAgent', `
    'Calculation','JMXAgent','SNMPTrap','DependentItem','HTTPAgent','SNMPAgent','Script'
    .PARAMETER Url
    URL string, required only for HTTP agent item type. Supports user macros, {HOST.IP}, {HOST.CONN}, {HOST.DNS}, {HOST.HOST}, {HOST.NAME}, {ITEM.ID}, {ITEM.KEY}
    .PARAMETER valueType
    Type fo information for the item. Values can be: 'NumericFloat','Character','Log','NumericUnsigned','Text'
    .PARAMETER allowTraps
    HTTP agent item field. Allow to populate value as in trapper item type also.
    .PARAMETER AuthType
    Used only by SSH agent items or HTTP agent items.

    SSH agent authentication method possible values:
    0 - (default) password;
    1 - public key.

    HTTP agent authentication method possible values:
    0 - (default) none
    1 - basic
    2 - NTLM
    3 - Kerberos
    .PARAMETER Description
    Description of item
    .PARAMETER followRedirects
    HTTP agent item field. Follow response redirects while pooling data.

    0 - Do not follow redirects.
    1 - (default) Follow redirects.
    .PARAMETER httpHeaders
    HTTP agent item field. Object with HTTP(S) request headers, where header name is used as key and header value as value.
    .PARAMETER History
    A time unit of how long the history data should be stored. Also accepts user macro.
    .PARAMETER httpProxyString
    HTTP agent item field. HTTP(S) proxy connection string.
    .PARAMETER inventoryLink
    ID of the host inventory field that is populated by the item.
    .PARAMETER ipmiSensor
    IPMI sensor. Used only by IPMI items.
    .PARAMETER JMXEndpoint
    MX agent custom connection string.

    Default value:
    service:jmx:rmi:///jndi/rmi://{HOST.CONN}:{HOST.PORT}/jmxrmi
    .PARAMETER MasterItemId
    Master item ID.
    Recursion up to 3 dependent items and maximum count of dependent items equal to 29999 are allowed.
    .PARAMETER additionalParams
    Additional parameters depending on the type of the item:
    - executed script for SSH and Telnet items;
    - SQL query for database monitor items;
    - formula for calculated items;
    - the script for script item.
    .PARAMETER scriptParams
    Additional parameters for script items. Array of objects with 'name' and 'value' properties, where name must be unique.
    .PARAMETER postType
    HTTP agent item field. Type of post data body stored in posts property.

    0 - (default) Raw data.
    2 - JSON data.
    3 - XML data.
    .PARAMETER posts
    HTTP agent item field. HTTP(S) request body data. Used with post_type.
    .PARAMETER privateKey
    Name of the private key file.
    .PARAMETER publicKey
    Name of the public key file.
    .PARAMETER queryFields
    HTTP agent item field. Query parameters. Array of objects with 'key':'value' pairs, where value can be empty string.
    .PARAMETER requestMethod
   	HTTP agent item field. Type of request method.

    0 - (default) GET
    1 - POST
    2 - PUT
    3 - HEAD
    .PARAMETER retrieveMode
    HTTP agent item field. What part of response should be stored.

    0 - (default) Body.
    1 - Headers.
    2 - Both body and headers will be stored.

    For request_method HEAD only 1 is allowed value.
    .PARAMETER snmpOID
    SNMP OID
    .PARAMETER sslCertFile
    HTTP agent item field. Public SSL Key file path.
    .PARAMETER sslKeyFile
    HTTP agent item field. Private SSL Key file path.
    .PARAMETER sslKeyPassword
    HTTP agent item field. Password for SSL Key file.
    .PARAMETER httpStatusCodes
    Status of the item.

    Possible values:
    0 - (default) enabled item;
    1 - disabled item.
    .PARAMETER Timeout
    Item data polling request timeout. Used for HTTP agent and script items. Supports user macros.

    default: 3s
    maximum value: 60s
    .PARAMETER trapperHost
    Allowed hosts. Used by trapper items or HTTP agent items.
    .PARAMETER Trends
    A time unit of how long the trends data should be stored. Also accepts user macro.
    .PARAMETER Units
    Value units
    .PARAMETER valueMapId
    ID of the associated value map.
    .PARAMETER verifyHost
    HTTP agent item field. Validate host name in URL is in Common Name field or a Subject Alternate Name field of host certificate.
    .PARAMETER verifyPeer
    HTTP agent item field. Validate is host certificate authentic.
    .PARAMETER NoProgress
    Do not show progress.
    .PARAMETER authcode
    Authorization code to use for the API call. If omitted read the authcode from the local configuration file.
    .OUTPUTS
    An object contioning the item Id(s) of updated item(s).
    #>
}

