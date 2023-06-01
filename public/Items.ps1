function Get-ZabbixItems() {
    [CmdletBinding()]
    Param(
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
        [string]$ProfileName
    )


    # if (-not $authCode) {
    #     $authCode = Read-ZabbixConfig
    # }

    $Parameters = @{
        method = 'item.get'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    }                

    # $payload = Get-Payload
    # $payload.method = 'item.get'

    $params = @{}

    if ($itemId) {
        $params.Add("itemids", $itemid)
    }
    if ($groupid) {
        $params.Add("groupids", $groupid)
    }
    if ($templateId) {
        $params.Add("templateids", $templateId)
    }
    if ($includeHosts) {
        $params.Add("selectHosts", "extend")
    }
    if ($filter) {
        $params.Add("filter", $filter)
    }
    if ($search) {
        $params.Add("search", $search)
    }
    if ($searchByAny.IsPresent) {
        $params.Add("searchByAny", $searchByAny.IsPresent)
    }
    if ($searchWildcardsEnabled.IsPresent) {
        $params.Add("searchWildcardsEnabled", $searchWildcardsEnabled.IsPresent)
    }
    if ($searchFromStart) {
        $params.Add("startSearch", $searchFromStart.IsPresent)
    
    }
    if ($hostId) {$params.Add("hostids", $hostId)}


    if ($params.count -eq 0) {
        $params.Add("limit", 50)
    }        
    
    #$payload.Add("auth", $authCode)

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Depth 10 -Compress

    try {
        #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
        $response = Invoke-ZabbixAPI @Parameters

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
    .PARAMETER ProfileName
    Name of the samed profile to use.
    #>
}

function Set-ZabbixItem() {
    [CmdletBinding()]
    Param(
        [psobject]$ItemId,
        [string]$Name,
        [string]$Delay,
        [switch]$Disabled,
        [string]$Key,
        [ValidateScript({$_ -is [ItemType]})] 
        [ItemType]$Type,
        [ValidateScript({ $_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter URL only valid when parameter Type -s HTTPAgent")]
        [string]$Url,
        [ValidateScript({$_ -is [ValueTYpe]})]
        [ItemValueType]$ValueType,
        [ValidateScript(
            {$_.IsPresent -and $type -eq [ItemType]::HTTPAgent}, ErrprMessage = "Parameter allowTraps only valid for HTTPAgent Item index.")]
        [switch]$allowTraps,
        [ValidateSet('none','Basic','NTLM','Kerberos','Password','PublicKey')]
        [ValidateScript(
            {$type -eq [ItemType]::SSHAgent  -and ($_ -eq [ItemAuthType]::Password -or $_ -eq [ItemAuthType]::PublicKey)}, 
                ErrorMessage = "Parameter AuthType is only valid for SSHAGent and HTTPAgent Item types.")]
        [ItemAuthType]$AuthType,
        [string]$Description,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter followRedirects is only valid for HTTPAgent Item type.")]
        [switch]$followRedirects,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter httpHeaders is only valid for HTTPAgent Item type.")]
        [psobject]$httpHeaders,
        [string]$History,
        [string]$httpProxyString,
        [int]$inventoryLink,
        [ValidateScript({$_ -and $type -eq [ItemType]::IPMIAgent}, ErrorMessage = "Parameter ipmiSensor is only valid for IPMIAgent Item type.")]
        [string]$ipmiSensor,
        [ValidateScript({$_ -and $type -eq [ItemType]::JMXAgent}, ErrorMessage = "Parameter JMXEndpoint is only valid for JMXAgent Item type.")]
        [string]$JMXEndpoint,
        [int]$MasterItemId,
        [ValidateScript({$_ -and $type -in [ItemType]::SSHAgent,[ItemType]::TelnetAgent,[ItemType]::DatabaseMonitor, [ItemType]::Script}, 
            ErrorMessage = "Parameter AdditionalParams only valid for SSHAgent, TelnetAgent, DatabaseMonitor and Script Item types.")]
        [psObject]$AdditionalParams,
        [ValidateScript({$_ -and $type -eq [ItemType]::Script}, ErrorMessage = "Parameter ScriptParams is only valid got Script Item type.")]
        [psobject]$scriptParams,
        [ValidateSet('Raw','JSON','XML')]
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter postType is only valid for HTTPAgent Item type.")]
        [ItemPostType]$PostType,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter posts is only valid for HTTPAgent Item type.")]
        [psobject]$Posts,
        [string]$privateKey,
        [string]$publicKey,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter QueryFields is only valid for HTTPAgent Item type.")]
        [psobject]$QueryFields,        
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter RequestMethod is only valid for HTTPAgent Item type.")]
        [RequestMethod]$requestMethod,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [ValidateScript({$_ -eq [RetrieveMode]::Header -and $RequestMethod -eq [RequestMethod]::Head}, 
            ErrorMessage = "If Parameter RetrieveMOde is set to Headers, Parameter RequestMethid must be set to Head" )]
        [string]$retrieveMode,
        [ValidateScript({$_ -and $type -eq [ItemType]::SNMPAgent}, ErrorMessage = "Parameter snmpOID os only valid for SNMPAgent item type")]
        [string]$snmpOID,
        [ValidateScript({$_ -and $type -ne [ItemType]::HTTPAgent}, ErrorMessage = "Parameter SslCertFile is only valid for HTTPAgent item type.")]
        [string]$SslCertFile,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter SslKeyFile is only valid for HTTPAgent item type.")]
        [string]$SslKeyFile,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter SslKeyPassword is only valid for HTTPAgent item type.")]
        [securestring]$SslKeyPassword,
        [string[]]$StatusCodes,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [string]$Timeout,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [string]$trapperHost,
        [string]$Trends,
        [string]$Units,
        [string]$valueMapId,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [switch]$verifyHost,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [switch]$verifyPeer,
        [switch]$NoProgress,
        [string]$ProfileName
    )


    # if (-not $autocode) {
    #     $authcode = Read-ZabbixConfig
    # }

    # $payload = Get-Payload
    # $payload.method = 'item.update'

    $Parameters = @{
        method = 'item.update'
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    }

    $params = @{}

    $params.Add("itemid", $itemId)
    if ($name) {
        $params.Add("name", $name)
    }
    if ($delay) {
        params.Add("delay", $delay)
    }
    if($Disabled.IsPresent) {
        $params.Add("status", 1)
    }
    if ($key) {
        $params.Add("key_", $key)
    }
    if ($type) {            
        #$typeIndex = $types.IndexOf($type)
        $params.Add("type", $type.Value__)
    }
    if ($Url) {
        $params.Add("url", $url)
    }
    if ($ValueType) {
        $params.Add("value_type", $ValueType.Value__)
    }
    if ($allowTraps) {
        $params.Add("allow_traps", 1)
    }
    if ($AuthType) {
            $params.Add("authtype", $AuthType.Value__)
    }
    if ($Description) {
        $params.Add("description", $Description)
    }
    if ($followRedirects) {
        $params.Add("follow_redirects", 1)
    }
    if ($httpHeaders) {
        $params.Add("headers", $httpHeaders)
    }
    if ($inventoryLink) {
        $params.Add("inventory_link", $inventoryLink)
    }
    if ($ipmiSensor) {
        $params.Add("ipmi_sensor", $ipmiSensor)
    }
    if ($JMXEndpoint) {
        $params.Add("jmx_endpoint",$JMXEndpoint)
    }
    if ($additionalParams) {
        $params.Add("params", $additionalParams)
    }
    if ($scriptParams) {
        $params.Add("parameters", $scriptParams)
    }
    if ($postType) {
        $params.Add("post_type", $PostType.Value__)
    }
    if ($posts) {
        $params.Add("posts", ($posts | ConvertTo-Json -Depth 10 -Compress))
    }
    if ($queryFields) {
        $params.Add("query_fields", $queryFields)
    }
    if ($requestMethod) {
        $params.Add("request_method", $requestMethod.value__)
    }
    if ($retrieveMode) {
        $params.Add("retrieve_mode",$retrieveMode.Value__)
    }

    #payload.Add("auth", $authcode)

    $Parameters.Add("params", $params)

    #$body = $payload | ConvertTo-Json -Depth 10 -Compress

    try {
        #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
        $response = Invoke-ZabbixAPI @Parameters

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
    .PARAMETER ProfileName
    The name of the saved profile to use.
    .OUTPUTS
    An object contioning the item Id(s) of updated item(s).
    #>
}

function Add-ZabbixItem() {
    [CmdletBinding()]
    Param(
        [psobject]$ItemId,
        [string]$Name,
        [string]$Delay,
        [switch]$Disabled,
        [string]$Key,
        [ValidateScript({$_ -is [ItemType]})] 
        [ItemType]$Type,
        [ValidateScript({ $_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter URL only valid when parameter Type -s HTTPAgent")]
        [string]$Url,
        [ValidateScript({$_ -is [ValueTYpe]})]
        [ItemValueType]$ValueType,
        [ValidateScript(
            {$_.IsPresent -and $type -eq [ItemType]::HTTPAgent}, ErrprMessage = "Parameter allowTraps only valid for HTTPAgent Item index.")]
        [switch]$allowTraps,
        [ValidateSet('none','Basic','NTLM','Kerberos','Password','PublicKey')]
        [ValidateScript(
            {$type -eq [ItemType]::SSHAgent  -and ($_ -eq [ItemAuthType]::Password -or $_ -eq [ItemAuthType]::PublicKey)}, 
                ErrorMessage = "Parameter AuthType is only valid for SSHAGent and HTTPAgent Item types.")]
        [ItemAuthType]$AuthType,
        [string]$Description,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter followRedirects is only valid for HTTPAgent Item type.")]
        [switch]$followRedirects,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter httpHeaders is only valid for HTTPAgent Item type.")]
        [psobject]$httpHeaders,
        [string]$History,
        [string]$httpProxyString,
        [int]$inventoryLink,
        [ValidateScript({$_ -and $type -eq [ItemType]::IPMIAgent}, ErrorMessage = "Parameter ipmiSensor is only valid for IPMIAgent Item type.")]
        [string]$ipmiSensor,
        [ValidateScript({$_ -and $type -eq [ItemType]::JMXAgent}, ErrorMessage = "Parameter JMXEndpoint is only valid for JMXAgent Item type.")]
        [string]$JMXEndpoint,
        [int]$MasterItemId,
        [ValidateScript({$_ -and $type -in [ItemType]::SSHAgent,[ItemType]::TelnetAgent,[ItemType]::DatabaseMonitor, [ItemType]::Script}, 
            ErrorMessage = "Parameter AdditionalParams only valid for SSHAgent, TelnetAgent, DatabaseMonitor and Script Item types.")]
        [psObject]$AdditionalParams,
        [ValidateScript({$_ -and $type -eq [ItemType]::Script}, ErrorMessage = "Parameter ScriptParams is only valid got Script Item type.")]
        [psobject]$scriptParams,
        [ValidateSet('Raw','JSON','XML')]
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter postType is only valid for HTTPAgent Item type.")]
        [ItemPostType]$PostType,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter posts is only valid for HTTPAgent Item type.")]
        [psobject]$Posts,
        [string]$privateKey,
        [string]$publicKey,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter QueryFields is only valid for HTTPAgent Item type.")]
        [psobject]$QueryFields,        
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter RequestMethod is only valid for HTTPAgent Item type.")]
        [RequestMethod]$requestMethod,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [ValidateScript({$_ -eq [RetrieveMode]::Header -and $RequestMethod -eq [RequestMethod]::Head}, 
            ErrorMessage = "If Parameter RetrieveMOde is set to Headers, Parameter RequestMethid must be set to Head" )]
        [string]$retrieveMode,
        [ValidateScript({$_ -and $type -eq [ItemType]::SNMPAgent}, ErrorMessage = "Parameter snmpOID os only valid for SNMPAgent item type")]
        [string]$snmpOID,
        [ValidateScript({$_ -and $type -ne [ItemType]::HTTPAgent}, ErrorMessage = "Parameter SslCertFile is only valid for HTTPAgent item type.")]
        [string]$SslCertFile,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter SslKeyFile is only valid for HTTPAgent item type.")]
        [string]$SslKeyFile,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter SslKeyPassword is only valid for HTTPAgent item type.")]
        [securestring]$SslKeyPassword,
        [string[]]$StatusCodes,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [string]$Timeout,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [string]$trapperHost,
        [string]$Trends,
        [string]$Units,
        [string]$valueMapId,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, ErrorMessage = "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [switch]$verifyHost,
        [ValidateScript({$_ -and $type -eq [ItemType]::HTTPAgent}, "Parameter retrieveMode is only valid for HTTPAgent item type.")]
        [switch]$verifyPeer,
        [switch]$NoProgress,
        [string]$ProfileName
    )

    $Parameters = @{
        method = 'item.update'        
    }

    if ($ProfileName) {
        $Parameters.Add("ProfikeName", $ProfileName)
    }
    
    $params = @{}

    if ($name) {$params.Add("name", $name)}
    if ($delay) {params.Add("delay", $delay)}
    if($Disabled.IsPresent) {$params.Add("status", 1)}
    if ($key) {$params.Add("key_", $key)}
    if ($type) {            
        $params.Add("type", $type.value__)
    }
    if ($Url) {
        $params.Add("url", $url)
    }
    if ($valueType) {
        $params.Add("value_type", $valueType.Value__)
    }
    if ($allowTraps) {
        $params.Add("allow_traps", 1)
    }
    if ($AuthType) {
            $params.Add("authtype", $authType.Value__)
    }
    if ($Description) {$params.Add("description", $Description)}
    if ($followRedirects) {$params.Add("follow_redirects", 1)}
    if ($httpHeaders) {$params.Add("headers", $httpHeaders)}
    if ($inventoryLink) {$params.Add("inventory_link", $inventoryLink)}
    if ($ipmiSensor) {$params.Add("ipmi_sensor", $ipmiSensor)}
    if ($JMXEndpoint) {$params.Add("jmx_endpoint",$JMXEndpoint)}
    if ($additionalParams) {$params.Add("params", $additionalParams)}
    if ($scriptParams) {$params.Add("parameters", $scriptParams)}
    if ($postType) {
        $params.Add("post_type", $postType.Value)
    }
    if ($posts) {$params.Add("posts", ($posts | ConvertTo-Json -Depth 10 -Compress))}
    if ($queryFields) {$params.Add("query_fields", $queryFields)}
    if ($requestMethod) {
        $params.Add("request_method", $requestMethod.Value__)
    }
    if ($retrieveMode) {
        $params.Add("retrieve_mode",$retrieveMode.Value)
    }

    $Parameters.add("params", $params)

    try {
        $response = Invoke-ZabbixAPI $Parameters
        
        if ($response.error) {
            throw $response.error.data
        }
        return $response.result
    } catch {
        throw $_
    }
    <#
    .SYNOPSIS 
    Add an Item to a host or template.
    .DESCRIPTION
    Add an Zabbix Item to a Zabbix host or template.
    .PARAMETER HostId
    Id of the host or template to add the item to.
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
    .PARAMETER ProfileName
    The name of the saved profile to use.
    .OUTPUTS
    An object contioning the item Id(s) of updated item(s).
    #>
}

function Remove-ZabbixItem() {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$ItemId,
        [string]$ProfileName
    )

    $Parameters = @{
        method = "item.delete"
    }

    if ($ProfileName) {
        $Parameters.Add("ProfileName", $ProfileName)
    }

    $params = @{
        itemids = $ItemId
    }

    $Parameters.Add("params", $params)

    $item = Get-ZabbixItems -itemId $ItemId

    if ($PSCmdlet.ShouldProcess("Delete", "Item: $($Item.name)($($Item.itemid))") ) {
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
    Remove an Item.
    .DESCRIPTION
    Remove a Zabbix Item.
    .PARAMETER ItemId
    Id of the Item to remove.
    .PARAMETER ProfileName
    Name of the save profile to use.
    .OUTPUTS
    An object contioning the item Id(s) of updated item(s).
    #>
}