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
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
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
        [Parameter(ParameterSetName = 'props')]        
        [switch]$Disabled,
        [Parameter(ParameterSetName = 'props')]
        [string]$key,
        [Parameter(ParameterSetName = 'props')]
        [switch]$NoProgress,
        [string]$autocode
    )

    Begin {
        if (-not $autocode) {
            $authcode = Read-ZabbixConfig
        }


    }

    Process {
        if (-not $NoProgress.IsPresent) {
            $percentComplete = 100
            Write-Progress -Activity "Updating Item:" -Status $ItemId -PercentComplete $percentComplete
        }
        $payload = Get-Payload
        $payload.method = 'item.update'
        $payload.params.Add("itemid", $itemId)
        $properties = $PSItem.psObject.Properties | Select-Object Name, value
        $properties.Where({$_.name -ne "itemid"}) | ForEach-Object {
            $payload.params.Add($_.name, $_.value)
        }

        $payload.Add("auth", $authcode)

        $body = $payload | ConvertTo-Json -Depth 10 -Compress
        try {
            $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            if ($response.error) {
                throw $response.error.data
            }            
        } catch {
            throw $_
        }
    }
    <#
    #>
}