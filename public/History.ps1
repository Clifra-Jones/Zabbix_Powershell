function Get-ZabbixHistory() {
    [CmdletBinding()]
    Param(
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$hostId,
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$itemid,
        [datetime]$startTime,
        [datetime]$endTime,
        [ValidateSet('float','character','log','numeric','text')]
        [string]$historyType,
        [int]$limit,
        [string]$ProfileName
    )

    Begin {
        # if (-not $authCode) {
        #     $authCode = Read-ZabbixConfig
        # }

        # $payload = Get-Payload
        # $payload.method = "history.get"
        $Parameters = @{
            method = 'history.get'
        }

        if ($ProfileName) {
            $Parameters.Add("ProfileName", $ProfileName)
        }

        $params = @{}

        if ($historyType) {
            switch ($historyType) {
                'float' {
                    $params.Add("history", 0)
                }
                'character' {
                    $params.Add("history", 1)
                }
                'log' {
                    $params.Add("history", 2)
                }
                'numeric' {
                    $params.Add("history", 3)
                }
                'text' {
                    $params.Add("history", 4)
                }
            }
        }

        $params.Add("sortfield", "clock")
        $params.Add("sortorder", "DESC")
        if ($limit) {$params.Add("limit", $limit)}
        
        if ($startTime) {
            $nixStartTime = ([System.DateTimeOffset]$startTime).ToUnixTimeSeconds()
            $params.Add("time_from", $nixStartTime)
        }
        if ($endTime) {
            $nixEndTime = ([System.DateTimeOffset]$endTime).ToUnixTimeSeconds()
            $params.Add("time_till", $nixEndTime)
        }
    }

    Process {
        if ($hostId) {$params.add("hostids", $hostId)}
        if ($itemid) {$params.Add("itemids", $itemid)}

        #$payload.Add("auth", $authCode)

        #$body = $payload | ConvertTo-Json -Compress
        $Parameters.Add("params", $params)

        try {
            #$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            $response = Invoke-ZabbixAPI @Parameters

            if ($response.error) {
                throw $response.error.data
            }
            foreach ($result in $response.result) {
                $item = Get-ZabbixItems -itemId $itemid | Select-Object itemId, units
                [datetime]$_clock = ([System.DateTimeOffset]::FromUnixTimeSeconds($result.clock).DateTime).ToLocalTime()
                $result | Add-Member -NotePropertyName "receiveDate" -NotePropertyValue $_clock
                switch ($item.units) {
                    'B' {
                        # Bytes
                        # display the value in KBs
                        if ($result.value -lt 1Kb) {
                            $_value = "{0} Bytes" -f $result.value
                        } elseif ($result.value -lt 1Mb) {
                            $_value = "{0} KB" -f ($result.value / 1Kb)
                        } elseif ($result.value -lt 1GB) {
                            $_value = "{0} MB" -f ($result.value / 1MB)
                        } else {
                            $_value = "{0} GB" -f ($result.value / 1GB)
                        }                
                    }
                    'Bps' {
                                # Bytes
                        # display the value in KBs
                        if ($result.value -lt 1Kb) {
                            $_value = "{0} Bps" -f $result.value
                        } elseif ($result.value -lt 1Mb) {
                            $_value = "{0} KBps" -f ($result.value / 1Kb)
                        } elseif ($result.value -lt 1GB) {
                            $_value = "{0} MBps" -f ($result.value / 1MB)
                        } else {
                            $_value = "{0} GBps" -f ($result.value / 1GB)
                        }     
                    }
                    'unixtime' {
                        $_value = [System.DateTimeOffset]::FromUnixTimeSeconds($result.value).DateTime.ToString("yyyy/MM/dd HH:mm:ss")
                    }
                    'uptime' {
                        $_value = [TimeSpan]::FromSeconds($result.value).ToString()
                    }
                    's' {
                        $_value = [timespan]::FromSeconds($result.value).ToString()
                    }            
                }
                $result | Add-Member -MemberType NoteProperty -Name "receivedValue" -Value $_value
            }
            return $response.result
        } catch {
            throw $_
        }
    }
    <#
    .SYNOPSIS
    Returns history for Zabbix items.
    .DESCRIPTION
    Returns the history for zabbix items.
    .PARAMETER hostId
    Returns the history for a specific host (this can be quite large). If itemId is supplied resticts hostory to that item.
    .PARAMETER itemid
    returns the history for a specific item.
    .PARAMETER startTime
    Returns only history after this date.
    .PARAMETER endTime
    REturns only history before this date.
    .PARAMETER historyType
    Return only history of this type.
    .PARAMETER limit
    limit the number of returned records.
    .PARAMETER authCode
    Authorization code to use for the API call. If omitted read the authcode from the local configuration file.
    #>
}