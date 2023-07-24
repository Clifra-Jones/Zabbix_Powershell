function Get-ZabbixTrends() {
    [CmdletBinding()]
    Param(
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$itemId,
        [datetime]$StartDate,
        [datetime]$EndDate,
        [int]$limit,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    Begin {
        # if (-not $authcode) {
        #     $authcode = Read-ZabbixConfig
        # }
        
        # $payload = Get-Payload
        # $payload.method = 'trend.get'
        $Parameters = @{
            method = 'trend.get'
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
        $params.Add("itemids", @($itemId))

        #$payload.Add("auth", $authcode)

        #$body = $payload | ConvertTo-Json -Depth 10 -Compress

        $Parameters.Add("params", $params)

        try {
            #$response = Invoke-WebRequest -Method POST -Uri $Uri -ContentType $contentType -Body $body
            $response = Invoke-ZabbixAPI @Parameters

            if ($response.error) {
                throw $response.error.data
            }
            return $response.content
        } catch {
            throw $_
        }
    }
    <#
    .SYNOPSIS
    Return items trend data.
    .PARAMETER itemId
    Return only trends with the given item IDs.
    .PARAMETER StartDate
    Return only values that have been collected after or at the given date/time.
    .PARAMETER EndDate
    Return only values that have been collected before or at the given date/time.
    .PARAMETER limit
    Limit the amount of retrieved objects.
    .PARAMETER ProfileName
    The named profile to use.
    .OUTPUTS
    An array of trend objects.
    #>
}