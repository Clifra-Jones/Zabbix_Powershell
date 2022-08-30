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
        [string]$authcode
    )

    Begin {
        if (-not $authcode) {
            $authcode = Read-ZabbixConfig
        }
        
        $payload = Get-Payload
        $payload.method = 'trend.get'
        if ($startTime) {
            $nixStartTime = ([System.DateTimeOffset]$startTime).ToUnixTimeSeconds()
            $payload.params.Add("time_from", $nixStartTime)
        }
        if ($endTime) {
            $nixEndTime = ([System.DateTimeOffset]$endTime).ToUnixTimeSeconds()
            $payload.params.Add("time_till", $nixEndTime)
        }
    }

    Process {
        $payload.params.Add("itemids", @($itemId))

        $payload.Add("auth", $authcode)

        $body = $payload | ConvertTo-Json -Depth 10 -Compress

        try {
            $response = Invoke-WebRequest -Method POST -Uri $Uri -ContentType $contentType -Body $body
            if ($response.error) {
                throw $response.error.data
            }
            return $response.content
        } catch {
            throw $_
        }
    }
}