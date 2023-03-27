function Get-ZabbixTemplates() {
    [CmdletBinding()]
    Param(
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$hostid,
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$groupid,
        [string]$authcode
    )

    Begin {
        if (-not $authcode) {
            $authcode = Read-ZabbixConfig
        }
        $payload = Get-Payload
        $payload.method = "template.get"
        $payload.params.Add("output", "extend")
        $payload.Add("auth", $authcode)
        $hostIds = @()
        $groupIds = @()
    }

    Process {        
        if ($hostId) { $hostIds += $hostid }
        if ($groupid) { $groupIds += $groupid }
    }

    End {
        if ($hostIds.Length -gt 0) {
            $payload.params.Add("hostids",$hostIds)
        }
        If ($groupIds.Length -gt 0) {
            $payload.params.Add("groupids", $groupIds)
        }

        $body = $payload | ConvertTo-Json -Compress -Depth 5

        try {
            $response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType $contentType -Body $body
            if ($response.error) {
                throw $response.error.data
            }
            return $response.result
        } catch {
            throw $_
        }
    }
}