function Get-ZabbixTemplate() {
    [CmdletBinding()]
    Param(
        [string]$TemplateId,
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$HostId,
        [Parameter(
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$GroupId,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    Begin {
        # if (-not $authcode) {
        #     $authcode = Read-ZabbixConfig
        # }
        # $payload = Get-Payload
        # $payload.method = "template.get"

        $Parameters = @{
            method = 'template.get'
        }
        #$payload.Add("auth", $authcode)

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
        if ($TemplateId) {
            $params.add("templateIds", $TemplateId)
        }

        if ($hostId) {
            $params.Add("hostids", $HostId)
        }

        if ($groupid) {
            $params.Add("groupids", $GroupId)     
        }

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
}

function Add-ZabbixTemplate() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$VisibleName,
        [string]$Description,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    $Parameters = @{
        method = "template.create"
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

    $params = @{
        host = $Name
    }

    if ($VisibleName) {
        $params.Add("name", $VisibleName)
    }

    if ($Description) {
        $params.Add("description", $Description)
    }

    $Parameters.Add("params", $params)

    try {
        $response = Invoke-ZabbixAPI @Parameters

        if ($response.error) {
            throw $response.error.data
        }
        return $response.result
    } catch {
        $_
    }
}

function Update-ZabbixTemplate() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateId,
        [string]$Name,
        [string]$VisibleName,
        [string]$Description,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    $Parameters = @{
        method = "template.update"
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

    if ($name) {
        $params.Add("host", $name)
    }

    if ($VisibleName) {
        $params.Add("name", $VisibleName)
    }

    if ($Description) {
        $params.Add("description", $Description)
    }

    $Parameters.Add("params", $params)

    try {
        $response = Invoke-ZabbixAPI @Parameters

        if ($response.error) {
            throw $response.error.data
        }

        return $response
    } catch {
        throw $_
    }    
}

function Remove-ZabbixTemplate() {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateId,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    $Parameters = @{
        method = "template.delete"
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

    $Params = @(
        $TemplateId
    )

    $Parameters.Add("params", $params)

    $template = Get-ZabbixTemplate -TemplateId $TemplateId

    if ($PSCmdlet.ShouldProcess("Delete", "Template: $($Template.host) ($($template.Name))")) {
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
}