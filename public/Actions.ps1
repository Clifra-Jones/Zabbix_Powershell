function Get-ZabbixAction() {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]$Actionid,
        [switch]$IncludeFilter,
        [switch]$IncludeOperations,
        [switch]$IncludeRecoveryOperations,
        [switch]$IncludeAcknowledgeOperations,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    $Parameters = @{
        method = "action.get"
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

    if ($Actionid) {
        $params.Add("ActionIds", $Actionid)
    }

    if ($IncludeFilter) {
        $params.Add("selectFilter", "extend")
    }

    if ($IncludeOperations) {
        $params.Add("selectOperations", "extend")
    }

    if ($IncludeRecoveryOperations) {
        $params.Add("selectRecoveryOperations", "extend")
    }

    if ($IncludeAcknowledgeOperations) {
        $params.Add("selectAcknowledgeOperations", "extend")
    }

    $Parameters.Add("params", $params)

    try {
        $response = Invoke-ZabbixAPI @Parameters

        if ($response.error) {
            throw $response.error.data
        }
        return $response.result
    } catch {
        throw
    }
}

function Add-ZabbixAction() {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$Name,
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [Alias("ExcelationPeriod")]
        [string]$Esc_Period,
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [string]$EventSource,
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$Disabled,
        [Parameter(ValueFromRemainingArguments)]
        [Alias('PauseEscalation')]
        [Switch]$Pause_Suppressed,
        [Parameter(ValueFromPipelineByPropertyName)]
        [psObject]$Filter,
        [psObject[]]$Operations,
        [psobject[]]$Recovery_Operations,
        [psobject[]]$Acknowledge_Operation,
        [string]$ProfileName,
        [string]$AuthCode,
        [string]$Uri
    )

    Begin {
        $Parameters = @{
            method = 'action.create'
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
    }

    Process {
        if ($Name) {
            $params.Add("name", $Name)
        }

        $params = @{}

        if ($Esc_Period) {
            $params.Add("esc_period", $Esc_Period)        
        }

        if ($EventSource) {
            $params.Add("event_source", $EventSource)
        }

        if ($Status.IsPresent) {
            $params.Add("status", 1)
        }

        if ($Pause_Suppressed) {
            $params.Add("pause_suppressed", $Pause_Suppressed)
        }

        if ($Filter) {
            $params.Add("filter", $Filter)
        }

        if ($Operations) {
            $params.Add("operations", $Operations)
        }

        if ($Recovery_Operations) {
            $params.Add("recovery_operations", $Recovery_Operations)
        }

        if ($Acknowledge_Operation) {
            $params.Add("acknowledge_operations", $Acknowledge_Operation)
        }

        $Parameters.Add("params", $params)

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

function Remove-ZabbixAction() {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory)]
        [string]$Actionid,
        [string]$ProfileName,
        [stirng]$AuthCode,
        [string]$Uri
    )

    $Parameters = @{
        method = 'action.delete'
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

    $params = @(
        $ActionId
    )

    $Parameters.Add("params", $params)

    $Action = Get-ZabbixAction -Actionid $Actionid

    if ($PSCmdlet.ShouldProcess("Delete", "Action: $($Action.Name)") ) {
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