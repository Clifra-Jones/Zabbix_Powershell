function Get-ZabbixAction() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]$ActionId,
        [switch]$IncludeFilter,
        [switch]$IncludeOperations,
        [switch]$IncludeRecoveryOperations,
        [switch]$IncludeAcknowledgeOperations,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
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

    if ($ActionId) {
        $params.Add("ActionIds", $ActionId)
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
    <#
    .SYNOPSIS 
    Retrieve Action(s).
    .DESCRIPTION
    Retrieve the Action(s) from the Zabbix server configuration.
    .PARAMETER ActionId
    The Id of the action to retrieve. If omitted all Actions are retrieved
    .PARAMETER IncludeFilter
    Include Filters in the output.
    .PARAMETER IncludeOperations
    Include Operations in the output.
    .PARAMETER IncludeRecoveryOperations
    Include Recovery Operations in the output.
    .PARAMETER IncludeAcknowledgeOperations
    Include Acknowledge Operations in the output.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)

    #>
}

function Add-ZabbixAction() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
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
        [Alias("EscalationPeriod")]
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
        [psobject[]]$Update_Operation,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
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
            $params.Add("update_operations", $Update_Operation)
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

    <#
    .SYNOPSIS
    Add a Zabbix Action
    .DESCRIPTION
    Add an Action to the Zabbix configuration.
    .PARAMETER Name
    The Name of the Action.
    .PARAMETER Esc_Period
    The escalation period.
    .PARAMETER EventSource
    The Event Source.
    .PARAMETER Disabled
    Create the Action as disabled.
    .PARAMETER Pause_Suppressed
    Set escalation to paused.
    .PARAMETER Filter
    A Filter object for this Action.
    .PARAMETER Operations
    An Operations object for this action
    .PARAMETER Recovery_Operations
    A Recovery Operations object for this action.
    .PARAMETER Update_Operation
    An Update Operation object for this action.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}

function Remove-ZabbixAction() {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory)]
        [string]$ActionId,
        [Parameter(Mandatory, ParameterSetName = 'profile')]
        [string]$ProfileName,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
        [string]$AuthCode,
        [Parameter(Mandatory, ParameterSetName = 'authcode')]
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

    $Action = Get-ZabbixAction -Actionid $ActionId

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
    <#
    .SYNOPSIS
    Remove a Zabbix Action
    .DESCRIPTION
    Remove the specified action from the Zabbix configuration.
    .PARAMETER ActionId
    The ID of the action to be removed.
    .PARAMETER ProfileName
    Zabbix profile to use to authenticate. If omitted the default profile will be used. (Cannot be used with AuthCode and Uri)
    .PARAMETER AuthCode
    Zabbix AuthCode to use to authenticate. (Cannot be used with Profile)
    .PARAMETER Uri
    The URI of the zabbix server. (Cannot be used with Profile)
    #>
}