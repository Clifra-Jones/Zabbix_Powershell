$configPath = "$home/.zabbix"
$script:configFile = "$configPath/auth.json"

function Convert-SeveritiesToInteger() {
    Param(
        [string[]]$Severities
    )
    $binary = ""

    if ($Severities -contains "NotClassified") {
        $binary += "1"
    } else {
        $binary += '0'
    }
    
    if ($Severities -contains "Information") {
        $binary += "1"
    } else {
        $binary += '0'
    }

    if ($Severities -contains "Warning") {
        $binary += "1"
    } else {
        $binary += '0'
    }

    if ($Severities -contains "Average") {
        $binary += "1"
    } else {
        $binary += '0'
    }

    if ($Severities -contains "High") {
        $binary += "1"
    } else {
        $binary += '0'
    }

    if ($Severities -contains "Disaster") {
        $binary += "1"
    } else {
        $binary += '0'
    }

    $IntegerSeverity = [Convert]::ToINt32($binary, 2)

    return $IntegerSeverity

}