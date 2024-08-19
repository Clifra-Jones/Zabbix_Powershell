$configPath = "$home/.zabbix"
$script:configFile = "$configPath/auth.json"

function Convert-SeverityToInteger() {
    Param(
        [string]$Severity
    )
    $binary = ""

    if ($SeveritY -eq "NotClassified") {
        $binary += "000001"
    } 
    
    if ($Severities -eq "Information") {
        $binary += "000011"
    } 

    if ($Severities -eq "Warning") {
        $binary += "000111"
    }

    if ($Severities -eq "Average") {
        $binary += "001111"
    }

    if ($Severities -contains "High") {
        $binary += "011111"
    } 

    if ($Severities -contains "Disaster") {
        $binary += "111111"
    }

    $IntegerSeverity = [Convert]::ToINt32($binary, 2)

    return $IntegerSeverity

}

