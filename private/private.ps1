Set-Variable -Name "CurrentProfile" -Value (Read-ZabbixConfig) -Scope Script

$configPath = "$home/.zabbix"
$[script]configFile = "$configPath/auth.json"