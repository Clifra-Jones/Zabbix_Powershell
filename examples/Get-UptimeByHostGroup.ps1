using namespace System.Collections.Generic

<#
    This example gathers up tie statistics from Zabbix items and averages the out by host groups.
#>
$List = [List[psobject]]::New()

# Gather up al lenabled hosts, include groups trhe host belongs to.
$hosts = Get-ZabbixHosts -includeGroups -excludeDisabled

# Sort and extract all the unique host names
$groupNames = $hosts.groups.name | Sort-Object | Get-Unique

# Gather the items for key 'system.uptime' for the hosts. Include a hosts property in tghe item object.
$items = $hosts | Get-ZabbixItems -filter @{"key_" = "system.uptime"} -includeHosts | `
# The 'lastvalue' property is returned as a string. Add a new property as an integer type and sort by that property.
Select-Object *, @{Name = "n_lastvalue"; Expression = {[INT64]$_.lastvalue}} | Sort-Object -Property n_lastvalue

# Get average uptime for all hosts
$AllHostAveUptime_seconds = ($items | Measure-Object -Property lastvalue -Average).Average
$AllHostAveUptime_timespan = [timespan]::FromSeconds($AllHostAveUptime_seconds)
$List.Add([PSCustomObject]@{
    Group = "Average All Hosts" 
    Uptime = $AllHostAveUptime_timespan.TotalDays
})

# Get longest uptime
$longest = $items | Select-Object -Last 1
if ($longest.hosts.count -gt 0) {
    $hostnames = $longest.hosts.name -Join ","
} else {
    $hostnames = $longest.hosts.name 
}
$longestUptime_seconds = $longest.lastvalue
$longestUptime_timespan = [timespan]::FromSeconds($longestUptime_seconds)
$list.Add([pscustomObject]@{
    Group = "Longest:($hostnames)" 
    Uptime = $longestUptime_timespan.TotalDays
})

# Get Shortest uptime
$shortest = $items | Select-Object -First 1
if ($shortest.hosts.count -gt 0) {
    $hostnames = $shortest.hosts.name -join ","
} else {
    $hostnames = $shortest.hosts.name
}
$shortestUptime_seconds = $shortest.lastvalue
$shortestUptime_timespan = [timespan]::FromSeconds($shortestUptime_seconds)
$list.Add([psCustomObject]@{
    Group = "Shortest: ($hostnames)"
    Uptime = $shortestUptime_timespan.TotalDays
})

# Get the average uptime for each host group.
foreach ($groupName in ($groupNames.Where({$_ -ne "Discovered hosts" -and $_ -ne "(vm)"}))) {
    $hostsInGroup = $hosts.Where({$_.groups.name -eq $groupName})
    $itemsInGroup = [List[psobject]]::New()
    foreach ($hostInGroup in $hostsInGroup) {
        $_Items = $items.Where({$_.hosts.hostid -eq $hostInGroup.hostid})
        $_items | ForEach-Object{$itemsInGroup.Add($_)}
    }
    if ($itemsInGroup) {
        $groupAveUptime_Seconds = ($itemsInGroup | Measure-Object -Property lastvalue -Average).Average
        $groupAveUptime_timespan = [timespan]::FromSeconds($groupAveUptime_Seconds)
        $list.Add([psCustomObject]@{
            Group = $groupName
            Uptime = $groupAveUptime_timespan.TotalDays
        })
    }
}
$List.ToArray() | export-csv -Path /home/cwilliams.local/Documents/Uptime.csv -NoTypeInformation
