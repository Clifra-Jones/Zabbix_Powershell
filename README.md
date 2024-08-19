# Zabbix API Powershell Module

Copyright 2022, Balfour Beatty US.

License: [Microsoft Public License](https://opensource.org/license/ms-pl-html)

Project Site: [PSZabbix](https://github.com/Clifra-Jones/PSZabbix)

This module offers interaction with the Zabbix API on your Zabbix server.

Not all the API methods have corresponding Powershell functions and not all functions expose all parameters of the API calls.

For instance the host.get API call accepts several array properties like hostids, groupids, itemids, etc. that can be used to return the associated hosts that corresponding to the values in those arrays. While the function Get-ZabbixHost only accepts the parameter -HostId which is a single host id.
You can pipe an array of Host Ids to the function to return the associated hosts.

This was done to preserve the "Powershell" way of doing things. In PowerShell when you want a function to return data for a collection of objects, you send those objects to the function through the pipeline |. This keeps the module consistent with how users are familiar with using powershell. This does result in more round trips to the API interface that would otherwise be necessary.

For any API function that does not have a corresponding PowerShell function or if you want to use more of the features of the API method you can use the Invoke-ZabbixAPI function to call the API methods more directly. If you are piping a large array to a function, it may be more efficient to use this function and pass an array of Ids for the object you are retrieving. Therefor, returning your data in one API call.

This module is a work in progress, not all functions have been fully tested. You should use all function that write to your Configuration with caution and fully test them before executing against your production servers.

All writable function require Admin and Super admin rights.

## Installation
<!-->
#### Install from the Powershell Gallary

```powershell
Install-Module Zabbix_Powershell
```
-->

#### Clone from source repository

You will need git installed to clone the repository.

Change directory to the PowerShell modules folder.

### Windows

```bash
cd %userprofile%\Documents\Powershell\Modules
```

### Linux

```bash
cd ~/.local/share/powershell/Modules
```

Then clone the repository.

```bash
git clone https://github.com/Clifra-Jones/Zabbix_Powershell.git
```

You can access the module function reference [here](https://clifra-jones.github.io/Zabbix_Powershell/docs/reference.html).
