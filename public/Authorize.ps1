
function Set-ZabbixAuthCode() {
    [CmdletBinding()]
    Param(
        [string]$Username,
        [securestring]$Password,
        [switch]$storeToProfile        
    )

    [pscredential]$Creds
    if (-not $Username) {
        $Creds = Get-Credential
    } elseIf (-not $Password) {
            $Creds = Get-Credential -UserName $Username
    } else {
            $Creds = [pscredential]::new($Username, $Password)
    } 

    $Username = $Creds.UserName
    $Passwd = ConvertFrom-SecureString -SecureString $creds.Password -AsPlainText

    $payload = Get-Payload

    $payload.method = "user.login"
    $payload.params = @{
        user = $UserName
        password = $Passwd
    }

    $body = $payload | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Method GET -Uri $Uri -ContentType $contentType -Body $body
        $authcode = $response.result
        $auth = @{
            authcode = $authcode
        }
        if (-not (Test-Path -Path $configPath)) {
            [void](New-Item -ItemType Directory -Path "$home/.zabbix")            
        }
        $Auth | ConvertTo-Json | Out-File $configFile
    } catch {
        Throw $_
    }
}