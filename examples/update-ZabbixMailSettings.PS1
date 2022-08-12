#requires -Modules @{ModuleName = "PSZabbix"; ModuleVersion="1.0"}
#Requires -Modules @{ModuleName='AWS.Tools.SecretsManager'; ModuleVersion='4.1.105'}

$SES_Creds = (Get-SECSecretValue -SecretId 'SES_SMTP_User').SecretString | ConvertFrom-Json

$mediaTypes = Get-ZabbixMediaTypes | Where-Object {$_.Name -like "*email*"}

Foreach ($mediaType in $mediaTypes) {
    if ($mediaType.username -ne $SES_Creds.Smtp_username) {
        $mediaTYpe | Set-ZabbixMediaType -UserName $SES_Creds.Smtp_username -passws $SES_Creds.smtp_password
    }
}