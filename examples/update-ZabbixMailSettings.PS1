#Requires -Modules @{ModuleName="PSZabbix"; MaximumVersion="1.0.0"}
#Requires -Modules @{ModuleName='AWS.Tools.SecretsManager'; ModuleVersion='4.1.105'}

try {
    $SES_Creds = (Get-SECSecretValue -SecretId 'SES_SMTP_User').SecretString | ConvertFrom-Json
} catch {
    Write-Host "Line: 4"
    throw $_.Exception.Message
}

$mediaTypes = Get-ZabbixMediaTypes | Where-Object {$_.Name -like "*Test email*"}

Foreach ($mediaType in $mediaTypes) {
    if ($mediaType.username -ne $SES_Creds.Smtp_username) {
        try{
            $mediaTYpe | Set-ZabbixMediaType -username $SES_Creds.SmtpUsername -passwd $SES_Creds.smtpPassword
        } catch {
            Write-Host "Line 16"
            throw $_.Exception.Message
        }
    }
}