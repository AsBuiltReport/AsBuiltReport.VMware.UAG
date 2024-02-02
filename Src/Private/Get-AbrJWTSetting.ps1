function Get-AbrJWTSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG JWT Settings.
    .DESCRIPTION
        Documents the configuration of VMware UAG in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        1.1.0
        Author:         Chris Hildebrandt, @childebrandt42
        Twitter:        @asbuiltreport
        Github:         AsBuiltReport
        Credits:        Iain Brighton (@iainbrighton) - PScribo module


    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.VMware.UAG
    #>

    [CmdletBinding()]
    param (
    )

    begin {
        Write-PScriboMessage "JWT Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PscriboMessage "Collecting UAG JWT Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $JWTSettings = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/jwt" -Credential $Credential
                } else {$JWTSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/jwt" -Credential $Credential}
                if ($JWTSettings.jwtSettingsList) {
                    section -Style Heading4 "JWT Settings Configuration" {
                        Paragraph "The following section will provide details on JWT Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine

                        if($null -ne $JWTSettings.jwtSettingsList.publicKeyURLSettings.trustedCertificates.name) {
                            $TrustedCerts = $JWTSettings.jwtSettingsList.publicKeyURLSettings.trustedCertificates.name -join "`n"
                        }else { $TrustedCerts = $null}
                        if($null -ne $JWTSettings.jwtSettingsList.StaticPublicKeys.name) {
                            $PublicKeys = $JWTSettings.jwtSettingsList.StaticPublicKeys.name -join "`n"
                        }else { $PublicKeys = $null}

                        $OutObj = @()
                        try {
                            $inObj = [ordered] @{
                                "Name" = $JWTSettings.jwtSettingsList.name
                                "Issuer" = $JWTSettings.jwtSettingsList.string
                                'JWT Type' = $JWTSettings.jwtSettingsList.jwtType
                                'JWT Signing Certificate Type' = $JWTSettings.jwtSettingsList.jwtSigningCertificateType
                                'JWT Signing Private Key' = $JWTSettings.jwtSettingsList.jwtSigningPrivateKey
                                'JWT Signing Certificate Chain' = $JWTSettings.jwtSettingsList.jwtSigningCertificatechain
                                'Configure Encryption Public Key Settings' = $JWTSettings.jwtSettingsList.configureEncryptionPublicKeySettings
                                "Dynamic Public Key URL" = $JWTSettings.jwtSettingsList.publicKeyURLSettings.URL
                                "Public key URL thumbprints" = $JWTSettings.jwtSettingsList.publicKeyURLSettings.urlThumbprints
                                "Trusted Certificates" = $TrustedCerts
                                "Public Key Refresh Interval" = $JWTSettings.jwtSettingsList.publicKeyURLSettings.urlResponseRefreshInterval
                                "Static Public Keys" = $PublicKeys
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }

                        $TableParams += @{
                            Name = "JWT Settings Configuration - $($($UAGServer).split('.')[0].ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property Name | Table @TableParams
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning $_.Exception.Message
            }
        }
    }
    end {}
}