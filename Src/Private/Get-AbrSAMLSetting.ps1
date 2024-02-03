function Get-AbrSAMLSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Horizon Radius Settings.
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
        Write-PScriboMessage "SAML Settings InfoLevel set at $($InfoLevel.UAG.AuthenticationSettings)."
        Write-PscriboMessage "Collecting UAG SAML Settings information."
    }

    process {
        if ($InfoLevel.UAG.AuthenticationSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $SAMLSettings = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/sp-metadata" -Credential $Credential
                } else {$SAMLSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/sp-metadata" -Credential $Credential}
                if ($SAMLSettings.items) {
                    section -Style Heading4 "SAML Settings" {
                        Paragraph "The following section will provide details for SAML Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine
                        foreach ($SAMLSetting in $SAMLSettings.items) {
                            if ($SAMLSetting) {
                                $OutObj = @()
                                section -Style Heading5 "SAML Settings - $($SAMLSetting.spName)" {
                                    try {
                                        $inObj = [ordered] @{
                                            "SP Name" = $SAMLSetting.spName
                                            #"MetaData XML" = $SAMLSetting.metadataXml
                                            'Assertion Lifetime' = $SAMLSetting.assertionLifetime
                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
                                        }

                                    $TableParams = @{
                                        Name = "SAML Settings - $($SAMLSetting.spName)"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                }
                            }
                        }
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