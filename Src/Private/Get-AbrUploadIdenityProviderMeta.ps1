function Get-AbrUploadIdenityProviderMeta {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Identity Provider Metadata Settings.
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
        Write-PScriboMessage "Identity Provider Metadata Settings InfoLevel set at $($InfoLevel.UAG.IdentityBridgeingSettings)."
        Write-PScriboMessage "Collecting UAG Identity Provider Metadata Settings information."
    }

    process {
        if ($InfoLevel.UAG.IdentityBridgeingSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $ExtMetadataSettings = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/idp-ext-metadata" -Credential $Credential
                } else { $ExtMetadataSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/idp-ext-metadata" -Credential $Credential }
                if ($ExtMetadataSettings.idPExternalMetadataSettingsList) {
                    Section -Style Heading4 "Identity Provider Metadata Settings" {
                        Paragraph "The following section will provide details on Identity Provider Metadata Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine
                        foreach ($ExtMetadataSetting in $ExtMetadataSettings.idPExternalMetadataSettingsList) {
                            if ($ExtMetadataSetting) {
                                Section -Style Heading5 "Identity Provider Metadata Settings - $($ExtMetadataSetting.entityId)" {
                                    $OutObj = @()
                                    try {
                                        $inObj = [ordered] @{
                                            "Entity ID" = $ExtMetadataSetting.entityId
                                            #"IDP Metadata" = $ExtMetadataSetting.metadata
                                            "Encryption Certificate" = $ExtMetadataSetting.encryptionCertificateType
                                            "Allow Unencrypted SAML Assertions" = $ExtMetadataSetting.allowUnencrypted
                                            'Always force SAML auth' = $ExtMetadataSetting.forceAuthN
                                            'Private Key PEM' = $ExtMetadataSetting.certificateChainAndKeyWrapper.privateKeyPem
                                            'Certificate Chain PEM' = $ExtMetadataSetting.certificateChainAndKeyWrapper.certChainPem
                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                    } catch {
                                        Write-PScriboMessage -IsWarning $_.Exception.Message
                                    }

                                    $TableParams = @{
                                        Name = "Identity Provider Metadata Settings - $($($UAGServer).split('.')[0].ToUpper())"
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
            } catch {
                Write-PScriboMessage -IsWarning $_.Exception.Message
            }
        }
    }
    end {}
}