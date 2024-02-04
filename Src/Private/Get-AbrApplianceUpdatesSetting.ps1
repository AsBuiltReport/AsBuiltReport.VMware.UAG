function Get-AbrApplianceUpdatesSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Appliance Update Settings.
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
        Write-PScriboMessage "Appliance Update Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PScriboMessage "Collecting UAG Appliance Update Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $PackageUpdates = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/packageupdates" -Credential $Credential
                } else { $PackageUpdates = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/packageupdates" -Credential $Credential }
                if ($PackageUpdates) {
                    Section -Style Heading4 "Appliance Update Settings" {
                        Paragraph "The following section will provide details on Appliance Update Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine
                        $OutObj = @()

                        try {
                            $inObj = [ordered] @{
                                "Apply Update Scheme" = $PackageUpdates.packageUpdatesScheme
                                'OS Update URL' = $PackageUpdates.packageUpdatesOSURL
                                'Appliance Update URL' = $PackageUpdates.packageUpdatesURL
                                'Trusted Certificates' = $($PackageUpdates.trustedCertificates.name -join ', ')
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }

                        $TableParams = @{
                            Name = "Appliance Update Settings - $($($UAGServer).split('.')[0].ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning $_.Exception.Message
            }
        }
    }
    end {}
}