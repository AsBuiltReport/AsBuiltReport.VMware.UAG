function Get-AbrWorkspaceOneIntelligenceDataSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Horizon Workspace One Intelligence Data Settings.
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
        Write-PScriboMessage "Workspace One Intelligence Data Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PScriboMessage "Collecting UAG Workspace One Intelligence Data Settings."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $WorkspaceOneData = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/ws1intelligencedata" -Credential $Credential
                } else { $WorkspaceOneData = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/ws1intelligencedata" -Credential $Credential }
                if ($WorkspaceOneData) {
                    Section -Style Heading4 "Workspace One Intelligence Data Settings" {
                        Paragraph "The following section will provide details on Workspace One Intelligence Data Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine
                        $OutObj = @()

                        try {
                            $inObj = [ordered] @{
                                "Enabled / Opt In" = $WorkspaceOneData.Enabled
                                'Workspace One Intelligence Connection' = $WorkspaceOneData.name
                                'Update Interval' = $WorkspaceOneData.updateInterval

                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }

                        $TableParams = @{
                            Name = "Workspace One Intelligence Data Settings - $($($UAGServer).split('.')[0].ToUpper())"
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