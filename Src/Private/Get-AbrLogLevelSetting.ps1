function Get-AbrLogLevelSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Log Level Settings.
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
        Write-PScriboMessage "Log Level Settings InfoLevel set at $($InfoLevel.UAG.SupportSettings)."
        Write-PScriboMessage "Collecting UAG Log Level Settings information."
    }

    process {
        if ($InfoLevel.UAG.SupportSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $LogLevelSettings = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/monitor/getLogLevels" -Credential $Credential
                } else { $LogLevelSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/monitor/getLogLevels" -Credential $Credential }
                if ($LogLevelSettings) {
                    $OutObj = @()
                    Section -Style Heading3 "Log Level Settings" {
                        Paragraph "The following section will provide details for Log Level Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine
                        try {
                            $inObj = [ordered] @{
                                "All" = $LogLevelSettings.All
                                "Admin" = $LogLevelSettings.Admin
                                'Horizon Edge Service - All' = $LogLevelSettings.HORIZON_ALL
                                'Horizon Edge Service - XMLAPI' = $LogLevelSettings.HORIZON_XMLAPI
                                'Horizon Edge Service - Authentication' = $LogLevelSettings.HORIZON_AUTH
                                'Horizon Edge Service - Blast' = $LogLevelSettings.HORIZON_BLAST
                                'Horizon Edge Service - Tunnel' = $LogLevelSettings.HORIZON_TUNNEL
                                'Horizon Edge Service - PCOIP' = $LogLevelSettings.HORIZON_PCOIP
                                'Horizon Edge Service - UDP Tunnel Server' = $LogLevelSettings.Horizon_UTServer
                                'Horizon Edge Service - Endpoint Compliance' = $LogLevelSettings.HORIZON_Compliance
                                'Web Reverse Proxy Edge Service - All' = $LogLevelSettings.WRP_ALL
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }

                        $TableParams = @{
                            Name = "Log Level Settings - $($($UAGServer).split('.')[0].ToUpper())"
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