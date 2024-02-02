function Get-AbrSyslogSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Syslog Server Settings.
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
        Write-PScriboMessage "Syslog Server Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PscriboMessage "Collecting UAG Syslog Server Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $Syslogs = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/syslog" -Credential $Credential
                } else {$Syslogs = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/syslog" -Credential $Credential}
                if ($Syslogs.syslogServerSettings) {
                    section -Style Heading4 "Syslog Server Settings" {
                        Paragraph "The following section will provide details on Syslog Server Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine

                        foreach ($Syslog in $Syslogs.syslogServerSettings) {
                            if($Syslog) {
                                section -Style Heading5 "Syslog Server Settings - $($Syslog.syslogSettingName)" {
                                    $OutObj = @()
                                    try {
                                        $inObj = [ordered] @{
                                            "Name" = $Syslog.syslogSettingName
                                            'Category' = $Syslog.syslogCategory
                                            'List of Privileges' = $($Syslog.syslogCategoryList -join ', ')
                                            'Protocol' = $Syslog.sysLogType
                                            'Format' = $Syslog.syslogFormat
                                            'Include System Messages' = $Syslog.syslogSystemMessagesEnabledV2
                                            'Syslog URL' = $Syslog.syslogURL
                                            'Validate Server Certificate' = $Syslog.validateServerCertificate
                                            'TLS Syslog Server Settings' = $Syslog.tlsSyslogServerSettings
                                            'TLS MQTT Server Settings' = $Syslog.tlsMqttServerSettings

                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
                                        }

                                    $TableParams += @{
                                        Name = "Syslog Server Settings - $($Syslog.syslogSettingName)"
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