function Get-AbrEndPointComplianceCheckProviderSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Endpoint Compliance Check Provider Settings.
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
        Write-PScriboMessage "Endpoint Compliance Check Provider Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PscriboMessage "Collecting UAG Endpoint Compliance Check Provider Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $DevicePolicy = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/devicepolicy/configured" -Credential $Credential
                } else {$DevicePolicy = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/devicepolicy/configured" -Credential $Credential}
                if ($DevicePolicy.devicePolicySettingsList) {
                    section -Style Heading4 "Endpoint Compliance Check Provider Settings" {
                        Paragraph "The following section will provide details on Endpoint Compliance Check Provider Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine

                        $OutObj = @()

                        try {
                            $inObj = [ordered] @{
                                'Endpoint Compliance Check Provider' = $DevicePolicy.devicePolicySettingsList.settingsId
                                #'Client Key' = $DevicePolicy.devicePolicySettingsList
                                'Hostname' = $DevicePolicy.devicePolicySettingsList.name
                                'Connectivity Check Interval' = $DevicePolicy.devicePolicySettingsList.complianceCheckTimeunit
                                #'Compliance Check Interval Timeunit' = $DevicePolicy.devicePolicySettingsList
                                #'Compliance Check Initial Delay' = $DevicePolicy.devicePolicySettingsList
                                'Compliance Check Fast Interval' = $DevicePolicy.devicePolicySettingsList.complianceCheckTimeunit
                                'Compliance Check Interval' = $DevicePolicy
                                'In compliance' = $DevicePolicy
                                'Not in compliance' = $DevicePolicy
                                'Out of license usage' = $DevicePolicy
                                'Assessment pending' = $DevicePolicy
                                'Endpoint unknown' = $DevicePolicy
                                'Others' = $DevicePolicy
                                'Windows File Upload Type' = $DevicePolicy
                                'Windows Executable File' = $DevicePolicy
                                'Windows Executable Name' = $DevicePolicy
                                'Windows Executable Parameters' = $DevicePolicy
                                'Windows Executable Flags' = $DevicePolicy
                                'Windows Executable Agent File URL' = $DevicePolicy
                                'Windows Executable Agent URL ThumbPrints' = $DevicePolicy
                                'Windows Trusted Certificates' = $DevicePolicy
                                'Windows Executable Agent File Refresh Interval (secs)' = $DevicePolicy
                                'macOS File Upload Type' = $DevicePolicy
                                'macOS Executable file ' = $DevicePolicy
                                'macOS Executable Name' = $DevicePolicy
                                'macOS Executable Parameters' = $DevicePolicy
                                'macOS Executable Flags' = $DevicePolicy
                                'macOS Path to Executable' = $DevicePolicy
                                'macOS Agent File URL' = $DevicePolicy
                                'macOS Agent URL ThumbPrints' = $DevicePolicy
                                'macOS Trusted Certs' = $DevicePolicy
                                'macOS Agent File refresh interval (secs)' = $DevicePolicy
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }

                        $TableParams += @{
                            Name = "Endpoint Compliance Check Provider Settings - $($WorkspaceOneIntel.Name)"
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