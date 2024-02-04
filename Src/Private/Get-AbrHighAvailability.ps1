function Get-AbrHighAvailability {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG High Availablity Settings.
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
        Write-PScriboMessage "High Availability Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PScriboMessage "Collecting High Availability Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $LoadBalancerSettings = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/loadbalancer/settings" -Credential $Credential
                } else { $LoadBalancerSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/loadbalancer/settings" -Credential $Credential }
                if ($LoadBalancerSettings) {
                    $OutObj = @()
                    Section -Style Heading4 "High Availability Settings" {
                        Paragraph "The following section will provide details for High Availability Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine
                        try {
                            $inObj = [ordered] @{
                                "High Availability Mode" = $LoadBalancerSettings.loadBalancerMode
                                "High Availability State" = $LoadBalancerState
                                "Virtual IP Address" = $LoadBalancerSettings.virtualIPAddress
                                "Group ID" = $LoadBalancerSettings.groupID
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }

                        $TableParams = @{
                            Name = "High Availability Settings - $($($UAGServer).split('.')[0].ToUpper())"
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