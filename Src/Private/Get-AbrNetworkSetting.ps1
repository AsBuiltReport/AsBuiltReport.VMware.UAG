function Get-AbrNetworkSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Horizon Network Settings.
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
        Write-PScriboMessage "Network Settings InfoLevel set at $($InfoLevel.UAG.AuthenticationSettings)."
        Write-PscriboMessage "Collecting Network Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $NICSettings = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/nic" -Credential $Credential
                } else {$NICSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/nic" -Credential $Credential}
                if ($NICSettings) {
                    Paragraph "The following section will provide details for Network Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                    BlankLine
                    $OutObj = @()
                    section -Style Heading4 "Network Settings" {
                        foreach($NICSetting in $NICSettings.nicSettingsList) {
                            $NICName = $NICSetting.nic
                            $CustomConfig = $NICSetting.customConfig | Out-String
                            if($null -ne $NICSetting.ipv4StaticRoutes) {
                                $StaticRoutes = $NICSetting.ipv4StaticRoutes -join "`n"
                            }else { $StaticRoutes = $null}

                            try {
                                $inObj = [ordered] @{
                                    "NIC" = $NICSetting.nic
                                    "IPv4 Address" = $NICSetting.ipv4Address
                                    "IPv4 Subnet" = $NICSetting.ipv4Netmask
                                    "IPv4 Gateway" = $NICSetting.ipv4DefaultGateway
                                    "IP Allocation Mode" = $NICSetting.allocationMode
                                    "Static Routes" = $StaticRoutes
                                    "Custom Configuration" = $CustomConfig
                                }
                                $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                }

                            $TableParams += @{
                                Name = "Network Settings - $($($UAGServer).split('.')[0].ToUpper())"
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
            catch {
                Write-PscriboMessage -IsWarning $_.Exception.Message
            }
        }
    }
    end {}
}