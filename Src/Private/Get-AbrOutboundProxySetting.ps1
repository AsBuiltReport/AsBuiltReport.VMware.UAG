function Get-AbrOutboundProxySetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Outbound Proxy Settings.
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
        Write-PScriboMessage "Outbound Proxy Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PscriboMessage "Collecting UAG Outbound Proxy Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $Proxys = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/proxy" -Credential $Credential
                } else {$Proxys = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/proxy" -Credential $Credential}
                if ($Proxys.outboundProxySettingsList) {
                    section -Style Heading4 "Outbound Proxy Settings" {
                        Paragraph "The following section will provide details on Outbound Proxy Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine

                        Foreach($Proxy in $Proxys.outboundProxySettingsList){
                            If($Proxy){
                                section -Style Heading5 "Outbound Proxy Settings - $($Proxy.Name)" {
                                    $OutObj = @()

                                    try {
                                        $inObj = [ordered] @{
                                            "Name" = $Proxy.Name
                                            "Type" = $Proxy.proxyType
                                            'Proxy URL' = $Proxy.proxyUrl
                                            'Proxy Include Host' = $($Proxy.includedHosts -join "`n")
                                            'Trusted Certificates' = $($Proxy.trustedCertificates.name -join "`n")
                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
                                        }

                                    $TableParams += @{
                                        Name = "Outbound Proxy Settings - $($Proxy.Name)"
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