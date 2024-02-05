function Get-AbrKeyTabSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Keytab Settings.
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
        Write-PScriboMessage "Keytab Settings InfoLevel set at $($InfoLevel.UAG.IdentityBridgeingSettings)."
        Write-PScriboMessage "Collecting UAG Keytab Settings information."
    }

    process {
        if ($InfoLevel.UAG.IdentityBridgeingSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $KerberosKeyTab = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/kerberos/keytab" -Credential $Credential
                } else { $KerberosKeyTab = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/kerberos/keytab" -Credential $Credential }
                if ($KerberosKeyTab) {
                    Section -Style Heading3 "Keytab Settings" {
                        Paragraph "The following section will provide details on Keytab Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine

                        $OutObj = @()

                        try {
                            $inObj = [ordered] @{
                                "Principal Name" = $KerberosKeyTab.principalName
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning $_.Exception.Message
                        }

                        $TableParams = @{
                            Name = "Keytab Settings - $($($UAGServer).split('.')[0].ToUpper())"
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