function Get-AbrRealmSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Realm Settings.
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
        Write-PScriboMessage "Realm Settings InfoLevel set at $($InfoLevel.UAG.IdentityBridgeingSettings)."
        Write-PscriboMessage "Collecting UAG Realm Settings information."
    }

    process {
        if ($InfoLevel.UAG.IdentityBridgeingSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $KerberosRealms = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/kerberos/realm" -Credential $Credential
                } else {$KerberosRealms = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/kerberos/realm" -Credential $Credential}
                if ($KerberosRealms.kerberosRealmSettingsList) {
                    section -Style Heading4 "Realm Settings" {
                        Paragraph "The following section will provide details on Realm Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine

                        Foreach($KerberosRealm in $KerberosRealms.kerberosRealmSettingsList){
                            If($KerberosRealm){
                                section -Style Heading5 "Realm Settings - $($KerberosRealm.Name)" {
                                    $OutObj = @()

                                    If ($KerberosRealm.noOfWRPsUsingThisRealm -like '-1') {
                                        $UsingThisRealm = 'Not in use'
                                    }else {
                                        $UsingThisRealm = 'In use'
                                    }
                                    try {
                                        $inObj = [ordered] @{
                                            "Name" = $KerberosRealm.Name
                                            "Key Distribution Centers (KDC)" = $($KerberosRealm.kdcHostNameList -join "`n")
                                            'KDC Timeout' = $KerberosRealm.kdcTimeout
                                            'KDC In Use' = $UsingThisRealm
                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
                                        }

                                    $TableParams = @{
                                        Name = "Realm Settings - $($KerberosRealm.Name)"
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