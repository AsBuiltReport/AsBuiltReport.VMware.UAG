function Get-AbrOSCSPSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG OCSP Settings.
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
        Write-PScriboMessage "OCSP Settings InfoLevel set at $($InfoLevel.UAG.IdentityBridgeingSettings)."
        Write-PscriboMessage "Collecting UAG OCSP Settings information."
    }

    process {
        if ($InfoLevel.UAG.IdentityBridgeingSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $OCSPs = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/authmethod/ocsp/fileNames" -Credential $Credential
                } else {$OCSPs = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/authmethod/ocsp/fileNames" -Credential $Credential}
                if ($OCSPs.ocspSet) {
                    section -Style Heading4 "OCSP Settings" {
                        Paragraph "The following section will provide details onOCSP Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine

                        foreach($OCSP in $OCSPs.ocspSet){
                            If($OCSP){

                                $trimmedOCSP = ($OCSP.Split(',')[0]) -replace 'CN=', ''

                                section -Style Heading5 "OCSP Settings - $($trimmedOCSP)" {
                                    $OutObj = @()

                                    try {
                                        $inObj = [ordered] @{
                                            "OCSP Set File Name" = $OCSP
                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
                                        }

                                    $TableParams += @{
                                        Name = "OCSP Settings - $($trimmedOCSP)"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
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