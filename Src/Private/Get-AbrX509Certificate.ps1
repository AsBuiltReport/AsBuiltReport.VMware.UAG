function Get-AbrX509Certificate {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG X509 Certificate Settings.
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
        Write-PScriboMessage "X509 Certificate Settings InfoLevel set at $($InfoLevel.UAG.AuthenticationSettings)."
        Write-PscriboMessage "Collecting UAG X509 Certificate Settings information."
    }

    process {
        if ($InfoLevel.UAG.AuthenticationSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $AuthCert = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/authmethod/certificate-auth" -Credential $Credential
                } else {$AuthCert = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/authmethod/certificate-auth" -Credential $Credential}
                if ($AuthCert) {
                    Paragraph "The following section will provide details for X509 Certificate Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                    BlankLine
                    $OutObj = @()
                    section -Style Heading4 "X509 Certificate Settings" {
                        try {
                            $inObj = [ordered] @{
                                "Enable X.509 Certificate" = $AuthCert.enabled
                                "Root and Intermediate CA Certificates" = $($AuthCert.caCertificates | Out-String)
                                "Enable Cert Revocation" = $AuthCert.enableCertRevocation
                                "Use CRL from Certificates" = $AuthCert.enableCertCRL
                                "CRL Location" = $AuthCert.crlLocation
                                "Enable OCSP Revocation" = $AuthCert.enableCertRevocation
                                "Use CRL in case of OCSP Failure" = $AuthCert.enableOCSPCRLFailover
                                "Send OCSP Nonce" = $AuthCert.sendOCSPNonce
                                "OCSP URL" = $AuthCert.ocspURL
                                "Use OCSP URL from certificate" = $AuthCert.ocspURLFromCert
                                "Enable Consent Form before Authentication" = $AuthCert.enableConsentForm
                                "Consent Form Content" = $AuthCert.consentForm
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }

                        $TableParams += @{
                            Name = "X509 Certificate Settings - $($($UAGServer).split('.')[0].ToUpper())"
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