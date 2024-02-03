function Get-AbrTLSServerCertificateSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Horizon TLS Server Certificate Settings.
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
        Write-PScriboMessage "TLS Server Certificate Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PscriboMessage "Collecting TLS Server Certificate Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $ServerCertConfig = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/certs/ssl" -Credential $Credential
                    $ServerCertAdmin = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/certs/ssl/admin" -Credential $Credential
                    $ServerCertEndUser = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/certs/ssl/end_User" -Credential $Credential
                } else {$ServerCertConfig = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/certs/ssl" -Credential $Credential
                        $ServerCertAdmin = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/certs/ssl/admin" -Credential $Credential
                        $ServerCertEndUser = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/certs/ssl/end_User" -Credential $Credential
                }
                if ($ServerCertAdmin -or $ServerCertEndUser) {
                    section -Style Heading4 "TLS Server Certificate Settings" {
                        Paragraph "The following section will provide details for Admin TLS Server Certificate Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine
                        if ($ServerCertAdmin){
                            $index = @('')
                            $Cert = @('')
                            $certBytes = @('')
                            $cn = @('')
                            $o = @('')
                            $DNSList = @('')

                            $index = $ServerCertAdmin.IndexOf("-----END CERTIFICATE-----")
                            if($index){
                                $Cert = $ServerCertAdmin.Substring(0, $index)
                                if($Cert){
                                    # Convert the certificate data to a byte array
                                    $certBytes = [System.Convert]::FromBase64String($Cert -replace '-.*-')

                                    # Create an X509Certificate2 object from the byte array
                                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)
                                    if($cert){
                                        # Split the string on the comma
                                        $CertParts = $Cert.SubjectName.Name.Split(',')
                                        if($CertParts){
                                            # Get the CN and O parts and remove the prefix
                                            $cn = ($CertParts | Where-Object { $_.Trim().StartsWith('CN=') }).Trim().Substring(3)
                                            $o = ($CertParts | Where-Object { $_.Trim().StartsWith('O=') }).Trim().Substring(2)
                                        }
                                    }
                                }
                            }


                            # Foreach $DNSlist Name create comma separated list
                            if($null -ne $Cert.DnsNameList.unicode) {
                                $DNSList = $Cert.DnsNameList.unicode -join "`n"
                            }else { $DNSList = $null}

                            $OutObj = @()
                            section -Style Heading5 "User TLS Server Certificate Settings" {
                                try {
                                    $inObj = [ordered] @{
                                        "Admin TLS Server Cert Configured" = 'True'
                                        'Common Name' = $cn
                                        'Organization' = $o
                                        'Issuer Name' = $Cert.IssuerName.Name
                                        'Valid From' = $Cert.NotBefore
                                        'Valid To' = $Cert.NotAfter
                                        'Friendly Name' = $Cert.FriendlyName
                                        'Serial Number' = $Cert.SerialNumber
                                        'Thumbprint' = $Cert.Thumbprint
                                        'Includes Private Key' = $Cert.HasPrivateKey
                                        'DNS List' = $DNSList
                                        'Subject Name' = $Cert.SubjectName.Name
                                        'Version' = $Cert.Version
                                        'Handle' = $Cert.Handle
                                    }
                                    $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                    }

                                $TableParams = @{
                                    Name = "User Server Certificate Settings - $($($UAGServer).split('.')[0].ToUpper())"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                        if ($ServerCertEndUser){
                            $index = @('')
                            $Cert = @('')
                            $certBytes = @('')
                            $cn = @('')
                            $o = @('')
                            $DNSList = @('')

                            $index = $ServerCertEndUser.IndexOf("-----END CERTIFICATE-----")
                            $Cert = $ServerCertEndUser.Substring(0, $index)

                            # Convert the certificate data to a byte array
                            $certBytes = [System.Convert]::FromBase64String($Cert -replace '-.*-')

                            # Create an X509Certificate2 object from the byte array
                            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)

                            # Split the string on the comma
                            $CertParts = $Cert.SubjectName.Name.Split(',')

                            # Get the CN and O parts and remove the prefix
                            $cn = ($CertParts | Where-Object { $_.Trim().StartsWith('CN=') }).Trim().Substring(3)
                            $o = ($CertParts | Where-Object { $_.Trim().StartsWith('O=') }).Trim().Substring(2)

                            # Foreach $DNSlist Name create comma separated list
                            if($null -ne $Cert.DnsNameList.unicode) {
                                $DNSList = $Cert.DnsNameList.unicode -join "`n"
                            }else { $DNSList = $null}

                            $OutObj = @()
                            section -Style Heading5 "Admin TLS Server Certificate Settings" {
                                try {
                                    $inObj = [ordered] @{
                                        "Admin TLS Server Cert Configured" = 'True'
                                        'Common Name' = $cn
                                        'Organization' = $o
                                        'Issuer Name' = $Cert.IssuerName.Name
                                        'Valid From' = $Cert.NotBefore
                                        'Valid To' = $Cert.NotAfter
                                        'Friendly Name' = $Cert.FriendlyName
                                        'Serial Number' = $Cert.SerialNumber
                                        'Thumbprint' = $Cert.Thumbprint
                                        'Includes Private Key' = $Cert.HasPrivateKey
                                        'DNS List' = $DNSList
                                        'Subject Name' = $Cert.SubjectName.Name
                                        'Version' = $Cert.Version
                                        'Handle' = $Cert.Handle
                                    }
                                    $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                    }

                                $TableParams = @{
                                    Name = "Admin Server Certificate Settings - $($($UAGServer).split('.')[0].ToUpper())"
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
            catch {
                Write-PscriboMessage -IsWarning $_.Exception.Message
            }
        }
    }
    end {}
}