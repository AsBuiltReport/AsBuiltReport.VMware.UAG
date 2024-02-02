function Get-AbrSystemConfiguration {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Edge Services.
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
        Write-PScriboMessage "Edge Services InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PscriboMessage "Collecting UAG Horizon Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $SystemSettings = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/system" -Credential $Credential
                } else {$SystemSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/system" -Credential $Credential}
                if ($SystemSettings) {
                    section -Style Heading4 "System Configuration" {
                        Paragraph "The following section will provide details on System Configuration Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine
                        $OutObj = @()

                        if($null -ne $SystemSettings.allowedHostHeaderValues) {
                            $HostHeaders = $SystemSettings.allowedHostHeaderValues -join "`n"
                        }else { $HostHeaders = $null}
                        if($null -ne $SystemSettings.ntpServers) {
                            $NTPSettings = $SystemSettings.ntpServers -join "`n"
                        }else { $NTPSettings = $null}
                        if($null -ne $SystemSettings.fallBackNtpServers) {
                            $fallBackNtpServers = $SystemSettings.fallBackNtpServers -join "`n"
                        }else { $fallBackNtpServers = $null}


                        $SMTPSettings = $SystemSettings.snmpSettings | Out-String

                        try {
                            $inObj = [ordered] @{
                                "UAG Name" = $SystemSettings.uagName
                                'Password Age' = $SystemSettings.adminPasswordExpirationDays
                                'Monitoring User Password Age' = $SystemSettings.monitoringUsersPasswordExpirationDays
                                'Root Password Age' = $SystemSettings.rootPasswordExpirationDays
                                'Admin Password Policy Settings' = $SystemSettings.adminPasswordPolicySettings
                                'Password Policy Settings' = $SystemSettings.passwordPolicySettings
                                'IP Mode' = $SystemSettings.ipMode
                                'FIPs Mode' = $SystemSettings.fipsEnabled
                                'DS Compliance OS' = $SystemSettings.dsComplianceOS
                                'OS Login Username' = $SystemSettings.osLoginUsername
                                'Admin Cert Rollback Enabled' = $SystemSettings.adminCertRolledBack
                                'TLS Server Cipher Suites' = $SystemSettings.cipherSuites
                                'TLS Client Cipher Suites' = $SystemSettings.outboundCipherSuites
                                'Enable TLS 1.0' = $SystemSettings.tls10Enabled
                                'Enable TLS 1.1' = $SystemSettings.tls11Enabled
                                'Enable TLS 1.2' = $SystemSettings.tls12Enabled
                                'Enable TLS 1.3' = $SystemSettings.tls13Enabled
                                'Enable SSLv3' = $SystemSettings.ssl30Enabled
                                'SSL Provider' = $SystemSettings.sslProvider
                                'TLS Named Groups' = $SystemSettings.tlsNamedGroups
                                'TLS Signature Schemes' = $SystemSettings.tlsSignatureSchemes
                                'TLS Port Sharing' = $SystemSettings.tlsPortSharingEnabled
                                'Allowed Host Headers' =  $HostHeaders
                                'Health Check URL' = $SystemSettings.healthCheckUrl
                                'HTTP Health Monitor' = $SystemSettings.enableHTTPHealthMonitor
                                'Unrecognized Sessions Monitoring Enabled' = $SystemSettings.unrecognizedSessionsMonitoringEnabled
                                'Cookies to be Cached' = $SystemSettings.cookiesToBeCached
                                'Quiesce Mode' = $SystemSettings.quiesceMode
                                'Monitor Interval' = $SystemSettings.monitorInterval
                                'Enable SAML Certificate Rollover Support' = $SystemSettings.samlCertRolloverSupported
                                'Authentication Timeout' = $SystemSettings.authenticationTimeout
                                'Body Receive Timeout' = $SystemSettings.bodyReceiveTimeoutMsec
                                'Maximum Connections per Session' = $SystemSettings.maxConnectionsAllowedPerSession
                                'Client Connection Idle Timeout' = $SystemSettings.clientConnectionIdleTimeout
                                'Request Timeout' = $SystemSettings.requestTimeoutMsec
                                'Http Connection Timeout' = $SystemSettings.httpConnectionTimeout
                                'Admin Max Concurrent Sessions' = $SystemSettings.adminMaxConcurrentSessions
                                'Admin Session Idle Timeout' = $SystemSettings.adminSessionIdleTimeoutMinutes
                                'Root Session Idle Timeout' = $SystemSettings.rootSessionIdleTimeoutSeconds
                                'OS Max Login Limit' = $SystemSettings.osMaxLoginLimit
                                'Clock Skew Tolerance' = $SystemSettings.clockSkewTolerance
                                'Max Allowed System CPU Usage' = $SystemSettings.maxSystemCPUAllowed
                                'Session Timeout' = $SystemSettings.sessionTimeout
                                'Join CEIP' = $SystemSettings.ceipEnabled
                                'Enable SNMP' = $SystemSettings.snmpEnabled
                                'SNMP Settings' = $SMTPSettings
                                'Admin Disclaimer Text' = $SystemSettings.adminDisclaimerText
                                'DNS' = $SystemSettings.dns
                                'DNS Search' = $SystemSettings.dnsSearch
                                'Time Sync with Host' = $SystemSettings.timeSyncWithHost
                                'Host Clock Sync Enabled' = $SystemSettings.hostClockSyncEnabled
                                'Host Clock Sync Supported' = $SystemSettings.hostClockSyncSupported
                                'NTP Servers' = $NTPSettings
                                'Fallback NTP Servers' = $fallBackNtpServers
                                'Extended Server Certificate Validation' = $SystemSettings.extendedServerCertValidationEnabled
                                'SSH Enabled' = $SystemSettings.sshEnabled
                                'SSH Password Access Enabled' = $SystemSettings.sshPasswordAccessEnabled
                                'SSH Key Access Enabled' = $SystemSettings.sshKeyAccessEnabled

                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }

                        $TableParams += @{
                            Name = "System Configuration - $($($UAGServer).split('.')[0].ToUpper())"
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