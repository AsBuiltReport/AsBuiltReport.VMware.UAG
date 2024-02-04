function Get-AbrEdgeServiceSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Horizon Edge Service Settings.
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
        Write-PScriboMessage "Edge Services InfoLevel set at $($InfoLevel.UAG.EdgeServices)."
        Write-PScriboMessage "Collecting UAG Horizon Settings information."
    }

    process {
        if ($InfoLevel.UAG.EdgeServices -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $EdgeServiceSettings = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/edgeservice" -Credential $Credential
                } else { $EdgeServiceSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/edgeservice" -Credential $Credential }
                if ($EdgeServiceSettings.edgeServiceSettingsList.enabled -like 'true') {
                    Paragraph "The following section will provide details on Edge Service Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                    BlankLine
                    $OutObj = @()
                    foreach ($EdgeServiceSetting in $EdgeServiceSettings.edgeServiceSettingsList) {
                        if ($EdgeServiceSetting.identifier -eq 'VIEW') {
                            Section -Style Heading4 "Horizon Settings" {
                                if ($null -ne $EdgeServiceSetting.trustedCertificates) {
                                    $trustedCertificatesData = $EdgeServiceSetting.trustedCertificates.name -join "`n"
                                } else { $trustedCertificatesData = $null }
                                if ($null -ne $EdgeServiceSetting.hostEntries) {
                                    $hostEntriesData = $EdgeServiceSetting.hostEntries -join "`n"
                                } else { $hostEntriesData = $null }
                                if ($null -ne $EdgeServiceSetting.customExecutableList) {
                                    $clientCustomExecutablesData = $EdgeServiceSetting.customExecutableList -join "`n"
                                } else { $clientCustomExecutablesData = $null }
                                if ($null -ne $EdgeServiceSetting.customExecutableList) {
                                    $SAMLAudiences = $EdgeServiceSetting.customExecutableList -join "`n"
                                } else { $SAMLAudiences = $null }

                                $securityHeaders = $EdgeServiceSetting.securityHeaders | Out-String

                                try {
                                    $inObj = [ordered] @{
                                        "Enable Horizon" = $EdgeServiceSetting.enabled
                                        'Connection Server URL' = $EdgeServiceSetting.proxyDestinationUrl
                                        'Minimum SHA Hash Size' = $EdgeServiceSetting.minSHAHashSize
                                        'Connection Server URL Thumbprint' = $EdgeServiceSetting.proxyDestinationUrlThumbprints
                                        'Honor Connection Server Redirect' = $EdgeServiceSetting.hostRedirectionEnabled
                                        'Connection Server IP Mode' = $EdgeServiceSetting.proxyDestinationIPSupport
                                        'Client Encryption Mode' = $EdgeServiceSetting.clientEncryptionMode
                                        'Auth Methods' = $EdgeServiceSetting.authMethods
                                        'Identity Provider' = $EdgeServiceSetting.idpEntityID
                                        'SAML Audiences' = $($EdgeServiceSetting.allowedAudiences -join "`n")
                                        'SAML Unauthenticated Username Attribute' = $EdgeServiceSetting.samlUnauthUsernameAttribute
                                        'Default Unauthenticated Username' = $EdgeServiceSetting.defaultUnauthUsername
                                        'Health Check URI Path' = $EdgeServiceSetting.healthCheckUrl
                                        'Re-Write Origin Header' = $EdgeServiceSetting.rewriteOriginHeader
                                        'Enable PCOIP' = $EdgeServiceSetting.pcoipEnabled
                                        'Disable PCOIP Legacy Certificate' = $EdgeServiceSetting.pcoipDisableLegacyCertificate # Only if using PCOIP
                                        'PCOIP External URL' = $EdgeServiceSetting.proxyDestinationIPSupport #Only if using PCOIP
                                        'Enable Blast' = $EdgeServiceSetting.blastEnabled
                                        'Blast External URL' = $EdgeServiceSetting.blastExternalUrl # Only if using Blast
                                        'Enable UDP Tunnel Server' = $EdgeServiceSetting.udpTunnelServerEnabled
                                        'Blast Proxy Certificate' = $EdgeServiceSetting.proxyBlastPemCert # Only if using Blast
                                        'Blast Allowed Host Header Values' = $EdgeServiceSetting.blastAllowedHostHeaderValues # Only if using Blast
                                        'Enable Tunnel' = $EdgeServiceSetting.tunnelEnabled
                                        'Tunnel External URL' = $EdgeServiceSetting.tunnelExternalUrl # Only if using Tunnel
                                        'Tunnel Proxy Certificate' = $EdgeServiceSetting.proxyTunnelPemCert # Only if using Tunnel
                                        'Endpoint Compliance Check Provider' = $EdgeServiceSetting.devicePolicyServiceProvider
                                        'Proxy Pattern' = $EdgeServiceSetting.proxyPattern
                                        'Enable Proxy Pattern Canonical Match' = $EdgeServiceSetting.canonicalizationEnabled
                                        'SAM SP' = $EdgeServiceSetting.samlSP
                                        'User Name Label for RADIUS' = $EdgeServiceSetting.radiusUsernameLabel # Only Radius
                                        'Passcode Label for RADIUS' = $EdgeServiceSetting.radiusPasscodeLabel # Only Radius
                                        'Logout On Certificate Removal' = $EdgeServiceSetting.logoutOnCertRemoval # Only if Using X509
                                        'Match Windows User Name' = $EdgeServiceSetting.matchWindowsUserName
                                        'Gateway Location' = $EdgeServiceSetting.gatewayLocation
                                        'Enable Windows SSO' = $EdgeServiceSetting.matchWindowsUserName
                                        'RADIUS Class Attributes' = $EdgeServiceSetting.radiusClassAttributeList # Only Radius
                                        'Disclaimer Text' = $EdgeServiceSetting.disclaimerText
                                        'Show Connection Server Pre-Login Message' = $EdgeServiceSetting.proxyDestinationPreLoginMessageEnabled
                                        'Trusted Certificates' = $trustedCertificatesData
                                        'Response Security Headers' = "$securityHeaders"
                                        'Client Custom Executables' = $clientCustomExecutablesData
                                        'Host Port Redirect Mappings' = $EdgeServiceSetting.redirectHostMappingList
                                        'Host Entries' = $hostEntriesData
                                        'Disable HTML Access' = $EdgeServiceSetting.disableHtmlAccess
                                    }
                                    $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }

                                $TableParams += @{
                                    Name = "Horizon Settings Summary - $($($UAGServer).split('.')[0].ToUpper())"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property Name | Table @TableParams
                            }
                        }
                        if ($EdgeServiceSetting.identifier -eq 'WEB_REVERSE_PROXY') {
                            Section -Style Heading4 "Reverse Proxy Settings" {
                                foreach ($ProxySetting in ($EdgeServiceSetting | Where-Object { $_.identifier -eq 'WEB_REVERSE_PROXY' })) {
                                    if ($null -ne $EdgeServiceSetting.trustedCertificates) {
                                        $trustedCertificatesDataProxy = $EdgeServiceSetting.trustedCertificates.name -join "`n"
                                    } else { $trustedCertificatesDataProxy = $null }
                                    if ($null -ne $EdgeServiceSetting.hostEntries) {
                                        $hostEntriesDataProxy = $EdgeServiceSetting.hostEntries -join "`n"
                                    } else { $hostEntriesDataProxy = $null }

                                    Section -Style Heading4 "Reverse Proxy Settings - $($EdgeServiceSetting.instanceId)" {
                                        $securityHeaders = $EdgeServiceSetting.securityHeaders | Out-String
                                        try {
                                            $inObj = [ordered] @{
                                                'Enable Reverse Proxy Settings' = $EdgeServiceSetting.enabled
                                                'Instance ID' = $EdgeServiceSetting.instanceId
                                                'Proxy Destination URL' = $EdgeServiceSetting.proxyDestinationUrl
                                                'Proxy Destination URL Thumbprints' = $EdgeServiceSetting.proxyDestinationUrlThumbprints
                                                #'Auth Method' = $EdgeServiceSetting.authMethods
                                                'Health Check URI Path' = $EdgeServiceSetting.healthCheckUrl
                                                'SAML SP' = $EdgeServiceSetting.samlSP
                                                'External URL' = $EdgeServiceSetting.externalUrl
                                                'Proxy Pattern' = $EdgeServiceSetting.proxyPattern
                                                'Enable Proxy Pattern Canonical Match' = $EdgeServiceSetting.canonicalizationEnabled
                                                'Unsecure Pattern' = $EdgeServiceSetting.unSecurePattern
                                                'Auth Cookie' = $EdgeServiceSetting.authCookie
                                                'Login Redirect URL' = $EdgeServiceSetting.loginRedirectURL
                                                'Proxy Host Pattern' = $EdgeServiceSetting.proxyHostPattern
                                                'Trusted Certificates' = $trustedCertificatesDataProxy
                                                'Response Security Headers' = "$securityHeaders"
                                                'Host Entries' = $hostEntriesDataProxy
                                                'Enable Identity Bridging' = $EdgeServiceSetting
                                                'Authentication Type' = $EdgeServiceSetting.wrpAuthConsumeType
                                                #'Identity Provider' = $EdgeServiceSetting
                                                #'KeyTab' = $EdgeServiceSetting
                                                'Target Service Principal Name' = $EdgeServiceSetting.targetSPN
                                                'User Header Name' = $EdgeServiceSetting.userNameHeader
                                                #'SAML Attributes' = $EdgeServiceSetting
                                                #'SAML Audiences' = $EdgeServiceSetting

                                            }
                                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                        } catch {
                                            Write-PScriboMessage -IsWarning $_.Exception.Message
                                        }

                                        $TableParams += @{
                                            Name = "Reverse Proxy Settings - $($EdgeServiceSetting.instanceId)"
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
                        if ($EdgeServiceSetting.identifier -eq 'TUNNEL_GATEWAY') {
                            Section -Style Heading4 "Tunnel Settings" {
                                if ($null -ne $EdgeServiceSetting.trustedCertificates) {
                                    $trustedCertificates = $EdgeServiceSetting.trustedCertificates -join "`n"
                                } else { $trustedCertificates = $null }
                                if ($null -ne $EdgeServiceSetting.hostEntries) {
                                    $hostEntriesDataTunnel = $EdgeServiceSetting.hostEntries -join "`n"
                                } else { $hostEntriesDataTunnel = $null }

                                try {
                                    $inObj = [ordered] @{
                                        "Enable Tunnel Proxy" = $EdgeServiceSetting.enabled
                                        'API Server URL' = $EdgeServiceSetting.apiServerUrl
                                        'API Server Username' = $EdgeServiceSetting.apiServerUsername
                                        'Tunnel Server Hostname' = $EdgeServiceSetting.airwatchServerHostname
                                        'Organization Group ID' = $EdgeServiceSetting.organizationGroupCode
                                        'Tunnel Configuration ID' = $EdgeServiceSetting.tunnelConfigurationId
                                        'Lock Configuration' = $EdgeServiceSetting.disableAutoConfigUpdate
                                        'Outbound Proxy Host' = $EdgeServiceSetting.outboundProxyHost
                                        'Outbound Proxy Port' = $EdgeServiceSetting.outboundProxyPort
                                        'Outbound Proxy Username' = $EdgeServiceSetting.outboundProxyUsername
                                        'Enable NTLM Authentication' = $EdgeServiceSetting.ntlmAuthentication
                                        'Trusted Certificates' = $trustedCertificatesData
                                        'Host Entries' = $hostEntriesDataTunnel
                                    }
                                    $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }

                                $TableParams += @{
                                    Name = "Tunnel Settings - $($($UAGServer).split('.')[0].ToUpper())"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property Name | Table @TableParams
                            }
                        }
                        if ($EdgeServiceSetting.identifier -eq 'SEG') {
                            Section -Style Heading4 "Secure Email Gateway" {
                                if ($null -ne $EdgeServiceSetting.trustedCertificates) {
                                    $trustedCertificates = $EdgeServiceSetting.trustedCertificates -join "`n"
                                } else { $trustedCertificates = $null }
                                if ($null -ne $EdgeServiceSetting.hostEntries) {
                                    $hostEntriesDataSEG = $EdgeServiceSetting.hostEntries -join "`n"
                                } else { $hostEntriesDataSEG = $null }
                                try {
                                    $inObj = [ordered] @{
                                        "Enable Tunnel Proxy" = $EdgeServiceSetting.enabled
                                        'API Server URL' = $EdgeServiceSetting.apiServerUrl
                                        'API Server Username' = $EdgeServiceSetting.apiServerUsername
                                        'Secure Email Gateway Hostname' = $EdgeServiceSetting.airwatchServerHostname
                                        'Memory Config GUID' = $EdgeServiceSetting.memConfigurationId
                                        'Outbound Proxy Host' = $EdgeServiceSetting.outboundProxyHost
                                        'Outbound Proxy Port' = $EdgeServiceSetting.outboundProxyPort
                                        'Outbound Proxy Username' = $EdgeServiceSetting.outboundProxyUsername
                                        'Trusted Certificates' = $trustedCertificates
                                        'Host Entries' = $hostEntriesDataSEG
                                        'Reinitialize Gateway Process' = $EdgeServiceSetting.reinitializeGatewayProcess
                                        'NTLM Authentication' = $EdgeServiceSetting.ntlmAuthentication
                                        'AirWatch Components Installed' = $EdgeServiceSetting.airwatchComponentsInstalled
                                        'AirWatch Agent Start Up Mode' = $EdgeServiceSetting.airwatchAgentStartUpMode
                                        'Service Port' = $EdgeServiceSetting.servicePort
                                        'Service Install Status' = $EdgeServiceSetting.serviceInstallStatus
                                        'Service Installation Message' = $EdgeServiceSetting.serviceInstallationMessage
                                    }
                                    $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }

                                $TableParams += @{
                                    Name = "Secure Email Gateway - $($($UAGServer).split('.')[0].ToUpper())"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property Name | Table @TableParams
                            }
                        }
                        if ($EdgeServiceSetting.identifier -eq 'CONTENT_GATEWAY') {
                            Section -Style Heading4 "Content Gateway" {
                                if ($null -ne $EdgeServiceSetting.trustedCertificates) {
                                    $trustedCertificates = $EdgeServiceSetting.trustedCertificates -join "`n"
                                } else { $trustedCertificates = $null }
                                if ($null -ne $EdgeServiceSetting.hostEntries) {
                                    $hostEntriesDataCG = $EdgeServiceSetting.hostEntries -join "`n"
                                } else { $hostEntriesDataCG = $null }
                                try {
                                    $inObj = [ordered] @{
                                        "Enable Content Gateway Proxy" = $EdgeServiceSetting.enabled
                                        'API Server URL' = $EdgeServiceSetting.apiServerUrl
                                        'API Server Username' = $EdgeServiceSetting.apiServerUsername
                                        'Content Gateway Hostname' = $EdgeServiceSetting.airwatchServerHostname
                                        'Content Gateway Configuration GUID' = $EdgeServiceSetting.cgConfigurationId
                                        'Outbound Proxy Host' = $EdgeServiceSetting.outboundProxyHost
                                        'Outbound Proxy Port' = $EdgeServiceSetting.outboundProxyPort
                                        'Outbound Proxy Username' = $EdgeServiceSetting.outboundProxyUsername
                                        'Trusted Certificates' = $trustedCertificates
                                        'Host Entries' = $hostEntriesDataCG
                                        'NTLM Authentication' = $EdgeServiceSetting.ntlmAuthentication
                                        'AirWatch Outbound Proxy' = $EdgeServiceSetting.airwatchOutboundProxy
                                        'AirWatch Components Installed' = $EdgeServiceSetting.airwatchComponentsInstalled
                                        'AirWatch Agent Start Up Mode' = $EdgeServiceSetting.airwatchAgentStartUpMode
                                        'Service Install Status' = $EdgeServiceSetting.serviceInstallStatus

                                    }
                                    $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }

                                $TableParams += @{
                                    Name = "Content Gateway - $($($UAGServer).split('.')[0].ToUpper())"
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
            } catch {
                Write-PScriboMessage -IsWarning $_.Exception.Message
            }
        }
    }
    end {}
}