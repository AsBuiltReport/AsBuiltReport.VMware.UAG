function Invoke-AsBuiltReport.VMware.UAG {
    <#
    .SYNOPSIS
        PowerShell script which documents the configuration of VMware UAG Appliance in Word/HTML/XML/Text formats
    .DESCRIPTION
        Documents the configuration of VMware UAG Appliance in Word/HTML/XML/Text formats using PScribo.
    .NOTES
        Version:        0.1.1
        Author:         Chris Hildebrandt
        Twitter:        @childebrandt42
        Github:         https://github.com/AsBuiltReport
        Credits:        Iain Brighton (@iainbrighton) - PScribo module


    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.VMware.UAG
    #>

    [CmdletBinding()]
    param (
        [String[]] $Target,
        [PSCredential] $Credential,
        [String] $StylePath
    ) #Close out Param

    # Import JSON Configuration for Options and InfoLevel
    #$InfoLevel = $ReportConfig.InfoLevel
    #$Options = $ReportConfig.Options

    # If custom style not set, use default style
    if (!$StylePath) {
        & "$PSScriptRoot\..\..\AsBuiltReport.VMware.UAG.Style.ps1"
    } #Close out If (!$StylePath)

    foreach ($UAGServer in $Target) {
    
        Try {
            $UAGServerRest = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/monitor/stats" -Credential $Credential
        } Catch { 
            Write-Error $_
        } #Close Out Try Catch

        #---------------------------------------------------------------------------------------------#
        #                                       SCRIPT BODY                                           #
        #---------------------------------------------------------------------------------------------#
        

        # Generate report if connection to UAG Server Status is Running
        if ($UAGServerRest.accessPointStatusAndStats.overAllStatus.status) {

            #Environment Varibles

            #Admin Users
            $AdminUsers = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/adminusers" -Credential $Credential

            #Auth Methods
                Try {
                    $AuthPassword = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/authmethod/password-auth" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  
                
                try {
                    $AuthRSA = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer/rest/v1/config/authmethod/rsaaa-auth" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }                
                
                Try {
                    $AuthSecureID = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/authmethod/securid-auth" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  
                
                Try {
                    $AuthRadius = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/authmethod/radius-auth" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  

                Try {    
                    $AuthCert = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/authmethod/certificate-auth" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  

                Try {
                    $AuthMethodOCSP = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/authmethod/ocsp/fileNames" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 

                #Custom Branding
                Try {
                    $CustomBranding = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/customBranding" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  

                #Device Policy Settings
                Try {
                    $DevicePolicyConfigured = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/devicepolicy/configured" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  
                
                #EdgeServiceSettings
                Try {
                    $EdgeServiceSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/edgeservice" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  

                #IdentityProviderExternalMetadata
                try {
                    $IDPMetaData = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/idp-metadata" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 

                #JWT Settings
                Try {
                    $JWTSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/jwt" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  

                #KerberosSettings
                Try {
                    $KerberosKeyTab = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/kerberos/keytab" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  

                Try {
                    $KerberosRealms = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/kerberos/realm" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                }  

                #LoadBalancerSettings
                Try {
                    $LoadBalancerSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/loadbalancer/settings" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 
                
                Try{
                    $LoadBalancerState = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/loadbalancer/state" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 
                
                Try{
                    $LoadBalancerStats = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/loadbalancer/stats" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 

                #LogSettings
                Try {
                    $LogMonitorStats = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/monitor/stats" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 

                Try {
                    $LogMonitorGetLogLevels = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/monitor/getLogLevels" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 

                #NIC Settings
                Try {
                    $NICSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/nic" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 

                #Service Provider MetaData
                <#
                Try {
                    $SPMetatDataSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/sp-metadata" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 
                #>

                #Server Certificate
                Try{
                    $ServerCertConfig = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/certs/ssl" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 

                #System Settings
                Try{
                    $SystemSettings = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$UAGServer`:9443/rest/v1/config/system" -Credential $Credential
                } catch {
                    $Trash = $_.Exception.Response.StatusCode.value__
                } 
            
        } # Close out if ($UAGServer) 
        $Trash = ''
        $Trash   #Just using to clear warning in VS code

        #---------------------------------------------------------------------------------------------#
        #                     UAG General Info Edge Service Settings                                  #
        #---------------------------------------------------------------------------------------------#
        
        section -Style Heading1 "Unified Access Gateway $($UAGServer) General Settings" {
        # Generate report if connection to AppVolumes Manager General Information is successful
            if ($EdgeServiceSettings) {
                section -Style Heading2 'Edge Service Settings' {
                    Foreach($EdgeServiceRaw in $EdgeServiceSettings.edgeServiceSettingsList) {

                        #---------------------------------------------------------------------------------------------#
                        #                   UAG General Info Edge Service Settings for Horizon                        #
                        #---------------------------------------------------------------------------------------------#

                        if ($EdgeServiceRaw.identifier -eq 'VIEW') {
                            section -Style Heading3 'Horizon Settings' {

                                Foreach($EdgeServiceSetting in $EdgeServiceRaw) {                                
                                    $EdgeServiceHorizonPSObj = [PSCustomObject]@{
                                        "Enable Horizon" = $EdgeServiceSetting.enabled
                                        'Connection Server URL' = $EdgeServiceSetting.proxyDestinationUrl
                                        'Connection Server URL Thumbprint' = $EdgeServiceSetting.proxyDestinationUrlThumbprints
                                        'Connection Server IP Mode' = $EdgeServiceSetting.proxyDestinationIPSupport
                                        'Enable PCOIP' = $EdgeServiceSetting.pcoipEnabled
                                        'Disable PCOIP Legacy Certificate' = $EdgeServiceSetting.pcoipDisableLegacyCertificate 
                                        'PCOIP External URL' = $EdgeServiceSetting.proxyDestinationIPSupport
                                        'Enable Blast' = $EdgeServiceSetting.blastEnabled
                                        'Blast External URL' = $EdgeServiceSetting.blastExternalUrl
                                        'Enable UDP Tunnel Server' = $EdgeServiceSetting.udpTunnelServerEnabled
                                        'Blast Proxy Certificate' = $EdgeServiceSetting.proxyBlastPemCert
                                        'Enable Tunnel' = $EdgeServiceSetting.tunnelEnabled
                                        'Tunnel External URL' = $EdgeServiceSetting.tunnelExternalUrl
                                        'Tunnel Proxy Certificate' = $EdgeServiceSetting.proxyTunnelPemCert

                                    } # Close out Foreach($EdgeServiceSetting in $EdgeServiceRaw)
                                    $EdgeServiceHorizonPSObj | Table -Name 'UAG Edge Horizon Services ' -List -ColumnWidths 50,50



                                    $i = 0
                                    foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates) {
                                        if($i -gt 0){
                                            $trustedCertificatesData += "`n"
                                        } # Close out if
                                        $trustedCertificatesData += $trustedCertificates.name
                                        $i++
                                    } # Close out foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates)
                                    
                                    $i = 0
                                    foreach ($hostEntries in $EdgeServiceSetting.hostEntries) {
                                        if($i -gt 0){
                                            $hostEntriesData += "`n"
                                        } # Close out if
                                        $hostEntriesData += $hostEntries
                                        $i++
                                    } # Close out foreach ($hostEntries in $EdgeServiceSetting.hostEntries)

                                    $securityHeaders = $EdgeServiceSetting.securityHeaders | Out-String

                                    $EdgeServiceHorizonMorePSObj = [PSCustomObject]@{
                                        "Auth Methods" = $EdgeServiceSetting.authMethods
                                        "Health Check URI Path" = $EdgeServiceSetting.healthCheckUrl
                                        "Endpoint Compliance Check Provider" = $EdgeServiceSetting.devicePolicyServiceProvider
                                        "Proxy Pattern" = $EdgeServiceSetting.proxyPattern
                                        "SAM SP" = $EdgeServiceSetting.samlSP 
                                        "User Name Label for RADIUS" = $EdgeServiceSetting.radiusUsernameLabel
                                        "Passcode Label for RADIUS" = $EdgeServiceSetting.radiusPasscodeLabel
                                        "Match Windows User Name" = $EdgeServiceSetting.matchWindowsUserName
                                        "Enable Windows SSO" = $EdgeServiceSetting.matchWindowsUserName
                                        "Gateway Location" = $EdgeServiceSetting.gatewayLocation
                                        "RADIUS Class Attributes" = $EdgeServiceSetting.radiusClassAttributeList
                                        "Disclaimer Text" = $EdgeServiceSetting.disclaimerText 
                                        "Trusted Certificates" = $trustedCertificatesData
                                        "Response Security Headers" = "$securityHeaders" 
                                        "Host Redirect Mappings" = $EdgeServiceSetting.redirectHostMappingList
                                        "Host Entries" = $hostEntriesData
                                        "Disable HTML Access" = $EdgeServiceSetting.disableHtmlAccess
                                    } # Close Out $EdgeServiceHorizonMorePSObj = [PSCustomObject]
                                    $EdgeServiceHorizonMorePSObj | Table -Name 'UAG Edge Horizon Services ' -List -ColumnWidths 50,50
                                } # Close out Foreach($EdgeServiceSetting in $EdgeServiceRaw)
                            } # End of Horizon
                        PageBreak
                        } # Close Out if ($EdgeServiceRaw.identifier -eq 'VIEW')
                        

                        #---------------------------------------------------------------------------------------------#
                        #               UAG General Info Edge Service Settings for Reverse Proxy                      #
                        #---------------------------------------------------------------------------------------------#


                        if ($EdgeServiceRaw.identifier -eq 'WEB_REVERSE_PROXY') {
                            section -Style Heading3 'Reverse Proxy Settings' {

                                Foreach($EdgeServiceSetting in $EdgeServiceRaw) {      

                                    $i = 0
                                    foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates) {
                                        if($i -gt 0){
                                            $trustedCertificatesData += "`n"
                                        } # Close out if
                                        $trustedCertificatesData += $trustedCertificates.name
                                        $i++
                                    } # Close out foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates)

                                    $i = 0
                                    foreach ($hostEntries in $EdgeServiceSetting.hostEntries) {
                                        if($i -gt 0){
                                            $hostEntriesData += "`n"
                                        } # Close out if
                                        $hostEntriesData += $hostEntries
                                        $i++
                                    } # Close out foreach ($hostEntries in $EdgeServiceSetting.hostEntries)

                                    $securityHeaders = $EdgeServiceSetting.securityHeaders | Out-String
                    
                                    $EdgeServiceReverseProxyPSObj = [PSCustomObject]@{
                                        "Enable Reverse Proxy" = $EdgeServiceSetting.enabled
                                        'Proxy Server URL' = $EdgeServiceSetting.proxyDestinationUrl
                                        'Proxy Server URL Thumbprint' = $EdgeServiceSetting.proxyDestinationUrlThumbprints
                                        'Proxy Server Auth Mode' = $EdgeServiceSetting.authMethods
                                        'Health Check URI Path' = $EdgeServiceSetting.healthCheckUrl
                                        'SAML SP' = $EdgeServiceSetting.samlSP 
                                        'External URL' = $EdgeServiceSetting.externalUrl
                                        'Proxy Pattern' = $EdgeServiceSetting.proxyPattern
                                        'UnSecure Pattern' = $EdgeServiceSetting.unSecurePattern
                                        'Auth Cookie' = $EdgeServiceSetting.authCookie
                                        'Login Redirect URL' = $EdgeServiceSetting.loginRedirectURL
                                        'Proxy Host Pattern' = $EdgeServiceSetting.proxyHostPattern
                                        'Trusted Certificates' = $trustedCertificatesData
                                        'Response Security Headers' = $securityHeaders
                                        'Host Entries' = $hostEntriesData
                                    } # Close out $EdgeServiceReverseProxyPSObj = [PSCustomObject]
                                    $EdgeServiceReverseProxyPSObj | Table -Name 'UAG Edge Reverse Proxy Settings' -List -ColumnWidths 50,50
                                } # Close out Foreach($EdgeServiceSetting in $EdgeServiceRaw)
                            } # Close out section -Style Heading3 'Reverse Proxy Settings'
                        PageBreak
                        } # Close Out if ($EdgeServiceRaw.identifier -eq 'WEB_REVERSE_PROXY')


                        #---------------------------------------------------------------------------------------------#
                        #              UAG General Info Edge Service Settings for Tunnel Settings                     #
                        #---------------------------------------------------------------------------------------------#


                        if ($EdgeServiceRaw.identifier -eq 'TUNNEL_GATEWAY') {
                            section -Style Heading3 'Tunnel Settings' {

                                Foreach($EdgeServiceSetting in $EdgeServiceRaw) {      

                                    $i = 0
                                    foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates) {
                                        if($i -gt 0){
                                            $trustedCertificatesData += "`n"
                                        } # Close out if
                                        $trustedCertificatesData += $trustedCertificates.name
                                        $i++
                                    } # Close out foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates)

                                    $i = 0
                                    foreach ($hostEntries in $EdgeServiceSetting.hostEntries) {
                                        if($i -gt 0){
                                            $hostEntriesData += "`n"
                                        } # Close out if
                                        $hostEntriesData += $hostEntries
                                        $i++
                                    } # Close out foreach ($hostEntries in $EdgeServiceSetting.hostEntries)
                    
                                    $EdgeServiceTunnelSettingsPSObj = [PSCustomObject]@{
                                        "Enable Tunnel Proxy" = $EdgeServiceSetting.enabled
                                        'API Server URL' = $EdgeServiceSetting.apiServerUrl
                                        'API Server Username' = $EdgeServiceSetting.apiServerUsername
                                        'Organization Group ID' = $EdgeServiceSetting.organizationGroupCode
                                        'Tunnel Server Hostname' = $EdgeServiceSetting.airwatchServerHostname
                                        'Outbound Proxy Host' = $EdgeServiceSetting.outboundProxyHost 
                                        'Outbound Proxy Port' = $EdgeServiceSetting.outboundProxyPort
                                        'Outbound Proxy Username' = $EdgeServiceSetting.outboundProxyUsername
                                        'Enable NTLM Authentication' = $EdgeServiceSetting.ntlmAuthentication
                                        'Use for Tunnel Proxy' = $EdgeServiceSetting.airwatchOutboundProxy
                                        'Trusted Certificates' = $trustedCertificatesData
                                        'Host Entries' = $hostEntriesData
                                        'AirWatch Components Installed' = $EdgeServiceSetting.airwatchComponentsInstalled
                                        'AirWatch Agent Start Up Mode' = $EdgeServiceSetting.airwatchAgentStartUpMode
                                        'Service Install Status' = $EdgeServiceSetting.serviceInstallStatus

                                    } # Close out $EdgeServiceTunnelSettingsPSObj = [PSCustomObject]
                                    $EdgeServiceTunnelSettingsPSObj | Table -Name 'UAG Edge Tunnel Settings' -List -ColumnWidths 50,50
                                } # Close out Foreach($EdgeServiceSetting in $EdgeServiceRaw)
                            } # Close out section -Style Heading3 'Tunnel Settings'
                        PageBreak
                        } # Close Out if ($EdgeServiceRaw.identifier -eq 'TUNNEL_GATEWAY')


                        #---------------------------------------------------------------------------------------------#
                        #       UAG General Info Edge Service Settings for Secure Email Gateway Settings              #
                        #---------------------------------------------------------------------------------------------#


                        if ($EdgeServiceRaw.identifier -eq 'SEG') {
                            section -Style Heading3 'Secure Email Gateway Settings' {

                                Foreach($EdgeServiceSetting in $EdgeServiceRaw) {      

                                    $i = 0
                                    foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates) {
                                        if($i -gt 0){
                                            $trustedCertificatesData += "`n"
                                        } # Close out if
                                        $trustedCertificatesData += $trustedCertificates.name
                                        $i++
                                    } # Close out foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates)

                                    $i = 0
                                    foreach ($hostEntries in $EdgeServiceSetting.hostEntries) {
                                        if($i -gt 0){
                                            $hostEntriesData += "`n"
                                        } # Close out if
                                        $hostEntriesData += $hostEntries
                                        $i++
                                    } # Close out foreach ($hostEntries in $EdgeServiceSetting.hostEntries)
                    
                                    $EdgeServiceTunnelSettingsPSObj = [PSCustomObject]@{
                                        "Enable Tunnel Proxy" = $EdgeServiceSetting.enabled
                                        'API Server URL' = $EdgeServiceSetting.apiServerUrl
                                        'API Server Username' = $EdgeServiceSetting.apiServerUsername
                                        'Secure Email Gateway Hostname' = $EdgeServiceSetting.airwatchServerHostname
                                        'Memory Config GUID' = $EdgeServiceSetting.memConfigurationId
                                        'Outbound Proxy Host' = $EdgeServiceSetting.outboundProxyHost
                                        'Outbound Proxy Port' = $EdgeServiceSetting.outboundProxyPort
                                        'Outbound Proxy Username' = $EdgeServiceSetting.outboundProxyUsername
                                        'Trusted Certificates' = $trustedCertificatesData
                                        'Host Entries' = $hostEntriesData
                                        'Reinitialize Gateway Process' = $EdgeServiceSetting.reinitializeGatewayProcess
                                        'NTLM Authentication' = $EdgeServiceSetting.ntlmAuthentication
                                        'AirWatch Outbound Proxy' = $EdgeServiceSetting.airwatchOutboundProxy
                                        'AirWatch Components Installed' = $EdgeServiceSetting.airwatchComponentsInstalled
                                        'AirWatch Agent Start Up Mode' = $EdgeServiceSetting.airwatchAgentStartUpMode
                                        'Service Port' = $EdgeServiceSetting.servicePort
                                        'Service Install Status' = $EdgeServiceSetting.serviceInstallStatus
                                        'Service Installation Message' = $EdgeServiceSetting.serviceInstallationMessage

                                    } # Close out $EdgeServiceTunnelSettingsPSObj = [PSCustomObject]
                                    $EdgeServiceTunnelSettingsPSObj | Table -Name 'UAG Edge Secure Email Gateway Settings' -List -ColumnWidths 50,50
                                } # Close out Foreach($EdgeServiceSetting in $EdgeServiceRaw)
                            } # Close out section -Style Heading3 'Secure Email Gateway Settings'
                        PageBreak
                        } # Close Out if ($EdgeServiceRaw.identifier -eq 'SEG')


                        #---------------------------------------------------------------------------------------------#
                        #       UAG General Info Edge Service Settings for Content Gateway Settings                   #
                        #---------------------------------------------------------------------------------------------#


                        if ($EdgeServiceRaw.identifier -eq 'CONTENT_GATEWAY') {
                            section -Style Heading3 'Content Gateway Settings' {

                                Foreach($EdgeServiceSetting in $EdgeServiceRaw) {      

                                    $i = 0
                                    foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates) {
                                        if($i -gt 0){
                                            $trustedCertificatesData += "`n"
                                        } # Close out if
                                        $trustedCertificatesData += $trustedCertificates.name
                                        $i++
                                    } # Close out foreach ($trustedCertificates in $EdgeServiceSetting.trustedCertificates)

                                    $i = 0
                                    foreach ($hostEntries in $EdgeServiceSetting.hostEntries) {
                                        if($i -gt 0){
                                            $hostEntriesData += "`n"
                                        } # Close out if
                                        $hostEntriesData += $hostEntries
                                        $i++
                                    } # Close out foreach ($hostEntries in $EdgeServiceSetting.hostEntries)
                    
                                    $EdgeServiceTunnelSettingsPSObj = [PSCustomObject]@{
                                        "Enable Content Gateway Proxy" = $EdgeServiceSetting.enabled
                                        'API Server URL' = $EdgeServiceSetting.apiServerUrl
                                        'API Server Username' = $EdgeServiceSetting.apiServerUsername
                                        'Content Gateway Hostname' = $EdgeServiceSetting.airwatchServerHostname
                                        'Content Gateway Configuration GUID' = $EdgeServiceSetting.cgConfigurationId
                                        'Outbound Proxy Host' = $EdgeServiceSetting.outboundProxyHost
                                        'Outbound Proxy Port' = $EdgeServiceSetting.outboundProxyPort
                                        'Outbound Proxy Username' = $EdgeServiceSetting.outboundProxyUsername
                                        'Trusted Certificates' = $trustedCertificatesData
                                        'Host Entries' = $hostEntriesData
                                        'NTLM Authentication' = $EdgeServiceSetting.ntlmAuthentication
                                        'AirWatch Outbound Proxy' = $EdgeServiceSetting.airwatchOutboundProxy
                                        'AirWatch Components Installed' = $EdgeServiceSetting.airwatchComponentsInstalled
                                        'AirWatch Agent Start Up Mode' = $EdgeServiceSetting.airwatchAgentStartUpMode
                                        'Service Install Status' = $EdgeServiceSetting.serviceInstallStatus

                                    } # Close out $EdgeServiceTunnelSettingsPSObj = [PSCustomObject]
                                    $EdgeServiceTunnelSettingsPSObj | Table -Name 'UAG Edge Content Gateway Settings' -List -ColumnWidths 50,50
                                } # Close out Foreach($EdgeServiceSetting in $EdgeServiceRaw)
                            } # Close out section -Style Heading3 'Content Gateway Settings'
                        PageBreak
                        } # Close Out if ($EdgeServiceRaw.identifier -eq 'CONTENT_GATEWAY')
                    } # Close Out Foreach($EdgeServiceRaw in $EdgeServiceSettings.edgeServiceSettingsList)
                } #Close out section -Style Heading2 'Edge Service Settings'
            } #Close Out if ($EdgeServiceSettings)


            #---------------------------------------------------------------------------------------------#
            #                               Authentication Settings                                       #
            #---------------------------------------------------------------------------------------------#

            section -Style Heading2 'Authentication Settings' {

                #---------------------------------------------------------------------------------------------#
                #                                        RSA SecurID                                          #
                #---------------------------------------------------------------------------------------------#
                
                if ($AuthSecureID) {
                    section -Style Heading3 'RSA SecurID' {
                        $AuthSecureIDPSObj = [PSCustomObject]@{
                            "Enable RSA SecurID" = $AuthSecurID.enabled
                            "Name" = $AuthSecurID.name
                            "Display Name" = $AuthSecurID.displayname
                            "Class Name" = $AuthSecurID.classname
                            "Authentication Method" = $AuthSecurID.authMethod
                            "Version Number" = $AuthSecurID.versionNum
                            "Number if Iterations" = $AuthSecurID.numIterations
                            "External Host Name" = $AuthSecurID.externalHostName
                            "Internal Host Name" = $AuthSecurID.internalHostName
                            "Name ID Suffix" = $AuthSecurID.nameIdSuffix
                        } # Close out $AuthSecureIDPSObj = [PSCustomObject]
                        $AuthSecureIDPSObj | Table -Name 'RSA SecurID' -List -ColumnWidths 50,50
                    } # Close out section -Style Heading3 'RSA SecurID'
                PageBreak
                } # Close out if ($AuthSecureID)


                #---------------------------------------------------------------------------------------------#
                #                                  RADIUS Settings                                            #
                #---------------------------------------------------------------------------------------------#
                
                if ($AuthRadius) {
                    section -Style Heading3 'RADIUS Settings' {
                        $AuthRadiusPSObj = [PSCustomObject]@{
                            "Enable RADIUS" = $AuthRadius.enabled
                            "Authentication Type" = $AuthRadius.authType
                            "Num of Authentication attempts allowed" = $AuthRadius.numIterations
                            "Number of attempts to RADIUS server" = $AuthRadius.numAttempts
                            "Server Timeout in Seconds " = $AuthRadius.serverTimeout
                            "RADIUS Server Host name" = $AuthRadius.hostName
                            "RADIUS Server Display name" = $AuthRadius.displayName
                            "Authentication Port" = $AuthRadius.authPort
                            "Realm Prefix" = $AuthRadius.realmPrefix
                            "Realm suffix" = $AuthRadius.realmSuffix
                            "Name Id Suffix" = $AuthRadius.nameIdSuffix
                            "Login page passphrase hint" = $AuthRadius.radiusDisplayHint
                            "Enable basic MS-CHAPv2 validation" = $AuthRadius.enableBasicMSCHAPv2Validation_1
                            "RADIUS Accounting Port" = $AuthRadius.accountingPort
                            "Enable secondary server" = $AuthRadius.enabledAux
                            "Number of attempts to secondary RADIUS server" = $AuthRadius.numAttempts_2
                            "Server Timeout in Seconds" = $AuthRadius.serverTimeout_2
                            "RADIUS server Hostname/Address for secondary server" = $AuthRadius.hostName_2
                            "Authentication PORT for secondary server" = $AuthRadius.authPort_2
                            "Authentication type for secondary server" = $AuthRadius.authType_2
                            "Realm prefix for secondary server" = $AuthRadius.realmPrefix_2
                            "Realm suffix for secondary server" = $AuthRadius.realmSuffix_2
                            "Enable basic MS-CHAPv2 validation for secondary server" = $AuthRadius.enableBasicMSCHAPv2Validation_2
                            "Secondary RADIUS Accounting Port" = $AuthRadius.accountingPort_2
                            "RADIUS Version " = $AuthRadius.versionNum
                            "Show Domain If User Input Available" = $AuthRadius.showDomainIfUserInputAvailable
                            "Direct Auth Chained Username" = $AuthRadius.directAuthChainedUsername
                            "Auth Method" = $AuthRadius.authMethod
                            "Class Name" = $AuthRadius.className
                        } # Close out $AuthRadiusPSObj = [PSCustomObject]
                        $AuthRadiusPSObj | Table -Name 'RADIUS Settings' -List -ColumnWidths 50,50
                    } # Close out section -Style Heading3 'RADIUS Settings'
                PageBreak
                } # Close out if ($AuthRadius)
                

                #---------------------------------------------------------------------------------------------#
                #                             x.509 Certificate Settings                                      #
                #---------------------------------------------------------------------------------------------#
                
                if ($AuthCert) {
                    section -Style Heading3 'X.509 Certificate Settings' {
                        $AuthCertPSObj = [PSCustomObject]@{
                            "Enable X.509 Certificate" = $AuthCert.enabled
                            "Root and Intermediate CA Certificates" = $AuthCert.authType
                            "Enable Cert Revocation" = $AuthCert.numIterations
                            "Use CRL from Certificates" = $AuthCert.numAttempts
                            "CRL Location" = $AuthCert.serverTimeout
                            "Enable OCSP Revocation" = $AuthCert.hostName
                            "Use CRL in case of OCSP Failure" = $AuthCert.displayName
                            "Send OCSP Nonce" = $AuthCert.authPort
                            "OCSP URL" = $AuthCert.realmPrefix
                            "Use OCSP URL from certificate" = $AuthCert.realmSuffix
                            "Enable Consent Form before Authentication" = $AuthCert.nameIdSuffix
                            "Consent Form Content" = $AuthCert.radiusDisplayHint
                        } # Close out $AuthCertPSObj = [PSCustomObject]
                        $AuthCertPSObj | Table -Name 'X.509 Certificate' -List -ColumnWidths 50,50
                    } # Close out section -Style Heading3 'X.509 Certificate'
                PageBreak
                } # Close out if ($AuthCert)
                

                #---------------------------------------------------------------------------------------------#
                #                             RSA Adaptive Authentication                                     #
                #---------------------------------------------------------------------------------------------#
                

                if ($AuthRSA) {
                    section -Style Heading3 'RSA Adaptive Authentication Settings' {
                        $AuthRSAPSObj = [PSCustomObject]@{
                            "Enable RADIUS" = $AuthRSA.enabled
                            "Authentication Type" = $AuthRSA.authType
                            "Num of Authentication attempts allowed" = $AuthRSA.numIterations
                            "Number of attempts to RADIUS server" = $AuthRSA.numAttempts
                            "Server Timeout in Seconds " = $AuthRSA.serverTimeout
                            "RADIUS Server Host name" = $AuthRSA.hostName
                            "RADIUS Server Display name" = $AuthRSA.displayName
                            "Authentication Port" = $AuthRSA.authPort
                            "Realm Prefix" = $AuthRSA.realmPrefix
                            "Realm suffix" = $AuthRSA.realmSuffix
                            "Name Id Suffix" = $AuthRSA.nameIdSuffix
                            "Login page passphrase hint" = $AuthRSA.radiusDisplayHint
                            "Enable basic MS-CHAPv2 validation" = $AuthRSA.enableBasicMSCHAPv2Validation_1
                            "RADIUS Accounting Port" = $AuthRSA.accountingPort
                            "Enable secondary server" = $AuthRSA.enabledAux
                            "Number of attempts to secondary RADIUS server" = $AuthRSA.numAttempts_2
                            "Server Timeout in Seconds" = $AuthRSA.serverTimeout_2
                            "RADIUS server Hostname/Address for secondary server" = $AuthRSA.hostName_2
                            "Authentication PORT for secondary server" = $AuthRSA.authPort_2
                            "Authentication type for secondary server" = $AuthRSA.authType_2
                            "Realm prefix for secondary server" = $AuthRSA.realmPrefix_2
                            "Realm suffix for secondary server" = $AuthRSA.realmSuffix_2
                            "Enable basic MS-CHAPv2 validation for secondary server" = $AuthRSA.enableBasicMSCHAPv2Validation_2
                            "Secondary RADIUS Accounting Port" = $AuthRSA.accountingPort_2
                            "RADIUS Version " = $AuthRSA.versionNum
                            "Show Domain If User Input Available" = $AuthRSA.showDomainIfUserInputAvailable
                            "Direct Auth Chained Username" = $AuthRSA.directAuthChainedUsername
                            "Auth Method" = $AuthRSA.authMethod
                            "Class Name" = $AuthRSA.className
                        } # Close out $AuthRSAPSObj = [PSCustomObject]
                        $AuthRSAPSObj | Table -Name 'RSA Adaptive Authentication Settings' -List -ColumnWidths 50,50
                    } # Close section -Style Heading3 'RSA Adaptive Authentication Settings'
                PageBreak
                } # Close if ($AuthRSA)


                #---------------------------------------------------------------------------------------------#
                #                                  Password Auth                                              #
                #---------------------------------------------------------------------------------------------#
                
                if ($AuthPassword) {
                    section -Style Heading3 'Password Auth' {
                        $AuthPasswordPSObj = [PSCustomObject]@{
                            "Enable Password" = $AuthPassword.Enabled
                            "Name" = $AuthPassword.name
                            "Display Name" = $AuthPassword.displayName
                            "Class Name" = $AuthPassword.className
                            "Authentication Method" = $AuthPassword.authMethod
                            "Version Number" = $AuthPassword.versionNum
                            "Number if Iterations" = $AuthPassword.numIterations
                            "Directory Type" = $AuthPassword.dirtype
                            "Port" = $AuthPassword.port
                            "Host" = $AuthPassword.host
                            "Is SSL Enabled" = $AuthPassword.isSsl
                            "User Service Account" = $AuthPassword.useSrv
                            "Base DN" = $AuthPassword.baseDN
                            "Bind DN" = $AuthPassword.bindDN
                            "Directory UID Attribute" = $AuthPassword.dirUIDAttribute
                            "SAML Name Id Format" = $AuthPassword.samlNameIdFormat
                            "Cert" = $AuthPassword.cert
                            "Use Start TLS" = $AuthPassword.useStartTls
                            "Is Password Reset Feature Enabled" = $AuthPassword.isPasswordResetFeatureEnabled
                            "Group Object Query" = $AuthPassword.groupObjectQuery
                            "Bind User Object Query" = $AuthPassword.bindUserObjectQuery
                            "User Object Query" = $AuthPassword.userObjectQuery
                            "Custom Directory Search Attribute" = $AuthPassword.customDirectorySearchAttribute
                            "Membership Attribute" = $AuthPassword.membershipAttribute
                            "Object UUID Attribute" = $AuthPassword.objectUuidAttribute
                            "Distinguished Name Attribute" = $AuthPassword.distinguishedNameAttribute
                            "Canonical Name Attribute" = $AuthPassword.canonicalNameAttribute
                            "Cross Refs" = $AuthPassword.crossRefs
                            "Show Domain If User Input Available" = $AuthPassword.showDomainIfUserInputAvailable
                        } # Close out $AuthPasswordPSObj = [PSCustomObject]
                        $AuthPasswordPSObj | Table -Name 'Password Auth' -List -ColumnWidths 50,50
                    } # Close out section -Style Heading3 'Password Auth'
                PageBreak
                } # Close out if ($AuthPassword)
            } # Close out section -Style Heading2 'Edge Service Settings'
        } # Close Out section -Style Heading1 'Unified Access Gateway General Settings'

        #---------------------------------------------------------------------------------------------#
        #                                UAG Advanced Settings                                        #
        #---------------------------------------------------------------------------------------------#
    
        section -Style Heading1 'Unified Access Gateway Advanced Settings' {
            # Generate report if connection to AppVolumes Manager General Information is successful

            #---------------------------------------------------------------------------------------------#
            #                                Advanced Settings                                            #
            #---------------------------------------------------------------------------------------------#

            section -Style Heading2 'Advanced Settings' {

                #---------------------------------------------------------------------------------------------#
                #                                System Configuration                                         #
                #---------------------------------------------------------------------------------------------#
                if ($SystemSettings) {
                    section -Style Heading3 'System Configuration' {
                        $SystemSettingsPSObj = [PSCustomObject]@{
                            "UAG Name" = $SystemSettings.uagName
                            "UAG Locale" = $SystemSettings.locale
                            "FIPS Enabled" = $SystemSettings.fipsEnabled
                            "Password Age" = $SystemSettings.adminPasswordExpirationDays
                            "Cipher Suites" = $SystemSettings.cipherSuites
                            "Honor Cipher Order" = $SystemSettings.honorCipherOrder
                            "Enable TLS 1.0" = $SystemSettings.tls10Enabled
                            "Enable TLS 1.1" = $SystemSettings.tls11Enabled
                            "Enable TLS 1.2" = $SystemSettings.tls12Enabled
                            "Enable SSLv3.0" = $SystemSettings.ssl30Enabled
                            "Syslog Type" = $SystemSettings.sysLogType
                            "Syslog URL" = $SystemSettings.syslogUrl
                            "Syslog Audit URL" = $SystemSettings.syslogAuditUrl
                            "Health Check URL" = $SystemSettings.healthCheckUrl
                            "Cookies to Be Cached" = $SystemSettings.cookiesToBeCached
                            "Quiesce Mode" = $SystemSettings.quiesceMode
                            "Monitor Interval" = $SystemSettings.monitorInterval
                            "Authentication Timeout" = $SystemSettings.authenticationTimeout
                            "Body Receive Timeout" = $SystemSettings.bodyReceiveTimeoutMsec
                            "Client Connection Idle Timeout" = $SystemSettings.clientConnectionIdleTimeout
                            "Request Timeout" = $SystemSettings.requestTimeoutMsec
                            "HTTP Connection Timeout" = $SystemSettings.httpConnectionTimeout
                            "Clock Skew Tolerance" = $SystemSettings.clockSkewTolerance
                            "Session Timeout" = $SystemSettings.sessionTimeout
                            "TLS Port Sharing Enabled" = $SystemSettings.TLSPortSharingEnabled
                            "Join CEIP" = $SystemSettings.ceipEnabled
                            "Enable SNMP" = $SystemSettings.snmpEnabled
                            "DNS" = $SystemSettings.dns
                            "DNS Search" = $SystemSettings.dnsSearch
                            "NTP Servers" = $SystemSettings.ntpServers
                            "Fallback NTP Servers" = $SystemSettings.fallBackNtpServers
                            "SSH Enabled" = $SystemSettings.sshenabled
                            "IP Mode NIC1" = $SystemSettings.ipmode
                            "IP Mode NIC2" = $SystemSettings.ipModeforNIC2
                            "IP Mode NIC3" = $SystemSettings.ipModeforNIC3
                            "Default Redirect Host" = $SystemSettings.defaultRedirectHost
                        } # Close Out $SystemSettingsPSObj = [PSCustomObject]
                        $SystemSettingsPSObj | Table -Name 'UAG System Configuration' -List -ColumnWidths 50,50
                    } # Close out section -Style Heading3 'System Configuration'
                PageBreak
                } # End System Settings


                #---------------------------------------------------------------------------------------------#
                #                                Network Settings                                             #
                #---------------------------------------------------------------------------------------------#
                if ($NICSettings) {
                    section -Style Heading3 'Network Settings' {
                        foreach($NICSetting in $NICSettings.nicSettingsList) {
                            if ($NICSetting.nic -eq 'eth0') {
                                $IPMode = $SystemSettings.ipmode
                            } # Close out If
                            if ($NICSetting.nic -eq 'eth1') {
                                $IPMode = $SystemSettings.ipModeforNIC2
                            } # Close out If
                            if ($NICSetting.nic -eq 'eth2') {
                                $IPMode = $SystemSettings.ipModeforNIC3
                            } # Close out If
                            $NICName = $NICSetting.nic
                            section -Style Heading4 "Network Adapter $NICName" {
                                $NICSettingsPSObj = [PSCustomObject]@{
                                    "NIC" = $NICSetting.nic
                                    "IPv4 Address" = $NICSetting.ipv4Address
                                    "IPv4 Subnet" = $NICSetting.ipv4Netmask
                                    "IP Allocation Mode" = $NICSetting.allocationMode
                                    "IP Mode" = $IPMode
                                }  # Close out $NICSettingsPSObj = [PSCustomObject] 
                            $NICSettingsPSObj | Table -Name 'UAG Network Settings ' -List -ColumnWidths 50,50
                            } # Close out section -Style Heading4 "Network Adapter $NICName"
                        } # Close out foreach($NICSetting in $NICSettings.nicSettingsList)
                    } # Close Out section -Style Heading3 'Network Settings'
                } # Close Out if ($NICSettings)
            
            
                #---------------------------------------------------------------------------------------------#
                #                         High Availability Settings                                           #
                #---------------------------------------------------------------------------------------------#
                if ($LoadBalancerSettings) {
                    section -Style Heading3 'High Availability Settings' {
                        $LoadBalancerSettingsPSObj = [PSCustomObject]@{
                            "High Availability Mode" = $LoadBalancerSettings.loadBalancerMode
                            "High Availability State" = $LoadBalancerState
                            "Virtual IP Address" = $LoadBalancerSettings.virtualIPAddress
                            "Group ID" = $LoadBalancerSettings.groupID
                        } # Close out $LoadBalancerSettingsPSObj = [PSCustomObject]
                        $LoadBalancerSettingsPSObj | Table -Name 'UAG High Availability Settings' -List -ColumnWidths 50,50
                    } # Close section -Style Heading3 'High Availability Settings'


                    section -Style Heading3 'High Availability Stats' {
                        $LoadBalancerSettingsPSObj = [PSCustomObject]@{
                            "Current Connections" = $LoadBalancerStats.ALL.currentConnections
                            "Connection High Watermark" = $LoadBalancerStats.ALL.connectionHighWatermark
                            "Total Connections" = $LoadBalancerStats.ALL.totalConnections
                            "Node Status" = $LoadBalancerStats.ALL.nodeStatus
                            "Bytes Sent to Node" = $LoadBalancerStats.ALL.bytesSentToNode
                            "Bytes Received from Node" = $LoadBalancerStats.ALL.bytesReceivedFromNode
                            "Incoming Connection Failure Count" = $LoadBalancerStats.ALL.incomingConnectionFailureCount
                            "Backend Connection Failure Count" = $LoadBalancerStats.ALL.backendConnectionFailureCount
                            "Health Check Failure Count" = $LoadBalancerStats.ALL.healthCheckFailureCount
                            "Average Connection Queue Time To Backend" = $LoadBalancerStats.ALL.averageConnectionQueueTimeToBackend
                        } # Close out $LoadBalancerSettingsPSObj = [PSCustomObject]
                        $LoadBalancerSettingsPSObj | Table -Name 'UAG High Availability Stats' -List -ColumnWidths 50,50
                    } # Close section -Style Heading3 'High Availability Stats'
                } # Close if ($LoadBalancerSettings)


                #---------------------------------------------------------------------------------------------#
                #                         Custom Branding Settings                                            #
                #---------------------------------------------------------------------------------------------#
                if ($CustomBranding) {
                    section -Style Heading3 'Custom Branding Settings' {
                        $CustomBrandingPSObj = [PSCustomObject]@{
                            "Resource Content" = $CustomBranding.customBrandingList.resourceContent
                            "Resource Name" = $CustomBranding.customBrandingList.resourceName
                            "Resource Map Key" = $CustomBranding.customBrandingList.resourceMapKey
                        } # Close out section -Style Heading3 'Custom Branding Settings'
                        $CustomBrandingPSObj | Table -Name 'Custom Branding Settings' -List -ColumnWidths 50,50
                    } # Close section -Style Heading3 'Custom Branding Settings'
                } # Close if ($CustomBranding)


                #---------------------------------------------------------------------------------------------#
                #                               TLS Server Settings                                           #
                #---------------------------------------------------------------------------------------------#
                if ($ServerCertConfig) {
                    section -Style Heading3 'TLS Server Certificate Settings' {
                        $ServerCertConfigPSObj = [PSCustomObject]@{
                            "TLS Server Cert Configured" = 'True'
                        } # Close out $ServerCertConfigPSObj = [PSCustomObject]
                        $ServerCertConfigPSObj | Table -Name 'UAG High Avalability Settings ' -List -ColumnWidths 50,50
                    } # Close out  section -Style Heading3 'TLS Server Certificate Settings'
                } # Close out  if ($ServerCertConfig)

                
                #---------------------------------------------------------------------------------------------#
                #                                     SAML Settings                                           #
                #---------------------------------------------------------------------------------------------#
                if ($IDPMetaData) {
                    section -Style Heading3 'SAML Settings' {
                        $IDPMetaDataPSObj = [PSCustomObject]@{
                            "Private Key Pem" = $IDPMetaData.privatekeyPem
                            "Cert Chain Pem" = $IDPMetaData.certchainPem
                            "Metadata XML" = $IDPMetaData.metadataXml
                        } # Close out section -Style Heading3 'SAML Settings'
                        $IDPMetaDataPSObj | Table -Name 'SAML Settings' -List -ColumnWidths 50,50
                    } # Close out  section -Style Heading3 'SAML Settings'
                } # Close out  if ($IDPMetaData)
                

                #---------------------------------------------------------------------------------------------#
                #                     Endpoint Compliance Check Provider Settings                             #
                #---------------------------------------------------------------------------------------------#
                if ($DevicePolicyConfigured.devicePolicySettingsList) {
                    section -Style Heading3 'Endpoint Compliance Check Provider Settings' {
                        $DevicePolicyConfiguredPSObj = [PSCustomObject]@{
                            "Name" = $DevicePolicyConfigured.devicePolicySettingsList.name
                            "User Name" = $DevicePolicyConfigured.devicePolicySettingsList.username
                            "Host Name" = $DevicePolicyConfigured.devicePolicySettingsList.hostName
                            "Allowed Statuses" = $DevicePolicyConfigured.devicePolicySettingsList.allowedStatuses
                        } # Close out $DevicePolicyConfiguredPSObj = [PSCustomObject]
                        $DevicePolicyConfiguredPSObj | Table -Name 'Endpoint Compliance Check Provider Settings ' -List -ColumnWidths 50,50
                    } # Close out  section -Style Heading3 'Endpoint Compliance Check Provider Settings'
                } # Close out  if ($DevicePolicyConfigured)
                

                #---------------------------------------------------------------------------------------------#
                #                                      JWT Settings                                           #
                #---------------------------------------------------------------------------------------------#
                if ($JWTSettings) {
                    section -Style Heading3 'JWT Settings' {
                        $JWTSettingsPSObj = [PSCustomObject]@{
                            "JWT Name" = $JWTSettings.jwtSettingsList.name
                            "JWT Issuer" = $JWTSettings.jwtSettingsList.name
                            "JWT Dynamic Public Key URL" = $JWTSettings.jwtSettingsList.publicKeyURLSettings.URL
                            "JWT Public key URL thumbprints" = $JWTSettings.jwtSettingsList.publicKeyURLSettings.urlThumbprints
                            "JWT Trusted Certificates" = $JWTSettings.jwtSettingsList.publicKeyURLSettings.trustedCertificates.name
                            "JWT Public Key Refresh Interval" = $JWTSettings.jwtSettingsList.publicKeyURLSettings.urlResponseRefreshInterval
                            "JWT Static Public Keys" = $JWTSettings.jwtSettingsList.StaticPublicKeys.name #May Need to loop
                        } # Close out $JWTSettingsPSObj = [PSCustomObject]
                        $JWTSettingsPSObj | Table -Name 'JWT Settings ' -List -ColumnWidths 50,50
                    } # Close out  section -Style Heading3 'JWT Settings'
                } # Close out  if ($JWTSettings)


                #---------------------------------------------------------------------------------------------#
                #                                  Account Settings                                           #
                #---------------------------------------------------------------------------------------------#
                if ($AdminUsers) {
                    section -Style Heading3 'Account Settings' {
                        foreach($AdminUser in $AdminUsers.adminUsersList) {
                            $AdminUserName = $AdminUser.adminUsersList.name
                            $AdminRoles = $AdminUser.Roles | Out-String
                            section -Style Heading4 "UAG Admin User $AdminUserName" {
                                $AdminUsersPSObj = [PSCustomObject]@{
                                    "Name" = $AdminUser.name
                                    "User ID" = $AdminUser.userId
                                    "Enabled" = $AdminUser.enabled
                                    "Roles" = $AdminRoles
                                    "Admin Password Set Time" = $AdminUser.adminPasswordSetTime
                                    "Num of Days Remaining for Pwd Expiry" = $AdminUser.noOfDaysRemainingForPwdExpiry
                                } # Close out $AdminUsersPSObj = [PSCustomObject]
                            $AdminUsersPSObj | Table -Name 'Account Settings ' -List -ColumnWidths 50,50
                            } # Close out section -Style Heading4 "UAG Admin User $AdminUserName"
                        } # Close out foreach($AdminUser in $AdminUsers.adminUsersList)
                    } # Close out section -Style Heading3 'Account Settings'
                } # Close out if ($AdminUsers)
            } # Close out section -Style Heading2 'Advanced Settings'


            #---------------------------------------------------------------------------------------------#
            #                             Identity Bridge Settings                                        #
            #---------------------------------------------------------------------------------------------#

            section -Style Heading2 'Identity Bridge Settings' {

                #---------------------------------------------------------------------------------------------#
                #                         Identity Provider Metadata                                          #
                #---------------------------------------------------------------------------------------------#
                if ($IDPMetaData) {
                    section -Style Heading3 'Identity Provider Metadata' {
                        $IDPMetaDataPSObj = [PSCustomObject]@{
                            "Metadate Entity ID" = $IDPMetaData.entityID   #Need to fing out more info
                            "Always force SAML auth" = $IDPMetaData.metadata   #Need to fing out more info
                        } # Close out $IDPMetaDataPSObj = [PSCustomObject]
                        $IDPMetaDataPSObj | Table -Name 'Identity Provider Metadata' -List -ColumnWidths 50,50
                    } # Close section -Style Heading3 'Identity Provider Metadata'
                } # Close if ($IDPMetaData)


                #---------------------------------------------------------------------------------------------#
                #                                    Keytab Settings                                          #
                #---------------------------------------------------------------------------------------------#
                if ($KerberosKeyTab) {
                    section -Style Heading3 'Keytab Settings' {
                        $KerberosKeyTabPSObj = [PSCustomObject]@{
                            "Principal Name" = $KerberosKeyTab.principalName
                        } # Close out $KerberosKeyTabPSObj = [PSCustomObject]
                        $KerberosKeyTabPSObj | Table -Name 'Keytab Settings' -List -ColumnWidths 50,50
                    } # Close section -Style Heading3 'Keytab Settings'
                } # Close if ($KerberosKeyTab


                #---------------------------------------------------------------------------------------------#
                #                            Kerberos Realm Settings                                           #
                #---------------------------------------------------------------------------------------------#
                if ($KerberosRealms.kerberosRealmSettingsList) {
                    section -Style Heading3 'Kerberos Realm Settings' {
                        foreach($KerberosRealm in $KerberosRealms.kerberosRealmSettingsList) {
                            foreach ($KerberosRealmkdcHostNameList in $KerberosRealm.kdcHostNameList) {
                                $KerberosRealmkdcHostNameListData += "$KerberosRealmkdcHostNameList, "
                            } # Close out foreach ($KerberosRealmkdcHostNameList in $KerberosRealm.kdcHostNameList)
                            $KerberosRealmkdcHostNameListDatatrim = $KerberosRealmkdcHostNameListData.TrimEnd(", ") 

                            $KerberosRealmsPSObj = [PSCustomObject]@{
                                "Name" = $KerberosRealm.name
                                "Key Distribution Centers" = $KerberosRealmkdcHostNameListDatatrim
                                "KDC Timeout (in seconds)" = $KerberosRealm.kdcTimeout
                                "No of WRPs Using This Realm" = $KerberosRealm.noOfWRPsUsingThisRealm
                            } # Close out $KerberosRealmsPSObj = [PSCustomObject]
                        } # Close out foreach($KerberosRealm in $KerberosRealms.kerberosRealmSettingsList)
                        $KerberosRealmsPSObj | Table -Name 'Kerberos Realm Settings' -List -ColumnWidths 50,50
                    } # Close out section -Style Heading3 'Kerberos Realm Settings'
                } # Close out if ($KerberosRealms)


                #---------------------------------------------------------------------------------------------#
                #                                    OCSP Settings                                            #
                #---------------------------------------------------------------------------------------------#
                if ($AuthMethodOCSP) {
                    section -Style Heading3 'OCSP Settings' {
                        $AuthMethodOCSPocspSet = $AuthMethodOCSP.ocspSet | Out-String
                        $AuthMethodOCSPPSObj = [PSCustomObject]@{
                            "OCSP Signing Certificate Subject DN List" = $AuthMethodOCSPocspSet
                        } # Close out $AuthMethodOCSPPSObj = [PSCustomObject]
                        $AuthMethodOCSPPSObj | Table -Name 'OCSP Settings' -List -ColumnWidths 50,50
                    } # Close out section -Style Heading3 'OCSP Settings'
                } # Close out if ($AuthMethodOCSP)
            } # Close out section -Style Heading1 'Identity Bridge Settings'       
        } # Close out section -Style Heading1 'Unified Access Gateway Advanced Settings'


        #---------------------------------------------------------------------------------------------#
        #                                UAG Support Settings                                        #
        #---------------------------------------------------------------------------------------------#
    
        section -Style Heading1 'Unified Access Gateway Support Settings' {

            #---------------------------------------------------------------------------------------------#
            #                                Support Settings                                            #
            #---------------------------------------------------------------------------------------------#

            section -Style Heading2 'Support Settings' {
                #---------------------------------------------------------------------------------------------#
                #                            Edge Service Session Statistics                                  #
                #---------------------------------------------------------------------------------------------#
                if ($LogMonitorStats) {
                    section -Style Heading3 'Edge Service Session Statistics' {
                        $PCOIPSessions = $LogMonitorStats.accessPointStatusAndStats.viewEdgeServiceStats.protocol.sessions[0]
                        $TunnelSessions = $LogMonitorStats.accessPointStatusAndStats.viewEdgeServiceStats.protocol.sessions[1]
                        $BlastSessions = $LogMonitorStats.accessPointStatusAndStats.viewEdgeServiceStats.protocol.sessions[2]
                        $PCOIPMaxSessions = $LogMonitorStats.accessPointStatusAndStats.viewEdgeServiceStats.protocol.maxSessions[0]
                        $TunnelMaxSessions = $LogMonitorStats.accessPointStatusAndStats.viewEdgeServiceStats.protocol.maxSessions[1]
                        $BlastMaxSessions = $LogMonitorStats.accessPointStatusAndStats.viewEdgeServiceStats.protocol.maxSessions[2]

                        $LogMonitorStatsPPSObj = [PSCustomObject]@{
                            "Total Sessions" = $LogMonitorStats.accessPointStatusAndStats.sessionCount
                            "Active Logged in Sessions" = $LogMonitorStats.accessPointStatusAndStats.authenticatedSessionCount
                            "Inactive Sessions" = $LogMonitorStats.accessPointStatusAndStats.edgeServiceSessionStats.unauthenticatedSessions
                            "Failed Login Attempts" = $LogMonitorStats.accessPointStatusAndStats.edgeServiceSessionStats.failedLoginAttempts
                            "Total Active Users" = $LogMonitorStats.accessPointStatusAndStats.edgeServiceSessionStats.userCount
                            "Session High Water Mark" = $LogMonitorStats.accessPointStatusAndStats.highWaterMark
                            "Current PCoIP Sessions" = $PCOIPSessions
                            "Highest PCoIP Sessions" = $PCOIPMaxSessions
                            "Current Blast Sessions" = $BlastSessions
                            "Highest Blast Sessions" = $BlastMaxSessions
                            "Current Tunnel Sessions" = $TunnelSessions
                            "Highest Tunnel Sessions" = $TunnelMaxSessions
                        } # Close out $LogMonitorStatsPPSObj = [PSCustomObject]@
                        $LogMonitorStatsPPSObj | Table -Name 'Edge Service Session Statistics' -List -ColumnWidths 50,50
                    } # Close out section -Style Heading3 'Edge Service Session Statistics'
                } # Close out if ($LogMonitorStats)
                

                #---------------------------------------------------------------------------------------------#
                #                                    Log Level Settings                                       #
                #---------------------------------------------------------------------------------------------#
                if ($AuthMethodOCSP) {
                    section -Style Heading3 'Log Level Settings' {
                        $AuthMethodOCSPPSObj = [PSCustomObject]@{
                            "Log Level All" = $LogMonitorGetLogLevels.all
                            "Log Level View" = $LogMonitorGetLogLevels.view
                            "Log Level Web Reverse Proxy" = $LogMonitorGetLogLevels.webReverseProxy
                            "Log Level AirWatch" = $LogMonitorGetLogLevels.airwatch
                            "Log Level Network" = $LogMonitorGetLogLevels.network
                        } # Close out $AuthMethodOCSPPSObj = [PSCustomObject]
                        $AuthMethodOCSPPSObj | Table -Name 'Log Level Settings' -List -ColumnWidths 50,50
                    } # Close section -Style Heading3 'Log Level Settings'
                } # Close if ($AuthMethodOCSP)
            } #Close out section -Style Heading2 'Support Settings'
        } #Close section -Style Heading1 'Unified Access Gateway Advanced Settings'
    } # Close Out foreach ($UAGServer in $Target)
} # Close out function Invoke-AsBuiltReport.VMware.UAG