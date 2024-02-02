function Invoke-AsBuiltReport.VMware.UAG {
    <#
    .SYNOPSIS
        PowerShell script which documents the configuration of VMware UAG in Word/HTML/XML/Text formats
    .DESCRIPTION
        Documents the configuration of VMware UAG in Word/HTML/XML/Text formats using PScribo.
    .NOTES
        Version:        1.1.0
        Author:         Chris Hildebrandt, @childebrandt42
        Editor:         Jonathan Colon, @jcolonfzenpr
        Twitter:        @asbuiltreport
        Github:         AsBuiltReport
        Credits:        Iain Brighton (@iainbrighton) - PScribo module


    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.VMware.UAG
    #>


    [CmdletBinding()]
    param (
        [String[]] $Target,
        [PSCredential] $Credential,
        [String] $StylePath
    )

    if ($PSVersionTable.PSEdition -ne 'Core') {

        add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    }


    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    Write-PScriboMessage -IsWarning "Please refer to the AsBuiltReport.VMware.UAG github website for more detailed information about this project."
    Write-PScriboMessage -IsWarning "Do not forget to update your report configuration file after each new version release."
    Write-PScriboMessage -IsWarning "Documentation: https://github.com/AsBuiltReport/AsBuiltReport.VMware.UAG"
    Write-PScriboMessage -IsWarning "Issues or bug reporting: https://github.com/AsBuiltReport/AsBuiltReport.VMware.UAG/issues"

    # Check the current AsBuiltReport.VMware.UAG installed module
    Try {
        $InstalledVersion = Get-Module -ListAvailable -Name AsBuiltReport.VMware.UAG -ErrorAction SilentlyContinue | Sort-Object -Property Version -Descending | Select-Object -First 1 -ExpandProperty Version

        if ($InstalledVersion) {
            Write-PScriboMessage -IsWarning "AsBuiltReport.VMware.UAG $($InstalledVersion.ToString()) is currently installed."
            $LatestVersion = Find-Module -Name AsBuiltReport.Veeam.VBR -Repository PSGallery -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
            if ($LatestVersion -gt $InstalledVersion) {
                Write-PScriboMessage -IsWarning "AsBuiltReport.VMware.UAG $($LatestVersion.ToString()) is available."
                Write-PScriboMessage -IsWarning "Run 'Update-Module -Name AsBuiltReport.VMware.UAG -Force' to install the latest version."
            }
        }
    } Catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }

    # Check if the required version of VMware PowerCLI is installed
    Get-RequiredModule -Name 'VMware.PowerCLI' -Version '12.7'

    # Import JSON Configuration for Options and InfoLevel
    $Report = $ReportConfig.Report
    $InfoLevel = $ReportConfig.InfoLevel
    $Options = $ReportConfig.Options

    $RESTAPIUser = $Credential.UserName
    $RESTAPIPassword = $Credential.GetNetworkCredential().password

    $AppVolRestCreds = @{
        username = $RESTAPIUser
        password = $RESTAPIPassword
    }

    foreach ($UAGServer in $Target) {
        $UAGServerName = $UAGServer.ToString()
        Write-PScriboMessage "Processing $UAGServerName..."

        Try {
            if ($PSVersionTable.PSEdition -eq 'Core') {
                $UAGServerRest = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/monitor/stats" -Credential $Credential
            } else {$UAGServerRest = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/monitor/stats" -Credential $Credential}
        } Catch {        }

        # Generate report if connection to UAG Server Connection is successful
        if ($UAGServerRest.accessPointStatusAndStats.overAllStatus.status) {
            section -Style Heading1 "Universal Access Gateway (UAG) - $($($UAGServer).split('.')[0].ToUpper())" {
                Paragraph "The following section provides a summary of the implemented components on the VMware UAG infrastructure."
                if($InfoLevel.UAG.EdgeServices -ge 1 -or $InfoLevel.UAG.AuthenticationSettings -ge 1){
                    section -Style Heading2 "General Settings" {
                        if($InfoLevel.UAG.EdgeServices -ge 1){
                            section -Style Heading3 "Edge Service Settings" {
                                Get-AbrEdgeServiceSetting
                            }
                        }
                        if($InfoLevel.UAG.AuthenticationSettings -ge 1){
                            section -Style Heading3 "Authentication Settings" {
                                Get-AbrRSASecureID
                                Get-AbrRadius
                                Get-AbrX509Certificate
                            }
                        }
                    }
                }
                if($InfoLevel.UAG.AdvancedSettings -ge 1 -or $InfoLevel.UAG.IdentityBridgeingSettings -ge 1){
                    section -Style Heading2 "Advanced Settings" {
                        if($InfoLevel.UAG.AdvancedSettings -ge 1){
                            section -Style Heading3 "Advanced Settings" {
                                Get-AbrSystemConfiguration
                                Get-AbrNetworkSetting
                                Get-AbrHighAvailability
                                Get-AbrTLSServerCertificateSetting
                                Get-AbrSAMLSetting
                                #Get-AbrEndPointComplianceCheckProviderSetting
                                Get-AbrClientCustomExecutable
                                Get-AbrJWTSetting
                                Get-AbrOutboundProxySetting
                                Get-AbrWorkspaceOneIntelligenceConnectionSetting
                                Get-AbrWorkspaceOneIntelligenceDataSetting
                                Get-AbrAccountSetting
                                Get-AbrApplianceUpdatesSetting
                                Get-AbrSyslogSetting
                            }
                        }
                        if($InfoLevel.UAG.IdentityBridgeingSettings -ge 1){
                            section -Style Heading3 "Identity Bridging Settings" {
                                Get-AbrUploadIdenityProviderMeta
                                Get-AbrKeyTabSetting
                                Get-AbrRealmSetting
                                Get-AbrOSCSPSetting
                            }
                        }

                    }
                }
                if($InfoLevel.UAG.SupportSettings -ge 1){
                    section -Style Heading2 "Support Settings" {
                        section -Style Heading3 "Support Settings" {
                            Get-AbrLogLevelSetting
                        }
                    }
                }
            }
        }
    }
}
