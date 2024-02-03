function Get-AbrClientCustomExecutable {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Client Custom Executable.
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
        Write-PScriboMessage "Client Custom Executable InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PscriboMessage "Collecting UAG Client Custom Executable information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $CustomExecutables = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/resource" -Credential $Credential
                } else {$CustomExecutables = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/resource" -Credential $Credential}
                if ($CustomExecutables.customExecutableList) {
                    section -Style Heading4 "Client Custom Executables" {
                        Paragraph "The following section will provide details on custom executables on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine

                        foreach($CustomExecutable in $CustomExecutables.customExecutableList){
                            If($CustomExecutable){
                                section -Style Heading5 "Client Custom Executables - $($CustomExecutable.hostedResourceMetadata.name)" {

                                    if($null -ne $CustomExecutable.resourceURLSettings.trustedCertificates.name) {
                                        $TrustedCerts = $CustomExecutable.resourceURLSettings.trustedCertificates.name -join "`n"
                                    }else { $TrustedCerts = $null}

                                    if($null -ne $CustomExecutable.hostedResourceMetadata.trustedSigningCertificate.name) {
                                        $TrustedSigning = $CustomExecutable.hostedResourceMetadata.trustedSigningCertificate.name -join "`n"
                                    }else { $TrustedSigning = $null}

                                    $OutObj = @()
                                    try {
                                        $inObj = [ordered] @{
                                            "Name" = $CustomExecutable.hostedResourceMetadata.name
                                            'Path' = $CustomExecutable.hostedResourceMetadata.path
                                            'Sha256 Sum' = $CustomExecutable.hostedResourceMetadata.sha256sum
                                            'parameters' = $CustomExecutable.hostedResourceMetadata.params
                                            'Flags' = $CustomExecutable.hostedResourceMetadata.flags.flags
                                            'Executable' = $CustomExecutable.hostedResourceMetadata.executable
                                            'From URL' = $CustomExecutable.hostedResourceMetadata.isObtainedfromURL
                                            'File Type' = $CustomExecutable.hostedResourceMetadata.fileType
                                            'Trusted Signing Certificate' = $TrustedSigning
                                            'OS Type' = $CustomExecutable.hostedResourceMetadata.osType
                                            'File URL' = $CustomExecutable.resourceURLSettings.URL
                                            'File Thumbprint' = $CustomExecutable.resourceURLSettings.urlThumbprints
                                            'Trusted Cert' = $TrustedCerts
                                            'URL Response Refresh Interval' = $CustomExecutable.resourceURLSettings.urlResponseRefreshInterval
                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                    }

                                    $TableParams = @{
                                        Name = "Client Custom Executable - $($CustomExecutable.hostedResourceMetadata.name)"
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