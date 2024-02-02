function Get-AbrRadius {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Horizon Radius Settings.
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
        Write-PScriboMessage "Radius Settings InfoLevel set at $($InfoLevel.UAG.AuthenticationSettings)."
        Write-PscriboMessage "Collecting UAG Radius Settings information."
    }

    process {
        if ($InfoLevel.UAG.AuthenticationSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    try{$AuthRadius = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/authmethod/radius-auth" -Credential $Credential}
                    catch {Write-Output 'SAML Auth is not configured'}
                } else {try {$AuthRadius = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/authmethod/radius-auth" -Credential $Credential}
                        catch {Write-Output 'SAML Auth is not configured'}}
                if ($AuthRadius) {
                    Paragraph "The following section will provide details for Radius Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                    BlankLine
                    $OutObj = @()
                    section -Style Heading3 "Radius Settings" {
                        try {
                            $inObj = [ordered] @{
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
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }

                        $TableParams += @{
                            Name = "Radius Settings - $($($UAGServer).split('.')[0].ToUpper())"
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