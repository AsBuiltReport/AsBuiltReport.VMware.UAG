function Get-AbrRSASecureID {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Horizon RSA SecurID Settings.
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
        Write-PScriboMessage "RSA SecureID InfoLevel set at $($InfoLevel.UAG.AuthenticationSettings)."
        Write-PscriboMessage "Collecting UAG RSA SecureID Settings information."
    }

    process {
        if ($InfoLevel.UAG.AuthenticationSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    try {$AuthSecureID = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/authmethod/securid-auth" -Credential $Credential}
                    catch {Write-Output 'SAML Auth is not configured'}
                } else {try {$AuthSecureID = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/authmethod/securid-auth" -Credential $Credential}
                            catch {Write-Output 'SAML Auth is not configured'}}
                if ($AuthSecureID) {
                    Paragraph "The following section will provide details for RSA SecureID Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                    BlankLine
                    $OutObj = @()
                    section -Style Heading3 "RSA SecureID Settings" {
                        try {
                            $inObj = [ordered] @{
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
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }

                        $TableParams += @{
                            Name = "RSA SecureID Settings - $($($UAGServer).split('.')[0].ToUpper())"
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