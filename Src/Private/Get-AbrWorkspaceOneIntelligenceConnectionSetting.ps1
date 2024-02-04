function Get-AbrWorkspaceOneIntelligenceConnectionSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Workspace One Intelligence Connection Settings.
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
        Write-PScriboMessage "Workspace One Intelligence Connection Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PScriboMessage "Collecting UAG Workspace One Intelligence Connection Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $WorkspaceOneIntel = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/ws1intelligence" -Credential $Credential
                } else { $WorkspaceOneIntel = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/ws1intelligence" -Credential $Credential }
                if ($WorkspaceOneIntel.workspaceOneIntelligenceSettingsList) {
                    Section -Style Heading4 "Workspace One Intelligence Connection Settings" {
                        Paragraph "The following section will provide details on Workspace One Intelligence Connection Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine

                        foreach ($WorkspaceOneInt in $WorkspaceOneIntel.workspaceOneIntelligenceSettingsList) {
                            if ($WorkspaceOneInt) {
                                Section -Style Heading5 "Workspace One Intelligence Connection Settings - $($WorkspaceOneIntel.Name)" {
                                    $OutObj = @()

                                    try {
                                        $inObj = [ordered] @{
                                            "Name" = $WorkspaceOneIntel.Name
                                            #"Workspace ONE Intelligence Credentials file Name" = $WorkspaceOneIntel.credentialsFileName
                                            "Trusted Certs" = $($WorkspaceOneIntel.trustedCertificates -join ', ')
                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                    } catch {
                                        Write-PScriboMessage -IsWarning $_.Exception.Message
                                    }

                                    $TableParams = @{
                                        Name = "Workspace One Intelligence Connection Settings - $($WorkspaceOneIntel.Name)"
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
            } catch {
                Write-PScriboMessage -IsWarning $_.Exception.Message
            }
        }
    }
    end {}
}