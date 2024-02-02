function Get-AbrAccountSetting {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve VMware UAG Account Settings.
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
        Write-PScriboMessage "Account Settings InfoLevel set at $($InfoLevel.UAG.AdvancedSettings)."
        Write-PscriboMessage "Collecting UAG Account Settings information."
    }

    process {
        if ($InfoLevel.UAG.AdvancedSettings -ge 1) {
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $adminusers = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/adminusers/samlAuth" -Credential $Credential
                    try {$AdminSAMLAuth = Invoke-RestMethod -SkipCertificateCheck -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/adminusers/samlAuth" -Credential $Credential}
                    catch {}
                } else {$adminusers = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/adminusers" -Credential $Credential
                    try {$AdminSAMLAuth = Invoke-RestMethod -Method Get -ContentType application/json -Uri "https://$($UAGServer):9443/rest/v1/config/adminusers/samlAuth" -Credential $Credential}
                    catch {}
                }
                if ($adminusers.adminUsersList) {
                    section -Style Heading4 "Account Settings" {
                        Paragraph "The following section will provide details on Account Settings on the UAG - $($($UAGServer).split('.')[0].ToUpper())."
                        BlankLine
                        foreach($adminuser in $adminusers.adminUsersList){
                            if($adminuser){
                                section -Style Heading5 "Account Settings - $($adminuser.name)" {
                                    $OutObj = @()

                                    try {
                                        $inObj = [ordered] @{
                                            'Name' = $adminuser.name
                                            'User ID' = $adminuser.userId
                                            'Enabled' = $adminuser.enabled
                                            'Roles' = $adminuser.roles -join ', '
                                            'Password Last Set' = $adminuser.adminPasswordSetTime
                                            'Days till Password Expires' = $adminuser.noOfDaysRemainingForPwdExpiry
                                            'User Type' = $adminuser.userType
                                        }
                                        $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
                                        }

                                    $TableParams += @{
                                        Name = "Account Settings - $($adminuser.name)"
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

                        if($AdminSAMLAuth){
                            section -Style Heading4 "A Settings - $($adminuser.name)" {
                                $OutObj = @()

                                try {
                                    $inObj = [ordered] @{
                                        'Enable' = $AdminSAMLAuth.enable
                                        'Identity Provider' = $AdminSAMLAuth.entityId
                                        'Sign SAML Request wiht Admin UI TLS Certificate' = $AdminSAMLAuth.signAuthNRequestWithAdminCert
                                        'Static SP Entity ID' = $AdminSAMLAuth.spEntityId
                                    }
                                    $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                    }

                                $TableParams += @{
                                    Name = "Account Settings - $($adminuser.name)"
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
            catch {
                Write-PscriboMessage -IsWarning $_.Exception.Message
            }
        }
    }
    end {}
}