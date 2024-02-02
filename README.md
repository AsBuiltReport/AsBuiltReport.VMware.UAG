<!-- ********** DO NOT EDIT THESE LINKS ********** -->
<p align="center">
    <a href="https://www.asbuiltreport.com/" alt="AsBuiltReport"></a>
            <img src='https://avatars.githubusercontent.com/u/42958564' width="8%" height="8%" /></a>
</p>
<p align="center">
    <a href="https://www.powershellgallery.com/packages/AsBuiltReport.VMware.UAG/" alt="PowerShell Gallery Version">
        <img src="https://img.shields.io/powershellgallery/v/AsBuiltReport.VMware.UAG.svg" /></a>
    <a href="https://www.powershellgallery.com/packages/AsBuiltReport.VMware.UAG/" alt="PS Gallery Downloads">
        <img src="https://img.shields.io/powershellgallery/dt/AsBuiltReport.VMware.UAG.svg" /></a>
    <a href="https://www.powershellgallery.com/packages/AsBuiltReport.VMware.UAG/" alt="PS Platform">
        <img src="https://img.shields.io/powershellgallery/p/AsBuiltReport.VMware.UAG.svg" /></a>
</p>
<p align="center">
    <a href="https://github.com/AsBuiltReport/AsBuiltReport.VMware.UAG/graphs/commit-activity" alt="GitHub Last Commit">
        <img src="https://img.shields.io/github/last-commit/AsBuiltReport/AsBuiltReport.VMware.UAG/master.svg" /></a>
    <a href="https://raw.githubusercontent.com/AsBuiltReport/AsBuiltReport.VMware.UAG/master/LICENSE" alt="GitHub License">
        <img src="https://img.shields.io/github/license/AsBuiltReport/AsBuiltReport.VMware.UAG.svg" /></a>
    <a href="https://github.com/AsBuiltReport/AsBuiltReport.VMware.UAG/graphs/contributors" alt="GitHub Contributors">
        <img src="https://img.shields.io/github/contributors/AsBuiltReport/AsBuiltReport.VMware.UAG.svg"/></a>
</p>
<p align="center">
    <a href="https://twitter.com/AsBuiltReport" alt="Twitter">
            <img src="https://img.shields.io/twitter/follow/AsBuiltReport.svg?style=social"/></a>
</p>
<!-- ********** DO NOT EDIT THESE LINKS ********** -->

# VMware UAG As Built Report

VMware UAG As Built Report is a PowerShell module which works in conjunction with [AsBuiltReport.Core](https://github.com/AsBuiltReport/AsBuiltReport.Core).

[AsBuiltReport](https://github.com/AsBuiltReport/AsBuiltReport) is an open-sourced community project which utilises PowerShell to produce as-built documentation in multiple document formats for multiple vendors and technologies.

Please refer to the AsBuiltReport [website](https://www.asbuiltreport.com) for more detailed information about this project.

# :books: Sample Reports

## Sample Report - Custom Style
Sample VMware UAG As Built report PDF file: [Sample VMware UAG As Built Report.pdf](https://raw.githubusercontent.com/AsBuiltReport/AsBuiltReport.VMware.UAG/dev/Samples/Sample%20VMware%20UAG%20As%20Built%20Report.pdf)

# :beginner: Getting Started
Below are the instructions on how to install, configure and generate a VMware UAG As Built report.

## :floppy_disk: Supported Versions
<!-- ********** Update supported UAG versions ********** -->
The VMware UAG As Built Report supports the following UAG versions;

- Should work on version on all UAGs
- Has been tested on all 230# Builds

## :rotating_light: Known Issues
The Endpoint Compliance Check Provider Settings does not report. If you have it setup and want to share, please open a bug, and we can get this working.

### PowerShell
This report is compatible with the following PowerShell versions;

<!-- ********** Update supported PowerShell versions ********** -->
| Windows PowerShell 5.1 |     PowerShell 7    |
|:----------------------:|:--------------------:|
|   :white_check_mark:   | :white_check_mark: |
## :wrench: System Requirements
<!-- ********** Update system requirements ********** -->
PowerShell 5.1 or PowerShell 7, and the following PowerShell modules are required for generating a VMware UAG As Built Report.

- [VMware PowerCLI Module](https://www.powershellgallery.com/packages/VMware.PowerCLI/)
- [AsBuiltReport.VMware.UAG Module](https://www.powershellgallery.com/packages/AsBuiltReport.VMware.UAG/)

### :closed_lock_with_key: Required Privileges

* To generate a VMware UAG report, a user account with the Admin role or higher on the UAG is required. (Required Admin rights to use the AppVol APIs)

## :package: Module Installation

### PowerShell
<!-- ********** Add installation for any additional PowerShell module(s) ********** -->
```powershell
install-module AsBuiltReport.VMware.UAG
```

### GitHub
If you are unable to use the PowerShell Gallery, you can still install the module manually. Ensure you repeat the following steps for the [system requirements](https://github.com/AsBuiltReport/AsBuiltReport.VMware.UAG#wrench-system-requirements) also.

1. Download the code package / [latest release](https://github.com/AsBuiltReport/AsBuiltReport.VMware.UAG/releases/latest) zip from GitHub
2. Extract the zip file
3. Copy the folder `AsBuiltReport.VMware.UAG` to a path that is set in `$env:PSModulePath`.
4. Open a PowerShell terminal window and unblock the downloaded files with
    ```powershell
    $path = (Get-Module -Name AsBuiltReport.VMware.UAG -ListAvailable).ModuleBase; Unblock-File -Path $path\*.psd1; Unblock-File -Path $path\Src\Public\*.ps1; Unblock-File -Path $path\Src\Private\*.ps1
    ```
5. Close and reopen the PowerShell terminal window.

_Note: You are not limited to installing the module to those example paths, you can add a new entry to the environment variable PSModulePath if you want to use another path._

## :pencil2: Configuration

The VMware UAG As Built Report utilises a JSON file to allow configuration of report information, options, detail and healthchecks.

A VMware UAG report configuration file can be generated by executing the following command;
```powershell
New-AsBuiltReportConfig -Report VMware.UAG -FolderPath <User specified folder> -Filename <Optional>
```

Executing this command will copy the default VMware UAG report JSON configuration to a user specified folder.

All report settings can then be configured via the JSON file.

The following provides information of how to configure each schema within the report's JSON file.

<!-- ********** DO NOT CHANGE THE REPORT SCHEMA SETTINGS ********** -->
### Report
The **Report** schema provides configuration of the VMware UAG report information.

| Sub-Schema          | Setting      | Default                        | Description                                                  |
|---------------------|--------------|--------------------------------|--------------------------------------------------------------|
| Name                | User defined | VMware UAG As Built Report | The name of the As Built Report                              |
| Version             | User defined | 1.1                            | The report version                                           |
| Status              | User defined | Released                       | The report release status                                    |
| ShowCoverPageImage  | true / false | true                           | Toggle to enable/disable the display of the cover page image |
| ShowTableOfContents | true / false | true                           | Toggle to enable/disable table of contents                   |
| ShowHeaderFooter    | true / false | true                           | Toggle to enable/disable document headers & footers          |
| ShowTableCaptions   | true / false | true                           | Toggle to enable/disable table captions/numbering            |

### Options
The **Options** schema allows certain options within the report to be toggled on or off.

<!-- ********** Add/Remove the number of InfoLevels as required ********** -->
### InfoLevel
The **InfoLevel** schema allows configuration of each section of the report at a granular level. The following sections can be set.

There are 3 levels (0-2) of detail granularity for each section as follows;

| Setting | InfoLevel         | Description                                                                                                                                |
|:-------:|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
|    0    | Disabled          | Does not collect or display any information                                                                                                |
|    1    | Enabled / Summary | Provides summarised information for a collection of objects                                                                                |
|    2    | Adv Summary       | Provides condensed, detailed information for a collection of objects                                                                       |

The table below outlines the default and maximum InfoLevel settings for each section.

| Sub-Schema   | Default Setting | Maximum Setting |
|--------------|:---------------:|:---------------:|
General | 1 | 1 |
Application | 1 | 1 |
Package | 1 | 1 |
Program | 1 | 1 |
Assignment | 1 | 1 |
Writeables | 1 | 1 |
ADUsers | 1 | 1 |
Computers | 1 | 1 |
ADGroups | 1 | 1 |
ADOUs | 1 | 1 |
Machines | 1 | 1 |
StorageLocations | 1 | 1 |
StorageGroups | 1 | 1 |
Instance | 1 | 1 |
Jobs | 1 | 1 |
Troubleshooting | 1 | 1 |
License | 1 | 1 |
ADDomains | 1 | 1 |
AdminGroups | 1 | 1 |
MachineManagers | 1 | 1 |
Storage | 1 | 1 |
Managers | 1 | 1 |
Settings | 1 | 1 |


### Healthcheck
The **Healthcheck** schema is used to toggle health checks on or off.

Health checks are yet to be developed.

## :computer: Examples

```powershell
# Generate a As Built Report for UAG Manager Server 'Manager-apv-01.corp.local' using specified credentials. Export report to HTML & DOCX formats. Use default report style. Append timestamp to report filename. Save reports to 'C:\Users\Jon\Documents'
PS C:\> New-AsBuiltReport -Report VMware.UAG -Target 'Manager-apv-01.corp.local' -Username 'administrator@domain.local' -Password 'VMware1!' -Format Html,Word -OutputFolderPath 'C:\Users\Jon\Documents' -Timestamp

# Generate a As Built Report for UAG Manager Server 'Manager-apv-01.corp.local' using specified credentials and report configuration file. Export report to Text, HTML & DOCX formats. Use default report style. Save reports to 'C:\Users\Jon\Documents'. Display verbose messages to the console.
PS C:\> New-AsBuiltReport -Report VMware.UAG -Target 'Manager-apv-01.corp.local' -Username 'administrator@domain.local' -Password 'VMware1!' -Format Text,Html,Word -OutputFolderPath 'C:\Users\Jon\Documents' -ReportConfigFilePath 'C:\Users\Jon\AsBuiltReport\AsBuiltReport.VMware.UAG.json' -Verbose

# Generate a As Built Report for UAG Manager Server 'Manager-apv-01.corp.local' using stored credentials. Export report to HTML & Text formats. Use default report style. Highlight environment issues within the report. Save reports to 'C:\Users\JOn\Documents'.
PS C:\> $Creds = Get-Credential
PS C:\> New-AsBuiltReport -Report VMware.UAG -Target 'Manager-apv-01.corp.local' -Credential $Creds -Format Html,Text -OutputFolderPath 'C:\Users\Jon\Documents' -EnableHealthCheck

# Generate a single As Built Report for UAG Manager Servers 'Manager-apv-01.corp.local' and 'UAG-cs-02.corp.local' using specified credentials. Report exports to WORD format by default. Apply custom style to the report. Reports are saved to the user profile folder by default.
PS C:\> New-AsBuiltReport -Report VMware.UAG -Target 'Manager-apv-01.corp.local','UAG-cs-02.corp.local' -Username 'administrator@domain.local' -Password 'VMware1!' -StyleFilePath 'C:\Scripts\Styles\MyCustomStyle.ps1'

# Generate a As Built Report for UAG Manager Server 'Manager-apv-01.corp.local' using specified credentials. Export report to HTML & DOCX formats. Use default report style. Reports are saved to the user profile folder by default. Attach and send reports via e-mail.
PS C:\> New-AsBuiltReport -Report VMware.UAG -Target 'Manager-apv-01.corp.local' -Username 'administrator@domain.local' -Password 'VMware1!' -Format Html,Word -OutputFolderPath 'C:\Users\Jon\Documents' -SendEmail
