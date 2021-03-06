# AsBuiltReport.VMware.UAG
Repository for VMware UAG AsBuilt Report


# Sample Reports

<Coming Soon>

# Getting Started

Below are the instructions on how to install, configure and generate a VMware UAG (Universial Access Gateway) As Built Report

## Pre-requisites
The following PowerShell modules are required for generating a VMware UAG (Universial Access Gateway) As Built report.

Each of these modules can be easily downloaded and installed via the PowerShell Gallery 

- [AsBuiltReport Module](https://www.powershellgallery.com/packages/AsBuiltReport/)

### Module Installation

Open a Windows PowerShell terminal window and install each of the required modules as follows;
```powershell
Install-Module AsBuiltReport
```

### Required Privileges

To generate a VMware UAG (Universial Access Gateway) report, a user account with the Role_Monitoring role or higher on the UAG is required.

## Configuration

The VMware UAG (Universial Access Gateway) As Built Report utilises a JSON file to allow configuration of report information, options, detail and healthchecks.

A VMware UAG (Universial Access Gateway) report configuration file can be generated by executing the following command;
```powershell
New-AsBuiltReportConfig -Report VMware.UAG -Path <User specified folder> -Name <Optional>
```

Executing this command will copy the default UAG report JSON configuration to a user specified folder.

All report settings can then be configured via the JSON file.

The following provides information of how to configure each schema within the report's JSON file.

InfoLevel
The InfoLevel sub-schema allows configuration of each section of the report at a granular level.

There are 4 levels (0-3) of detail granularity for each section as follows;

Setting	InfoLevel	Description
0	Disabled	does not collect or display any information
1	Summary	provides summarised information for a collection of objects
2	Detailed	provides detailed information for a collection of objects
3	Comprehensive	provides comprehensive information for individual objects
The following sections can be set

Schema	    Sub-Schema	            Default Setting     Max Setting
InfoLevel	EdgeServiceSettings     3                   3
InfoLevel	Horizon	                3                   3
InfoLevel	AdvancedSettings        3                   3


## Examples
There is one example listed below on running the AsBuiltReport script against a VMware UAG (Universial Access Gateway) target. Refer to the `README.md` file in the main AsBuiltReport project repository for more examples.

- The following creates a VMware UAG (Universial Access Gateway) As-Built report in HTML & Word formats in the folder C:\scripts\.
```powershell
PS C:\>New-AsBuiltReport -Report VMware.UAG -Target 192.168.1.100 -Credential (Get-Credential) -Format HTML,Word -OutputPath C:\scripts\
```

## Known Issues
The UAG Management port is required to have a trusted cert installed. If there is no trusted cert it will error. Workaround is to install a trusted cert or add the cert to the trusted certs store on the machine running the VMware UAG (Universial Access Gateway) AS-Built Report.

## Supported Versions
Has been run on most versions of UAG in NON-FIPS configuration. Has been tested on UAG version 3.4 to 3.9