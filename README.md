# Support scripts
This project contains diagnostic and troubleshooting scripts

## Check-HybridMailflowConfig.ps1
This script can be used to detect common misconfigurations with On-Premises send connectors for Office 365.

What it checks for:
* Precense of hybrid configuration
* Connector TLS settings
* Matching certificate and validation status
* Correctly configured recipient domains

## Example:
> .\Check-HybridMailflowConfig.ps1

Will also check recipient domain if provided

> .\Check-HybridMailflowConfig.ps1 -RecipientDomain contoso.com