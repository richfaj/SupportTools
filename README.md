# Support scripts
This project contains diagnostic and troubleshooting scripts

## Check-HybridMailflowConfig.ps1

__NO LONGER BEING MAINTAINED__
The checks in this script have been incorporated into the Exchange On-Premises HealthChecker script available here: https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker

More details: https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/CloudConnectorCheck/

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
