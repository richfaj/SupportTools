<#
MIT License

Copyright (c) 2023 Richard Fajardo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

<#
 .Synopsis
  Script to validate cloud based connectors.
 .Description
  Used to check if On-Premises send connectors are correctly configured for sending mail to Office 365 tenant. This script will examine both HCW and non HCW created connectors.
 .Parameter RecipientDomain
  Optional paramater to check if the recipient domain is correctly configured On-Premises.
 .Example
   # Check connector(s) configuration
   .\Check-HybridMailflowConfig.ps1
 .Example
   # Validate connector(s) and recipient domain
   .\Check-HybridMailflowConfig.ps1 -RecipientDomain contoso.com
#>

# Version 1.0.5
# Exchange versions supported: 2013, 2016, 2019

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$RecipientDomain
)

function LogMessage() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [string]$Type,
        [Parameter(Mandatory = $false)]
        [string]$ForegroundColor,
        [Parameter(Mandatory = $false)]
        [switch]$LogOnly
    )

    if (-not $LogOnly) {
        if (-not $ForegroundColor) {
            $ForegroundColor = "White"
        }

        if (-not $Type) {
            $Type = "Information"
        }
        if ($Type -eq "Warning") {
            Write-Warning $Message
            $Message = "WARNING: $Message"
        }
        elseif ($Type -eq "Verbose") {
            Write-Verbose $Message
            $Message = "VERBOSE: $Message"
        }
        elseif ($Type -eq "Error") {
            Write-Error $Message -ErrorAction Stop
        }
        else {
            Write-Host $Message -ForegroundColor $ForegroundColor
        }
    }

    $Script:Log += $Message
}

function WriteLogToFile() {
    $logFile = "Check-HybridMailflowConfig_$($env:COMPUTERNAME).log"
    $logPath = Join-Path $PSScriptRoot $logFile

    if (-not (Test-Path $logPath)) {
        New-Item -Path $logPath -ItemType File -Force | Out-Null
    }

    $dateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddThh:mm:ss.fffK")
    $log = @()
    $log += "Script run time: $dateTime `n"
    $log += $Script:Log

    Add-Content -Path $logPath -Value $log

    Write-Host "Log file created at: $logPath" -ForegroundColor Green
}

function ParseDomain($domain) {
    return $domain.Substring($domain.IndexOf('.') + 1)
}

function IsCloudConnector($connector) {
    # Cloud connector if the address space contains remote routing domain and MX record lookup is enabled
    if ($connector.DNSRoutingEnabled) {
        foreach ($address in $connector.AddressSpaces) {
            if ($address.Domain -like "*.mail.onmicrosoft.com") {
                return $true
            }
        }
    }

    # Cloud connector if smart host contains EOP/EXO endpoint
    if (-not $connector.DNSRoutingEnabled) {
        foreach ($hostName in $connector.SmartHosts) {
            if ($hostName.Domain.HostnameString -like "*.mail.protection.outlook.com") {
                return $true
            }
        }
    }
}

function IsCertEnabledForSmtp($cert) {
    $services = $cert.Services.ToString()

    if ([string]::IsNullOrEmpty($services)) {
        LogMessage -Message "Certificate 'Services' property is null." -Type Verbose
        return $false
    }
    else {
        $services = $services.Split(',').Trim()
        if ($services.Contains('SMTP')) {
            return $true
        }
    }

    # SMTP service not found
    return $false
}

function FindCertBySubjectAndReturnFirst() {
    param(
        [Parameter(Mandatory = $true)]
        [object]$TlsCertificateName
    )

    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "My", "LocalMachine";
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $matchingCerts = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindBySubjectDistinguishedName, $TlsCertificateName.CertificateSubject, $true);

    LogMessage -Message "Found '$($matchingCerts.Count)' matching certificate(s) for '$($TlsCertificateName.CertificateSubject)' in computer certificate store." -Type Verbose

    foreach ($cert in $matchingCerts) {
        # Return the first matching certificate by issuer
        if ($cert.Issuer -eq $TlsCertificateName.CertificateIssuer) {
            return $cert
        }
    }
}
function MatchValidCertificate($connector) {
    # List of matching certificates
    $matchingCertificates = @()

    if (-not [string]::IsNullOrEmpty($connector.TlsCertificateName)) {
        $matchingCertificates = FindCertBySubjectAndReturnFirst -TlsCertificateName $connector.TlsCertificateName
        $matchingCertificates = Get-ExchangeCertificate -Thumbprint $matchingCertificates.Thumbprint -ErrorAction SilentlyContinue
        if ($matchingCertificates.Status -ne "Valid") {
            LogMessage -Message "Matching Certificate '$($matchingCertificates.Thumbprint)' is not valid." -Type Warning
            return $false
        }
    }
    else {
        foreach ($cert in $certificates) {
            # Skip and log if cert is self signed
            if ($cert.IsSelfSigned) {
                LogMessage -Message "Skipping self signed certificate: '<I>$($cert.Issuer)<S>$($cert.Subject)'" -LogOnly
                continue
            }

            # Skip and log if cert is invalid
            if ($cert.Status -ne "Valid") {
                LogMessage -Message "Skipping invalid certificate: '<I>$($cert.Issuer)<S>$($cert.Subject)'" -Type Warning
                continue
            }

            # Check if there is a wild card domain
            # If wild card domain is present try to match FQDN to wild card
            $wildCardDomain = ($cert.CertificateDomains | Where-Object IncludeSubDomains -eq $true).Address

            if ($wildCardDomain) {
                # Parse the domain from mail.domain.com to domain.com
                $d = ParseDomain($connector.Fqdn.Domain)

                if ($d -eq $wildCardDomain) {
                    $matchingCertificates += $cert
                }
            }

            # Check all domains for a matching domain
            foreach ($domain in $cert.CertificateDomains.Domain) {
                if ($connector.Fqdn.Domain -eq $domain) {
                    $matchingCertificates += $cert
                }
            }

        }
    }

    # No matching certificates found
    if ($matchingCertificates.Count -eq 0) {
        return $false
    }

    # Only one matching certificate found
    if ($matchingCertificates.Count -eq 1) {
        if (IsCertEnabledForSmtp($matchingCertificates[0])) {
            return $true
        }
        else {
            LogMessage -Message "Skipping certificate '$($cert.Thumbprint)' as it is not enabled for SMTP service." -Type Verbose
            return $false
        }
    }

    # Multiple matching certificates found
    if ($matchingCertificates.Count -gt 1) {
        LogMessage -Message "Multiple matching certificates found for connector '$($connector.Name)'." -Type Verbose
        # Sort connector by NotBefore date
        $matchingCertificates = $matchingCertificates | Sort-Object -Property NotBefore -Descending

        # Is the first certificate enabled for SMTP. If not, then the connector is misconfigured
        # Even if other certs are enabled, transport will pick the newest certificate
        if (IsCertEnabledForSmtp($matchingCertificates[0])) {
            return $true
        }
        else {
            LogMessage -Message "First certificate in collection is not enabled for SMTP service. Skipping all certificates." -Type Verbose
            LogMessage -Message "Multiple matching certificates found for connector '$($connector.Name)'. Cannot determine correct certificate." -Type Warning
            return $false
        }
    }
}

function AnalyzeSendConnectors() {
    foreach ($c in $sendConnectors) {
        if (IsCloudConnector($c)) {
            [bool]$skipCertCheck = $false

            $r = [PSCustomObject] @{
                ConnectorName            = $c.Name
                MisConfigured            = $false
                CustomConnectorDetected  = $false
                TlsCertificateName       = $c.TlsCertificateName
                TlsAuthLevel             = $c.TlsAuthLevel
                TlsDomain                = $c.TlsDomain
                CloudServicesMailEnabled = $c.CloudServicesMailEnabled
                Fqdn                     = $c.Fqdn
                MatchedValidCertificate  = $false
            }
            # Detect if custom connector
            if (-not ($c.Name -match 'Outbound to Office 365 - [a-fA-F\d]{8}-[a-fA-F\d]{4}-[a-fA-F\d]{4}-[a-fA-F\d]{4}-[a-fA-F\d]{12}')) {
                $r.CustomConnectorDetected = $true
            }

            # Needed for header preservation
            if (-not $c.CloudServicesMailEnabled) {
                $r.MisConfigured = $true
                LogMessage -Message "CloudServicesMailEnabled is set to false. Expected a value of 'True'." -Type Warning
            }

            # Needed for XOORG and client certificate auth
            if ($c.TlsAuthLevel -ne "DomainValidation") {
                $r.MisConfigured = $true
                LogMessage -Message "TlsAuthLevel is set to '$($c.TlsAuthLevel)'. Expected a value of 'DomainValidation'." -Type Warning
            }

            # Matching on *.outlook.com to catch prior versions
            if ($c.TlsDomain -notlike "*.outlook.com") {
                $r.MisConfigured = $true
                LogMessage -Message "TlsDomain is set to '$($c.TlsDomain)'. Expected a value of 'mail.protection.outlook.com'." -Type Warning
            }

            # Either should be set but if both null the wrong certificate may be used
            # Ideally the TlsCertificateName property is used which is set by HCW
            if ([string]::IsNullOrEmpty($c.TlsCertificateName) -and [string]::IsNullOrEmpty($c.Fqdn)) {
                $r.MisConfigured = $true
                $skipCertCheck = $true
                LogMessage -Message "TlsCertificateName and FQDN are null. A value should be set to specify the certificate to be used." -Type Warning
            }

            # Only run cert check if the source transport server is this machine
            if (-not ($c.SourceTransportServers.Name -contains $env:COMPUTERNAME)) {
                # If one of the machines is an EDGE role continue with cert check
                # Since you can't mix Hub/Mailbox and Edge roles checking one server should be safe
                if (-not (Get-ExchangeServer -Identity $c.SourceTransportServers[0].Name -Verbose:$false).ServerRole.value__ -eq 64) {
                    $skipCertCheck = $true
                    LogMessage -Message "$($env:COMPUTERNAME) is not a source transport server for this connector." -Type Warning
                }
            }

            if ($c.SourceTransportServers.Count -gt 1) {
                LogMessage -Message "Re-run this script for all source transport servers for this connector. SourceTransportServers: $($c.SourceTransportServers -join ',')" -Type Warning
            }

            # Is there a matching certificate
            if (-not $skipCertCheck) {
                if ([string]::IsNullOrEmpty($c.TlsCertificateName)) {
                    LogMessage -Message "Consider specifying a certificate using TlsCertificateName property." -Type Warning
                }

                if (MatchValidCertificate($c)) {
                    $r.MatchedValidCertificate = $true
                }
                else {
                    $r.MisConfigured = $true
                    LogMessage -Message "There were no matching valid certificates for this connector." -Type Warning
                }
            }

            if ($r.MisConfigured) {
                LogMessage -Message "Connector '$($r.ConnectorName)' is misconfigured. See additional details to resolve." -ForegroundColor Red
            }
            else {
                LogMessage "No issues found with connector '$($r.ConnectorName)'." -ForegroundColor Green
            }

            # Display results
            $r
            # Log results in Json format
            LogMessage -Message ($r | ConvertTo-Json) -LogOnly
        }
    }
}

function ValidateRecipientRoutingDomain($domain) {
    $acceptedDomains = Get-AcceptedDomain
    # If there is an accepted domain
    if ($acceptedDomains | Where-Object { $_.DomainName.Domain -eq $domain }) {
        return $true
    }
    # If accepted domains include subdomains
    $subAcceptedDomains = $acceptedDomains | Where-Object MatchSubDomains -eq $true
    if ($subAcceptedDomains) {
        $d = ParseDomain($domain)
        foreach ($subDomain in $subAcceptedDomains) {
            if ($subDomain.DomainName.Domain -eq $d) {
                LogMessage -Message "Found matching accepted domain '$($subDomain.DomainName.Domain)' with 'MatchSubDomains' set to true." -Type Verbose
                return $true
            }
        }
    }

    # Check if there is a correctly configured remote domain
    $remoteDomain = Get-RemoteDomain | Where-Object DomainName -eq $domain

    if ([string]::IsNullOrEmpty($remoteDomain)) {
        return $false
    }
    else {
        $validDomain = $true
        LogMessage -Message "Found RemoteDomain for domain '$domain'."
        if ($remoteDomain.IsInternal -eq $false) {
            $validDomain = $false
            LogMessage -Message "Remote domain IsInternal is 'False'. Expected a value of 'True'. " -Type Warning
        }

        if ($remoteDomain.TrustedMailOutboundEnabled -eq $false) {
            $validDomain = $false
            LogMessage "Remote domain TrustedMailOutboundEnabled is 'False'. Expected a value of 'True'." -Type Warning
        }
        return $validDomain
    }
}

$Script:Log = @()

# Check if running in local Exchange PowerShell
if (-not (Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -Registered -ErrorAction SilentlyContinue)) {
    LogMessage "Diagnostic script must be run in shell with Exchange snap-in. Remote session is not supported for this script." -Type Error
}

$serverRole = Get-ExchangeServer -identity $env:COMPUTERNAME -Verbose:$false | Select-Object ServerRole

# If Hybrid Configuration is detected advise running CSS Health Checker script
if ($serverRole -eq "Mailbox" -and $null -ne (Get-HybridConfiguration)) {
    LogMessage -Message "This script is not intended for use with Hybrid Configuration. Please run the CSS Health Checker script instead." -Type Warning
}

LogMessage "Collecting all send connectors."
$sendConnectors = Get-SendConnector -Verbose:$false

LogMessage "Collecting list of certificates using Get-ExchangeCertificate for this machine '$($env:COMPUTERNAME)'."
$certificates = Get-ExchangeCertificate -Verbose:$false

# Terminate if no connectors found
if ($sendConnectors.Count -eq 0) {
    LogMessage "No send connectors found." -Type Error
}

LogMessage -Message "Analyzing send connectors..."
LogMessage -Message " "
AnalyzeSendConnectors

if ($RecipientDomain) {
    LogMessage -Message "Verifying recipient domain '$RecipientDomain'."

    if (ValidateRecipientRoutingDomain($RecipientDomain)) {
        LogMessage -Message "Recipient domain is correctly configured." -ForegroundColor Green
    }
    else {
        LogMessage -Message "Manual investigation is needed. Either there is no accepted domain or the remote domain is misconfigured." -ForegroundColor Red
    }
}

# Save log to file
WriteLogToFile
