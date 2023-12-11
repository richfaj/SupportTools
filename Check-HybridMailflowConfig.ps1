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
                if (-not (Get-ExchangeServer -Identity $c.SourceTransportServers[0].Name -Verbose:$false).ServerRole.HasFlag([Microsoft.Exchange.Data.Directory.SystemConfiguration]::Edge)) {
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

function ContainsCloudCapability([object]$tlsDomain) {
    foreach ($entry in $tlsDomain) {
        if ($entry.Domain.Domain -eq "mail.protection.outlook.com") {
            if ($entry.Capabilities.HasFlag([Microsoft.Exchange.Data.SmtpReceiveCapabilities]::AcceptCloudServicesMail) `
                    -or $entry.Capabilities.HasFlag([Microsoft.Exchange.Data.SmtpReceiveCapabilities]::AcceptOorgProtocol)) {
                return $true
            }
        }
    }
    return $false
}

function AnalyzeReceiveConnectors() {
    $connectorList = @()
    $connectorData = @()

    # Get all receive connectors that listen on port 25
    foreach ($c in $recvConnectors) {
        if (([array]$c.Bindings.Port).Contains(25)) {
            $connectorList += $c
        }
    }

    foreach ($c in $connectorList) {
        $connectorData += [PSCustomObject] @{
            ConnectorName         = $c.Name
            TlsDomainCapabilities = $c.TlsDomainCapabilities
            Fqdn                  = $c.Fqdn
            SupportsHybridMail    = ContainsCloudCapability($c.TlsDomainCapabilities)
        }
    }

    if ([int]($connectorData | Where-Object { $_.SupportsHybridMail -eq $true } | Measure-Object).Count -eq 0) {
        LogMessage "No receieve connectors found that support Hybrid Mail flow." -Type Warning
        $connectorData | Format-Table -AutoSize
    }
    else {
        [int]$detectedConnectorCount = ($connectorData | Where-Object { $_.SupportsHybridMail -eq $true } | Measure-Object).Count
        [int]$eligibleConnectorCount = ($connectorData | Measure-Object).Count
        LogMessage "Detected '$detectedConnectorCount' out of '$eligibleConnectorCount' eligible receive connectors that support Hybrid Mail flow:" -ForegroundColor Green
        $connectorData | Where-Object { $_.SupportsHybridMail -eq $true } | Format-Table -AutoSize
    }

    LogMessage -Message ($connectorData | ConvertTo-Json) -LogOnly
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
if ($serverRole.HasFlag([Microsoft.Exchange.Data.Directory.SystemConfiguration]::Mailbox) -and $null -ne (Get-HybridConfiguration)) {
    LogMessage -Message "Hybrid Configuration detected. Consider using the Exchange Health Checker script https://aka.ms/ExchangeHealthChecker." -Type Warning
}

LogMessage "Collecting all send connectors."
$sendConnectors = Get-SendConnector -Verbose:$false

LogMessage "Collecting receive connectors listening on port 25."
$recvConnectors = Get-ReceiveConnector -Verbose:$false

LogMessage "Collecting list of certificates using Get-ExchangeCertificate for machine '$($env:COMPUTERNAME)'."
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

LogMessage -Message "Analyzing Receive connectors..."
LogMessage -Message " "
AnalyzeReceiveConnectors

# Save log to file
WriteLogToFile

# SIG # Begin signature block
# MIIm8wYJKoZIhvcNAQcCoIIm5DCCJuACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUR/u8S0BqPAMQIp31TyKo7hb6
# VSSggiCbMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSYoAMCAQICEAitQLJg0pxM
# n17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIxMDQyOTAwMDAwMFoXDTM2
# MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DFu8SFJjCfpI5o2Fz16zQk
# B+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1wJGSzjeIIfTR9TIBXEmtD
# mpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn+piASTWHPVEZ6JAheEUu
# oZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmjeEL0UV13oGBNlxX+yT4Us
# SKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50pa85tqtgEuPo1rn3MeHc
# reQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+wOwnXx5syWsL/amBUi0nB
# k+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0UogzYqZihfsHPOiyYlBrKD
# 1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXMu+NIUPN3kRr+21CiRshh
# WJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0tddGFNPxKRdt6/WMtyEClB
# 8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBzhRAjIVlgimRUwcwhGug4
# GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkCzGw8DFYRAgMBAAGjggFZ
# MIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8B
# Af8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1UdIAQVMBMwBwYFZ4EMAQMw
# CAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9jQh27o+8OpnTVuACGqX4
# SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8Ol1IbZXVP0n0J7sWgUVQ
# /Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2vaFIGH7c2IAaERkYzWGZ
# gVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI1Rr+1yc//ZDRdobdHLBg
# XPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4M8hPOBSSmfXdzlRt2V0C
# FB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrOJukYvpAHsEN/lYgggnDw
# zMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcKBtYmZ7eS5k5f3nqsSc8u
# pHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE6BaRUotBwEiES5ZNq0RA
# 443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0zh57ju+168u38HcT5uco
# P6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpqQDBISzSoUSC7rRuFCOJZ
# DW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD7YZF9LRhbr9o4iZghurI
# r6n+lB3nYxs6hlZ4TjCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTla
# MEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UE
# AxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIV
# WMGpkxGnzaqyat0QKYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9Yr
# IBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5x
# XsQGmjzwxS55DxtmUuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4
# KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUd
# vJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZ
# BzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02ke
# fGRNnQ/fztFejKqrUBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1
# x4Nk1nXNjxJ2VqUk+tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhv
# ltXhEBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPs
# CvERLmTgyyIryvEoEyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQAB
# o4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T
# 5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0
# YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGlt
# ZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1P
# ijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09
# SI64a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5
# j9smViuw86e9NwzYmHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXT
# UOREEr4gDZ6pRND45Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08z
# jdSNd311RaGlWCZqA0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9N
# UvPJYCHEVkft2hFLjDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg2
# 1Llyln6XeThIX8rC3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44Owde
# OVj0fHMxVaCAEcsUDH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLYOrixRoZr
# uhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7
# KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywG
# Ru9BHvDwX+Db2a2QgESvgBBBijCCBtowggTCoAMCAQICEArx8amB0NDrO6HOBWrh
# kz4wDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2ln
# bmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMTAeFw0yMzAzMTEwMDAwMDBaFw0y
# NTAzMTMyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIEwVUZXhhczEPMA0G
# A1UEBxMGSXJ2aW5nMRgwFgYDVQQKEw9SaWNoYXJkIEZhamFyZG8xGDAWBgNVBAMT
# D1JpY2hhcmQgRmFqYXJkbzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGB
# AMMH8sXjUbUrpEqDBEM5vtduT1uEurj0xmp8SeNNCZvipsc7rZ4d6sK7gpc9fsZk
# wn6BVeQAip9hBA03xmNK0sBdOFzAsk1mHSvZbFYifv7fb9bHDQUivKfykIaZgZmD
# /tD+vn/Fg1qUOv6/fMhB+H4zbi9Ln8xJy9LokGJhXNjwNa1MXfNW+QTKah3Be+2D
# AdbfkmEjfH9kIfBQXmiaXRhvy0SrMDn63rGk1nMBnO+7fvDgDhl9/zI8cZBPHcn/
# kyl/dKi3RgmuFxRPuOu4V3jZDM0z+HVchuBg/WTjOKJhAm8WnN8QJWH9o0Z/Xh+L
# jGm+AZpOloeXSHBEUN/3xEstblm7qELU/QvdLqjtER57RgEKvD6orKFEKDXQXqtO
# nTepNPBxmk5qxD0qvxTBpNJc5fxkrXjPAO7bM/A9E5vTNA7yJN7qRddaq91QQR86
# etCx+RJG9i1FFlmjvKDshXs8c17uvDR3ry96FXh9YwQG3IwKfvf/1pkl5qJNXdWZ
# vQIDAQABo4ICAzCCAf8wHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsIiGX0TkIw
# HQYDVR0OBBYEFG6ItulYwbKWmNAlQK2JcPHPUGo0MA4GA1UdDwEB/wQEAwIHgDAT
# BgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JT
# QTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0
# MjAyMUNBMS5jcmwwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggrBgEFBQcCARYb
# aHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGUBggrBgEFBQcBAQSBhzCBhDAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFwGCCsGAQUFBzAC
# hlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRD
# b2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNydDAJBgNVHRMEAjAAMA0G
# CSqGSIb3DQEBCwUAA4ICAQBrSBP6l3VUVEKOQA+58A2z8gp48suJ7pfcFdtQpWKH
# Rjq0V61+n+1Pgr2/efFmtExY0fd97j/zwbdLAk9kqAS4jYuR4Wk1di42mED1lQki
# ROdUFKfN7zq2LJpKC5WHCvsE5Szgoe5Kq7b8TLyVSf2Ulpcsen9qzQ1ZZcSDmVIf
# uiGkGEQ4fakhcxxL9Eho48fwepZnpAr0kQ7/SQVN9Mpt4UkVaRUVKrQkjTJHxW1D
# GTaKwUb2xRMtnW/bj4EScHAN9JYIjr5UptCUyg5RFZn1fnUHtq61kDdwRqA/G+wg
# lgWAUWmar9pGKO7rc07iF8iqIPysrMVz8CWnnkZXfJJ6bw5JeAine5GTQ0Ryf2P+
# PF9RyIQSEp7I7uDBWXVIBiint9PIC3z6fkHKsVA7W4wx2facvTCDG+KmnnGZ0EqI
# uw39ne2tRWCWObKqs3LsELN9sdoi43/OhF/Qj60u3S+of+EapwxUuQuoVhE8tHFN
# pkukENJ6K3SUWSG37Rj1bylpRqgILHGhsUKSCtTCiuB615s4cT0JzXUhuiz6smoZ
# ql+Cfy/A7BIvfZU6Spucft4Z2gm4e+o9sG/3qTQSRDIB61Hq92GeEOvNx780E9Rp
# 9iR2/F5ggsYxQQ3hQxNQfGFQGNA21OckIN2P7TayxjNmvKa1fGh61VYd6XqsUlzI
# +jGCBcIwggW+AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmlu
# ZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQCvHxqYHQ0Os7oc4FauGTPjAJBgUr
# DgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkq
# hkiG9w0BCQQxFgQU+LvK/ZKtEoDIYbyn/+X97/t4SH8wDQYJKoZIhvcNAQEBBQAE
# ggGAGxtNQZUiMSv6ByTY3xEa3efTUImERTr64CZS7LBZS/hmwqu5Z3zEsTvbd5NE
# pkcxDVTd7xN8UAZRP9XYm1w8dnyb8SRywb5PWvNGusnyRII9EtQK+wNoqOlTfuca
# 4g9vD0II5ti1MNxZc7Vb3QVNWCczuxSw+R21TAa9/+pzIgEamMnS4vMsTgicug/g
# 1VmJPFTTKl+j/8Gnf4nL6Mltm5R/UdV3Vb9tPKVdu1Foq4FJSiNs5oSlx6ZwqzKG
# kEDeFLjllotm+lT+pW5iBoft1T1XEi2grt+J+Lrcq41aS3/m756KlC4oYZhgmUrl
# NHWIzH1qSzwf9/2LUNiILeYxdmqaxUbxbQQiQMZ0Hj7JGIINvbW2IonjctOADpgC
# CoE5T714EU5kLyjYbDeIRE3F56j9WyiiB3QrbwyQMVHlXKxvZt2azx3EQn4qMEuv
# Myac07RHJqQrcgylFKl96b0Y++o/dM/npqyLacjelZTri+xu7MNWFMfZ+K1+YmgL
# dgO4oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQBUSv85Sd
# CDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG
# 9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMTIxMTE2MTY1MFowLwYJKoZIhvcNAQkE
# MSIEIPCvteUI8zXJSFInEnt2xn33m+oJCTGuBxEHT9nBzxq3MA0GCSqGSIb3DQEB
# AQUABIICAI+KmwaRqDXeBYqIAjH+2aF4YcXm10/pYlqn3wlOTuY9tY2bH5UlkqJ9
# b5ti2+bCpkUPuOhz8TXHg1H6pSvj6iNqR8/KrXMTGKmvvlPINMrmBhrsA+k9sAoO
# k4k1tVWuzDVrsUZ4pu55ZcclgtteA6VtK2x4BVmw3n+TMmEzU2+ETTK8Yma715Mn
# CbDWpbIplZRo7yNP7QlVA5d9cOBnOaR1NWlTIEqLkdvfdGv/R4Auc8QIanAYa/ih
# RoYSUWjT/L8GQhEjSxSElBa5LCZrNG/iXXV5OAao1+ZQmiWR9sNnTnprykgFMQPg
# YKvHtGv3GpAei7LmUhuMwdooX4TwhBrkHq6zEPwpaTXL26in2I4n2q2D2Ylm9Jx0
# VNm3YJsp/rDaNjURL8JDZvmLYOU57SH2E12MQzCFvvdGH1x6WL/ePXGbc3hyxjXA
# bojxecXwGFZk+98UsF9+v6EHAttNqTHWlFaeM2Xduawiz537hK/ci4x1Z0ERiMfp
# YvJ+WgIlPvXrCHjXDP2pJKa/1Mqrs0cIcfi0SJ92oMk1UyXmMF7nf0pcsvu/vMAi
# bEBdujDykchyztTCck/G9+uGfKOtUhjskSOoCtVjf75V1x8ibfkYCQdOLBd4aEdV
# A1LxaKPkhCsNVdSVbc00x3ZQuPQHgh3gjOfwIFmYO+aOxpyUOv/H
# SIG # End signature block
