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

# Version 1.0.4
# Exchange versions supported: 2013, 2016, 2019

param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$RecipientDomain
)

function LogMessage(){
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

    if (-not $LogOnly){
        if(-not $ForegroundColor){
            $ForegroundColor = "White"
        }

        if(-not $Type){
            $Type = "Information"
        }
        if($Type -eq "Warning"){
            Write-Warning $Message
            $Message = "WARNING: $Message"
        }
        elseif($Type -eq "Verbose"){
            Write-Verbose $Message
            $Message = "VERBOSE: $Message"
        }
        elseif($Type -eq "Error"){
            Write-Error $Message -ErrorAction Stop
        }
        else {
            Write-Host $Message -ForegroundColor $ForegroundColor
        }
    }

    $Script:Log += $Message
}

function WriteLogToFile(){
    $logFile = "Check-HybridMailflowConfig_$($env:COMPUTERNAME).log"
    $logPath = Join-Path $PSScriptRoot $logFile

    if(-not (Test-Path $logPath)){
        New-Item -Path $logPath -ItemType File -Force | Out-Null
    }

    $dateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddThh:mm:ss.fffK")
    $log = @()
    $log += "Script run time: $dateTime `n"
    $log += $Script:Log

    Add-Content -Path $logPath -Value $log

    Write-Host "Log file created at: $logPath" -ForegroundColor Green
}

function ParseDomain($domain){
    return $domain.Substring($domain.IndexOf('.') + 1)
}

function IsCloudConnector($connector)
{
    # Cloud connector if the address space contains remote routing domain and MX record lookup is enabled
    if ($connector.DNSRoutingEnabled){
        foreach($address in $connector.AddressSpaces){
            if ($address.Domain -like "*.mail.onmicrosoft.com"){
                return $true
            }
        }
    }

    # Cloud connector if smart host contains EOP/EXO endpoint
    if (-not $connector.DNSRoutingEnabled){
        foreach($hostName in $connector.SmartHosts){
            if($hostName.Domain.HostnameString -like "*.mail.protection.outlook.com"){
                return $true
            }
        }
    }
}

function IsCertEnabledForSmtp($cert)
{
    $services = $cert.Services.ToString()

    if([string]::IsNullOrEmpty($services)){
        LogMessage -Message "Certificate 'Services' property is null." -Type Verbose
        return $false
    }
    else {
        $services = $services.Split(',').Trim()
        if($services.Contains('SMTP')){
            return $true
        }
    }

    # SMTP service not found
    return $false
}

function MatchValidCertificate($connector){
    # List of matching certificates
    $matchingCertificates = @()
    foreach($cert in $certificates){
        # Skip and log if cert is self signed
        if($cert.IsSelfSigned){
            LogMessage -Message "Skipping self signed certificate: '<I>$($cert.Issuer)<S>$($cert.Subject)'" -LogOnly
            continue
        }

        # Skip and log if cert is invalid
        if($cert.Status -ne "Valid"){
            LogMessage -Message "Skipping invalid certificate: '<I>$($cert.Issuer)<S>$($cert.Subject)'" -Type Warning
            continue
        }

        if (-not [string]::IsNullOrEmpty($connector.TlsCertificateName)){
            foreach($cert in $certificates){
                $foundMatch = ($connector.TlsCertificateName.CertificateSubject -eq $cert.Subject -and $connector.TlsCertificateName.CertificateIssuer -eq $cert.Issuer)
                LogMessage -Message "ExchangeCertMatchesConnector:$foundMatch ExchangeCert:'<I>$($cert.Issuer)<S>$($cert.Subject)'" -Type Verbose
                if ($foundMatch){
                    $matchingCertificates += $cert
                }
            }
        }
        else {
            # Check if there is a wild card domain
            # If wild card domain is present try to match FQDN to wild card
            $wildCardDomain = ($cert.CertificateDomains | Where-Object IncludeSubDomains -eq $true).Address
            
            if($wildCardDomain){
                # Parse the domain from mail.domain.com to domain.com
                $d = ParseDomain($connector.Fqdn.Domain)

                if ($d -eq $wildCardDomain){
                    $matchingCertificates += $cert
                }
            }

            # Check all domains for a matching domain
            foreach ($domain in $cert.CertificateDomains.Domain){
                if ($connector.Fqdn.Domain -eq $domain){
                    $matchingCertificates += $cert
                }
            }
        }
    }

    # No matching certificates found
    if ($matchingCertificates.Count -eq 0){
        return $false
    }

    # Only one matching certificate found
    if ($matchingCertificates.Count -eq 1){
        if(IsCertEnabledForSmtp($matchingCertificates[0])){
            return $true
        }
        else {
            LogMessage -Message "Skipping certificate '$($cert.Thumbprint)' as it is not enabled for SMTP service." -Type Verbose
            return $false
        }
    }

    # Multiple matching certificates found
    if ($matchingCertificates.Count -gt 1){
        LogMessage -Message "Multiple matching certificates found for connector '$($connector.Name)'." -Type Verbose
        # Sort connector by NotBefore date
        $matchingCertificates = $matchingCertificates | Sort-Object -Property NotBefore -Descending

        # Is the first certificate enabled for SMTP. If not, then the connector is misconfigured
        # Even if other certs are enabled, transport will pick the newest certificate
        if(IsCertEnabledForSmtp($matchingCertificates[0])){
            return $true
        }
        else {
            LogMessage -Message "First certificate in collection is not enabled for SMTP service. Skipping all certificates." -Type Verbose
            LogMessage -Message "Multiple matching certificates found for connector '$($connector.Name)'. Cannot determine correct certificate." -Type Warning
            return $false
        }
    }
}

function AnalyzeSendConnectors()
{
    foreach($c in $sendConnectors){
        if (IsCloudConnector($c)){
    
            [bool]$skipCertCheck = $false
    
            $r = [PSCustomObject] @{
                ConnectorName = $c.Name
                MisConfigured = $false
                CustomConnectorDetected = $false
                TlsCertificateName = $c.TlsCertificateName
                TlsAuthLevel = $c.TlsAuthLevel
                TlsDomain = $c.TlsDomain
                CloudServicesMailEnabled = $c.CloudServicesMailEnabled
                Fqdn = $c.Fqdn
                MatchedValidCertificate = $false
            }
            # Detect if custom connector
            if(-not ($c.Name -match 'Outbound to Office 365 - [a-fA-F\d]{8}-[a-fA-F\d]{4}-[a-fA-F\d]{4}-[a-fA-F\d]{4}-[a-fA-F\d]{12}')){
                $r.CustomConnectorDetected = $true
            }
    
            # Needed for header preservation
            if (-not $c.CloudServicesMailEnabled){
                $r.MisConfigured = $true
                LogMessage -Message "CloudServicesMailEnabled is set to false. Expected a value of 'True'." -Type Warning
            }
    
            # Needed for XOORG and client certificate auth
            if ($c.TlsAuthLevel -ne "DomainValidation"){
                $r.MisConfigured = $true
                LogMessage -Message "TlsAuthLevel is set to '$($c.TlsAuthLevel)'. Expected a value of 'DomainValidation'." -Type Warning
            }

            # Matching on *.outlook.com to catch prior versions
            if ($c.TlsDomain -notlike "*.outlook.com"){
                $r.MisConfigured = $true
                LogMessage -Message "TlsDomain is set to '$($c.TlsDomain)'. Expected a value of 'mail.protection.outlook.com'." -Type Warning
            }
    
            # Either should be set but if both null the wrong certificate may be used
            # Ideally the TlsCertificateName property is used which is set by HCW
            if ([string]::IsNullOrEmpty($c.TlsCertificateName) -and [string]::IsNullOrEmpty($c.Fqdn)){
                $r.MisConfigured = $true
                $skipCertCheck = $true
                LogMessage -Message "TlsCertificateName and FQDN are null. A value should be set to specify the certificate to be used." -Type Warning
            }

            # Only run cert check if the source transport server is this machine
            if(-not ($c.SourceTransportServers.Name -contains $env:COMPUTERNAME)){
                # If one of the machines is an EDGE role continue with cert check
                # Since you can't mix Hub/Mailbox and Edge roles checking one server should be safe
                if (-not (Get-ExchangeServer -Identity $c.SourceTransportServers[0].Name -Verbose:$false).ServerRole.value__ -eq 64){
                    $skipCertCheck = $true
                    LogMessage -Message "$($env:COMPUTERNAME) is not a source transport server for this connector." -Type Warning
                }
            }

            if($c.SourceTransportServers.Count -gt 1){
                LogMessage -Message "Re-run this script for all source transport servers for this connector. SourceTransportServers: $($c.SourceTransportServers -join ',')" -Type Warning
            }
    
            # Is there a matching certificate
            if (-not $skipCertCheck){
                if([string]::IsNullOrEmpty($c.TlsCertificateName)){
                    LogMessage -Message "Consider specifying a certificate using TlsCertificateName property." -Type Warning
                }

                if(MatchValidCertificate($c)){
                    $r.MatchedValidCertificate = $true
                }
                else {
                    $r.MisConfigured = $true
                    LogMessage -Message "There were no matching certificates for this connector." -Type Warning
                }
            }

            if ($r.MisConfigured){
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

function ValidateRecipientRoutingDomain($domain)
{
    $acceptedDomains = Get-AcceptedDomain
    # If there is an accepted domain 
    if ($acceptedDomains | Where-Object {$_.DomainName.Domain -eq $domain}){
        return $true
    }
    # If accepted domains include subdomains
    $subAcceptedDomains = $acceptedDomains | Where-Object MatchSubDomains -eq $true
    if ($subAcceptedDomains){
        $d = ParseDomain($domain)
        foreach($subDomain in $subAcceptedDomains){
            if ($subDomain.DomainName.Domain -eq $d){
                LogMessage -Message "Found matching accepted domain '$($subDomain.DomainName.Domain)' with 'MatchSubDomains' set to true." -Type Verbose
                return $true
            }
        }
    }

    # Check if there is a correctly configured remote domain
    $remoteDomain = Get-RemoteDomain | Where-Object DomainName -eq $domain

    if ([string]::IsNullOrEmpty($remoteDomain)){
        return $false
    }
    else {
        $validDomain = $true
        LogMessage -Message "Found RemoteDomain for domain '$domain'."
        if ($remoteDomain.IsInternal -eq $false){
            $validDomain = $false
            LogMessage -Message "Remote domain IsInternal is 'False'. Expected a value of 'True'. " -Type Warning
        }

        if ($remoteDomain.TrustedMailOutboundEnabled -eq $false){
            $validDomain = $false
            LogMessage "Remote domain TrustedMailOutboundEnabled is 'False'. Expected a value of 'True'." -Type Warning
        }
        return $validDomain
    }
}

$Script:Log = @()

# Check if running in local Exchange PowerShell
if (-not (Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -Registered -ErrorAction SilentlyContinue))
{
    LogMessage "Diagnostic script must be run in shell with Exchange snap-in. Remote session is not supported for this script." -Type Error
}

$serverRole = Get-ExchangeServer -identity $env:COMPUTERNAME -Verbose:$false | Select-Object ServerRole

# If Hybrid Configuration is detected advise running CSS Health Checker script
if($serverRole -eq "Mailbox" -and $null -ne (Get-HybridConfiguration)){
    LogMessage -Message "This script is not intended for use with Hybrid Configuration. Please run the CSS Health Checker script instead." -Type Warning
}

LogMessage "Collecting all send connectors."
$sendConnectors = Get-SendConnector -Verbose:$false

LogMessage "Collecting list of certificates using Get-ExchangeCertificate for this machine '$($env:COMPUTERNAME)'."
$certificates = Get-ExchangeCertificate -Verbose:$false

# Terminate if no connectors found
if ($sendConnectors.Count -eq 0){
    LogMessage "No send connectors found." -Type Error
}

LogMessage -Message "Analyzing send connectors..."
LogMessage -Message " "
AnalyzeSendConnectors

if ($RecipientDomain){
    LogMessage -Message "Verifying recipient domain '$RecipientDomain'."

    if (ValidateRecipientRoutingDomain($RecipientDomain))
    {
        LogMessage -Message "Recipient domain is correctly configured." -ForegroundColor Green
    }
    else {
        LogMessage -Message "Manual investigation is needed. Either there is no accepted domain or the remote domain is misconfigured." -ForegroundColor Red
    }
}

# Save log to file
WriteLogToFile

# SIG # Begin signature block
# MIIm8QYJKoZIhvcNAQcCoIIm4jCCJt4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUi86RjuzyAj0Floz8OZ53oy8s
# F2qggiCZMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
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
# r6n+lB3nYxs6hlZ4TjCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVowDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMjA5MjEwMDAwMDBaFw0zMzExMjEyMzU5NTla
# MEYxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEkMCIGA1UEAxMbRGln
# aUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAz+ylJjrGqfJru43BDZrboegUhXQzGias0BxVHh42bbySVQxh9J0J
# dz0Vlggva2Sk/QaDFteRkjgcMQKW+3KxlzpVrzPsYYrppijbkGNcvYlT4DotjIdC
# riak5Lt4eLl6FuFWxsC6ZFO7KhbnUEi7iGkMiMbxvuAvfTuxylONQIMe58tySSge
# TIAehVbnhe3yYbyqOgd99qtu5Wbd4lz1L+2N1E2VhGjjgMtqedHSEJFGKes+JvK0
# jM1MuWbIu6pQOA3ljJRdGVq/9XtAbm8WqJqclUeGhXk+DF5mjBoKJL6cqtKctvdP
# bnjEKD+jHA9QBje6CNk1prUe2nhYHTno+EyREJZ+TeHdwq2lfvgtGx/sK0YYoxn2
# Off1wU9xLokDEaJLu5i/+k/kezbvBkTkVf826uV8MefzwlLE5hZ7Wn6lJXPbwGqZ
# IS1j5Vn1TS+QHye30qsU5Thmh1EIa/tTQznQZPpWz+D0CuYUbWR4u5j9lMNzIfMv
# wi4g14Gs0/EH1OG92V1LbjGUKYvmQaRllMBY5eUuKZCmt2Fk+tkgbBhRYLqmgQ8J
# JVPxvzvpqwcOagc5YhnJ1oV/E9mNec9ixezhe7nMZxMHmsF47caIyLBuMnnHC1mD
# jcbu9Sx8e47LZInxscS451NeX1XSfRkpWQNO+l3qRXMchH7XzuLUOncCAwEAAaOC
# AYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAf
# BgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUYore0GH8
# jzEU7ZcLzT0qlBTfUpwwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFt
# cGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAVaoqGvNG83hXNzD8deNP
# 1oUj8fz5lTmbJeb3coqYw3fUZPwV+zbCSVEseIhjVQlGOQD8adTKmyn7oz/AyQCb
# Ex2wmIncePLNfIXNU52vYuJhZqMUKkWHSphCK1D8G7WeCDAJ+uQt1wmJefkJ5ojO
# fRu4aqKbwVNgCeijuJ3XrR8cuOyYQfD2DoD75P/fnRCn6wC6X0qPGjpStOq/CUkV
# NTZZmg9U0rIbf35eCa12VIp0bcrSBWcrduv/mLImlTgZiEQU5QpZomvnIj5EIdI/
# HMCb7XxIstiSDJFPPGaUr10CU+ue4p7k0x+GAWScAMLpWnR1DT3heYi/HAGXyRkj
# gNc2Wl+WFrFjDMZGQDvOXTXUWT5Dmhiuw8nLw/ubE19qtcfg8wXDWd8nYiveQclT
# uf80EGf2JjKYe/5cQpSBlIKdrAqLxksVStOYkEVgM4DgI974A6T2RUflzrgDQkfo
# QTZxd639ouiXdE4u2h4djFrIHprVwvDGIqhPm73YHJpRxC+a9l+nJ5e6li6FV8Bg
# 53hWf2rvwpWaSxECyIKcyRoFfLpxtU56mWz06J7UWpjIn7+NuxhcQ/XQKujiYu54
# BNu90ftbCqhwfvCXhHjjCANdRyxjqCU4lwHSPzra5eX25pvcfizM/xdMTQCi2NYB
# DriL7ubgclWJLCcZYfZ3AYwwggbaMIIEwqADAgECAhAK8fGpgdDQ6zuhzgVq4ZM+
# MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjMwMzExMDAwMDAwWhcNMjUw
# MzEzMjM1OTU5WjBiMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxDzANBgNV
# BAcTBklydmluZzEYMBYGA1UEChMPUmljaGFyZCBGYWphcmRvMRgwFgYDVQQDEw9S
# aWNoYXJkIEZhamFyZG8wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDD
# B/LF41G1K6RKgwRDOb7Xbk9bhLq49MZqfEnjTQmb4qbHO62eHerCu4KXPX7GZMJ+
# gVXkAIqfYQQNN8ZjStLAXThcwLJNZh0r2WxWIn7+32/Wxw0FIryn8pCGmYGZg/7Q
# /r5/xYNalDr+v3zIQfh+M24vS5/MScvS6JBiYVzY8DWtTF3zVvkEymodwXvtgwHW
# 35JhI3x/ZCHwUF5oml0Yb8tEqzA5+t6xpNZzAZzvu37w4A4Zff8yPHGQTx3J/5Mp
# f3Sot0YJrhcUT7jruFd42QzNM/h1XIbgYP1k4ziiYQJvFpzfECVh/aNGf14fi4xp
# vgGaTpaHl0hwRFDf98RLLW5Zu6hC1P0L3S6o7REee0YBCrw+qKyhRCg10F6rTp03
# qTTwcZpOasQ9Kr8UwaTSXOX8ZK14zwDu2zPwPROb0zQO8iTe6kXXWqvdUEEfOnrQ
# sfkSRvYtRRZZo7yg7IV7PHNe7rw0d68vehV4fWMEBtyMCn73/9aZJeaiTV3Vmb0C
# AwEAAaOCAgMwggH/MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0G
# A1UdDgQWBBRuiLbpWMGylpjQJUCtiXDxz1BqNDAOBgNVHQ8BAf8EBAMCB4AwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIw
# MjFDQTEuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQ
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkq
# hkiG9w0BAQsFAAOCAgEAa0gT+pd1VFRCjkAPufANs/IKePLLie6X3BXbUKVih0Y6
# tFetfp/tT4K9v3nxZrRMWNH3fe4/88G3SwJPZKgEuI2LkeFpNXYuNphA9ZUJIkTn
# VBSnze86tiyaSguVhwr7BOUs4KHuSqu2/Ey8lUn9lJaXLHp/as0NWWXEg5lSH7oh
# pBhEOH2pIXMcS/RIaOPH8HqWZ6QK9JEO/0kFTfTKbeFJFWkVFSq0JI0yR8VtQxk2
# isFG9sUTLZ1v24+BEnBwDfSWCI6+VKbQlMoOURWZ9X51B7autZA3cEagPxvsIJYF
# gFFpmq/aRiju63NO4hfIqiD8rKzFc/Alp55GV3ySem8OSXgIp3uRk0NEcn9j/jxf
# UciEEhKeyO7gwVl1SAYop7fTyAt8+n5ByrFQO1uMMdn2nL0wgxvipp5xmdBKiLsN
# /Z3trUVgljmyqrNy7BCzfbHaIuN/zoRf0I+tLt0vqH/hGqcMVLkLqFYRPLRxTaZL
# pBDSeit0lFkht+0Y9W8paUaoCCxxobFCkgrUworgetebOHE9Cc11Ibos+rJqGapf
# gn8vwOwSL32VOkqbnH7eGdoJuHvqPbBv96k0EkQyAetR6vdhnhDrzce/NBPUafYk
# dvxeYILGMUEN4UMTUHxhUBjQNtTnJCDdj+02ssYzZrymtXxoetVWHel6rFJcyPox
# ggXCMIIFvgIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTECEArx8amB0NDrO6HOBWrhkz4wCQYFKw4D
# AhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwG
# CisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZI
# hvcNAQkEMRYEFBpYJXRVezzcKP9AhyMwAZEqshR2MA0GCSqGSIb3DQEBAQUABIIB
# gESuN44+lwLm9vKyzKQO89xDY4pS0hp6xl4G0kAa94xrbdZsv8v+CQy3ZXhs7NXn
# k7+36hxEJ/1s7dQSdCk6NWcLRU5UDjdLodRKrXB1Gi+mIYhpzQ72/MZ5yFk3lw5+
# rK5JOrz00ZdxUZqravobXlnbAHidrfaK+yXrZV0otHpcSx704D5p0CELI1v2tDCp
# TSjmVuNOfvZAKOwBB+WhqQdVxT8bQSfH+/m2mJwDEXU6INlaal3ATdWuX95AG5pp
# enhlWKgVmuCIc0J5pAQpmWblllIJZIyYMDQG+h7Ii4lXFvQTsboWYPnKNUAyIuqu
# +emrqiQ3t12h6AdHQAWNOfAIVPRBU9IO67kFxC2+CiVId+xTvNwVJL2bP6LhH9bI
# +DVN7EqcEgOHsm/rGKQTT0FykUk/AgC/nKFySBfzW9p/m4nEQhfZ0uV722Ajb79H
# n5L2NCkwr8CsL/gHe/7tiX33bvQSLCAyljeEYpjBVCVsXgyQh4iL4mDDBY7fSIZ0
# AKGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAxNaXJLlPo8
# Kko9KQeAPVowDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yMzA1MjIyMTI5NDlaMC8GCSqGSIb3DQEJBDEi
# BCAzX/hAsIzUscB+aBuijpLtCPIilJB39neDR6I/ctMvPjANBgkqhkiG9w0BAQEF
# AASCAgAITRUn9nRzMhDhFnfu7oIoGzDivmYEIY2zBCCT7YYx/EOXg6iFsX7023vW
# eaPLmlfDfxyJKrT0cy3ImoS6otOHRWMzQjfRt9HiaQT00OtQ7RHEa/jrbuByA6t8
# znzW731/9EUDKVhHlO2PsFspACqt5vURYbxw7UeFqXZrwZtNJJ30E7pKz1jLfzLw
# 5y8L1Ty+rQq+aHQvbdO78JTPtFQLnq84JIzpF9ezugmT2P0rzNbdCSwbui27GMbD
# wfeQFl58mlsbLQZ1UfEw+RDTeIJWJa3HXfCQr3ud3GJ4u2GhF/UnG3Hoyx3rP7zw
# +55vE5uX8m4AfP2EZ/vML9+0VLl/5gsDOgdnt4cpHd/oF9vZVyEnGwPUnxnUPtId
# 4LsG2Vt2hUBQx0D2lO9n0Jl71u4guMwcGDz2Rj3YH/fXBBXscl22fJepnlwLOFEH
# TFN10UdRBNChm7FBwVsGvGrQmcihLF7jBSfX8rglrwiCGNNd1aFUkOekZq6CQoh4
# us906U/zeq9j59rxr/zjZxL6+wVQ7Kc6LsOWDzWg6VbqEFq1cH6yDXxO8upYJbj0
# g5wpMAaRWVTGZO0DTWm2uDaXBUaHv5mIo6PXFWC4sC753IzNr0B0Z1CpVjSXp/nh
# HuCS4kwZQ6QiJaUPARQ6mO5aAPTGVr19fu+v6oNqUIEMTyqSiQ==
# SIG # End signature block
