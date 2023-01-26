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
  Used to validate if On-Premises send connectors are correctly configured for sending mail to Office 365 tenant. This script will examine both HCW and non HCW created connectors.
 .Parameter RecipientDomain
  Optional paramater to validate if the recipient domain is correctly configured On-Premises.
 .Example
   # Validate connector(s)
   .\ValidateCloudConnectors.ps1
 .Example
   # Validate connector(s) and recipient domain
   .\ValidateCloudConnectors.ps1 -RecipientDomain contoso.com
#>

# Version 1.0.2

# Exchange versions supported: 2013, 2016, 2019

param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$RecipientDomain
)

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
        Write-Verbose "Certificate 'Services' property is null."
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
    foreach($cert in $certificates){
        $certEnabled = IsCertEnabledForSmtp($cert)
        if($certEnabled -eq $false){
            # Move on to next cert if SMTP service is not enabled
            Write-Verbose "Skipping certificate '$($cert.Thumbprint)' as it is not enabled for SMTP service."
            continue
        }

        if (-not [string]::IsNullOrEmpty($connector.TlsCertificateName)){
            foreach($cert in $certificates){
                $certName = '<I>' + $cert.Issuer + '<S>' + $cert.Subject
    
                if ($c.TlsCertificateName -eq $certName){
                    return $true
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
                    return $true
                }
            }

            # Check all domains for a matching domain
            foreach ($domain in $cert.CertificateDomains.Domain){
                if ($connector.Fqdn.Domain -eq $domain){
                    return $true
                }
            }
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
                Write-Warning "CloudServicesMailEnabled is set to false. Expected a value of 'True'."
            }
    
            # Needed for XOORG and client certificate auth
            if ($c.TlsAuthLevel -ne "DomainValidation"){
                $r.MisConfigured = $true
                Write-Warning "TlsAuthLevel is set to '$($c.TlsAuthLevel)'. Expected a value of 'DomainValidation'."
            }

            # Matching on *.outlook.com to catch prior versions
            if ($c.TlsDomain -notlike "*.outlook.com"){
                $r.MisConfigured = $true
                Write-Warning "TlsDomain is set to '$($c.TlsDomain)'. Expected a value of 'mail.protection.outlook.com'."
            }
    
            # Either should be set but if both null the wrong certificate may be used
            # Ideally the TlsCertificateName property is used which is set by HCW
            if ([string]::IsNullOrEmpty($c.TlsCertificateName) -and [string]::IsNullOrEmpty($c.Fqdn)){
                $r.MisConfigured = $true
                $skipCertCheck = $true
                Write-Warning "TlsCertificateName and FQDN are null. A value should be set to specify the certificate to be used."
            }

            # Only run cert check if the source transport server is this machine
            if(-not ($c.SourceTransportServers.Name -contains $env:COMPUTERNAME)){
                # If one of the machines is an EDGE role continue with cert check
                # Since you can't mix Hub/Mailbox and Edge roles checking one server should be safe
                if (-not (Get-ExchangeServer -Identity $c.SourceTransportServers[0].Name).ServerRole.value__ -eq 64){
                    $skipCertCheck = $true
                    Write-Warning "$($env:COMPUTERNAME) is not a source transport server for this connector."
                }
            }

            if($c.SourceTransportServers.Count -gt 1){
                Write-Warning "Re-run this script for all source transport servers for this connector. SourceTransportServers: $($c.SourceTransportServers -join ',')"
            }
    
            # Is there a matching certificate
            if (-not $skipCertCheck){
                if([string]::IsNullOrEmpty($c.TlsCertificateName)){
                    Write-Warning "Consider specifying a certificate using TlsCertificateName property."
                }

                if(MatchValidCertificate($c)){
                    $r.MatchedValidCertificate = $true
                }
                else {
                    $r.MisConfigured = $true
                    Write-Warning "There were no matching certificates for this connector."
                }
            }

            if ($r.MisConfigured){
                Write-Host "Connector '$($r.ConnectorName)' is misconfigured. See additional details to resolve." -ForegroundColor Red
            }
            else {
                Write-Host "No issues found with connector '$($r.ConnectorName)'." -ForegroundColor Green
            }
            
            # Display results
            $r
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
                Write-Verbose "Found matching accepted domain '$($subDomain.DomainName.Domain)' with 'MatchSubDomains' set to true."
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
        Write-Host "Found RemoteDomain for domain '$domain'."
        if ($remoteDomain.IsInternal -eq $false){
            $validDomain = $false
            Write-Warning "Remote domain IsInternal is 'False'. Expected a value of 'True'. "
        }

        if ($remoteDomain.TrustedMailOutboundEnabled -eq $false){
            $validDomain = $false
            Write-Warning "Remote domain TrustedMailOutboundEnabled is 'False'. Expected a value of 'True'."
        }
        return $validDomain
    }
}

# Check if running in local Exchange PowerShell
if (-not (Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -Registered -ErrorAction SilentlyContinue))
{
    Write-Error "Diagnostic script must be run in shell with Exchange snap-in. Remote session is not supported for this script." -ErrorAction Stop
}

# If Hybrid Configuration is detected advise running CSS Health Checker script
if(Get-HybridConfiguration){
    Write-Warning "Hybrid Configuration detected. Consider using https://aka.ms/ExchangeHealthChecker for additional diagnostic details."
}

Write-Host "Collecting all send connectors."
$sendConnectors = Get-SendConnector

Write-Host "Collecting list of certificates using Get-ExchangeCertificate for this machine '$($env:COMPUTERNAME)'."
$certificates = Get-ExchangeCertificate | Where-Object {($_.IsSelfSigned -eq $false) -and ($_.Status -eq "Valid")}

# Terminate if no connectors found
if ($sendConnectors.Count -eq 0){
    Write-Error "No send connectors found." -ErrorAction Stop
}

Write-Host "Analyzing send connectors..."
Write-Host ""
AnalyzeSendConnectors

if ($RecipientDomain){
    Write-Host "Verifying recipient domain '$RecipientDomain'."

    if (ValidateRecipientRoutingDomain($RecipientDomain))
    {
        Write-Host "Recipient domain is correctly configured." -ForegroundColor Green
    }
    else {
        Write-Host "Manual investigation is needed. Either there is no accepted domain or the remote domain is misconfigured." -ForegroundColor Red
    }
}