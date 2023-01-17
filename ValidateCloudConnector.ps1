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

function MatchCertificate($connector){
    foreach($cert in $certificates){
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
            # If wild card domain present try to match FQDN to wild card
            $wildCardDomain = ($cert.CertificateDomains | Where-Object IncludeSubDomains -eq $true).Address

            if($wildCardDomain){
                if ($connector.Fqdn -like $wildCardDomain){
                    return $true
                }
            }

            # Else match FQDN to a domain in certificate domains
            else {
                foreach ($domain in $cert.CertificateDomains.Domain){
                    if ($connector.Fqdn -eq $domain){
                        return $true
                    }
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
                TlsCertificateName = $c.TlsCertificateName
                TlsAuthLevel = $c.TlsAuthLevel
                TlsDomain = $c.TlsDomain
                CloudServicesMailEnabled = $c.CloudServicesMailEnabled
                Fqdn = $c.Fqdn
                MatchedValidCertificate = $false
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
                Write-Warning "TlsDomain iset set to '$($c.TlsDomain)'. Expected a value of 'mail.protection.outlook.com'."
            }
    
            # Either should be set but if both null the wrong certificate may be used
            # Ideally the TlsCertificateName property is used which is set by HCW
            if ([string]::IsNullOrEmpty($c.TlsCertificateName) -and [string]::IsNullOrEmpty($c.Fqdn)){
                $r.MisConfigured = $true
                $skipCertCheck = $true
                Write-Warning "TlsCertificateName and FQDN are null. A value should be set to specify the certificate to be used."
            }
    
            # Is there a matching certificate
            if (-not $skipCertCheck){
                if([string]::IsNullOrEmpty($c.TlsCertificateName)){
                    Write-Host "Consider specifying a certificate using TlsCertificateName property." -ForegroundColor Yellow
                }

                if(MatchCertificate($c)){
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

# Checking if running in local PowerShell
if (-not (Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -Registered -ErrorAction SilentlyContinue))
{
    Write-Error "Diagnostic script must be run in shell with Exchange snap-in. Remote session is not supported for this script." -ErrorAction Stop
}

Write-Host "Collecting all send connectors."
$sendConnectors = Get-SendConnector

Write-Host "Collecting list of certificates using Get-ExchangeCertificate for this machine only."
$certificates = Get-ExchangeCertificate | Where-Object IsSelfSigned -eq $false

# Bail if no connectors found
if ($sendConnectors.Count -eq 0){
    Write-Error "No send connectors found." -ErrorAction Stop
}

Write-Host "Analyzing send connectors"
AnalyzeSendConnectors
