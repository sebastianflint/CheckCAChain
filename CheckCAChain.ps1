<#
.SYNOPSIS
    Retrieves and displays all certificates (the full chain) presented by an HTTPS endpoint.

.DESCRIPTION
    Connects to the given HTTPS URL (or host), performs a TLS handshake and shows
    the leaf certificate plus all intermediate/root certificates that were built
    into the chain. Works even if the certificate is invalid, expired or self-signed.

.PARAMETER Url
    The HTTPS URL or hostname to inspect, e.g. "https://example.com" or "example.com".

.PARAMETER Port
    Optional port, default 443 (ignored if the URL already contains a port).

.PARAMETER ExportPath
    Optional folder. If given, every certificate in the chain is exported there
    as a .cer (DER) file.

.EXAMPLE
    .\Get-HttpsCertificateChain.ps1 -Url https://www.google.com

.EXAMPLE
    .\Get-HttpsCertificateChain.ps1 -Url example.com -Port 8443 -ExportPath C:\Temp\Certs
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Url,

    [Parameter(Mandatory = $false)]
    [int]$Port = 443,

    [Parameter(Mandatory = $false)]
    [string]$ExportPath
)

# --- Parse input: accept full URLs or bare hostnames -------------------------
$targetHost = $Url
if ($Url -match '^\w+://') {
    try {
        $uri = [Uri]$Url
        if ($uri.Scheme -ne 'https') {
            Write-Warning "Scheme '$($uri.Scheme)' given - connecting via TLS anyway."
        }
        $targetHost = $uri.Host
        if (-not $uri.IsDefaultPort) { $Port = $uri.Port }
    }
    catch {
        Write-Error "Could not parse URL '$Url': $_"
        return
    }
}
else {
    # allow "host:port" notation
    if ($targetHost -match '^(?<h>[^:/]+):(?<p>\d+)') {
        $targetHost = $Matches.h
        $Port = [int]$Matches.p
    }
    # strip any trailing path
    $targetHost = ($targetHost -split '/')[0]
}

Write-Host ""
Write-Host "Connecting to $targetHost on port $Port ..." -ForegroundColor Cyan

# --- TLS handshake, accept any certificate so we can inspect broken ones -----
$leafCert   = $null
$tlsInfo    = $null

# Try modern protocols first, then fall back. Windows PowerShell 5.1 / .NET
# Framework often does NOT offer TLS 1.2+ by default, which causes the
# "SSPI call failed" error against modern servers.
$protocolAttempts = @(
    @{ Name = 'TLS 1.3';        Value = 12288 },   # SslProtocols.Tls13 (not on older .NET - handled below)
    @{ Name = 'TLS 1.2';        Value = [System.Security.Authentication.SslProtocols]::Tls12 },
    @{ Name = 'System default'; Value = [System.Security.Authentication.SslProtocols]::None }
)

$callback  = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $cert, $chain, $errors) $true }
$lastError = $null

foreach ($attempt in $protocolAttempts) {
    $tcpClient = $null
    $sslStream = $null
    try {
        # Skip TLS 1.3 if this .NET version doesn't know it
        $proto = $attempt.Value
        if ($attempt.Name -eq 'TLS 1.3') {
            try { $proto = [System.Security.Authentication.SslProtocols]12288 } catch { continue }
        }

        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        $tcpClient.ReceiveTimeout = 10000
        $tcpClient.SendTimeout    = 10000

        $connectTask = $tcpClient.ConnectAsync($targetHost, $Port)
        if (-not $connectTask.Wait(10000)) {
            throw "Connection to ${targetHost}:${Port} timed out."
        }

        # Callback returns $true so invalid/expired/self-signed certs are still retrieved
        $sslStream = [System.Net.Security.SslStream]::new($tcpClient.GetStream(), $false, $callback)
        $sslStream.AuthenticateAsClient($targetHost, $null, $proto, $false)

        $tlsInfo = [PSCustomObject]@{
            Protocol        = $sslStream.SslProtocol
            CipherAlgorithm = $sslStream.CipherAlgorithm
            CipherStrength  = $sslStream.CipherStrength
            HashAlgorithm   = $sslStream.HashAlgorithm
            KeyExchange     = $sslStream.KeyExchangeAlgorithm
        }

        $leafCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
        break   # success - stop trying further protocols
    }
    catch {
        # Collect the innermost exception message for a useful error report
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        $lastError = "{0} attempt failed: {1}" -f $attempt.Name, $ex.Message
        Write-Verbose $lastError
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Dispose() }
    }
}

if (-not $leafCert) {
    Write-Error "TLS connection failed on all protocol attempts. Last error: $lastError"
    return
}

# --- Build the chain from the leaf certificate -------------------------------
$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
$chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
$chainIsValid = $chain.Build($leafCert)

# --- Output: connection info -------------------------------------------------
Write-Host ""
Write-Host "=== TLS Connection ===" -ForegroundColor Green
Write-Host ("  Protocol : {0}"        -f $tlsInfo.Protocol)
Write-Host ("  Cipher   : {0} ({1} bit)" -f $tlsInfo.CipherAlgorithm, $tlsInfo.CipherStrength)
Write-Host ("  Hash     : {0}"        -f $tlsInfo.HashAlgorithm)
Write-Host ("  KeyExch  : {0}"        -f $tlsInfo.KeyExchange)
Write-Host ("  Chain OK : {0}"        -f $chainIsValid) -ForegroundColor ($(if ($chainIsValid) { 'Green' } else { 'Yellow' }))

if (-not $chainIsValid) {
    foreach ($status in $chain.ChainStatus) {
        Write-Host ("    -> {0}: {1}" -f $status.Status, $status.StatusInformation.Trim()) -ForegroundColor Yellow
    }
}

# --- Helper to render one certificate ---------------------------------------
function Show-Certificate {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [int]$Index,
        [int]$Total
    )

    $role = switch ($Index) {
        0            { 'Leaf (server certificate)' }
        ($Total - 1) { if ($Cert.Subject -eq $Cert.Issuer) { 'Root CA' } else { 'Last in chain' } }
        default      { 'Intermediate CA' }
    }

    $now     = Get-Date
    $expired = $now -gt $Cert.NotAfter -or $now -lt $Cert.NotBefore
    $daysLeft = [int]($Cert.NotAfter - $now).TotalDays

    Write-Host ""
    Write-Host ("--- Certificate {0} of {1}  [{2}] ---" -f ($Index + 1), $Total, $role) -ForegroundColor Cyan
    Write-Host ("  Subject      : {0}" -f $Cert.Subject)
    Write-Host ("  Issuer       : {0}" -f $Cert.Issuer)
    Write-Host ("  Valid from   : {0:yyyy-MM-dd HH:mm}" -f $Cert.NotBefore)
    Write-Host ("  Valid until  : {0:yyyy-MM-dd HH:mm}  ({1} days left)" -f $Cert.NotAfter, $daysLeft) -ForegroundColor ($(if ($expired) { 'Red' } elseif ($daysLeft -lt 30) { 'Yellow' } else { 'Gray' }))
    Write-Host ("  Serial       : {0}" -f $Cert.SerialNumber)
    Write-Host ("  Thumbprint   : {0}" -f $Cert.Thumbprint)
    Write-Host ("  Signature    : {0}" -f $Cert.SignatureAlgorithm.FriendlyName)
    Write-Host ("  Public key   : {0} ({1} bit)" -f $Cert.PublicKey.Oid.FriendlyName, $Cert.PublicKey.Key.KeySize)

    # Subject Alternative Names (leaf certs mostly)
    $sanExt = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if ($sanExt) {
        $sanText = ($sanExt.Format($false) -replace ',\s*', ', ')
        Write-Host ("  SANs         : {0}" -f $sanText)
    }
}

# --- Output: all certificates in the chain -----------------------------------
$elements = @($chain.ChainElements)
Write-Host ""
Write-Host ("=== Certificate chain ({0} certificate(s)) ===" -f $elements.Count) -ForegroundColor Green

for ($i = 0; $i -lt $elements.Count; $i++) {
    Show-Certificate -Cert $elements[$i].Certificate -Index $i -Total $elements.Count
}

# --- Optional export ---------------------------------------------------------
if ($ExportPath) {
    if (-not (Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $cert = $elements[$i].Certificate
        $cn = ($cert.GetNameInfo('SimpleName', $false) -replace '[\\/:*?"<>|]', '_')
        $file = Join-Path $ExportPath ("{0}_{1}.cer" -f $i, $cn)
        [IO.File]::WriteAllBytes($file, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        Write-Host ("Exported: {0}" -f $file) -ForegroundColor DarkGray
    }
}

Write-Host ""

# --- Also return objects to the pipeline for further processing --------------
$elements | ForEach-Object {
    [PSCustomObject]@{
        Subject    = $_.Certificate.Subject
        Issuer     = $_.Certificate.Issuer
        NotBefore  = $_.Certificate.NotBefore
        NotAfter   = $_.Certificate.NotAfter
        Thumbprint = $_.Certificate.Thumbprint
        Serial     = $_.Certificate.SerialNumber
    }
} | Out-Null  # remove Out-Null if you want the objects on the pipeline
