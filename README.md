# CheckCAChain

Get-HttpsCertificateChain

A PowerShell script that retrieves and displays the full certificate chain of any HTTPS endpoint — including expired, self-signed, or otherwise invalid certificates.

Connects via raw TLS handshake (TLS 1.3 → 1.2 → system default fallback), then prints the leaf, intermediate, and root certificates with subject, issuer, validity dates, serial number, thumbprint, signature algorithm, key size, and SANs. Also shows the negotiated TLS protocol and cipher, chain validation errors, and days until expiry (color-coded warnings). Certificates can optionally be exported as .cer files.

Usage

powershell
.\Get-HttpsCertificateChain.ps1 -Url https://example.com
.\Get-HttpsCertificateChain.ps1 -Url myserver.local -Port 8443 -ExportPath C:\Temp\Certs

Works with Windows PowerShell 5.1 and PowerShell 7+. No external dependencies.
