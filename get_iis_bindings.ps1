try {
    # Check if IIS is available
    $iisService = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if (-not $iisService) {
        Write-Error "IIS service (W3SVC) not found - IIS may not be installed"
        exit 1
    }

    # Try to import WebAdministration module
    Import-Module WebAdministration -ErrorAction Stop

    # Get all bindings
    $bindings = Get-WebBinding -ErrorAction Stop

    if ($bindings.Count -eq 0) {
        # Empty array for no bindings
        $result = @()
    } else {
        $result = @()
        foreach ($b in $bindings) {
            $cert = $null
            if ($b.certificateHash) {
                $certObj = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $b.certificateHash }
                if ($certObj) {
                    $cert = @{
                        Subject = $certObj.Subject
                        Expiry  = $certObj.NotAfter.ToString("o")
                        Issuer  = $certObj.Issuer
                        Thumbprint = $certObj.Thumbprint
                    }
                }
            }
            $result += @{
                Site       = $b.siteName
                Protocol   = $b.protocol
                Binding    = $b.bindingInformation
                Store      = $b.certificateStoreName
                SSLFlags   = $b.sslFlags
                Certificate= $cert
            }
        }
    }
    # Output only JSON to stdout
    $result | ConvertTo-Json -Depth 5 -Compress
} catch {
    Write-Error $_.Exception.Message
    exit 1
}