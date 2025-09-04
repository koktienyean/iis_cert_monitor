import subprocess
import json
import ssl
import socket
from datetime import datetime

# Pick which IIS sites to monitor
MONITOR_SITES = ["qr.novax-intl.com"]


def get_iis_sites():
    """Get IIS site bindings and SSL details from PowerShell"""
    ps_script = r"""
    Import-Module WebAdministration
    $bindings = Get-WebBinding | Select-Object protocol, bindingInformation, certificateHash, certificateStoreName, sslFlags, siteName
    $result = @()
    foreach ($b in $bindings) {
        $cert = $null
        if ($b.certificateHash) {
            $certObj = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $b.certificateHash }
            if ($certObj) {
                $cert = @{
                    Subject = $certObj.Subject
                    Expiry  = $certObj.NotAfter
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
    $result | ConvertTo-Json -Depth 5
    """
    process = subprocess.run(
        ["powershell", "-Command", ps_script],
        capture_output=True,
        text=True
    )
    if process.returncode != 0:
        raise Exception(f"Error: {process.stderr}")
    return json.loads(process.stdout)


def extract_hostname(binding_info: str):
    """Extract hostname from IIS binding (format: IP:Port:Hostname)"""
    parts = binding_info.split(":")
    if len(parts) == 3:
        return parts[2] if parts[2] else None
    return None


def check_ssl_certificate(hostname, port=443):
    """Check SSL certificate details for a hostname"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Extract expiry
                expiry_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")

                remaining_days = (expiry_date - datetime.utcnow()).days

                return {
                    "hostname": hostname,
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "subject": dict(x[0] for x in cert['subject']),
                    "expiry": expiry_date,
                    "remaining_days": remaining_days,
                    "status": "OK" if remaining_days > 0 else "Expired"
                }
    except ssl.SSLError as e:
        return {"hostname": hostname, "status": f"SSL Error: {e}"}
    except Exception as e:
        return {"hostname": hostname, "status": f"Connection Failed: {e}"}


if __name__ == "__main__":
    all_sites = get_iis_sites()
    selected_sites = [s for s in all_sites if any(site in s['Binding'] for site in MONITOR_SITES)]

    if not selected_sites:
        print("⚠️ No matching sites found in IIS for your monitor list.")
    else:
        for s in selected_sites:
            print(f"🌐 Site: {s['Site']}")
            print(f"   Protocol: {s['Protocol']}")
            print(f"   Binding : {s['Binding']}")
            print(f"   SSLFlags: {s['SSLFlags']} (SNI={'Yes' if s['SSLFlags']==1 else 'No'})")

            hostname = extract_hostname(s["Binding"])
            if hostname:
                ssl_status = check_ssl_certificate(hostname)
                print(f"   🔒 SSL Status: {ssl_status['status']}")
                if "expiry" in ssl_status:
                    print(f"   Expiry   : {ssl_status['expiry']}")
                    print(f"   Remaining: {ssl_status['remaining_days']} days")
            else:
                print("   ⚠️ No hostname found in binding (might be IP-only)")
            print()
