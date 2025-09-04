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


def test_https_connection(hostname, port=443):
    """Test if HTTPS connection works"""
    try:
        import urllib.request
        import urllib.error
        
        url = f"https://{hostname}:{port}"
        req = urllib.request.Request(url, method='HEAD')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            return {"status": "OK", "code": response.status}
    except urllib.error.HTTPError as e:
        return {"status": "HTTP_ERROR", "code": e.code}
    except urllib.error.URLError as e:
        return {"status": "URL_ERROR", "error": str(e)}
    except Exception as e:
        return {"status": "CONNECTION_FAILED", "error": str(e)}


def toggle_sni_setting(site_name, binding_info, current_sni_flag):
    """Toggle SNI setting for a specific binding"""
    # Extract IP and port from binding
    parts = binding_info.split(':')
    if len(parts) >= 2:
        ip = parts[0] if parts[0] else "*"
        port = parts[1]
        hostname = parts[2] if len(parts) > 2 else ""
        
        # Toggle SNI flag (1 = SNI required, 0 = SNI not required)
        new_sni_flag = 0 if current_sni_flag == 1 else 1
        
        ps_script = f'''
        Import-Module WebAdministration
        try {{
            $binding = Get-WebBinding -Name "{site_name}" -Protocol "https" -Port {port}
            if ($binding) {{
                Set-WebBinding -Name "{site_name}" -BindingInformation "{binding_info}" -PropertyName "sslFlags" -Value {new_sni_flag}
                Write-Output "SUCCESS: SNI flag changed from {current_sni_flag} to {new_sni_flag}"
            }} else {{
                Write-Output "ERROR: Binding not found"
            }}
        }} catch {{
            Write-Output "ERROR: $($_.Exception.Message)"
        }}
        '''
        
        process = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True,
            text=True
        )
        
        return {
            "success": "SUCCESS" in process.stdout,
            "output": process.stdout.strip(),
            "new_sni_flag": new_sni_flag if "SUCCESS" in process.stdout else current_sni_flag
        }
    
    return {"success": False, "output": "Invalid binding format", "new_sni_flag": current_sni_flag}


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
                # Test HTTPS connection first
                https_result = test_https_connection(hostname)
                print(f"   🌐 HTTPS Test: {https_result['status']}")
                
                if https_result['status'] == 'OK':
                    print(f"   ✅ HTTPS connection successful (HTTP {https_result.get('code', 'N/A')})")
                    
                    # Also check SSL certificate details
                    ssl_status = check_ssl_certificate(hostname)
                    print(f"   🔒 SSL Status: {ssl_status['status']}")
                    if "expiry" in ssl_status:
                        print(f"   Expiry   : {ssl_status['expiry']}")
                        print(f"   Remaining: {ssl_status['remaining_days']} days")
                else:
                    print(f"   ❌ HTTPS connection failed: {https_result.get('error', 'Unknown error')}")
                    print("   🔧 Attempting to fix by toggling SNI setting...")
                    
                    # Try to fix by toggling SNI
                    sni_result = toggle_sni_setting(s['Site'], s['Binding'], s['SSLFlags'])
                    print(f"   SNI Toggle: {sni_result['output']}")
                    
                    if sni_result['success']:
                        print("   🔄 Retesting HTTPS connection...")
                        retry_result = test_https_connection(hostname)
                        if retry_result['status'] == 'OK':
                            print(f"   ✅ HTTPS now working after SNI toggle (HTTP {retry_result.get('code', 'N/A')})")
                        else:
                            print(f"   ❌ HTTPS still failing after SNI toggle: {retry_result.get('error', 'Unknown error')}")
                            # Toggle back if it didn't help
                            print("   🔄 Reverting SNI setting...")
                            revert_result = toggle_sni_setting(s['Site'], s['Binding'], sni_result['new_sni_flag'])
                            print(f"   SNI Revert: {revert_result['output']}")
            else:
                print("   ⚠️ No hostname found in binding (might be IP-only)")
            print()
