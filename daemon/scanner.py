import nmap

# --- List of Nmap Scripts for Red Team Quick Checks ---
NSE_SCRIPTS = (
    "ftp-anon",         
    "http-title",       
    "smb-os-discovery", 
    "smb-vuln-ms17-010", # EternalBlue
    "ssh-hostkey",      
    "samba-vuln-cve-2017-7494" # SambaCry
)
NMAP_ARGS = f"-Pn -sV --open --script {','.join(NSE_SCRIPTS)}"


def scan_device_ports(ip):
    """
    Runs a full Nmap scan including service detection and Red Team NSE scripts.
    """
    nm = nmap.PortScanner()
    result = {"open_ports": {}, "vulnerabilities": []}

    try:
        nm.scan(hosts=ip, arguments=NMAP_ARGS, timeout=60) 

        if ip in nm.all_hosts():
            host_data = nm[ip]
            
            # --- 1. Process Ports and Service Versions ---
            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in ports:
                    info = host_data[proto][port]
                    
                    risk = "Low"
                    if port in (23, 139, 445, 5900, 3389) or 'ftp' in info.get('name'):
                        risk = "High" 

                    result['open_ports'][port] = {
                        'service': info.get('name', 'N/A'),
                        'version': info.get('version', 'N/A'),
                        'product': info.get('product', 'N/A'),
                        'risk': risk
                    }
            
            # --- 2. Process NSE Script Output for Vulnerability Data ---
            if 'hostscript' in host_data:
                for script in host_data['hostscript']:
                    script_id = script.get('id')
                    script_output = script.get('output', '').strip()
                    
                    if not script_output:
                        continue
                        
                    if script_id == 'ftp-anon' and 'Anonymous FTP login allowed' in script_output:
                        result['vulnerabilities'].append("🚨 CRITICAL: Anonymous FTP Allowed (Auth Bypass)")
                    
                    elif script_id == 'smb-vuln-ms17-010' and 'VULNERABLE' in script_output:
                        result['vulnerabilities'].append("⚠️ CRITICAL: ETERNALBLUE/MS17-010 VULNERABLE")
                        
                    elif script_id == 'samba-vuln-cve-2017-7494' and 'VULNERABLE' in script_output:
                        result['vulnerabilities'].append("⚠️ HIGH: SAMBACRY/CVE-2017-7494 VULNERABLE")

                    elif script_id == 'http-title':
                        title = script_output.replace('http-title: ', '')
                        result['vulnerabilities'].append(f"INFO: Web Title: {title}")
                        
                    elif script_id == 'smb-os-discovery':
                        if 'OS:' in script_output:
                            os_line = [line.strip() for line in script_output.split('\n') if line.startswith('OS:')][0]
                            result['vulnerabilities'].append(f"INFO: OS/Type: {os_line}")
                    
                    elif ('VULNERABLE' in script_output.upper() or 'EXPOSED' in script_output.upper()) and script_id not in ('smb-os-discovery', 'http-title'):
                         result['vulnerabilities'].append(f"❓ POTENTIAL: {script_id.upper()} finding. Inspect.")

    except nmap.PortScannerError as e:
        result['error'] = f"Nmap error: {e}. Check if nmap is installed and accessible."
    except Exception as e:
        result['error'] = str(e)
        
    return result
