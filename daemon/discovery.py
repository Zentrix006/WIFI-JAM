import socket
import ipaddress
import sys
import netifaces
import scapy.all as scapy
from mac_vendor_lookup import MacLookup

# Initialize MacLookup DB
try:
    mac_lookup_instance = MacLookup()
    # CRITICAL FIX: Removed the blocking update_vendors() call (fixes startup hang)
except Exception as e:
    mac_lookup_instance = None
    print(f"[!] Could not initialize MacLookup: {e}", file=sys.stderr)

def resolve_hostname(ip):
    """Performs a reverse DNS lookup to get the hostname for a given IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, IndexError):
        return "Unknown"

def get_vendor(mac):
    """Looks up the vendor for a given MAC address."""
    if not mac_lookup_instance or not mac:
        return "Unknown Vendor"
    try:
        return mac_lookup_instance.lookup(mac.upper().replace(':', '-'))
    except Exception:
        return "Unknown Vendor"

def get_subnet(interface="wlan0"):
    """Detects the network CIDR (e.g., 192.168.1.0/24) for the specified interface."""
    try:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info.get("addr")
            netmask = ip_info.get("netmask")
            if ip and netmask:
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return str(network)
    except Exception:
        pass
    return None

def get_available_interfaces():
    """Returns a list of all detected network interface names."""
    if not netifaces:
        return ["Error: netifaces not available"]
    
    available_interfaces = []
    for iface in netifaces.interfaces():
        try:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                available_interfaces.append(iface)
        except Exception:
            pass
            
    return available_interfaces

def arp_scan(cidr, timeout=2):
    """Performs an ARP scan on the given CIDR range using Scapy."""
    results = []
    if scapy is None:
        print("Scapy is not installed. ARP scan is not possible.", file=sys.stderr)
        return results
    try:
        pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=cidr)
        answered, _ = scapy.srp(pkt, timeout=timeout, retry=1, verbose=False) 
        for _, recv in answered:
            ip = recv.psrc
            mac = recv.hwsrc
            results.append({"ip": ip, "mac": mac})
    except Exception as e:
        print(f"An error occurred during ARP scan: {e}", file=sys.stderr)
    return results
