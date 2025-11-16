from collections import Counter
import sys
from scapy.all import sniff, IP, TCP, UDP, DNS
from scapy.config import conf

# Set Scapy's global verbosity level to 0 (silent)
conf.verb = 0 

def analyze_packets(packets):
    """Helper function to analyze a list of packets."""
    protocols = Counter()
    dns_queries = []

    for pkt in packets:
        if IP in pkt:
            protocols['IP'] += 1
            if TCP in pkt:
                protocols['TCP'] += 1
            if UDP in pkt:
                protocols['UDP'] += 1
            if DNS in pkt:
                protocols['DNS'] += 1
                if pkt.qd and pkt.qd.qname:
                    try:
                        query = pkt.qd.qname.decode().strip('.')
                        dns_queries.append(query)
                    except UnicodeDecodeError:
                        pass
    return protocols, dns_queries

def capture_traffic(interface, target_mac, duration=5):
    """Captures traffic for a fixed duration (used by Worker for initial analysis)."""
    try:
        capture_filter = f"ether host {target_mac}"
        packets = sniff(iface=interface, filter=capture_filter, timeout=duration, store=1) 
        
        protocols, dns_queries = analyze_packets(packets)

        return {
            "packet_count": len(packets),
            "protocols": dict(protocols),
            "dns_queries": dns_queries
        }
    except Exception as e:
        return {"error": str(e)}

def capture_traffic_live(interface, target_mac, duration=2):
    """Captures traffic for a small interval (used by Live Monitor)."""
    try:
        capture_filter = f"ether host {target_mac}"
        packets = sniff(iface=interface, filter=capture_filter, timeout=duration, store=1)
        
        protocols, dns_queries = analyze_packets(packets)
        
        return {
            "packet_count": len(packets),
            "protocols": dict(protocols),
            "dns_queries": dns_queries
        }
    except Exception as e:
        return {"error": str(e)}
