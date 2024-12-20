from scapy.all import IP, ICMP, sr1

def icmp_ping(host):
    # Invia un pacchetto ping ICMP all'host specificato
    pkt = IP(dst=host)/ICMP()
    response = sr1(pkt, timeout=1, verbose=False)
    return response is not None

