import ipaddress

from .icmp_tester import icmp_ping
from .tcp_scanner import tcp_scan  # Importa la scansione TCP dal modulo TCP
import time

# Funzione per la scansione di un intervallo IP

def ip_range_scan(start_ip, end_ip, ports):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    open_hosts = {}

    for ip in range(int(start), int(end) + 1):
        ip_str = str(ipaddress.IPv4Address(ip))
        try:
            # Verifica se l'host è attivo tramite ping ICMP
            if icmp_ping(ip_str):
                open_ports = tcp_scan(ip_str, ports)
                if open_ports:
                    open_hosts[ip_str] = open_ports
            time.sleep(0.1)  # Aggiungi una breve pausa per evitare sovraccarico di rete
        except Exception as e:
            print(f"Errore durante la scansione dell'IP {ip_str}: {str(e)}")
    return open_hosts
