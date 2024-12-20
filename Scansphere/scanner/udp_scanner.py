from scapy.all import IP, UDP, sr1


def udp_scan(host, ports):
    """
    Funzione per effettuare una scansione delle porte UDP su un host specifico usando Scapy.

    Args:
        host (str): L'indirizzo IP o il nome host da scansionare.
        ports (list): Lista di porte da scansionare.

    Returns:
        list: Lista di porte UDP aperte.
    """
    open_ports = []
    for port in ports:
        # Crea un pacchetto UDP per la porta specificata
        pkt = IP(dst=host) / UDP(dport=port)
        response = sr1(pkt, timeout=1, verbose=False)

        if response is None:
            # Nessuna risposta potrebbe indicare che la porta è aperta o filtrata
            open_ports.append(port)
        elif response.haslayer(UDP):
            # Se otteniamo una risposta UDP, la porta è aperta
            open_ports.append(port)
    return open_ports
