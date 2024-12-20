from scapy.all import IP, TCP, sr1


def tcp_scan(host, ports):
    """
    Funzione per effettuare una scansione delle porte TCP su un host specifico usando Scapy.

    Args:
        host (str): L'indirizzo IP o il nome host da scansionare.
        ports (list): Lista di porte da scansionare.

    Returns:
        list: Lista di porte TCP aperte.
    """
    open_ports = []
    for port in ports:
        # Crea un pacchetto SYN per la porta specificata
        pkt = IP(dst=host) / TCP(dport=port, flags='S')
        response = sr1(pkt, timeout=1, verbose=False)

        if response is not None:
            # Se il flag SYN-ACK è impostato, significa che la porta è aperta
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
                # Invia un pacchetto RST per chiudere la connessione
                sr1(IP(dst=host) / TCP(dport=port, flags='R'), timeout=1, verbose=False)
    return open_ports