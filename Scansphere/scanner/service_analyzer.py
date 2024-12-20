import socket

def service_analysis(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, port))
            s.send(b'HEAD / HTTP/1.1\r\n\r\n')
            response = s.recv(100).decode()
            return response.splitlines()[0]
    except socket.timeout:
        return "Timeout del servizio"
    except ConnectionRefusedError:
        return "Connessione rifiutata"
    except Exception as e:
        return f"Errore: {e}"
