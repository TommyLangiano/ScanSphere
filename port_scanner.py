import sys
import csv
import socket
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout,
    QTextEdit, QCheckBox, QMessageBox, QProgressBar
)
from PyQt5.QtCore import pyqtSignal, QThread
from scanner.icmp_tester import icmp_ping
from scanner.service_analyzer import service_analysis
from scanner.tcp_scanner import tcp_scan
from scanner.udp_scanner import udp_scan
import ipaddress


class ScannerThread(QThread):
    update_text = pyqtSignal(str)  # Segnale per aggiornare l'interfaccia utente con il progresso testuale
    update_progress = pyqtSignal(int)  # Segnale per aggiornare la barra di progresso
    update_csv = pyqtSignal(dict)  # Segnale per aggiornare il file CSV con i risultati

    def __init__(self, host, ip_range, ports, check_tcp, check_udp, check_icmp):
        super().__init__()
        self.host = host
        self.ip_range = ip_range
        self.ports = ports
        self.check_tcp = check_tcp
        self.check_udp = check_udp
        self.check_icmp = check_icmp
        self._is_running = True  # Flag per fermare il thread di scansione se necessario
        self.scan_results = []

    def run(self):
        try:
            total_tasks = 0

            # Calcola il numero totale di compiti in base al range IP e alle porte
            if self.ip_range:
                start_ip, end_ip = map(lambda x: ipaddress.IPv4Address(x.strip()), self.ip_range.split('-'))
                total_tasks += (int(end_ip) - int(start_ip) + 1) * (1 if self.check_icmp else 0)
                total_tasks += (int(end_ip) - int(start_ip) + 1) * len(self.ports) * (self.check_tcp + self.check_udp)

            if self.host:
                total_tasks += 1 if self.check_icmp else 0
                total_tasks += len(self.ports) * (self.check_tcp + self.check_udp)

            completed_tasks = 0

            # Esegue la scansione per ogni IP nel range specificato
            if self.ip_range:
                start_ip, end_ip = map(lambda x: ipaddress.IPv4Address(x.strip()), self.ip_range.split('-'))
                for ip in range(int(start_ip), int(end_ip) + 1):
                    if not self._is_running:
                        break  # Ferma la scansione se il thread viene interrotto
                    ip_str = str(ipaddress.IPv4Address(ip))
                    self.scan_host(ip_str, self.scan_results)
                    completed_tasks += (1 if self.check_icmp else 0) + len(self.ports) * (self.check_tcp + self.check_udp)
                    self.update_progress.emit(int((completed_tasks / total_tasks) * 100))

            # Esegue la scansione per un singolo host se specificato
            if self.host and self._is_running:
                self.scan_host(self.host, self.scan_results)
                completed_tasks += (1 if self.check_icmp else 0) + len(self.ports) * (self.check_tcp + self.check_udp)
                self.update_progress.emit(int((completed_tasks / total_tasks) * 100))

            if self._is_running:
                self.update_progress.emit(100)  # Assicura che la barra di progresso sia piena
                self.update_text.emit("<span style='color:green;'>Scansione terminata</span>")

            for result in self.scan_results:
                self.update_csv.emit(result)  # Emette i risultati per aggiornare il CSV

        except Exception as e:
            self.update_text.emit(f"Errore durante la scansione: {str(e)}\n")

    def scan_host(self, ip, scan_results):
        # Esegue il ping ICMP se richiesto
        is_active = icmp_ping(ip) if self.check_icmp else True
        status = 'Host attivo' if is_active else 'Host inattivo'
        self.update_text.emit(f"{ip}: {status}\n")

        scan_result = {
            "Range IP": self.ip_range if self.ip_range else "Singolo IP",
            "IP": ip,
            "Stato ICMP": status,
            "Range Porte": "" if not is_active else (f"{min(self.ports)} - {max(self.ports)}" if (self.ports and (self.check_tcp or self.check_udp)) else ""),
            "Porte TCP Aperte": "" if not is_active or not self.check_tcp else "Vuoto",
            "Porte UDP Aperte": "" if not is_active or not self.check_udp else "Vuoto"
        }

        # Esegue le scansioni TCP e UDP se l'host è attivo
        if is_active:
            if self.check_tcp:
                open_tcp_ports = tcp_scan(ip, self.ports)
                self.add_port_results(ip, open_tcp_ports, scan_result, "Porte TCP Aperte", "TCP")

            if self.check_udp:
                open_udp_ports = udp_scan(ip, self.ports)
                self.add_port_results(ip, open_udp_ports, scan_result, "Porte UDP Aperte", "UDP")

        scan_results.append(scan_result)

    def add_port_results(self, ip, open_ports, scan_result, port_key, protocol):
        # Aggiorna i risultati della scansione con le porte aperte e aggiorna l'interfaccia
        if open_ports:
            self.update_text.emit(f"Porte {protocol} aperte per {ip}: {open_ports}\n")
            scan_result[port_key] = ', '.join(map(str, open_ports)) if open_ports else "Vuoto"
        else:
            self.update_text.emit(f"Nessuna porta {protocol} aperta per {ip}\n")

    def stop(self):
        self._is_running = False  # Imposta il flag di esecuzione su False per fermare il thread


class PortScannerApp(QWidget):
    def confirm_exit(self):
        # Mostra una finestra di conferma prima di uscire
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle('Conferma Uscita')
        msg_box.setText("Sei sicuro di voler uscire?")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        yes_button = msg_box.button(QMessageBox.Yes)
        no_button = msg_box.button(QMessageBox.No)
        yes_button.setText("Sì")
        no_button.setText("No")

        reply = msg_box.exec_()

        if reply == QMessageBox.Yes:
            self.close()

    def __init__(self):
        super().__init__()
        self.initUI()
        self.csv_file = "scan_results.csv"
        self.init_csv()

    def initUI(self):
        # Imposta l'interfaccia utente
        self.setWindowTitle('Scansphere')
        self.setGeometry(100, 100, 500, 600)
        main_layout = QVBoxLayout()

        self.label_host = QLabel('Host/IP:')
        self.entry_host = QLineEdit(self)
        self.entry_host.setText(socket.gethostbyname(socket.gethostname()))

        self.label_ip_range = QLabel('Range IP (es: 192.168.1.1-192.168.1.10):')
        self.entry_ip_range = QLineEdit(self)

        self.label_ports = QLabel('Porte (separate da virgole o range, es: 20-80):')
        self.entry_ports = QLineEdit(self)

        self.check_icmp = QCheckBox('Ping ICMP')
        self.check_icmp.setChecked(True)
        self.check_icmp.setEnabled(False)  # ICMP è sempre attivo e non modificabile
        self.check_icmp.setStyleSheet('color: black')
        self.check_tcp = QCheckBox('Scansione TCP')
        self.check_udp = QCheckBox('Scansione UDP')

        self.button_scan = QPushButton('Avvia Scansione', self)
        self.button_scan.clicked.connect(self.start_scan)

        self.button_stop = QPushButton('Interrompi Scansione', self)
        self.button_stop.setEnabled(False)
        self.button_stop.clicked.connect(self.stop_scan)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)

        self.text_output = QTextEdit(self)
        self.text_output.setReadOnly(True)

        self.button_exit = QPushButton('Esci', self)
        self.button_exit.clicked.connect(self.confirm_exit)

        main_layout.addWidget(self.label_host)
        main_layout.addWidget(self.entry_host)
        main_layout.addWidget(self.label_ip_range)
        main_layout.addWidget(self.entry_ip_range)
        main_layout.addWidget(self.label_ports)
        main_layout.addWidget(self.entry_ports)
        main_layout.addWidget(self.check_icmp)
        main_layout.addWidget(self.check_tcp)
        main_layout.addWidget(self.check_udp)
        main_layout.addWidget(self.button_scan)
        main_layout.addWidget(self.button_stop)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.text_output)

        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.button_exit)

        main_layout.addLayout(bottom_layout)

        self.setLayout(main_layout)

    def init_csv(self):
        # Inizializza il file CSV con le intestazioni delle colonne
        with open(self.csv_file, mode='w', newline='') as file:
            writer = csv.DictWriter(file,
                                    fieldnames=["Range IP", "IP", "Stato ICMP", "Range Porte", "Porte TCP Aperte", "Porte UDP Aperte"])
            writer.writeheader()

    def parse_ports(self, ports_text):
        # Analizza il campo di input delle porte in una lista di porte
        ports = set()
        for part in ports_text.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start_port, end_port = map(int, part.split('-'))
                    if start_port > end_port:
                        raise ValueError
                    ports.update(range(start_port, end_port + 1))
                except ValueError:
                    QMessageBox.warning(self, "Input Errato", f"Range di porte non valido: {part}")
                    return []
            elif part.isdigit():
                ports.add(int(part))
            else:
                QMessageBox.warning(self, "Input Errato", f"Formato porta non valido: {part}")
                return []
        return sorted(ports)

    def start_scan(self):
        # Avvia il processo di scansione
        self.button_scan.setEnabled(False)
        self.button_stop.setEnabled(True)
        ip_range = self.entry_ip_range.text()
        if ip_range:
            self.entry_host.clear()
        host = self.entry_host.text() if not ip_range else None
        ports_text = self.entry_ports.text()

        if not host and not ip_range:
            QMessageBox.warning(self, "Input Errato", "Inserisci un host o un range di IP da scansionare.")
            self.button_scan.setEnabled(True)
            self.button_stop.setEnabled(False)
            return

        ports = self.parse_ports(ports_text) if ports_text.strip() else []
        if not ports and (self.check_tcp.isChecked() or self.check_udp.isChecked()):
            QMessageBox.warning(self, "Input Errato", "Inserisci un range di porte valido per scansioni TCP/UDP.")
            self.button_scan.setEnabled(True)
            self.button_stop.setEnabled(False)
            return

        self.text_output.clear()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.scan_thread = ScannerThread(host, ip_range, ports,
                                         self.check_tcp.isChecked(),
                                         self.check_udp.isChecked(),
                                         self.check_icmp.isChecked())

        self.scan_thread.update_text.connect(self.append_text)
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.update_csv.connect(self.write_csv)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()

    def stop_scan(self):
        # Ferma la scansione in esecuzione
        if self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.button_stop.setEnabled(False)  # Disabilita il pulsante "Interrompi Scansione"
            self.scan_thread.finished.connect(lambda: self.scan_finished(interrupted=True))

    def scan_finished(self, interrupted=False):
        # Gestisce il completamento della scansione
        self.button_scan.setEnabled(True)
        self.button_stop.setEnabled(False)
        self.progress_bar.setValue(100)
        if interrupted:
            self.append_text("<span style='color:green;'>Scansione interrotta</span>\n")

    def append_text(self, text):
        # Aggiunge il testo al campo di output
        self.text_output.append(text)

    def update_progress(self, value):
        # Aggiorna il valore della barra di progresso
        self.progress_bar.setValue(value)

    def write_csv(self, data):
        # Scrive i dati dei risultati della scansione nel file CSV
        with open(self.csv_file, mode='a', newline='') as file:
            writer = csv.DictWriter(file,
                                    fieldnames=["Range IP", "IP", "Stato ICMP", "Range Porte", "Porte TCP Aperte", "Porte UDP Aperte"])
            writer.writerow(data)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    scanner = PortScannerApp()
    scanner.show()
    sys.exit(app.exec_())
