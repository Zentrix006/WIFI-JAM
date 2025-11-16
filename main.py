#!/usr/bin/env python3
import sys
import socket
import csv
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QMessageBox, QLabel,
    QComboBox, QFileDialog, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from concurrent.futures import ThreadPoolExecutor

from daemon import discovery, scanner, capture, exploit, external
from gui.live_traffic_monitor import LiveTrafficMonitor

# ------------------- Threaded Worker for Background Tasks -------------------
class Worker(QThread):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    device_discovered = pyqtSignal(dict) 
    device_found = pyqtSignal(dict)      

    def __init__(self, interface, known_devices):
        super().__init__()
        self.interface = interface
        self.known_devices = known_devices

    def run(self):
        try:
            # Step 1: Discover devices (ARP Scan)
            try:
                subnet = discovery.get_subnet(self.interface)
                if not subnet:
                    self.error.emit(f"Could not detect subnet for interface '{self.interface}'. Please check your network connection.")
                    return
            except socket.error as e:
                self.error.emit(f"Network error: {e}. Check if the interface '{self.interface}' is valid or if you have the necessary privileges.")
                return

            print(f"[*] Scanning subnet: {subnet}")
            discovered_devices = discovery.arp_scan(subnet)

            if not discovered_devices:
                self.error.emit(f"No devices found on subnet '{subnet}'.")
                self.finished.emit([])
                return

            # --- PRE-ANALYSIS: Enrichment and Immediate Display ---
            devices_for_analysis = []
            for d in discovered_devices:
                mac = d.get('mac')
                ip = d.get('ip')
                
                ip_history = [ip]
                if mac in self.known_devices:
                    if self.known_devices[mac]['ip'] != ip:
                        ip_history = [self.known_devices[mac]['ip'], ip]
                
                d['hostname'] = discovery.resolve_hostname(ip)
                d['vendor'] = discovery.get_vendor(mac)
                d['ip_history'] = ip_history
                
                devices_for_analysis.append(d)
                self.known_devices[mac] = {'ip': ip, 'data': d}
                
                self.device_discovered.emit(d)
            
            # Step 2: Run slow scans concurrently
            print("[*] Running concurrent port scans and traffic analysis...")
            with ThreadPoolExecutor(max_workers=15) as executor: 
                futures = {}
                for d in devices_for_analysis:
                    future = executor.submit(self.process_device_full_analysis, d)
                    futures[future] = d['ip']
                
                for future in futures:
                    device_info = future.result()
                    self.device_found.emit(device_info)
            
            self.finished.emit(devices_for_analysis)
            
        except Exception as e:
            self.error.emit(f"An unexpected error occurred: {e}")

    def process_device_full_analysis(self, device):
        ip = device['ip']
        mac = device['mac']
        
        ports_and_vulns = scanner.scan_device_ports(ip)
        traffic_stats = capture.capture_traffic(self.interface, target_mac=mac, duration=5)
        
        device['open_ports'] = ports_and_vulns.get('open_ports', {})
        device['vulnerabilities'] = ports_and_vulns.get('vulnerabilities', [])
        device['port_scan_error'] = ports_and_vulns.get('error', None)
        device['traffic_stats'] = traffic_stats
        
        return device

# ------------------- Main GUI Application -------------------
class WifiJamGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WIFI-JAM: Red Team Asset Analyzer (Faculty Perfected)")
        self.setGeometry(100, 100, 1200, 750) 
        
        self.worker = None
        self.known_devices = {}
        self.mac_to_row = {}
        self.live_monitor = None 
        self.active_bettercap_pid = None 

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # Title (Jhacker motivated)
        self.title_label = QLabel("WIFI-JAM: Red Team Intelligence Platform")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-size: 20pt; font-weight: bold; color: #8fbcbb;")
        self.layout.addWidget(self.title_label)
        
        # --- Control Panel Layout ---
        control_layout = QHBoxLayout()
        
        # 1. Interface Selection
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(150)
        self.load_interfaces()
        control_layout.addWidget(QLabel("Interface:"))
        control_layout.addWidget(self.interface_combo)
        
        # 2. Global Tool Buttons (Wireshark)
        self.live_tools_button = QPushButton("Launch Live Tools (Wireshark)")
        self.live_tools_button.clicked.connect(self.launch_external_tools)
        self.live_tools_button.setStyleSheet("background-color: #88c0d0;")
        control_layout.addWidget(self.live_tools_button)
        
        control_layout.addStretch(1)
        
        # 3. Action Buttons
        self.refresh_button = QPushButton("Scan Network (Full Recon)")
        self.refresh_button.clicked.connect(self.start_scan)
        self.refresh_button.setStyleSheet("background-color: #a3be8c;")
        control_layout.addWidget(self.refresh_button)
        
        self.export_button = QPushButton("Export to CSV")
        self.export_button.clicked.connect(self.export_to_csv)
        self.export_button.setEnabled(False)
        control_layout.addWidget(self.export_button)

        self.layout.addLayout(control_layout)
        
        # Status Label
        self.status_label = QLabel("Select interface and click 'Scan Network'.")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-style: italic; color: #d8dee9;")
        self.layout.addWidget(self.status_label)

        # QTableWidget for scan results
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(7) 
        self.device_table.setHorizontalHeaderLabels(['S.No.', 'MAC Address', 'IP Address', 'Hostname/Vendor', 'Vulnerabilities/Ports', 'Risk Level', 'Actions/Control'])
        self.device_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.device_table.horizontalHeader().setStretchLastSection(True)
        self.layout.addWidget(self.device_table)
        
    def load_interfaces(self):
        try:
            interfaces = discovery.get_available_interfaces()
            self.interface_combo.addItems(interfaces)
            if not interfaces:
                self.interface_combo.addItem("No active interfaces found")
                self.refresh_button.setEnabled(False)
        except Exception:
            self.interface_combo.addItem("Error loading interfaces")
            self.refresh_button.setEnabled(False)

    @pyqtSlot()
    def start_scan(self):
        if self.worker and self.worker.isRunning():
            return
        
        selected_interface = self.interface_combo.currentText()
        if not selected_interface or selected_interface == "No active interfaces found":
            QMessageBox.warning(self, "Interface Error", "Please select a valid network interface.")
            return

        self.status_label.setText(f"Scanning on {selected_interface}... Running ARP, Ports & NSE Scripts.")
        self.refresh_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.device_table.setRowCount(0)
        self.mac_to_row = {}
        
        self.worker = Worker(interface=selected_interface, known_devices=self.known_devices)
        self.worker.finished.connect(self.scan_finished)
        self.worker.error.connect(self.show_error_message)
        self.worker.device_discovered.connect(self.add_device_to_table)
        self.worker.device_found.connect(self.update_device_row)
        self.worker.start()

    def calculate_risk_level(self, device):
        """Calculates a summary risk level for visual categorization."""
        if device.get('port_scan_error'): return "ERROR"
            
        vulnerabilities = device.get('vulnerabilities', [])
        open_ports = device.get('open_ports', {})
        
        if any('CRITICAL' in v for v in vulnerabilities) or any('ETHERNALBLUE' in v.upper() for v in vulnerabilities):
            return "CRITICAL"
        
        if any('HIGH RISK' in v for v in vulnerabilities) or any(info.get('risk') == 'High' for info in open_ports.values()):
            return "HIGH"
            
        if any('Web Title' in v for v in vulnerabilities) or len(open_ports) > 0:
            return "MEDIUM"
            
        return "LOW"

    @pyqtSlot(dict)
    def add_device_to_table(self, device):
        mac = device.get('mac')
        if mac in self.mac_to_row:
            row = self.mac_to_row[mac]
        else:
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            self.mac_to_row[mac] = row
            self.device_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            self.device_table.setItem(row, 1, QTableWidgetItem(mac))
            
            # --- ACTION/CONTROL CONTAINER (Column 6) ---
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(0, 0, 0, 0)
            
            # 1. View Traffic Button
            traffic_button = QPushButton("View Traffic")
            traffic_button.clicked.connect(lambda _, d=device: self.show_traffic_info(d))
            action_layout.addWidget(traffic_button)

            # 2. Inject Payload Button (Red Team Action)
            inject_button = QPushButton("Inject ARP Test")
            inject_button.setStyleSheet("background-color: #bf616a;")
            inject_button.clicked.connect(lambda _, d=device: self.show_injection_dialog(d))
            action_layout.addWidget(inject_button)

            # NEW: Bettercap Control Placeholder (Column 7)
            self.device_table.setCellWidget(row, 6, self._create_bettercap_widget(device))
            
            self.device_table.setCellWidget(row, 5, self._create_risk_label("SCANNING")) # Risk Level (Col 5)
            self.device_table.setCellWidget(row, 6, action_widget) # Actions (Col 6)
            
        ip_history = device.get('ip_history', [device.get('ip', 'N/A')])
        
        if len(ip_history) > 1:
            ip_text = f"<html><s>{ip_history[0]}</s> &rarr; **{ip_history[1]}**</html>"
            ip_item = QTableWidgetItem()
            ip_item.setData(Qt.DisplayRole, ip_text) 
            self.device_table.setItem(row, 2, ip_item)
        else:
            self.device_table.setItem(row, 2, QTableWidgetItem(ip_history[0]))
        
        host_vendor_text = f"{device.get('hostname', 'Unknown')} ({device.get('vendor', 'Unknown')})"
        self.device_table.setItem(row, 3, QTableWidgetItem(host_vendor_text))
        
        self.device_table.setItem(row, 4, QTableWidgetItem("Scanning (Ports/NSE)..."))
        
    def _create_risk_label(self, risk_level):
        """Creates a colored QLabel for the Risk Level column."""
        label = QLabel(risk_level)
        label.setAlignment(Qt.AlignCenter)
        color = {
            "CRITICAL": "background-color: #bf616a; color: white;",
            "HIGH": "background-color: #d08770; color: black;",
            "MEDIUM": "background-color: #ebcb8b; color: black;",
            "LOW": "background-color: #a3be8c; color: black;",
            "SCANNING": "background-color: #5e81ac; color: white;",
            "ERROR": "background-color: #4c566a; color: white;",
        }.get(risk_level, "background-color: #4c566a; color: white;")
        label.setStyleSheet(f"padding: 4px; border-radius: 3px; font-weight: bold; {color}")
        return label

    def _create_bettercap_widget(self, device):
        """Creates the widget for Bettercap control (Column 7)."""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        cap_button = QPushButton("MITM/Proxy")
        cap_button.setStyleSheet("background-color: #b48ead; color: white;")
        cap_button.setToolTip(f"Launch Bettercap HTTP Proxy for {device.get('ip')}. Requires manual stop.")
        cap_button.clicked.connect(lambda _, d=device: self.launch_bettercap_proxy(d))
        layout.addWidget(cap_button)
        
        return widget


    @pyqtSlot(dict)
    def update_device_row(self, device):
        mac = device.get('mac')
        if mac in self.mac_to_row:
            row = self.mac_to_row[mac]
            
            ports = device.get('open_ports', {})
            vulnerabilities = device.get('vulnerabilities', [])
            ports_lines = []
            
            if vulnerabilities:
                ports_lines.extend(vulnerabilities)
            
            if ports:
                for port, info in ports.items():
                    text = f"Port {port} ({info.get('service', 'N/A')}/{info.get('version', 'N/A')})"
                    if info.get('risk') == 'High':
                        text = f"🔥 {text} [HIGH RISK PORT]" 
                    ports_lines.append(text)
            
            ports_text = "\n".join(ports_lines) if ports_lines else "No open ports/vulns detected."
            
            host_vendor_text = f"{device.get('hostname', 'N/A')} ({device.get('vendor', 'N/A')})"
            self.device_table.setItem(row, 3, QTableWidgetItem(host_vendor_text))

            item = QTableWidgetItem(ports_text)
            self.device_table.setItem(row, 4, item)
            
            # --- UPDATE RISK LEVEL (Column 5) ---
            risk_level = self.calculate_risk_level(device)
            self.device_table.setCellWidget(row, 5, self._create_risk_label(risk_level)) 
            
            # --- Reconnect Action Buttons (Columns 6 & 7) ---
            action_widget = self.device_table.cellWidget(row, 6) # Actions
            if action_widget:
                traffic_button = action_widget.layout().itemAt(0).widget()
                if traffic_button:
                    try: traffic_button.clicked.disconnect()
                    except: pass
                    traffic_button.clicked.connect(lambda _, d=device: self.show_traffic_info(d))

                inject_button = action_widget.layout().itemAt(1).widget()
                if inject_button:
                    try: inject_button.clicked.disconnect()
                    except: pass
                    inject_button.clicked.connect(lambda _, d=device: self.show_injection_dialog(d))
            
            bettercap_widget = self.device_table.cellWidget(row, 7) # Bettercap Control 
            if bettercap_widget:
                # Reconnect the Bettercap button
                cap_button = bettercap_widget.layout().itemAt(0).widget()
                if cap_button:
                    try: cap_button.clicked.disconnect()
                    except: pass
                    cap_button.clicked.connect(lambda _, d=device: self.launch_bettercap_proxy(d))

    @pyqtSlot(list)
    def scan_finished(self, devices):
        self.status_label.setText(f"Scan complete. Found {self.device_table.rowCount()} devices.")
        self.refresh_button.setEnabled(True)
        self.export_button.setEnabled(True)

    @pyqtSlot(str)
    def show_error_message(self, message):
        self.status_label.setText("Scan failed.")
        self.refresh_button.setEnabled(True)
        self.export_button.setEnabled(False)
        QMessageBox.warning(self, "Scan Error", message)

    def launch_external_tools(self):
        selected_interface = self.interface_combo.currentText()
        if not selected_interface or selected_interface == "No active interfaces found":
            QMessageBox.warning(self, "Interface Error", "Please select a valid network interface first.")
            return

        reply = QMessageBox.question(self, 'Launch Wireshark',
            f"Launch Wireshark on {selected_interface}? Requires Wireshark to be installed.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        
        if reply == QMessageBox.Yes:
            # FIX: Removed the restrictive 'host 127.0.0.1' filter to capture all traffic
            result = external.open_wireshark_capture(selected_interface) 
            if result['status'] == 'error':
                QMessageBox.critical(self, "External Tool Error", result['message'])
                
    def launch_bettercap_proxy(self, device):
        if self.active_bettercap_pid:
            QMessageBox.warning(self, "Bettercap Active", f"Bettercap (PID: {self.active_bettercap_pid}) is already running. Please stop it manually via PID: {self.active_bettercap_pid}.")
            return
            
        selected_interface = self.interface_combo.currentText()
        target_ip = device.get('ip')
        
        result = external.run_bettercap_module(selected_interface, target_ip, module="http.proxy")
        
        if result['status'] == 'success':
            self.active_bettercap_pid = result['pid']
            QMessageBox.information(self, "Bettercap Started", 
                f"Bettercap HTTP Proxy started for {target_ip}!\nPID: {self.active_bettercap_pid}\nWARNING: Must be stopped externally."
            )
        else:
            QMessageBox.critical(self, "Bettercap Error", result['message'])

    def show_traffic_info(self, device):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "Cannot start live monitoring while a full network scan is running.")
            return

        selected_interface = self.interface_combo.currentText()
        
        self.live_monitor = LiveTrafficMonitor(
            interface=selected_interface,
            mac=device.get('mac'),
            ip=device.get('ip')
        )
        self.live_monitor.show()

    def show_injection_dialog(self, device):
        target_ip = device.get('ip')
        target_mac = device.get('mac')
        
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "Wait for the network scan to finish before active exploitation.")
            return
            
        reply = QMessageBox.question(self, 'Confirm Active Test',
            f"⚠️ **WARNING: ACTIVE EXPLOITATION** ⚠️\n\nTarget: {target_ip} ({target_mac})\n\nAre you sure you want to run the ARP injection test?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            payloads = exploit.get_available_payloads()
            
            if 'arp_spoof_check' in payloads:
                result = exploit.run_payload(target_ip, 'arp_spoof_check', self.interface_combo.currentText())
                
                if result.get("status") == "success":
                     QMessageBox.information(self, "Payload Success", f"Payload executed on {target_ip}:\n{result.get('message')}")
                else:
                    QMessageBox.critical(self, "Payload Error", f"Payload failed on {target_ip}:\n{result.get('message')}")
            else:
                 QMessageBox.information(self, "Payload Missing", "No active payloads found in the exploit module.")
                 
    def export_to_csv(self):
        if self.device_table.rowCount() == 0:
            QMessageBox.warning(self, "Export Failed", "No data to export.")
            return

        filePath, _ = QFileDialog.getSaveFileName(self, "Export Scan Results", "scan_results.csv", "CSV Files (*.csv)")
        
        if filePath:
            try:
                with open(filePath, 'w', newline='') as file:
                    writer = csv.writer(file)
                    
                    header = ['S.No.', 'MAC Address', 'Current IP', 'Previous IP', 'Hostname', 'Vendor', 'Risk Level', 'Open Ports & Versions & VULNS']
                    writer.writerow(header)
                    
                    for row in range(self.device_table.rowCount()):
                        ip_item = self.device_table.item(row, 2)
                        ip_text = ip_item.data(Qt.DisplayRole) if ip_item and ip_item.data(Qt.DisplayRole) else self.device_table.item(row, 2).text()
                        
                        ip_parts = ip_text.split(" &rarr; ")
                        current_ip = ip_parts[-1].strip().strip('<b></b>').strip('**').strip('<html>').strip('</html>')
                        prev_ip = ip_parts[0].replace('<s>', '').replace('</s>', '').strip() if len(ip_parts) > 1 else ""

                        host_vendor_text = self.device_table.item(row, 3).text()
                        hostname = host_vendor_text.split('(')[0].strip()
                        vendor = host_vendor_text.split('(')[1].strip(')') if '(' in host_vendor_text else 'N/A'
                        
                        risk_level = self.device_table.cellWidget(row, 5).text()
                        
                        ports_versions_vulns = self.device_table.item(row, 4).text().replace('\n', ' || ').replace('🚨', '').replace('🔥', '').strip()

                        row_data = [
                            self.device_table.item(row, 0).text(),
                            self.device_table.item(row, 1).text(), 
                            current_ip,
                            prev_ip,
                            hostname,
                            vendor,
                            risk_level,
                            ports_versions_vulns
                        ]
                        writer.writerow(row_data)
                        
                QMessageBox.information(self, "Export Success", f"Data successfully exported to:\n{filePath}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"An error occurred during export: {e}")

# ------------------- Main Execution Block -------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    try:
        with open("gui/styles.qss", "r") as f: 
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        print("[!] styles.qss not found. Running without custom styling.")
    
    window = WifiJamGUI()
    window.show()
    sys.exit(app.exec_())
