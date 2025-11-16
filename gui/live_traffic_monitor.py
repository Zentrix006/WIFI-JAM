import sys
import time
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit, QMessageBox, QTabWidget
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot

# Matplotlib integration for charting
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.style as mplstyle 

from daemon import capture 

# ----------------- Matplotlib Canvas Class -----------------
mplstyle.use('fast') 

class MplCanvas(FigureCanvas):
    """A figure canvas widget that displays a Matplotlib figure."""
    def __init__(self, parent=None, width=6, height=5, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super().__init__(fig)
        self.setParent(parent)
        
        # Apply dark theme styling
        self.axes.set_facecolor("#3b4252")
        fig.patch.set_facecolor("#2e3440")
        self.axes.tick_params(axis='x', colors='#eceff4')
        self.axes.tick_params(axis='y', colors='#eceff4')
        self.axes.yaxis.label.set_color('#eceff4')
        self.axes.xaxis.label.set_color('#eceff4')
        self.axes.title.set_color('#eceff4')
        self.axes.spines['bottom'].set_color('#4c566a')
        self.axes.spines['left'].set_color('#4c566a')
        self.axes.spines['top'].set_color('#4c566a')
        self.axes.spines['right'].set_color('#4c566a')


# ----------------- Live Traffic Monitor GUI -----------------
class LiveTrafficMonitor(QWidget):
    """A dedicated window to show live packet capture statistics and graphs."""
    
    def __init__(self, interface, mac, ip):
        super().__init__()
        
        # CRITICAL FIX: Ensure all arguments are correctly assigned
        self.interface = interface
        self.mac = mac
        self.ip = ip 
        
        self.setWindowTitle(f"Live Traffic: {self.ip} ({self.mac})")
        self.setGeometry(200, 200, 700, 750) 
        
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        
        self.title_label = QLabel(f"Monitoring Traffic for MAC: {self.mac}")
        self.layout.addWidget(self.title_label)
        
        # Data storage for graphing
        self.protocol_history = {}
        self.time_points = []
        self.start_time = time.time()
        
        # --- TAB WIDGET ---
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # Tab 1: Text Analysis
        self.text_tab = QWidget()
        self.text_layout = QVBoxLayout(self.text_tab)
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFontPointSize(10)
        self.text_layout.addWidget(self.output_text)
        self.tabs.addTab(self.text_tab, "Packet Log")
        
        # Tab 2: Graph Analysis
        self.graph_tab = QWidget()
        self.graph_layout = QVBoxLayout(self.graph_tab)
        
        self.canvas = MplCanvas(self, width=6, height=5, dpi=100)
        self.graph_layout.addWidget(self.canvas)
        self.tabs.addTab(self.graph_tab, "Real-time Protocols")
        # ------------------
        
        self.close_button = QPushButton("Close Monitor")
        self.close_button.clicked.connect(self.close_monitor)
        self.layout.addWidget(self.close_button)
        
        # Start the monitoring thread
        self.monitor_thread = TrafficMonitorThread(self.interface, self.mac)
        self.monitor_thread.data_update.connect(self.update_display)
        self.monitor_thread.error_signal.connect(self.show_thread_error)
        self.monitor_thread.start()

    @pyqtSlot(dict)
    def update_display(self, stats):
        """Receives statistics from the worker thread and updates the display and graphs."""
        
        # --- TEXT LOG UPDATE ---
        protocols_text = "\n".join([f"  - {p}: {c}" for p, c in stats['protocols'].items()]) if stats['protocols'] else "  - None Detected"
        dns_queries_text = "\n".join([f"  - {q}" for q in stats['dns_queries'][:5]]) if stats['dns_queries'] else "  - None Detected"
        
        output = (
            f"--- LIVE TRAFFIC UPDATE ({time.strftime('%H:%M:%S')}) ---\n"
            f"Total Cumulative Packets: {stats['packet_count']}\n"
            f"Protocol Distribution (Last Cycle):\n{protocols_text}\n"
            f"Recent DNS Queries (First 5):\n{dns_queries_text}\n"
        )
        self.output_text.setText(output + "\n\n" + self.output_text.toPlainText())
        
        # --- GRAPH UPDATE ---
        self._update_graph_data(stats['protocols'])
        self._draw_graph()

    def _update_graph_data(self, current_protocols):
        """Saves current protocol counts to history, ensuring synchronization."""
        
        # 1. Add current time point
        self.time_points.append(time.time() - self.start_time)
        current_len = len(self.time_points)
        
        # 2. Update and pad protocol histories (Fixes the ValueError)
        all_protocols = set(self.protocol_history.keys()) | set(current_protocols.keys())
        
        for p in all_protocols:
            count = current_protocols.get(p, 0)
            
            if p not in self.protocol_history:
                self.protocol_history[p] = [0] * (current_len - 1)
            
            while len(self.protocol_history[p]) < current_len - 1:
                self.protocol_history[p].append(0)

            self.protocol_history[p].append(count)
        
        # 3. Final Synchronization Check (Crucial for the ValueError)
        for p in self.protocol_history:
            while len(self.protocol_history[p]) < current_len:
                self.protocol_history[p].append(0)

        # 4. Keep history manageable (e.g., last 20 seconds)
        max_points = 20
        if current_len > max_points:
            self.time_points = self.time_points[-max_points:]
            for p in self.protocol_history:
                self.protocol_history[p] = self.protocol_history[p][-max_points:]


    def _draw_graph(self):
        """Draws the real-time protocol breakdown graph."""
        self.canvas.axes.cla() 
        
        for protocol, counts in self.protocol_history.items():
            self.canvas.axes.plot(self.time_points, counts, label=protocol, linewidth=2)
        
        self.canvas.axes.set_title("Protocol Packet Count (Last 20s)")
        self.canvas.axes.set_xlabel("Time (s)")
        self.canvas.axes.set_ylabel("Packets per Cycle")
        
        self.canvas.axes.set_facecolor("#3b4252")
        self.canvas.axes.legend(loc='upper right', frameon=False, labelcolor='#eceff4')
        self.canvas.draw()
        
    @pyqtSlot(str)
    def show_thread_error(self, message):
        """Handles errors coming from the background capture thread."""
        QMessageBox.critical(self, "Live Monitor Error", f"Capture Failed: {message}")
        self.close_monitor()

    def close_monitor(self):
        """Stops the thread and closes the window."""
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.monitor_thread.running = False
            self.monitor_thread.wait(5000)
            if self.monitor_thread.isRunning():
                self.monitor_thread.terminate()
        self.close()
        
    def closeEvent(self, event):
        self.close_monitor()
        event.accept()


class TrafficMonitorThread(QThread):
    data_update = pyqtSignal(dict)
    error_signal = pyqtSignal(str) 

    def __init__(self, interface, mac):
        super().__init__()
        self.interface = interface
        self.mac = mac
        self.running = True

    def run(self):
        cumulative_packet_count = 0 
        
        while self.running:
            stats = capture.capture_traffic_live(self.interface, self.mac, duration=2)
            
            if 'error' in stats:
                self.error_signal.emit(stats['error'])
                self.running = False
                break
                
            cumulative_packet_count += stats['packet_count']
            
            display_stats = {
                'packet_count': cumulative_packet_count,
                'protocols': stats['protocols'],
                'dns_queries': stats['dns_queries']
            }
            
            self.data_update.emit(display_stats)
            
            time.sleep(1)

    def terminate(self):
        self.running = False
        super().terminate()
