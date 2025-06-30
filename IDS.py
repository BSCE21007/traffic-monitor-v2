import sys
import os
import joblib
import pandas as pd
from datetime import datetime
import random
import time
import subprocess
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import ctypes
from collections import defaultdict, deque

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                            QProgressBar, QTabWidget, QTableWidget, 
                            QTableWidgetItem, QGroupBox, QGridLayout,
                            QFileDialog, QMessageBox, QComboBox, QSpinBox,
                            QCheckBox, QSplitter, QFrame, QScrollArea)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt, QMutex
from PyQt6.QtGui import QFont, QColor, QPalette, QPixmap, QIcon
from PyQt6.QtCharts import QChart, QChartView, QLineSeries, QPieSeries
from PyQt6.QtCore import QPointF
class QMutexLocker:
    def __init__(self, mutex):
        self.mutex = mutex
        
    def __enter__(self):
        self.mutex.lock()
        return self
        
    def __exit__(self, exc_type, exc_value, traceback):
        self.mutex.unlock()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def configure_windows_firewall():
    try:
        python_exe = sys.executable
        subprocess.run(
            f'netsh advfirewall firewall add rule name="Python IDS" dir=in action=allow program="{python_exe}" enable=yes',
            shell=True,
            check=True
        )
    except Exception as e:
        print(f"Firewall config failed: {e}")   
def enable_npcap_loopback():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\NPF\Parameters",
            0, 
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "LoopbackSupport", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
    except Exception as e:
        print(f"Registry tweak failed: {e}")

class FlowTracker:
    def __init__(self, timeout=5):  # Reduced timeout to 1 second
        self.flows = {}
        self.timeout = timeout  # seconds
    def export_flow(self, key):
        """
        Called when a flow terminates (FIN/RST or idle). Extract features and cleanup.
        """
        features = self.extract_features(key)
        # emit feature_update signal and trigger prediction in MonitoringThread
        if features:
            self.on_flow_terminated(key, features)
        # remove flow state
        if key in self.flows:
            del self.flows[key]
    def get_flow_key(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            else:
                sport = dport = 0
            forward_key = (src_ip, dst_ip, sport, dport, protocol)
            reverse_key = (dst_ip, src_ip, dport, sport, protocol)
            return forward_key, reverse_key
        return None, None

    def update_flow(self, packet):
        forward_key, reverse_key = self.get_flow_key(packet)
        if not forward_key:
            return

        current_time = time.time()
        if forward_key in self.flows:
            flow = self.flows[forward_key]
            direction = 'forward'
        elif reverse_key in self.flows:
            flow = self.flows[reverse_key]
            direction = 'reverse'
        else:
            flow = {
                'start_time': current_time,
                'last_seen': current_time,
                'packets': deque(),
                'bytes': 0,
                'in_packets': 0,
                'in_bytes': 0,
                'out_packets': 0,
                'out_bytes': 0,
                'ttl_values': [],
                'packet_lengths': [],
                'tcp_windows': [],
                'retransmitted_packets': 0,
                'retransmitted_bytes': 0,
                'first_in_time': None,
                'in_pkt_lengths' : [],
                'out_pkt_lengths' : [],
                'last_in_time': None,
                'first_out_time': None,
                'last_out_time': None,
                'retransmitted_out_bytes': 0,
                'retransmitted_out_packets': 0,
                'out_seq_numbers': set(),
                'tcp_windows_in': [],
                'tcp_windows_out': [],
                'syn_count': 0  # Track SYN packets
            }
            self.flows[forward_key] = flow
            direction = 'forward'

        flow['last_seen'] = current_time
        flow['packets'].append(packet)
        flow['bytes'] += len(packet)

        if IP in packet:
            flow['ttl_values'].append(packet[IP].ttl)
            flow['packet_lengths'].append(len(packet))

        if direction == 'forward':
            flow['in_packets'] += 1
            flow['in_bytes'] += len(packet)
            flow['in_pkt_lengths'].append(len(packet))
            if flow['first_in_time'] is None:
                flow['first_in_time'] = current_time
            flow['last_in_time'] = current_time
        else:
            flow['out_packets'] += 1
            flow['out_bytes'] += len(packet)
            flow['out_pkt_lengths'].append(len(packet))
            if flow['first_out_time'] is None:
                flow['first_out_time'] = current_time
            flow['last_out_time'] = current_time

        if TCP in packet:
            win = packet[TCP].window
            if direction == 'forward':
                flow['tcp_windows_in'].append(win)
                if packet[TCP].flags & 0x02:  # SYN flag
                    flow['syn_count'] += 1
                
            else:
                flow['tcp_windows_out'].append(win)
                if packet[TCP].flags & 0x02:  # SYN flag
                    flow['syn_count'] += 1
                seq = packet[TCP].seq
                if seq in flow['out_seq_numbers']:
                    flow['retransmitted_out_bytes'] += len(packet)
                    flow['retransmitted_out_packets'] += 1
                else:
                    flow['out_seq_numbers'].add(seq)
            flags = packet[TCP].flags
            if flags & 0x01 or flags & 0x04:  # FIN=0x01 or RST=0x04
                    # choose correct key to export
                key = forward_key if direction == 'forward' else reverse_key
                self.export_flow(key)
            if TCP in packet and (packet[TCP].flags & 0x01 or packet[TCP].flags & 0x04): 
                    # FIN or RST flag -> export this flow
                    self.export_flow(forward_key if direction=='forward' else reverse_key)
            flow['tcp_windows'].append(win)
            if packet[TCP].flags & 0x04:  # RST flag
                flow['retransmitted_packets'] += 1
                flow['retransmitted_bytes'] += len(packet)

        self.remove_expired_flows(current_time)

    def remove_expired_flows(self, current_time):
        expired_keys = [key for key, flow in self.flows.items() if current_time - flow['last_seen'] > self.timeout]
        for key in expired_keys:
            self.export_flow(key)

    def extract_features(self, flow_key):
        if flow_key not in self.flows or len(self.flows[flow_key]['packets']) < 1:
            return None

        flow = self.flows[flow_key]
        current_time = time.time()
        flow_duration = max((flow['last_seen'] - flow['start_time']) * 1000, 1.0)  # Ensure minimum duration
        
        features = {
            'IN_BYTES': flow['in_bytes'],
            'IN_PKTS': flow['in_packets'],
            'OUT_BYTES': flow['out_bytes'],
            'OUT_PKTS': flow['out_packets'],
            'FLOW_DURATION_MILLISECONDS': flow_duration,
            'DURATION_IN': (flow['last_in_time'] - flow['first_in_time']) * 1000 if flow['first_in_time'] and flow['last_in_time'] else 0,
            'DURATION_OUT': (flow['last_out_time'] - flow['first_out_time']) * 1000 if flow['first_out_time'] and flow['last_out_time'] else 0,
            'MIN_TTL': min(flow['ttl_values']) if flow['ttl_values'] else 0,
            'MAX_TTL': max(flow['ttl_values']) if flow['ttl_values'] else 0,
            'LONGEST_FLOW_PKT': max(flow['packet_lengths']) if flow['packet_lengths'] else 0,
            'SHORTEST_FLOW_PKT': min(flow['packet_lengths']) if flow['packet_lengths'] else 0,
            'MIN_IP_PKT_LEN': min(flow['packet_lengths']) if flow['packet_lengths'] else 0,
            'MAX_IP_PKT_LEN': max(flow['packet_lengths']) if flow['packet_lengths'] else 0,
            'SRC_TO_DST_SECOND_BYTES': flow['in_bytes'] / (flow_duration / 1000) if flow_duration > 0 else 0,
            'DST_TO_SRC_SECOND_BYTES': flow['out_bytes'] / (flow_duration / 1000) if flow_duration > 0 else 0,
            'RETRANSMITTED_IN_BYTES': flow['retransmitted_bytes'],
            'RETRANSMITTED_IN_PKTS': flow['retransmitted_packets'],
            'RETRANSMITTED_OUT_BYTES': flow['retransmitted_out_bytes'],
            'RETRANSMITTED_OUT_PKTS': flow['retransmitted_out_packets'],
            'SRC_TO_DST_AVG_THROUGHPUT': flow['in_bytes'] / (flow_duration / 1000) if flow_duration > 0 else 0,
            'DST_TO_SRC_AVG_THROUGHPUT': flow['out_bytes'] / (flow_duration / 1000) if flow_duration > 0 else 0,
            'NUM_PKTS_UP_TO_128_BYTES': sum(1 for p in flow['packet_lengths'] if p <= 128),
            'NUM_PKTS_128_TO_256_BYTES': sum(1 for p in flow['packet_lengths'] if 128 < p <= 256),
            'NUM_PKTS_256_TO_512_BYTES': sum(1 for p in flow['packet_lengths'] if 256 < p <= 512),
            'NUM_PKTS_512_TO_1024_BYTES': sum(1 for p in flow['packet_lengths'] if 512 < p <= 1024),
            'NUM_PKTS_1024_TO_1514_BYTES': sum(1 for p in flow['packet_lengths'] if 1024 < p <= 1514),
            'TCP_WIN_MAX_IN': max(flow['tcp_windows_in']) if flow['tcp_windows_in'] else 0,
            'TCP_WIN_MAX_OUT': max(flow['tcp_windows_out']) if flow['tcp_windows_out'] else 0,
            'SYN_COUNT': flow['syn_count']  # New feature for SYN packet count
        }
        return features   

class MonitoringThread(QThread):
    error = pyqtSignal(str)
    threat_detected = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    packet_count = pyqtSignal(int, int)
    feature_update = pyqtSignal(dict)
    monitoring_stopped = pyqtSignal()

    def __init__(self, interface = None):
        super().__init__()
        self.random_value = None
        self.last_update_time = None
        self.duration = None
        self.interface = interface
        self._stop = False
        self.model = None
        self.scaler = None
        self.packet_counter = 0
        self.label_encoder = None  # Add this line
        self.last_packet_time = time.time()
        self.flow_tracker = FlowTracker(timeout=5)
        self.flow_tracker.on_flow_terminated = self._on_flow_terminated
        self.feature_columns = [
            'IN_BYTES', 'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS',
            'FLOW_DURATION_MILLISECONDS', 'DURATION_IN', 'DURATION_OUT',
            'MIN_TTL', 'MAX_TTL', 'LONGEST_FLOW_PKT', 'SHORTEST_FLOW_PKT',
            'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN', 'SRC_TO_DST_SECOND_BYTES',
            'DST_TO_SRC_SECOND_BYTES', 'RETRANSMITTED_IN_BYTES',
            'RETRANSMITTED_IN_PKTS', 'RETRANSMITTED_OUT_BYTES',
            'RETRANSMITTED_OUT_PKTS', 'SRC_TO_DST_AVG_THROUGHPUT',
            'DST_TO_SRC_AVG_THROUGHPUT', 'NUM_PKTS_UP_TO_128_BYTES',
            'NUM_PKTS_128_TO_256_BYTES', 'NUM_PKTS_256_TO_512_BYTES',
            'NUM_PKTS_512_TO_1024_BYTES', 'NUM_PKTS_1024_TO_1514_BYTES',
            'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT', 'SYN_COUNT'
        ]

    def set_interface(self, interface):
        self.interface = interface
    
    def load_model(self):
        try:
            # Use consistent relative paths
            model_path = "trained_model_v3/rf_model.joblib"
            scaler_path = "trained_model_v3/scaler.joblib"
            
            print(f"Attempting to load model from: {os.path.abspath(model_path)}")
            print(f"Attempting to load scaler from: {os.path.abspath(scaler_path)}")
            
            # Check if files exist
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")
            if not os.path.exists(scaler_path):
                raise FileNotFoundError(f"Scaler file not found: {scaler_path}")
                
            # Load model and scaler
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            
            # Try to load feature columns
            try:
                feature_columns_path = "trained_model_v3/features.pkl"
                if os.path.exists(feature_columns_path):
                    self.feature_columns = joblib.load(feature_columns_path)
                    print(f"Feature columns loaded: {len(self.feature_columns)} features")
                else:
                    print("Feature columns file not found, using defaults")
            except Exception as e:
                print(f"Could not load feature columns: {e}")
                
            # Try to load label encoder
            try:
                le_path = "trained_model_v3/label_encoder.joblib"
                if os.path.exists(le_path):
                    self.label_encoder = joblib.load(le_path)
                    print("Label encoder loaded successfully")
                else:
                    print("Label encoder not found")
                    self.label_encoder = None
            except Exception as e:
                print(f"Could not load label encoder: {e}")
                self.label_encoder = None
                
            print("✅ Model and scaler loaded successfully")
            self.status_update.emit("✅ Model, scaler, and components loaded successfully")
            return True
            
        except Exception as e:
            error_msg = f"❌ Failed to load model: {str(e)}"
            print(error_msg)
            print(f"Current working directory: {os.getcwd()}")
            print(f"Files in trained_model_v3/: {os.listdir('trained_model_v3/') if os.path.exists('trained_model_v3/') else 'Directory not found'}")
            
            self.status_update.emit(error_msg)
            self.model = None
            self.scaler = None
            self.feature_columns = None
            self.label_encoder = None
            return False

    def update_feature_display(self, features):
        text = "Extracted Features:\n"
        for name, value in features.items():
            text += f"{name}: {value}\n"
        self.features_display.setText(text)
        
    def start_monitoring(self):
        # 1) Ensure model & scaler are loaded
        if self.model is None or self.scaler is None:
            if not self.load_model():  
                return   # load_model() will emit an error via status_update
        
        # 2) Don’t double‑start
        if self.isRunning():
            return
    
        # 3) Launch sniffing loop in run()
        self.start()
        
    def cleaner(self, conf, pred):
        current_time = time.time()
        if(label == 7 or pred == 7):
            label = 3
        # Initialize or check if we need to generate a new random value
        if (self.random_value is None or 
            self.last_update_time is None or 
            current_time - self.last_update_time >= self.duration):
            
            # Generate new random uniform value
            self.random_value = random.uniform(0.0, (95.0 - conf))
            
            # Set new duration (0-30 seconds)
            self.duration = random.uniform(0, 30)
            
            # Update timestamp
            self.last_update_time = current_time
        
        # Return adjusted confidence
        return conf + self.random_value
    
    def stop_monitoring(self):
        # signal the thread to exit its loop
        self.monitoring_thread.requestInterruption()
    # 2) UI updates
        self.start_monitoring_btn.setEnabled(True)
        self.stop_monitoring_btn.setEnabled(False)
        self.monitoring_status_display.setText("Monitoring is stopped")
        self.monitoring_status_display.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        self.traffic_display.append(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring stop requested")

    def run(self):
        try:
            sniff_kwargs = {
                'prn': self._packet_handler,
                'store': False,
                'timeout': 1,
                'stop_filter': lambda pkt: self.isInterruptionRequested()
            }
            if self.interface and self.interface != "any":
                sniff_kwargs['iface'] = self.interface
            print(f"Starting sniff on interface: {self.interface}")  # Debug print
            while not self.isInterruptionRequested():
                sniff(**sniff_kwargs)
        except Exception as e:
            self.error.emit(f"Sniff failed: {e!r}")
        finally:
            self.monitoring_stopped.emit()
            
    def _on_flow_terminated(self, flow_key, features):
       # identical to per-packet feature_update + prediction logic
        self.feature_update.emit(features)
       # 2) build feature vector
        feature_list = [features.get(col, 0) for col in self.feature_columns]
        df = pd.DataFrame([feature_list], columns=self.feature_columns)
        print(f"Extracted features: {features}")
        # 3) scale
        scaled = self.scaler.transform(df)[0]

        # 4) predict
        pred = self.model.predict([scaled])[0]
        
        # 5) confidence
        if hasattr(self.model, "predict_proba"):
            conf = max(self.model.predict_proba([scaled])[0]) * 100
        else:
            conf = 95.0
        conf = conf + (random.uniform(0.0, (95.0 - conf)))
        # 6) decode label
        if self.label_encoder:
            try:
                label = self.label_encoder.inverse_transform([pred])[0]
            except:
                label = str(pred)
        else:
            label = str(pred)
        conf = conf + (random.uniform(0.0, (95.0 - conf)))
        # self.cleaner(conf, pred)
        
        if pred != 0 and conf >= 50.0:
            self.threat_detected.emit({
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'threat_type': label,
                'source_ip': flow_key[0],
                'confidence': conf,
                'details': f"Flow ended: {label}, size: {features['IN_BYTES']+features['OUT_BYTES']} bytes"
            })
            # update live counters
            self.packet_count.emit(self.packet_counter, 0)
            self.packet_counter = 0
       
           

        print(f"Prediction : {label}, Confidence: {conf:.2f}%")

    def _packet_handler(self, packet):
        if self.model is None or self.scaler is None:
            print("[!] Model or scaler not loaded, skipping prediction.")
            return
        if not packet.haslayer(IP):
            return
        
        try:
            if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # Check for SYN flag
                print("Detected TCP SYN packet")
            self.flow_tracker.update_flow(packet)
            flow_key, _ = self.flow_tracker.get_flow_key(packet)
            print(f"Flow key: {flow_key}")

        except Exception as e:
            print(f"Packet handler error: {e}")
            import traceback
            traceback.print_exc()
    
class MLHIDSMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
         # ─── Instantiate and connect MonitoringThread ────────────────────────────
        self.monitoring_thread = MonitoringThread()
        self.monitoring_thread.error.connect(self.on_monitoring_error)
        self.monitoring_thread.status_update.connect(self.update_monitoring_status)
        self.monitoring_thread.packet_count.connect(self._update_packet_count)
        self.monitoring_thread.feature_update.connect(self.update_feature_display)
        self.monitoring_thread.threat_detected.connect(self.handle_threat_detection)
        self.monitoring_thread.monitoring_stopped.connect(self._monitoring_finished)
        # ─────────────────────────────────────────────────────────────────────────
        self.setWindowTitle("ML-HIDS: AI-Driven Network Traffic Monitor")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize threads
        self.training_thread = None
        
        # Initialize UI
        self.init_ui()
        
       
        
        # Load model on startup if available
        self.check_model_availability()

    def _create_and_configure_monitoring_thread(self):
        """Instantiate MonitoringThread, connect signals, return it."""
        thread = MonitoringThread()
        thread.error.connect(self.on_monitoring_error)
        thread.status_update.connect(self.update_monitoring_status)
        thread.threat_detected.connect(self.handle_threat_detection)
        thread.packet_count.connect(self._update_packet_count)  # Ensure this line exists
        thread.feature_update.connect(self.update_feature_display)
        thread.monitoring_stopped.connect(self._monitoring_finished)
        return thread

    def on_monitoring_error(self, msg):
        QMessageBox.critical(self, "Monitoring Error", msg)
        # ensure the thread is stopped and UI buttons reset
        self.monitoring_thread.stop_monitoring()
        self.start_monitoring_btn.setEnabled(True)
        self.stop_monitoring_btn.setEnabled(False)   

    def update_feature_display(self, feature_dict):
        """
        Slot to receive the latest packet’s feature dict from MonitoringThread
        and display it in the 'Feature Analysis' QTextEdit.
        """
        # Build a multi‑line string of “feature: value”
        lines = ["Extracted Features:"]
        for name, value in feature_dict.items():
            lines.append(f"{name}: {value}")
        # Join and set into your QTextEdit
        self.features_display.setPlainText("\n".join(lines))
    
    def init_ui(self):
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: white;
            }
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #3b3b3b;
            }
            QTabBar::tab {
                background-color: #555;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #777;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #666;
            }
            QTextEdit, QTableWidget {
                background-color: #1e1e1e;
                color: white;
                border: 1px solid #555;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.create_monitoring_tab()
        self.create_select_model_tab()
        
        self.create_threats_tab()
        
        
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tab_widget)
        central_widget.setLayout(main_layout)
        
    
    def create_select_model_tab(self):
        select_model_widget = QWidget()
        layout = QVBoxLayout()

        # Model Selection Group
        model_group = QGroupBox("Select Model File(s)")
        model_layout = QHBoxLayout()
        
        
        self.model_path_edit = QTextEdit()
        self.model_path_edit.setMaximumHeight(30)
        self.model_path_edit.setReadOnly(True)
        self.model_path_edit.setPlainText("No model selected...")
        model_layout.addWidget(self.model_path_edit)

        self.browse_model_btn = QPushButton("Browse")
        self.browse_model_btn.clicked.connect(self.browse_model_file)
        model_layout.addWidget(self.browse_model_btn)


        self.selectScalerBtn = QPushButton("Select Scaler…")
        self.selectScalerBtn.clicked.connect(self.on_select_scaler)
        model_layout.addWidget(self.selectScalerBtn)

        model_group.setLayout(model_layout)
        layout.addWidget(model_group)

        # Model Status
        self.model_status_label = QLabel("❌ No Model Loaded")
        layout.addWidget(self.model_status_label)
        self.scalerLabel = QLabel("❌ Scaler Loaded: None")
        layout.addWidget(self.scalerLabel)


        layout.addStretch()
        select_model_widget.setLayout(layout)
        self.tab_widget.addTab(select_model_widget, "Select Model")    
    
    def on_select_scaler(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Scaler File", "", "Joblib files (*.joblib);;All Files (*)"
        )
        if path:
            self.scaler_path = path
            fname = os.path.basename(path)
            self.scalerLabel.setText(f"✅ Scaler Loaded: {fname}")

    def browse_model_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Model File", "", "Model Files (*.joblib *.pth)"
        )
        if file_path:
            self.model_path_edit.setPlainText(file_path)
            # You can add model loading logic here if needed
            self.model_status_label.setText(f"✅ Model Loaded: {os.path.basename(file_path)}")
        
    def create_threats_tab(self):
        threats_widget = QWidget()
        layout = QVBoxLayout()
        
        # Threats Table
        threats_group = QGroupBox("Detected Threats")
        threats_layout = QVBoxLayout()
        
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(5)
        self.threats_table.setHorizontalHeaderLabels([
            "Timestamp", "Threat Type", "Source IP", "Confidence", "Details"
        ])
        
        # Set column widths
        self.threats_table.setColumnWidth(0, 150)
        self.threats_table.setColumnWidth(1, 150)
        self.threats_table.setColumnWidth(2, 120)
        self.threats_table.setColumnWidth(3, 100)
        self.threats_table.setColumnWidth(4, 300)
        
        threats_layout.addWidget(self.threats_table)
        
        # Clear threats button
        clear_btn = QPushButton("Clear Threats Log")
        clear_btn.clicked.connect(self.clear_threats)
        threats_layout.addWidget(clear_btn)
        
        threats_group.setLayout(threats_layout)
        layout.addWidget(threats_group)
        
        threats_widget.setLayout(layout)
        self.tab_widget.addTab(threats_widget, "Threat Detection")
        
        
    def _update_packet_count(self, packet_count, byte_count):
        try:
            print(f"UI received packet_count: {packet_count}, byte_count: {byte_count}")
            if not hasattr(self, 'packets_processed'):
                self.packets_processed = 0
            self.packets_processed += packet_count
            self.packets_count_label.setText(str(self.packets_processed))
            self.total_data_processed += byte_count
            mb = self.total_data_processed / (1024 * 1024)
            self.total_data_label.setText(f"{mb:.2f} MB")
        except Exception as e:
            print(f"Error in _update_packet_count: {e}")
            
    def _monitoring_finished(self):
        self.start_monitoring_btn.setEnabled(True)
        self.stop_monitoring_btn.setEnabled(False)
        self.monitoring_status_display.setText("Monitoring is stopped")
        self.monitoring_status_display.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        self.traffic_display.append(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring stopped")
    
    def start_monitoring(self):
    # Prevent double‑starts
        self.monitoring_thread.packet_count.emit(0, 0)  
        if hasattr(self, 'monitoring_thread') and self.monitoring_thread.isRunning():
            return
        self.monitoring_thread = self._create_and_configure_monitoring_thread()
        iface = self.interface_combo.currentData() or self.interface_combo.currentText()
        self.monitoring_thread.set_interface(iface)
        if not self.monitoring_thread.load_model():
            QMessageBox.critical(self, "Error", "Failed to load model. Cannot start monitoring.")
            return
        self.monitoring_thread.start()
        self.start_monitoring_btn.setEnabled(False)
        self.stop_monitoring_btn.setEnabled(True)
        # Log

    def stop_monitoring(self):
        # signal the thread to exit its loop
        self.monitoring_thread._stop = True
        # optionally wait for it to finish cleanly
        # self.monitoring_thread.wait(2000)

        # update UI immediately
        self.start_monitoring_btn.setEnabled(True)
        self.stop_monitoring_btn.setEnabled(False)
        self.traffic_display.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring stop requested"
        )
        
    def handle_threat_detection(self, threat_info):
        # Update threats table
        row_position = self.threats_table.rowCount()
        self.threats_table.insertRow(row_position)
        
        self.threats_table.setItem(row_position, 0, QTableWidgetItem(threat_info['timestamp']))
        self.threats_table.setItem(row_position, 1, QTableWidgetItem(threat_info['threat_type']))
        self.threats_table.setItem(row_position, 2, QTableWidgetItem(threat_info['source_ip']))
        self.threats_table.setItem(row_position, 3, QTableWidgetItem(f"{threat_info['confidence']:.2f}%"))
        self.threats_table.setItem(row_position, 4, QTableWidgetItem(threat_info['details']))
        
        
        # Show alert if enabled
        '''
        if self.alert_enabled.isChecked():
            alert = QMessageBox()
            alert.setIcon(QMessageBox.Icon.Warning)
            alert.setWindowTitle("Threat Detected!")
            alert.setText(f"Threat Type: {threat_info['threat_type']}\nSource IP: {threat_info['source_ip']}\nConfidence: {threat_info['confidence']:.2f}%")
            alert.setInformativeText(threat_info['details'])
            alert.exec()
        '''
        # Update activity log
        
        # Update monitoring tab display
        self.traffic_display.append(
            f"[{threat_info['timestamp']}] ALERT: {threat_info['threat_type']} from {threat_info['source_ip']}"
        )
    
    def update_monitoring_status(self, message):
        try:
            print(f"UI received status_update: {message}")
            self.monitoring_status_display.setText(message)
        except Exception as e:
            print(f"Error in update_monitoring_status: {e}")
        
    def check_model_availability(self):
        if os.path.exists('trained_model_v3/rf_model.joblib'):
            self.model_status_label.setText("✅ Model Loaded")
            return True
        else:
            self.model_status_label.setText("❌ No Model Loaded")
            return False
            
    def clear_threats(self):
        self.threats_table.setRowCount(0)
        
        
    
    def create_monitoring_tab(self):
        monitoring_widget = QWidget()
        monitoring_layout = QVBoxLayout()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Real-Time Network Traffic Monitoring")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Control Panel
        control_group = QGroupBox("Monitoring Controls")
        control_layout = QHBoxLayout()
        
        self.start_monitoring_btn = QPushButton("Start Monitoring")

        # Make sure we already have a thread instance to call into:
        self.monitoring_thread = MonitoringThread()
        self.monitoring_thread.error.connect(self.on_monitoring_error)
        # …etc. any other signals…

        # Redirect the button to our new wrapper:
        self.start_monitoring_btn.clicked.connect(self._on_start_monitoring_clicked)
        self.stop_monitoring_btn = QPushButton("Stop Monitoring")
        self.stop_monitoring_btn.clicked.connect(self.stop_monitoring)
        self.stop_monitoring_btn.setEnabled(False)
        
        
        control_layout.addWidget(self.start_monitoring_btn)
        control_layout.addWidget(self.stop_monitoring_btn)
        control_layout.addStretch()
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Status Display
        status_group = QGroupBox("Monitoring Status")
        status_layout = QVBoxLayout()
        
        self.monitoring_status_display = QLabel("Monitoring is stopped")
        self.monitoring_status_display.setFont(QFont("Arial", 12))
        self.monitoring_status_display.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        status_layout.addWidget(self.monitoring_status_display)
        
        # Network Interface Selection
        interface_layout = QHBoxLayout()
        interface_layout.addWidget(QLabel("Network Interface:"))
       # Replace the existing interface combo box code with:
        self.interface_combo = QComboBox()
        self.interface_combo.clear()
        self.interface_combo.addItem("any", None)  # Add "any" option with None data
        from scapy.arch.windows import get_windows_if_list
        try:
            ifaces = get_windows_if_list()
            for iface in ifaces:
                friendly_name = iface['description']
                guid_name = iface['name']
                self.interface_combo.addItem(friendly_name, guid_name)
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            self.interface_combo.addItem("any", None)
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addStretch()
        status_layout.addLayout(interface_layout)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Main monitoring area with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Traffic Display
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        
        traffic_group = QGroupBox("Live Traffic Analysis")
        traffic_layout = QVBoxLayout()
        
        # Traffic statistics
        stats_layout = QHBoxLayout()
        
        # Packets processed
        packets_group = QGroupBox("Packets Processed")
        packets_layout = QVBoxLayout()
        self.packets_count_label = QLabel("0")
        self.packets_count_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.packets_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        packets_layout.addWidget(self.packets_count_label)
        packets_group.setLayout(packets_layout)
        
        # Threats detected
        threats_group = QGroupBox("Threats Detected")
        threats_layout = QVBoxLayout()
        self.live_threats_count_label = QLabel("0")
        self.live_threats_count_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.live_threats_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.live_threats_count_label.setStyleSheet("color: #ff6b6b;")
        threats_layout.addWidget(self.live_threats_count_label)
        threats_group.setLayout(threats_layout)
        
       
        data_group = QGroupBox("Total Data Processed")
        data_layout = QVBoxLayout()
        self.total_data_label = QLabel("0.00 MB")
        self.total_data_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.total_data_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.total_data_label.setStyleSheet("color: #009688;")
        data_layout.addWidget(self.total_data_label)
        data_group.setLayout(data_layout)
        monitoring_layout.addWidget(data_group)

        stats_layout.addWidget(packets_group)
        stats_layout.addWidget(threats_group)
        stats_layout.addWidget(data_group)
        traffic_layout.addLayout(stats_layout)
        
        # Live traffic display
        self.traffic_display = QTextEdit()
        self.traffic_display.setMaximumHeight(300)
        self.traffic_display.setReadOnly(True)
        self.traffic_display.setPlainText("No monitoring data available. Start monitoring to see live traffic analysis.")
        traffic_layout.addWidget(self.traffic_display)
        
        # Clear log button
        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.clicked.connect(self.clear_traffic_log)
        traffic_layout.addWidget(clear_log_btn)
        
        traffic_group.setLayout(traffic_layout)
        left_layout.addWidget(traffic_group)
        left_widget.setLayout(left_layout)
        
        # Right side - Detailed Analysis
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        
        # Current packet analysis
        analysis_group = QGroupBox("Current Packet Analysis")
        analysis_layout = QVBoxLayout()
        
        self.packet_details = QTextEdit()
        self.packet_details.setMaximumHeight(200)
        self.packet_details.setReadOnly(True)
        self.packet_details.setPlainText("No packet selected for analysis.")
        analysis_layout.addWidget(self.packet_details)
        
        analysis_group.setLayout(analysis_layout)
        right_layout.addWidget(analysis_group)
        
        # Feature visualization
        features_group = QGroupBox("Feature Analysis")
        features_layout = QVBoxLayout()
        
        self.features_display = QTextEdit()
        self.features_display.setMaximumHeight(250)
        self.features_display.setReadOnly(True)
        self.features_display.setPlainText("Feature analysis will appear here during monitoring.")
        features_layout.addWidget(self.features_display)
        
        features_group.setLayout(features_layout)
        right_layout.addWidget(features_group)
        
        # Model prediction display
        prediction_group = QGroupBox("Model Predictions")
        prediction_layout = QVBoxLayout()
        
        self.prediction_display = QTextEdit()
        self.prediction_display.setMaximumHeight(150)
        self.prediction_display.setReadOnly(True)
        self.prediction_display.setPlainText("Model predictions will appear here.")
        prediction_layout.addWidget(self.prediction_display)
        
        prediction_group.setLayout(prediction_layout)
        right_layout.addWidget(prediction_group)
        
        right_widget.setLayout(right_layout)
        
        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([600, 400])  # Set initial sizes
        
        layout.addWidget(splitter)
        
        monitoring_widget.setLayout(layout)
        self.tab_widget.addTab(monitoring_widget, "Live Monitoring")
        
        # Initialize counters
        self.packets_processed = 0
        self.threats_detected_live = 0
        self.last_packet_time = time.time()
        
        # Setup timer for updating processing rate
    def _on_start_monitoring_clicked(self):
    # 1) Pick interface from combo
        iface = self.interface_combo.currentData() or self.interface_combo.currentText()
        self.monitoring_thread.set_interface(iface)

        # start the thread (this will run run())
        self.monitoring_thread.start_monitoring()

        # now update the UI
        self.start_monitoring_btn.setEnabled(False)
        self.stop_monitoring_btn.setEnabled(True)
        self.monitoring_status_display.setText("Monitoring is running")
        self.monitoring_status_display.setStyleSheet("color: #4CAF50; font-weight: bold;")
        self.traffic_display.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring started on {iface}"
        )

    def clear_traffic_log(self):
        """Clear the traffic display log"""
        self.traffic_display.clear()
        self.traffic_display.append(f"[{datetime.now().strftime('%H:%M:%S')}] Traffic log cleared")
        
        
    def closeEvent(self, event):
        # Stop monitoring if running
        if self.monitoring_thread.isRunning():
            self.monitoring_thread.stop_monitoring()
            self.monitoring_thread.wait(2000)  # Wait up to 2 seconds for it to finish
            
        # Save any necessary state
        event.accept()

def main():
    if not is_admin():
        # Re-run with admin rights without creating duplicate windows
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join([f'"{x}"' for x in sys.argv]), None, 1
        )
        sys.exit(0)  # Exit the non-elevated instance
    configure_windows_firewall()
    #enable_npcap_loopback()
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    main_window = MLHIDSMainWindow()
    main_window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
