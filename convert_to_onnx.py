import sys
import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import threading
import traceback
import time
import subprocess
from pathlib import Path
from scapy.all import sniff, IP, TCP, get_if_list
import ctypes

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
def extract_features_from_packet(packet):
        features = {
            'IN_BYTES': len(packet) if hasattr(packet, 'src') else 0,
            'IN_PKTS': 1,
            'OUT_BYTES': len(packet) if hasattr(packet, 'dst') else 0,
            'OUT_PKTS': 1,
            'FLOW_DURATION_MILLISECONDS': 0,
            'DURATION_IN': 0,
            'DURATION_OUT': 0,
            'MIN_TTL': packet[IP].ttl if IP in packet else 0,
            'MAX_TTL': packet[IP].ttl if IP in packet else 0,
            'LONGEST_FLOW_PKT': len(packet),
            'SHORTEST_FLOW_PKT': len(packet),
            'MIN_IP_PKT_LEN': len(packet),
            'MAX_IP_PKT_LEN': len(packet),
            'SRC_TO_DST_SECOND_BYTES': len(packet) if hasattr(packet, 'src') else 0,
            'DST_TO_SRC_SECOND_BYTES': len(packet) if hasattr(packet, 'dst') else 0,
            'RETRANSMITTED_IN_BYTES': 0,
            'RETRANSMITTED_IN_PKTS': 0,
            'RETRANSMITTED_OUT_BYTES': 0,
            'RETRANSMITTED_OUT_PKTS': 0,
            'SRC_TO_DST_AVG_THROUGHPUT': 0,
            'DST_TO_SRC_AVG_THROUGHPUT': 0,
            'NUM_PKTS_UP_TO_128_BYTES': 1 if len(packet) <= 128 else 0,
            'NUM_PKTS_128_TO_256_BYTES': 1 if 128 < len(packet) <= 256 else 0,
            'NUM_PKTS_256_TO_512_BYTES': 1 if 256 < len(packet) <= 512 else 0,
            'NUM_PKTS_512_TO_1024_BYTES': 1 if 512 < len(packet) <= 1024 else 0,
            'NUM_PKTS_1024_TO_1514_BYTES': 1 if 1024 < len(packet) <= 1514 else 0,
            'TCP_WIN_MAX_IN': packet[TCP].window if TCP in packet else 0,
            'TCP_WIN_MAX_OUT': packet[TCP].window if TCP in packet else 0
        }
        # Return as a list in the correct order
        feature_columns = [
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
            'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT'
        ]
        return [features[col] for col in feature_columns]    
class ModelTrainingThread(QThread):
    progress_update = pyqtSignal(int)
    status_update = pyqtSignal(str)
    training_complete = pyqtSignal(dict)
    
    def __init__(self, data_path, model_params):
        super().__init__()
        self.data_path = data_path
        self.model_params = model_params
    
    def run(self):
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report, accuracy_score
            
            self.status_update.emit("Loading dataset...")
            self.progress_update.emit(10)
            
            # Load data
            df = pd.read_csv(self.data_path)
            
            self.status_update.emit("Preprocessing data...")
            self.progress_update.emit(30)
            
            # Feature columns (same as in your original code)
            feature_columns = [
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
                'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT'
            ]
            
            # Prepare features and target
            X = df[feature_columns]
            y = df['Label']  # Assuming 'Label' is your target column
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            self.status_update.emit("Scaling features...")
            self.progress_update.emit(50)
            
            # Scale features
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            self.status_update.emit("Training model...")
            self.progress_update.emit(70)
            
            # Train model
            model = RandomForestClassifier(
                n_estimators=self.model_params.get('n_estimators', 100),
                max_depth=self.model_params.get('max_depth', None),
                random_state=42,
                n_jobs=-1
            )
            
            model.fit(X_train_scaled, y_train)
            
            self.status_update.emit("Evaluating model...")
            self.progress_update.emit(90)
            
            # Evaluate model
            y_pred = model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred, output_dict=True)
            
            # Save model and scaler
            os.makedirs('trained_model', exist_ok=True)
            joblib.dump(model, 'trained_model/random_forest_model.joblib')
            joblib.dump(scaler, 'trained_model/scaler.joblib')
            
            self.status_update.emit("Training completed successfully!")
            self.progress_update.emit(100)
            
            results = {
                'accuracy': accuracy,
                'classification_report': report,
                'feature_importance': dict(zip(feature_columns, model.feature_importances_))
            }
            
            self.training_complete.emit(results)
            
        except Exception as e:
            self.status_update.emit(f"Error: {str(e)}")

class MonitoringThread(QThread):
    error = pyqtSignal(str)
    threat_detected = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    packet_count = pyqtSignal(int)
    feature_update = pyqtSignal(dict)
    monitoring_stopped = pyqtSignal()

    def __init__(self, interface = None):
        super().__init__()
        self.interface = interface
        self._stop = False
        self.model = None
        self.scaler = None
        self.packet_counter = 0
        self.last_packet_time = time.time()

    def set_interface(self, interface):
        self.interface = interface

    def load_model(self):
        try:
            self.model = joblib.load('trained_model/random_forest_model.joblib')
            self.scaler = joblib.load('trained_model/scaler.joblib')
            self.status_update.emit("✅ Model loaded successfully")
            return True
        except Exception as e:
            self.status_update.emit(f"❌ Failed to load model: {str(e)}")
            return False

    def update_feature_display(self, features):
        text = "Extracted Features:\n"
        for name, value in features.items():
            text += f"{name}: {value}\n"
        self.features_display.setText(text)
        
    def start_monitoring(self):
        with QMutexLocker(self.mutex):
            self._is_running = True
        self.start_time = time.time()
        if not self.isRunning():
            self.start()

    def stop_monitoring(self):
        # signal the thread to exit its loop
        self.monitoring_thread._stop = True
        # update UI immediately
        self.start_monitoring_btn.setEnabled(True)
        self.stop_monitoring_btn.setEnabled(False)
        self.traffic_display.append(...)

    def run(self):
        try:
            if not self.load_model():
                return
            from scapy.all import conf
            conf.use_pcap = True
            conf.use_npcap = True

            # 3) notify GUI
            self.status_update.emit(f"Starting capture on {self.interface or 'any'}")
            while not self._stop:
                sniff(
                    iface=self.interface or None,
                    prn=self._packet_handler,
                    store=False,
                    timeout=1, 
                    # optional low‑level stop filter: returns True to stop sniff loop early
                    stop_filter=lambda pkt: self._stop
                )
            # done
        except Exception as e:
            # catch everything and emit it
            self.error.emit(f"Sniff failed: {e!r}")
        finally:
            self.status_update.emit("sMonitoring stopped")
            self.monitoring_stopped.emit()
            # Windows-specific setup for loopback
            

    def _packet_handler(self, packet):
        try:
            # Only process IPv4 packets
            if not packet.haslayer(IP):
                return

            # 1) Extract raw feature list
            features = extract_features_from_packet(packet)

            # 2) Emit for UI visualization (as a dict)
            feature_dict = dict(zip([
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
                'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT'
            ], features))
            self.feature_update.emit(feature_dict)

            # 3) Scale features if a scaler was loaded
            if self.scaler is not None:
                features = self.scaler.transform([features])[0]

            # 4) Run the model prediction
            prediction = self.model.predict([features])[0]

            # 5) Compute confidence if available
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba([features])[0]
                confidence = max(probs) * 100
            else:
                confidence = 95.0  # fallback

            # 6) If it's not 'normal', emit a threat signal
            if prediction != 0:
                self.threat_detected.emit({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'threat_type': str(prediction),
                    'source_ip': packet[IP].src,
                    'confidence': confidence,
                    'details': f"{packet.summary()} | Size: {len(packet)} bytes"
                })

            # 7) Update packet count & emit
            self.packet_count.emit(1)
            self.packet_counter += 1

            # 8) Update processing rate once per second
            now = time.time()
            elapsed = now - self.last_packet_time
            if elapsed >= 1.0:
                rate = self.packet_counter / elapsed
                self.status_update.emit(f"📦 Processing: {rate:.1f} pkt/s")
                self.packet_counter = 0
                self.last_packet_time = now

        except Exception as e:
            # Catch any error in packet handling so the thread won't crash
            print(f"Packet handler error: {e}")

    def _should_stop(self, _):
        with QMutexLocker(self.mutex):
            return not self._is_running
    
class MLHIDSMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
         # ─── Instantiate and connect MonitoringThread ────────────────────────────
        self.monitoring_thread = MonitoringThread()
        self.monitoring_thread.error.connect(self.on_monitoring_error)
        self.monitoring_thread.status_update.connect(self.update_monitoring_status)
        self.monitoring_thread.threat_detected.connect(self.handle_threat_detection)
        self.monitoring_thread.packet_count.connect(self._update_packet_count)
        self.monitoring_thread.feature_update.connect(self.update_feature_display)
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
        self.create_dashboard_tab()
        self.create_select_model_tab()
        self.create_monitoring_tab()
        self.create_threats_tab()
        self.create_settings_tab()
        
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tab_widget)
        central_widget.setLayout(main_layout)
        
    def create_dashboard_tab(self):
        dashboard_widget = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("ML-HIDS Dashboard")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Status cards
        status_layout = QHBoxLayout()
        
        # Model Status Card
        model_group = QGroupBox("Model Status")
        model_layout = QVBoxLayout()
        self.model_status_label = QLabel("❌ No Model Loaded")
        self.model_status_label.setFont(QFont("Arial", 12))
        model_layout.addWidget(self.model_status_label)
        model_group.setLayout(model_layout)
        
        # Monitoring Status Card
        monitoring_group = QGroupBox("Monitoring Status")
        monitoring_layout = QVBoxLayout()
        self.monitoring_status_label = QLabel("⏹️ Stopped")
        self.monitoring_status_label.setFont(QFont("Arial", 12))
        monitoring_layout.addWidget(self.monitoring_status_label)
        monitoring_group.setLayout(monitoring_layout)
        
        # Threats Card
        threats_group = QGroupBox("Threats Detected")
        threats_layout = QVBoxLayout()
        self.threats_count_label = QLabel("0")
        self.threats_count_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        self.threats_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        threats_layout.addWidget(self.threats_count_label)
        threats_group.setLayout(threats_layout)
        
        status_layout.addWidget(model_group)
        status_layout.addWidget(monitoring_group)
        status_layout.addWidget(threats_group)
        layout.addLayout(status_layout)
        
        # Quick Actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout()
        

        
        self.quick_monitor_btn = QPushButton("Start Monitoring")
        self.quick_monitor_btn.clicked.connect(self.start_monitoring)
        
        self.quick_stop_btn = QPushButton("Stop Monitoring")
        self.quick_stop_btn.clicked.connect(self.stop_monitoring)
        self.quick_stop_btn.setEnabled(False)
        
        actions_layout.addWidget(self.quick_monitor_btn)
        actions_layout.addWidget(self.quick_stop_btn)
        actions_group.setLayout(actions_layout)
        
        layout.addWidget(actions_group)
        
        # Recent Activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout()
        self.activity_log = QTextEdit()
        self.activity_log.setMaximumHeight(200)
        self.activity_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] System initialized")
        activity_layout.addWidget(self.activity_log)
        activity_group.setLayout(activity_layout)
        
        layout.addWidget(activity_group)
        layout.addStretch()
        
        dashboard_widget.setLayout(layout)
        self.tab_widget.addTab(dashboard_widget, "Dashboard")
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
        
    def create_settings_tab(self):
        settings_widget = QWidget()
        layout = QVBoxLayout()
        
        # Model Settings
        model_group = QGroupBox("Model Settings")
        model_layout = QGridLayout()
        
        model_layout.addWidget(QLabel("Model Path:"), 0, 0)
        self.model_path_edit = QTextEdit()
        self.model_path_edit.setMaximumHeight(30)
        self.model_path_edit.setPlainText("trained_model/")
        model_layout.addWidget(self.model_path_edit, 0, 1)
        
        # Alert Settings
        alert_group = QGroupBox("Alert Settings")
        alert_layout = QVBoxLayout()
        
        self.alert_enabled = QCheckBox("Enable Threat Alerts")
        self.alert_enabled.setChecked(True)
        alert_layout.addWidget(self.alert_enabled)
        
        alert_group.setLayout(alert_layout)
        
        model_group.setLayout(model_layout)
        layout.addWidget(model_group)
        layout.addWidget(alert_group)
        
        # Save Settings Button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        layout.addStretch()
        
        settings_widget.setLayout(layout)
        self.tab_widget.addTab(settings_widget, "Settings")
        
    def browse_dataset(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Dataset", "", "CSV Files (*.csv)"
        )
        if file_path:
            self.dataset_path_edit.setPlainText(file_path)
            
    def start_training(self):
        dataset_path = self.dataset_path_edit.toPlainText().strip()
        if not dataset_path or dataset_path == "Select dataset file...":
            QMessageBox.warning(self, "Warning", "Please select a dataset file.")
            return
            
        if not os.path.exists(dataset_path):
            QMessageBox.warning(self, "Warning", "Dataset file does not exist.")
            return
            
        # Prepare model parameters
        model_params = {
            'n_estimators': self.n_estimators_spin.value(),
            'max_depth': self.max_depth_spin.value() if self.max_depth_spin.value() > 0 else None
        }
        
        # Start training thread
        self.training_thread = ModelTrainingThread(dataset_path, model_params)
        self.training_thread.progress_update.connect(self.training_progress.setValue)
        self.training_thread.status_update.connect(self.training_status_label.setText)
        self.training_thread.training_complete.connect(self.training_completed)
        
        self.train_btn.setEnabled(False)
        self.training_thread.start()
        
    def training_completed(self, results):
        self.train_btn.setEnabled(True)
        
        # Display results
        results_text = f"""Training Completed Successfully!

Accuracy: {results['accuracy']:.4f}

Classification Report:
"""
        for class_name, metrics in results['classification_report'].items():
            if isinstance(metrics, dict):
                results_text += f"\n{class_name}:\n"
                for metric, value in metrics.items():
                    results_text += f"  {metric}: {value:.4f}\n"
                    
        results_text += "\nTop 10 Important Features:\n"
        sorted_features = sorted(results['feature_importance'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]
        for feature, importance in sorted_features:
            results_text += f"  {feature}: {importance:.4f}\n"
            
        self.training_results.setText(results_text)
        
        # Update model status
        self.check_model_availability()
        
        # Log activity
        self.activity_log.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] Model training completed with accuracy: {results['accuracy']:.4f}"
        )
        
        def start_monitoring(self):
        # prevent double-start
            if self.monitoring_thread.isRunning():
                return

            # 1) configure interface
            iface = self.interface_combo.currentData()  # or .currentText()
            self.monitoring_thread.set_interface(iface)

            # 2) clear any previous stop flag
            self.monitoring_thread._stop = False

            # 3) start the thread
            self.monitoring_thread.start()

            # 4) update UI buttons/log
            self.start_monitoring_btn.setEnabled(False)
            self.stop_monitoring_btn.setEnabled(True)
            self.traffic_display.append(
                f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring started on {iface}"
            )

        
    def _update_packet_count(self, count):
        current = int(self.packets_count_label.text())
        self.packets_count_label.setText(str(current + count))
        
    def _monitoring_finished(self):
        self.start_monitoring_btn.setEnabled(True)
        self.stop_monitoring_btn.setEnabled(False)
        self.traffic_display.append(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring stopped")
    
    def start_monitoring(self):
        # Prevent double‑starts
        if self.monitoring_thread.isRunning():
            return

        # 1) Pick up interface from the combo
        iface = self.interface_combo.currentData() or self.interface_combo.currentText()
        self.monitoring_thread.set_interface(iface)

        # 2) Clear any prior stop flag
        self.monitoring_thread._stop = False

        # 3) Launch the thread
        self.monitoring_thread.start()

        # 4) Update your quick‑action buttons
        self.quick_monitor_btn.setEnabled(False)
        self.quick_stop_btn.setEnabled(True)

        # 5) Optional log
        self.activity_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring started on {iface}")

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
        
        # Update threat count
        current_count = int(self.threats_count_label.text())
        self.threats_count_label.setText(str(current_count + 1))
        
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
        self.activity_log.append(
            f"[{threat_info['timestamp']}] Threat detected: {threat_info['threat_type']} from {threat_info['source_ip']} (Confidence: {threat_info['confidence']:.2f}%)"
        )
        
        # Update monitoring tab display
        self.traffic_display.append(
            f"[{threat_info['timestamp']}] ALERT: {threat_info['threat_type']} from {threat_info['source_ip']}"
        )
    
    def update_monitoring_status(self, message):
        self.monitoring_status_display.setText(message)
        
    def check_model_availability(self):
        if os.path.exists('trained_model/random_forest_model.joblib'):
            self.model_status_label.setText("✅ Model Loaded")
            return True
        else:
            self.model_status_label.setText("❌ No Model Loaded")
            return False
            
    def clear_threats(self):
        self.threats_table.setRowCount(0)
        self.threats_count_label.setText("0")
        self.activity_log.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] Threats log cleared"
        )
        
    def save_settings(self):
        # In a real application, we would save the settings to a config file
        QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
        self.activity_log.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] Settings saved"
        )
    def create_monitoring_tab(self):
        monitoring_widget = QWidget()
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
        self.start_monitoring_btn.clicked.connect(self.start_monitoring)
        
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
        self.interface_combo = QComboBox()
        self.interface_combo.clear()
        self.interface_combo.addItem("any", "any")
        for iface in get_if_list():
            self.interface_combo.addItem(iface, iface)
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
        
        # Processing rate
        rate_group = QGroupBox("Processing Rate")
        rate_layout = QVBoxLayout()
        self.processing_rate_label = QLabel("0 pkt/s")
        self.processing_rate_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.processing_rate_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        rate_layout.addWidget(self.processing_rate_label)
        rate_group.setLayout(rate_layout)
        
        stats_layout.addWidget(packets_group)
        stats_layout.addWidget(threats_group)
        stats_layout.addWidget(rate_group)
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
        self.rate_timer = QTimer()
        self.rate_timer.timeout.connect(self.update_processing_rate)
        self.rate_timer.start(1000)  # Update every second

    def clear_traffic_log(self):
        """Clear the traffic display log"""
        self.traffic_display.clear()
        self.traffic_display.append(f"[{datetime.now().strftime('%H:%M:%S')}] Traffic log cleared")
        
        # Log activity
        self.activity_log.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] Traffic monitoring log cleared"
        )


    def update_processing_rate(self):
        """Update the processing rate display"""
        current_time = time.time()
        time_diff = current_time - self.last_packet_time
        
        if time_diff > 0:
            # Calculate packets per second (this is a simplified calculation)
            # In a real implementation, you'd track packets over a rolling window
            rate = 1.0 / time_diff if time_diff < 1 else 0
            self.processing_rate_label.setText(f"{rate:.1f} pkt/s")
        
        self.last_packet_time = current_time    
    def show_training_tab(self):
        self.tab_widget.setCurrentIndex(1)  # Training tab is index 1 (second tab)
        
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
