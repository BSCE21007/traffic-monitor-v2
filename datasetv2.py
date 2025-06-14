from scapy.all import sniff, IP, TCP

import pandas as pd

import numpy as np

from sklearn.ensemble import RandomForestClassifier

from sklearn.model_selection import train_test_split

from sklearn.preprocessing import LabelEncoder, StandardScaler

from sklearn.metrics import (

    roc_auc_score, f1_score, precision_score, recall_score, confusion_matrix, 

    classification_report, roc_curve, auc

)

import matplotlib.pyplot as plt

from collections import defaultdict

import time

import joblib

import os

from tqdm import tqdm

from scapy.arch import windows

import winreg

import time

def time_program(func):

    def wrapper(*args, **kwargs):

        start_time = time.time_ns() / 1e6  # Get the start time in milliseconds

        result = func(*args, **kwargs)

        end_time = time.time_ns() / 1e6  # Get the end time in milliseconds

        print(f"Program execution time: {end_time - start_time:.2f} ms")

        return result

    return wrapper

class MLHIDS:

    def __init__(self, trusted_hosts=None, model_path='trained_model'):

        self.trusted_hosts = trusted_hosts or []

        self.model = RandomForestClassifier(n_estimators=100, max_depth=15,min_samples_split=20,n_jobs =-1, class_weight="balanced")

        self.scaler = StandardScaler()

        self.model_path = model_path

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

            'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT'

        ]

        self.syn_packet_count = defaultdict(int)

        self.last_update_time = time.time()



    def extract_features(self, packet):

        """Extract relevant features from a packet."""

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

        return features



    def packet_callback(self, packet):

        """Process each captured packet."""

        if not packet or IP not in packet:

            return



        src_ip = packet[IP].src

        dst_ip = packet[IP].dst



        if src_ip in self.trusted_hosts or dst_ip in self.trusted_hosts:

            return



        features = self.extract_features(packet)

        prediction = self.predict(features)



        if prediction == 1:

            self.alert(packet, features)



    def preprocess_data(self, data):

        """Preprocess the data to handle infinite values and outliers."""

        processed_data = data.copy()

        processed_data = processed_data.replace([np.inf, -np.inf], np.nan)



        for column in processed_data.columns:

            if processed_data[column].dtype in ['int64', 'float64']:

                median_value = processed_data[column].median()

                processed_data[column] = processed_data[column].fillna(median_value)



        for column in processed_data.select_dtypes(include=['int64', 'float64']).columns:

            lower_bound = processed_data[column].quantile(0.001)

            upper_bound = processed_data[column].quantile(0.999)

            processed_data[column] = processed_data[column].clip(lower_bound, upper_bound)



        return processed_data



    def save_model(self):

        """Save the trained model and scaler to disk."""

        if not os.path.exists(self.model_path):

            os.makedirs(self.model_path)



        joblib.dump(self.model, f'{self.model_path}/random_forest_model.joblib')

        joblib.dump(self.scaler, f'{self.model_path}/scaler.joblib')

        print(f"Model and scaler saved to {self.model_path}")



    def log_metrics(self, accuracy, roc_auc, f1, precision, recall, conf_matrix, classification_rep):

        """Log ML metrics to a file and print to console."""

        metrics_message = (

            f"Model Metrics:\n"

            f"Accuracy: {accuracy:.4f}\n"

            f"ROC-AUC: {roc_auc:.4f}\n"

            f"F1-Score: {f1:.4f}\n"

            f"Precision: {precision:.4f}\n"

            f"Recall: {recall:.4f}\n"

            f"Confusion Matrix:\n{conf_matrix}\n"

            f"Classification Report:\n{classification_rep}\n"

        )

        print(metrics_message)

        with open("model_metrics.log", "a") as log_file:

            log_file.write(metrics_message + "\n")

    def plot_roc_curve(self, y_true, y_pred_proba):

        """Plot ROC curve and save as an image."""

        fpr, tpr, thresholds = roc_curve(y_true, y_pred_proba)

        roc_auc = auc(fpr, tpr)



        plt.figure()

        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')

        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')

        plt.xlim([0.0, 1.0])

        plt.ylim([0.0, 1.05])

        plt.xlabel('False Positive Rate')

        plt.ylabel('True Positive Rate')

        plt.title('Receiver Operating Characteristic (ROC) Curve')

        plt.legend(loc="lower right")

        plt.savefig("roc_curve.png")

        plt.close()

    def verify_npcap_installation(self):

        """Verify Npcap is properly installed."""

        try:

            # Check for Npcap installation in registry

            key_path = r"SOFTWARE\WOW6432Node\Npcap"

            try:

                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)

                winreg.CloseKey(key)

                return True

            except WindowsError:

                return False

        except Exception as e:

            print(f"Error checking Npcap installation: {e}")

            return False



    def load_model(self):

        """Load the trained model and scaler from disk."""

        try:

            self.model = joblib.load(f'{self.model_path}/random_forest_model.joblib')

            self.scaler = joblib.load(f'{self.model_path}/scaler.joblib')

            print("Model and scaler loaded successfully")

            return True

        except FileNotFoundError:

            print("No saved model found")

            return False



    def train(self, file_path, batch_size=100000):

        """Train the Random Forest model using batch processing."""

        print("Starting model training...")



        total_rows = sum(1 for _ in open(file_path)) - 1

        print(f"Total rows in dataset: {total_rows:,}")



        chunks = pd.read_csv(file_path, chunksize=batch_size, low_memory=False)



        all_X = []

        all_y = []



        for i, chunk in enumerate(tqdm(chunks, desc="Processing data chunks")):

            X_chunk = chunk[self.feature_columns]

            X_chunk = self.preprocess_data(X_chunk)

            all_X.append(X_chunk)



            if chunk['Label'].dtype == 'object':

                le = LabelEncoder()

                y_chunk = le.fit_transform(chunk['Label'])

            else:

                y_chunk = chunk['Label']

            all_y.append(y_chunk)



        X = pd.concat(all_X)

        y = np.concatenate(all_y)



        X_train, X_test, y_train, y_test = train_test_split(

            X, y, test_size=0.2, random_state=42

        )



        print("Scaling features...")

        X_train_scaled = self.scaler.fit_transform(X_train)

        X_test_scaled = self.scaler.transform(X_test)



        X_train_scaled = X_train_scaled.astype(np.float64)

        X_test_scaled = X_test_scaled.astype(np.float64)



        print("Training model...")

        self.model.fit(X_train_scaled, y_train)



        # Predict on the test set

        y_pred = self.model.predict(X_test_scaled)

        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]



        # Calculate metrics

        accuracy = self.model.score(X_test_scaled, y_test)

        roc_auc = roc_auc_score(y_test, y_pred_proba)

        f1 = f1_score(y_test, y_pred)

        precision = precision_score(y_test, y_pred)

        recall = recall_score(y_test, y_pred)

        conf_matrix = confusion_matrix(y_test, y_pred)

        classification_rep = classification_report(y_test, y_pred)



        # Log metrics

        self.log_metrics(accuracy, roc_auc, f1, precision, recall, conf_matrix, classification_rep)



        # Plot ROC curve

        self.plot_roc_curve(y_test, y_pred_proba)



        # Feature importance

        feature_importance = pd.DataFrame({

            'feature': self.feature_columns,

            'importance': self.model.feature_importances_

        }).sort_values('importance', ascending=False)

        print("\nTop 10 most important features:")

        print(feature_importance.head(10))



        #self.save_model()



    def predict(self, features):

        """Make prediction on a single packet with preprocessing."""

        features_df = pd.DataFrame([features])

        features_df = features_df[self.feature_columns]



        features_df = self.preprocess_data(features_df)

        features_scaled = self.scaler.transform(features_df)

        features_scaled = features_scaled.astype(np.float64)



        return self.model.predict(features_scaled)[0]





    def alert(self, packet, features):

        """Handle detected attacks."""

        alert_message = (

            f"Potential attack detected!\n"

            f"Source IP: {packet[IP].src if IP in packet else 'Unknown'}\n"

            f"Destination IP: {packet[IP].dst if IP in packet else 'Unknown'}\n"

            f"Source MAC: {packet.src if hasattr(packet, 'src') else 'Unknown'}\n"

            f"Destination MAC: {packet.dst if hasattr(packet, 'dst') else 'Unknown'}\n"

            f"Features: {features}\n"

        )

        print(alert_message)



        with open("nids_alerts.log", "a") as log_file:

            log_file.write(alert_message + "\n")



    def start_monitoring(self, interface="eth0"):

        """Start packet capture and analysis."""

        print(f"Starting NIDS monitoring on interface {interface}")



        # Verify Npcap installation first

        if not self.verify_npcap_installation():

            print("Npcap not found. Please install Npcap from https://npcap.com/")

            return



        try:

            from scapy.arch.windows import get_windows_if_list

            from scapy.all import conf



            # Configure Scapy for Windows

            conf.use_pcap = True

            conf.use_npcap = True



            sniff(iface=interface, prn=self.packet_callback, store=0, filter="ip")

        except Exception as e:

            print(f"Error starting packet capture: {e}")

            print("Make sure you have the correct permissions and the interface exists.")

            print("If using Windows, ensure Npcap is installed from https://npcap.com/")





def get_windows_interfaces():

    """Get list of network interfaces on Windows using psutil."""

    import psutil

    import socket



    interfaces = []



    # Get all network interfaces

    for nic in psutil.net_if_addrs().items():

        name = nic[0]

        addresses = nic[1]



        # Get IPv4 addresses

        ipv4_addresses = []

        for addr in addresses:

            if addr.family == socket.AF_INET:

                ipv4_addresses.append(addr.address)



        if ipv4_addresses:  # Only include interfaces with IPv4 addresses

            interfaces.append({

                'name': name,

                'description': name,

                'addresses': ipv4_addresses

            })



    return interfaces



@time_program

def main():

    # Initialize HIDS

    trusted_hosts = ["192.168.1.0/24", "10.0.0.0/8", "192.168.100.74"]

    hids = MLHIDS(trusted_hosts=trusted_hosts)



    # Check if we have a saved model

    if not hids.load_model():

        print("No saved model found. Starting training...")

        file_path = r'F:\data\filtered_dataset.csv'

        hids.train(file_path)

'''

    # Get list of available interfaces

    interfaces = get_windows_interfaces()

    print("\nAvailable interfaces:")

    for idx, iface in enumerate(interfaces):

        print(f"{idx}. {iface['name']}")

        for addr in iface['addresses']:

            print(f"   IP: {addr}")



    # Let user select interface

    while True:

        try:

            idx = int(input("\nSelect interface number: "))

            if 0 <= idx < len(interfaces):

                break

            print("Invalid selection. Please try again.")

        except ValueError:

            print("Please enter a valid number.")



    selected_interface = interfaces[idx]['name']



    # Start monitoring

    print(f"\nStarting network monitoring on interface {selected_interface}...")

    hids.start_monitoring(interface=selected_interface)



'''

if __name__ == "__main__":

    main()