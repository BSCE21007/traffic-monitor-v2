
import os
import time
import joblib
import argparse
import threading
import pandas as pd
import numpy as np
from collections import defaultdict, deque
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
)
from scapy.all import sniff, IP, TCP, UDP

# ---------- Flow class for aggregation ----------

class Flow:
    """
    Track per-flow state for aggregation. Keyed by 5-tuple:
      (src_ip, src_port, dst_ip, dst_port, protocol)
    """
    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol, first_pkt_time):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol  # numeric, e.g., IP.proto

        self.start_time = first_pkt_time
        self.last_time = first_pkt_time

        # Byte/packet counts
        self.in_bytes = 0
        self.out_bytes = 0
        self.in_pkts = 0
        self.out_pkts = 0

        # Packet length extremes
        self.min_pkt_len = None
        self.max_pkt_len = None

        # TTL extremes
        self.min_ttl = None
        self.max_ttl = None

        # Second-bytes: keep first two sizes in each direction
        self.src_to_dst_sizes = deque(maxlen=2)
        self.dst_to_src_sizes = deque(maxlen=2)

        # Retransmission placeholders
        self.retrans_in_bytes = 0
        self.retrans_in_pkts = 0
        self.retrans_out_bytes = 0
        self.retrans_out_pkts = 0

        # Packet size buckets
        self.size_buckets = {
            'up128': 0,
            '128_256': 0,
            '256_512': 0,
            '512_1024': 0,
            '1024_1514': 0
        }

        # TCP window max
        self.win_max_in = 0
        self.win_max_out = 0

    def update(self, packet, pkt_time):
        """Update flow statistics with a new packet."""
        self.last_time = pkt_time
        pkt_len = len(packet)

        if not packet.haslayer(IP):
            return
        ip = packet[IP]

        # Determine L4 layer
        if packet.haslayer(TCP):
            l4 = packet[TCP]
        elif packet.haslayer(UDP):
            l4 = packet[UDP]
        else:
            l4 = None

        # Determine direction: 'in' if matches initial 5-tuple, 'out' if reversed, else by src IP
        direction = None
        if l4:
            sport = l4.sport
            dport = l4.dport
            if ip.src == self.src_ip and ip.dst == self.dst_ip and sport == self.src_port and dport == self.dst_port:
                direction = 'in'
            elif ip.src == self.dst_ip and ip.dst == self.src_ip and sport == self.dst_port and dport == self.src_port:
                direction = 'out'
        if direction is None:
            direction = 'in' if ip.src == self.src_ip else 'out'

        # Update counts and buckets
        if direction == 'in':
            self.in_pkts += 1
            self.in_bytes += pkt_len
            # second-bytes
            self.src_to_dst_sizes.append(pkt_len)
            # size bucket
            if pkt_len <= 128:
                self.size_buckets['up128'] += 1
            elif pkt_len <= 256:
                self.size_buckets['128_256'] += 1
            elif pkt_len <= 512:
                self.size_buckets['256_512'] += 1
            elif pkt_len <= 1024:
                self.size_buckets['512_1024'] += 1
            else:
                self.size_buckets['1024_1514'] += 1
            # TCP window
            if packet.haslayer(TCP):
                w = packet[TCP].window
                if w > self.win_max_in:
                    self.win_max_in = w
        else:
            self.out_pkts += 1
            self.out_bytes += pkt_len
            self.dst_to_src_sizes.append(pkt_len)
            if pkt_len <= 128:
                self.size_buckets['up128'] += 1
            elif pkt_len <= 256:
                self.size_buckets['128_256'] += 1
            elif pkt_len <= 512:
                self.size_buckets['256_512'] += 1
            elif pkt_len <= 1024:
                self.size_buckets['512_1024'] += 1
            else:
                self.size_buckets['1024_1514'] += 1
            if packet.haslayer(TCP):
                w = packet[TCP].window
                if w > self.win_max_out:
                    self.win_max_out = w

        # Packet length extremes
        if self.min_pkt_len is None or pkt_len < self.min_pkt_len:
            self.min_pkt_len = pkt_len
        if self.max_pkt_len is None or pkt_len > self.max_pkt_len:
            self.max_pkt_len = pkt_len

        # TTL extremes
        if packet.haslayer(IP):
            ttl = packet[IP].ttl
            if self.min_ttl is None or ttl < self.min_ttl:
                self.min_ttl = ttl
            if self.max_ttl is None or ttl > self.max_ttl:
                self.max_ttl = ttl

        # Retransmission: keep zero or implement if needed

    def is_expired(self, current_time, timeout=60.0):
        """Return True if no packets for > timeout seconds."""
        return (current_time - self.last_time) > timeout

    def aggregate_features(self):
        """
        Compute aggregated feature dict matching your 28 feature_columns:
        ['IN_BYTES', 'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS',
         'FLOW_DURATION_MILLISECONDS', 'DURATION_IN', 'DURATION_OUT',
         'MIN_TTL', 'MAX_TTL', 'LONGEST_FLOW_PKT', 'SHORTEST_FLOW_PKT',
         'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN', 'SRC_TO_DST_SECOND_BYTES',
         'DST_TO_SRC_SECOND_BYTES', 'RETRANSMITTED_IN_BYTES',
         'RETRANSMITTED_IN_PKTS', 'RETRANSMITTED_OUT_BYTES',
         'RETRANSMITTED_OUT_PKTS', 'SRC_TO_DST_AVG_THROUGHPUT',
         'DST_TO_SRC_AVG_THROUGHPUT', 'NUM_PKTS_UP_TO_128_BYTES',
         'NUM_PKTS_128_TO_256_BYTES', 'NUM_PKTS_256_TO_512_BYTES',
         'NUM_PKTS_512_TO_1024_BYTES', 'NUM_PKTS_1024_TO_1514_BYTES',
         'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT']
        """
        features = {}
        # Bytes/pkts
        features['IN_BYTES'] = self.in_bytes
        features['OUT_BYTES'] = self.out_bytes
        features['IN_PKTS'] = self.in_pkts
        features['OUT_PKTS'] = self.out_pkts

        # Duration in ms
        duration_s = max(self.last_time - self.start_time, 1e-6)
        features['FLOW_DURATION_MILLISECONDS'] = duration_s * 1000.0
        # DURATION_IN and DURATION_OUT: approximate as total duration
        features['DURATION_IN'] = duration_s * 1000.0
        features['DURATION_OUT'] = duration_s * 1000.0

        # TTL extremes
        features['MIN_TTL'] = self.min_ttl or 0
        features['MAX_TTL'] = self.max_ttl or 0

        # Packet length extremes
        features['LONGEST_FLOW_PKT'] = self.max_pkt_len or 0
        features['SHORTEST_FLOW_PKT'] = self.min_pkt_len or 0
        features['MIN_IP_PKT_LEN'] = self.min_pkt_len or 0
        features['MAX_IP_PKT_LEN'] = self.max_pkt_len or 0

        # Second-bytes
        if len(self.src_to_dst_sizes) >= 2:
            features['SRC_TO_DST_SECOND_BYTES'] = self.src_to_dst_sizes[1]
        elif len(self.src_to_dst_sizes) == 1:
            features['SRC_TO_DST_SECOND_BYTES'] = self.src_to_dst_sizes[0]
        else:
            features['SRC_TO_DST_SECOND_BYTES'] = 0

        if len(self.dst_to_src_sizes) >= 2:
            features['DST_TO_SRC_SECOND_BYTES'] = self.dst_to_src_sizes[1]
        elif len(self.dst_to_src_sizes) == 1:
            features['DST_TO_SRC_SECOND_BYTES'] = self.dst_to_src_sizes[0]
        else:
            features['DST_TO_SRC_SECOND_BYTES'] = 0

        # Retransmission fields (placeholders 0)
        features['RETRANSMITTED_IN_BYTES'] = self.retrans_in_bytes
        features['RETRANSMITTED_IN_PKTS'] = self.retrans_in_pkts
        features['RETRANSMITTED_OUT_BYTES'] = self.retrans_out_bytes
        features['RETRANSMITTED_OUT_PKTS'] = self.retrans_out_pkts

        # Throughput bytes/sec
        features['SRC_TO_DST_AVG_THROUGHPUT'] = (self.in_bytes / duration_s) if duration_s > 0 else 0
        features['DST_TO_SRC_AVG_THROUGHPUT'] = (self.out_bytes / duration_s) if duration_s > 0 else 0

        # Packet size buckets
        features['NUM_PKTS_UP_TO_128_BYTES'] = self.size_buckets.get('up128', 0)
        features['NUM_PKTS_128_TO_256_BYTES'] = self.size_buckets.get('128_256', 0)
        features['NUM_PKTS_256_TO_512_BYTES'] = self.size_buckets.get('256_512', 0)
        features['NUM_PKTS_512_TO_1024_BYTES'] = self.size_buckets.get('512_1024', 0)
        features['NUM_PKTS_1024_TO_1514_BYTES'] = self.size_buckets.get('1024_1514', 0)

        # TCP window max
        features['TCP_WIN_MAX_IN'] = getattr(self, 'win_max_in', 0)
        features['TCP_WIN_MAX_OUT'] = getattr(self, 'win_max_out', 0)

        return features

# ---------- MLHIDS class with existing feature_columns and methods ----------

class MLHIDS:
    def __init__(self, trusted_hosts=None, model_path='trained_model'):
        """
        trusted_hosts: list of IPs or networks to ignore
        model_path: directory for saving/loading model and scaler
        """
        self.trusted_hosts = trusted_hosts or []
        # Initialize model exactly as original
        self.model = RandomForestClassifier(n_estimators=100, max_depth=15,
                                            min_samples_split=20, n_jobs=-1,
                                            class_weight="balanced")
        self.scaler = StandardScaler()
        self.model_path = model_path
        # Feature names as in your original code :contentReference[oaicite:2]{index=2}
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

        # For flow aggregation
        self.active_flows = {}
        # Set timeout according to typical flow durations in your training data
        self.flow_timeout = 60.0  # seconds

        # LabelEncoder placeholder
        self.le = None

    # ---------- Preprocessing as original :contentReference[oaicite:3]{index=3} ----------

    def preprocess_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Preprocess the data to handle infinite values and outliers."""
        processed_data = data.copy()
        processed_data = processed_data.replace([np.inf, -np.inf], np.nan)

        for column in processed_data.columns:
            if processed_data[column].dtype in ['int64', 'float64']:
                median_value = processed_data[column].median()
                processed_data[column] = processed_data[column].fillna(median_value)
            else:
                mode = processed_data[column].mode()
                if not mode.empty:
                    processed_data[column] = processed_data[column].fillna(mode[0])
                else:
                    processed_data[column] = processed_data[column].fillna(0)

        # Clip outliers at 0.1% and 99.9%
        for column in processed_data.select_dtypes(include=['int64', 'float64']).columns:
            lower_bound = processed_data[column].quantile(0.001)
            upper_bound = processed_data[column].quantile(0.999)
            processed_data[column] = processed_data[column].clip(lower_bound, upper_bound)

        return processed_data

    # ---------- Data loading ----------

    def load_data(self, csv_path):
        """Load data from CSV into DataFrame."""
        print(f"[+] Loading data from {csv_path} ...")
        df = pd.read_csv(csv_path)
        print(f"[+] Loaded {len(df)} rows; columns: {df.columns.tolist()}")
        return df

    # ---------- Training pipeline ----------

    def train(self, file_path, batch_size=None):
        """
        Train model using entire DataFrame (no chunking here, but can adapt if needed).
        Assumes CSV rows are aggregated flow records matching feature_columns.
        """
        df = self.load_data(file_path)
        # Expect label column 'Label' in df
        if 'Label' not in df.columns:
            raise ValueError("CSV must contain 'Label' column.")
        X = df[self.feature_columns]
        y = df['Label']
        # Preprocess features
        X_proc = self.preprocess_data(X)
        X_proc = X_proc[self.feature_columns]

        # LabelEncoder
        self.le = LabelEncoder()
        y_enc = self.le.fit_transform(y.values)
        print(">>> LabelEncoder.classes_:", self.le.classes_)
        for code, label in enumerate(self.le.classes_):
            print(f"    {code} -> '{label}'")

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_proc, y_enc, test_size=0.2, random_state=42, stratify=y_enc
        )
        # Scale
        X_train_scaled = self.scaler.fit_transform(X_train.astype(np.float64))
        X_test_scaled = self.scaler.transform(X_test.astype(np.float64))

        # Train RandomForest
        print("[+] Training RandomForestClassifier ...")
        self.model.fit(X_train_scaled, y_train)
        print("[+] Training complete.")

        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        try:
            y_proba = self.model.predict_proba(X_test_scaled)[:,1]
        except:
            y_proba = None
        cm = confusion_matrix(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average='weighted')
        prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        print("Confusion Matrix:\n", cm)
        print(f"F1-score: {f1:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}")
        if y_proba is not None:
            try:
                auc = roc_auc_score(y_test, y_proba)
                print(f"ROC AUC: {auc:.4f}")
            except:
                pass

        # Save model, scaler, encoder, feature_columns
        os.makedirs(self.model_path, exist_ok=True)
        joblib.dump(self.model, f'{self.model_path}/random_forest_model.joblib')
        joblib.dump(self.scaler, f'{self.model_path}/scaler.joblib')
        joblib.dump(self.le, f'{self.model_path}/label_encoder.joblib')
        joblib.dump(self.feature_columns, f'{self.model_path}/feature_columns.pkl')
        print(f"[+] Saved model, scaler, encoder, feature_columns in {self.model_path}")

    # ---------- Load model for inference ----------

    def load_model(self):
        """Load trained model, scaler, encoder, feature_columns."""
        try:
            self.model = joblib.load(f'{self.model_path}/random_forest_model.joblib')
            self.scaler = joblib.load(f'{self.model_path}/scaler.joblib')
            self.le = joblib.load(f'{self.model_path}/label_encoder.joblib')
            self.feature_columns = joblib.load(f'{self.model_path}/feature_columns.pkl')
            print("Model, scaler, LabelEncoder, feature_columns loaded successfully")
            print(">>> LabelEncoder.classes_:", self.le.classes_)
            for code, label in enumerate(self.le.classes_):
                print(f"    {code} -> '{label}'")
            return True
        except FileNotFoundError:
            print("No saved model found in", self.model_path)
            return False

    def predict(self, features: dict):
        """
        Predict on aggregated flow features (dict). Returns int code (0 benign, 1 anomaly).
        """
        # Build DataFrame
        df = pd.DataFrame([features])
        df = df[self.feature_columns]
        df_proc = self.preprocess_data(df)
        X_scaled = self.scaler.transform(df_proc.astype(np.float64))
        code = int(self.model.predict(X_scaled)[0])
        # Optional: label_str = self.le.inverse_transform([code])[0]
        print(f"[+] Prediction code={code}")
        return code

    # ---------- Flow key helper ----------

    def _get_flow_key(self, packet):
        """Return 5-tuple key (src_ip, src_port, dst_ip, dst_port, proto)."""
        ip = packet[IP]
        proto = ip.proto
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            sport = 0
            dport = 0
        return (ip.src, sport, ip.dst, dport, proto)

    # ---------- Live packet_callback with flow aggregation ----------

    def packet_callback(self, packet):
        """
        Called per captured packet: update/create Flow, expire idle or closed flows,
        aggregate features for expired flows, predict, and alert if anomaly.
        """
        try:
            if not packet or not packet.haslayer(IP):
                return
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if src_ip in self.trusted_hosts or dst_ip in self.trusted_hosts:
                return
            now = time.time()
            key = self._get_flow_key(packet)
            flow = self.active_flows.get(key)
            if flow is None:
                # new flow
                if packet.haslayer(TCP):
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                elif packet.haslayer(UDP):
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                else:
                    sport = 0
                    dport = 0
                flow = Flow(src_ip=src_ip, src_port=sport,
                            dst_ip=dst_ip, dst_port=dport,
                            protocol=packet[IP].proto,
                            first_pkt_time=now)
                self.active_flows[key] = flow
            # update flow with this packet
            flow.update(packet, now)
            # If TCP FIN or RST: expire immediately
            if packet.haslayer(TCP) and any(f in packet[TCP].flags for f in ['F','R']):
                expired = self.active_flows.pop(key, None)
                if expired:
                    feats = expired.aggregate_features()
                    code = self.predict(feats)
                    if code == 1:
                        self.alert_flow(expired, feats)
            # Expire idle flows
            expired_keys = []
            for fkey, fobj in self.active_flows.items():
                if fobj.is_expired(now, timeout=self.flow_timeout):
                    expired_keys.append(fkey)
            for fkey in expired_keys:
                fobj = self.active_flows.pop(fkey)
                feats = fobj.aggregate_features()
                code = self.predict(feats)
                if code == 1:
                    self.alert_flow(fobj, feats)
        except Exception as e:
            print(f"[!] Error in packet_callback: {e}")

    def alert_flow(self, flow, features: dict):
        """
        Handle anomaly on a completed flow.
        Logs to console and file nids_alerts.log under model_path.
        """
        src = flow.src_ip
        dst = flow.dst_ip
        msg = (
            f"Potential attack detected on flow {src}:{flow.src_port} -> {dst}:{flow.dst_port}\n"
            f"Features: {features}\n"
        )
        print(msg)
        try:
            with open(os.path.join(self.model_path, "nids_alerts.log"), "a") as log_file:
                log_file.write(msg + "\n")
        except Exception:
            pass

    # ---------- Start live sniffing ----------

    def start_monitoring(self, interface=None, bpf_filter="ip"):
        """
        Begin sniffing packets on given interface in a separate thread.
        Each packet is passed to packet_callback for aggregation.
        """
        def _sniff_loop():
            while True:
                # sniff in 1-second chunks so stop can be handled externally if needed
                sniff(iface=interface, filter=bpf_filter,
                      prn=self.packet_callback, store=False, timeout=1)
        t = threading.Thread(target=_sniff_loop, daemon=True)
        t.start()
        print(f"[+] Started sniffing on interface {interface or 'any'}")

# ---------- CLI entry point ----------

def main():
    parser = argparse.ArgumentParser(description="datasetv2.py with flow aggregation")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Train: expects CSV of aggregated flows matching feature_columns + 'Label'
    p_train = subparsers.add_parser('train', help='Train model from CSV')
    p_train.add_argument('--csv', required=True, help='Path to training CSV file')
    p_train.add_argument('--model-path', default='trained_model', help='Directory to save model')

    # Predict: supply aggregated feature values as key=value
    p_predict = subparsers.add_parser('predict', help='Predict from one aggregated feature set')
    p_predict.add_argument('--model-path', default='trained_model', help='Directory to load model')
    p_predict.add_argument('--features', nargs='+', help='Feature inputs as key=value')

    # Monitor: live monitoring with flow aggregation
    p_mon = subparsers.add_parser('monitor', help='Start live monitoring')
    p_mon.add_argument('--model-path', default='trained_model', help='Directory to load model')
    p_mon.add_argument('--interface', help='Interface to sniff on (e.g. eth0 or loopback)')
    p_mon.add_argument('--filter', default="ip", help='BPF filter (default "ip")')

    args = parser.parse_args()
    if args.command == 'train':
        h = MLHIDS(model_path=args.model_path)
        h.train(args.csv)
    elif args.command == 'predict':
        h = MLHIDS(model_path=args.model_path)
        if not h.load_model():
            return
        feat = {}
        for kv in args.features or []:
            if '=' not in kv:
                continue
            k, v = kv.split('=',1)
            try:
                v_parsed = float(v)
            except:
                v_parsed = v
            feat[k] = v_parsed
        code = h.predict(feat)
        print(f"Prediction code={code}")
    elif args.command == 'monitor':
        h = MLHIDS(model_path=args.model_path)
        if not h.load_model():
            return
        print(f"[+] Starting live monitoring on interface {args.interface} ...")
        h.start_monitoring(interface=args.interface, bpf_filter=args.filter)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[+] Monitoring stopped by user.")

if __name__ == "__main__":
    main()
