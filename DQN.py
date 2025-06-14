import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from collections import deque
import random
from scapy.all import sniff, IP, TCP
import pandas as pd
from sklearn.preprocessing import StandardScaler
import time
import joblib  # Add to imports
class DQNNetwork(nn.Module):
    """Deep Q-Network for IDS decision making"""
    
    def __init__(self, input_size, hidden_size=256, output_size=3):
        super(DQNNetwork, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_size // 2, hidden_size // 4),
            nn.ReLU(),
            nn.Linear(hidden_size // 4, output_size)
        )
    
    def forward(self, x):
        return self.network(x)

class ReplayBuffer:
    """Experience replay buffer for DQN training"""
    
    def __init__(self, capacity=100000):
        self.buffer = deque(maxlen=capacity)
    
    def push(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))
    
    def sample(self, batch_size):
        batch = random.sample(self.buffer, batch_size)
        state, action, reward, next_state, done = map(np.stack, zip(*batch))
        return state, action, reward, next_state, done
    
    def __len__(self):
        return len(self.buffer)

class RLIDS:
    """Reinforcement Learning based Intrusion Detection System"""
    
    def __init__(self, feature_size=28, learning_rate=0.001, 
                 epsilon=1.0, epsilon_decay=0.995, epsilon_min=0.01):
        
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.feature_size = feature_size
        
        # Actions: 0=Allow, 1=Block, 2=Monitor_Closely
        self.action_size = 3
        
        # DQN Networks
        self.q_network = DQNNetwork(feature_size, output_size=self.action_size).to(self.device)
        self.target_network = DQNNetwork(feature_size, output_size=self.action_size).to(self.device)
        self.optimizer = optim.Adam(self.q_network.parameters(), lr=learning_rate)
        
        # RL Parameters
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.gamma = 0.95  # Discount factor
        self.batch_size = 32
        self.update_target_freq = 1000
        self.steps = 0
        
        # Experience Replay
        self.memory = ReplayBuffer()
        
        # Feature preprocessing
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Network flow tracking
        self.flow_states = {}
        self.flow_history = deque(maxlen=10000)
        
        # Reward system parameters
        self.threat_weights = {
            'dos': 10.0,
            'probe': 5.0,
            'r2l': 8.0,
            'u2r': 9.0,
            'normal': -1.0
        }
        
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
    
    def extract_features(self, packet):
        """Extract features from network packet - aligned with original feature columns"""
        features = {}
        
        # Extract features in the exact order of self.feature_columns
        for feature_name in self.feature_columns:
            if feature_name == 'IN_BYTES':
                features[feature_name] = len(packet) if hasattr(packet, 'src') else 0
            elif feature_name == 'IN_PKTS':
                features[feature_name] = 1
            elif feature_name == 'OUT_BYTES':
                features[feature_name] = len(packet) if hasattr(packet, 'dst') else 0
            elif feature_name == 'OUT_PKTS':
                features[feature_name] = 1
            elif feature_name == 'FLOW_DURATION_MILLISECONDS':
                features[feature_name] = 0
            elif feature_name == 'DURATION_IN':
                features[feature_name] = 0
            elif feature_name == 'DURATION_OUT':
                features[feature_name] = 0
            elif feature_name == 'MIN_TTL':
                features[feature_name] = packet[IP].ttl if IP in packet else 0
            elif feature_name == 'MAX_TTL':
                features[feature_name] = packet[IP].ttl if IP in packet else 0
            elif feature_name == 'LONGEST_FLOW_PKT':
                features[feature_name] = len(packet)
            elif feature_name == 'SHORTEST_FLOW_PKT':
                features[feature_name] = len(packet)
            elif feature_name == 'MIN_IP_PKT_LEN':
                features[feature_name] = len(packet)
            elif feature_name == 'MAX_IP_PKT_LEN':
                features[feature_name] = len(packet)
            elif feature_name == 'SRC_TO_DST_SECOND_BYTES':
                features[feature_name] = len(packet) if hasattr(packet, 'src') else 0
            elif feature_name == 'DST_TO_SRC_SECOND_BYTES':
                features[feature_name] = len(packet) if hasattr(packet, 'dst') else 0
            elif feature_name == 'RETRANSMITTED_IN_BYTES':
                features[feature_name] = 0
            elif feature_name == 'RETRANSMITTED_IN_PKTS':
                features[feature_name] = 0
            elif feature_name == 'RETRANSMITTED_OUT_BYTES':
                features[feature_name] = 0
            elif feature_name == 'RETRANSMITTED_OUT_PKTS':
                features[feature_name] = 0
            elif feature_name == 'SRC_TO_DST_AVG_THROUGHPUT':
                features[feature_name] = 0
            elif feature_name == 'DST_TO_SRC_AVG_THROUGHPUT':
                features[feature_name] = 0
            elif feature_name == 'NUM_PKTS_UP_TO_128_BYTES':
                features[feature_name] = 1 if len(packet) <= 128 else 0
            elif feature_name == 'NUM_PKTS_128_TO_256_BYTES':
                features[feature_name] = 1 if 128 < len(packet) <= 256 else 0
            elif feature_name == 'NUM_PKTS_256_TO_512_BYTES':
                features[feature_name] = 1 if 256 < len(packet) <= 512 else 0
            elif feature_name == 'NUM_PKTS_512_TO_1024_BYTES':
                features[feature_name] = 1 if 512 < len(packet) <= 1024 else 0
            elif feature_name == 'NUM_PKTS_1024_TO_1514_BYTES':
                features[feature_name] = 1 if 1024 < len(packet) <= 1514 else 0
            elif feature_name == 'TCP_WIN_MAX_IN':
                features[feature_name] = packet[TCP].window if TCP in packet else 0
            elif feature_name == 'TCP_WIN_MAX_OUT':
                features[feature_name] = packet[TCP].window if TCP in packet else 0
            else:
                features[feature_name] = 0
        
        # Return as ordered array matching feature_columns
        return np.array([features[col] for col in self.feature_columns], dtype=np.float32)
    
    def get_state(self, features):
        """Convert features to state representation"""
        if not self.is_trained:
            return features
        return self.scaler.transform(features.reshape(1, -1)).flatten()
    
    def choose_action(self, state):
        """Choose action using epsilon-greedy policy"""
        if np.random.random() <= self.epsilon:
            return np.random.choice(self.action_size)
        
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        q_values = self.q_network(state_tensor)
        return q_values.cpu().data.numpy().argmax()
    
    def calculate_reward(self, action, actual_threat_level, flow_id):
        """Calculate reward based on action taken and actual threat"""
        base_reward = 0
        
        # Reward for correct classification
        if actual_threat_level == 'normal' and action == 0:  # Allow normal traffic
            base_reward = 1.0
        elif actual_threat_level != 'normal' and action == 1:  # Block malicious traffic
            base_reward = self.threat_weights.get(actual_threat_level, 5.0)
        elif actual_threat_level != 'normal' and action == 2:  # Monitor suspicious
            base_reward = self.threat_weights.get(actual_threat_level, 5.0) * 0.7
        else:
            # Penalties for wrong actions
            if actual_threat_level == 'normal' and action == 1:  # False positive
                base_reward = -2.0
            elif actual_threat_level != 'normal' and action == 0:  # False negative
                base_reward = -self.threat_weights.get(actual_threat_level, 5.0)
        
        # Additional rewards for consistency in flow decisions
        if flow_id in self.flow_history:
            consistency_bonus = 0.1 if action == self.flow_history[-1] else -0.1
            base_reward += consistency_bonus
        
        return base_reward
    
    def train_step(self):
        """Perform one training step"""
        if len(self.memory) < self.batch_size:
            return
        
        # Sample batch from replay buffer
        states, actions, rewards, next_states, dones = self.memory.sample(self.batch_size)
        
        states = torch.FloatTensor(states).to(self.device)
        actions = torch.LongTensor(actions).to(self.device)
        rewards = torch.FloatTensor(rewards).to(self.device)
        next_states = torch.FloatTensor(next_states).to(self.device)
        dones = torch.BoolTensor(dones).to(self.device)
        
        # Current Q values
        current_q_values = self.q_network(states).gather(1, actions.unsqueeze(1))
        
        # Next Q values from target network
        next_q_values = self.target_network(next_states).max(1)[0].detach()
        target_q_values = rewards + (self.gamma * next_q_values * ~dones)
        
        # Compute loss
        loss = nn.MSELoss()(current_q_values.squeeze(), target_q_values)
        
        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), 1.0)
        self.optimizer.step()
        
        # Update target network
        if self.steps % self.update_target_freq == 0:
            self.target_network.load_state_dict(self.q_network.state_dict())
        
        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
    
    def pretrain_with_dataset(self, dataset_path, epochs=10):
        """Pre-train the model using labeled dataset"""
        print("Pre-training RL model with labeled data...")
        
        # Load and preprocess data
        print(f"Loading dataset from {dataset_path}...")
        data = pd.read_csv(dataset_path)
        print(f"Dataset loaded with shape: {data.shape}")
        
        # Check if all feature columns exist
        missing_cols = [col for col in self.feature_columns if col not in data.columns]
        if missing_cols:
            print(f"Warning: Missing columns in dataset: {missing_cols}")
            # Fill missing columns with zeros
            for col in missing_cols:
                data[col] = 0
        
        features = data[self.feature_columns].values
        labels = data['Label'].values if 'Label' in data.columns else data.iloc[:, -1].values
        
        print(f"Features shape: {features.shape}")
        print(f"Expected feature size: {self.feature_size}")
        
        # Verify feature dimensions match
        if features.shape[1] != self.feature_size:
            print(f"Error: Feature dimension mismatch. Expected {self.feature_size}, got {features.shape[1]}")
            return False
        
        # Handle missing values and infinite values
        features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)
        # Clip extreme outliers per feature using quantiles
        features_df = pd.DataFrame(features, columns=self.feature_columns)
        lower = features_df.quantile(0.001)
        upper = features_df.quantile(0.999)
        features_df = features_df.clip(lower=lower, upper=upper, axis=1)
        features = features_df.values
        
        # Fit scaler
        print("Fitting scaler...")
        self.scaler.fit(features)
        features_scaled = self.scaler.transform(features)
        
        # Convert labels to threat levels for reward calculation
        # Convert labels to threat levels for reward calculation
        label_to_threat = {
            'BENIGN': 'normal',
            'DoS Hulk': 'dos',
            'PortScan': 'probe',
            'DDoS': 'dos',
            'DoS GoldenEye': 'dos',
            'FTP-Patator': 'r2l',
            'SSH-Patator': 'r2l',
            'DoS slowloris': 'dos',
            'DoS Slowhttptest': 'dos',
            'Bot': 'u2r',
            'Web Attack \x96 Brute Force': 'r2l',
            'Web Attack \x96 XSS': 'u2r',
            'Infiltration': 'u2r',
            'Web Attack \x96 Sql Injection': 'u2r',
            'Heartbleed': 'probe'
        }
        # Sample data for training (to avoid memory issues)
        max_samples = min(50000, len(features_scaled))  # Limit training samples
        indices = np.random.choice(len(features_scaled), max_samples, replace=False)
        features_scaled = features_scaled[indices]
        labels = labels[indices]
        
        print(f"Training on {len(features_scaled)} samples...")
        
        for epoch in range(epochs):
            total_reward = 0
            epoch_losses = []
            
            # Shuffle data each epoch
            shuffle_idx = np.random.permutation(len(features_scaled))
            features_shuffled = features_scaled[shuffle_idx]
            labels_shuffled = labels[shuffle_idx]
            
            for i in range(len(features_shuffled)):
                state = features_shuffled[i]
                action = self.choose_action(state)
                
                # Simulate next state (could be improved with sequence modeling)
                next_state = state + np.random.normal(0, 0.01, size=state.shape)
                
                # Calculate reward
                threat_level = label_to_threat.get(str(labels_shuffled[i]).strip(), 'normal')
                reward = self.calculate_reward(action, threat_level, f"flow_{i}")
                total_reward += reward
                
                # Store experience
                self.memory.push(state, action, reward, next_state, False)
                
                # Train every 100 steps
                if i % 100 == 0 and len(self.memory) >= self.batch_size:
                    self.train_step()
                    self.steps += 1
                
                # Progress update
                if i % 5000 == 0 and i > 0:
                    print(f"  Processed {i}/{len(features_shuffled)} samples...")
            
            avg_reward = total_reward / len(features_shuffled)
            print(f"Epoch {epoch+1}/{epochs}, Average Reward: {avg_reward:.3f}, Epsilon: {self.epsilon:.3f}")
        
         # After training loop:
        print("\nEvaluating model performance...")
    
        # Generate predictions for evaluation
        y_true = []
        y_pred = []
        y_scores = []  # For probability scores
        
        # Use a subset for evaluation
        eval_size = min(10000, len(features_scaled))
        eval_indices = np.random.choice(len(features_scaled), eval_size, replace=False)
        
        for i in eval_indices:
            state = features_scaled[i]
            threat_level = label_to_threat.get(str(labels[i]).strip(), 'normal')
            
            # Get Q-values and convert to probabilities
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
                q_values = self.q_network(state_tensor).cpu().numpy()[0]
                probs = np.exp(q_values) / np.sum(np.exp(q_values))
            
            # Choose action
            action = np.argmax(q_values)
            
            y_true.append(1 if threat_level != 'normal' else 0)  # 1=attack, 0=normal
            y_pred.append(1 if action != 0 else 0)  # Action 0=allow (normal)
            y_scores.append(probs[1] + probs[2])  # Probability of attack (action 1 or 2)
        print("y_true distribution:", np.bincount(y_true))
        print("y_pred distribution:", np.bincount(y_pred))
        # Calculate metrics
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, 
            f1_score, confusion_matrix, roc_auc_score, roc_curve
        )
        
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred)
        recall = recall_score(y_true, y_pred)
        f1 = f1_score(y_true, y_pred)
        conf_matrix = confusion_matrix(y_true, y_pred)
        roc_auc = roc_auc_score(y_true, y_scores)
        
        # Calculate false positives/negatives
        if conf_matrix.shape == (2, 2):
            tn, fp, fn, tp = conf_matrix.ravel()
            print(f"False Positives: {fp} ({fp/(fp+tn):.2%})")
            print(f"False Negatives: {fn} ({fn/(fn+tp):.2%})")
        else:
            print("Confusion matrix is not 2x2, cannot unpack tn, fp, fn, tp.")
            print("Confusion matrix:", conf_matrix)
        
        # Plot ROC curve (optional)
        import matplotlib.pyplot as plt
        fpr, tpr, _ = roc_curve(y_true, y_scores)
        plt.figure()
        plt.plot(fpr, tpr, label=f'ROC curve (AUC = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], 'k--')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic')
        plt.legend()
        plt.savefig('roc_curve.png')
        print("ROC curve saved to roc_curve.png")
        
        self.is_trained = True
        print("Pre-training completed!")
        return True
    
    def packet_callback(self, packet):
        """Process each captured packet with RL decision making"""
        if not packet or IP not in packet:
            return
        
        # Extract features
        features = self.extract_features(packet)
        state = self.get_state(features)
        
        # Choose action
        action = self.choose_action(state)
        
        # Create flow ID
        flow_id = f"{packet[IP].src}_{packet[IP].dst}_{getattr(packet[TCP], 'sport', 0)}_{getattr(packet[TCP], 'dport', 0)}"
        
        # Take action
        self.take_action(action, packet, flow_id)
        
        # Store state for potential learning
        self.flow_states[flow_id] = {
            'state': state,
            'action': action,
            'timestamp': time.time(),
            'packet_info': {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'size': len(packet)
            }
        }
    
    def take_action(self, action, packet, flow_id):
        """Execute the chosen action"""
        actions = {
            0: "ALLOW",
            1: "BLOCK", 
            2: "MONITOR"
        }
        
        action_name = actions[action]
        
        if action == 1:  # Block
            self.log_alert(f"BLOCKED: {packet[IP].src} -> {packet[IP].dst}", packet, "HIGH")
        elif action == 2:  # Monitor closely
            self.log_alert(f"MONITORING: {packet[IP].src} -> {packet[IP].dst}", packet, "MEDIUM")
        
        # Log action
        print(f"Action: {action_name} for flow {flow_id}")
    
    def log_alert(self, message, packet, severity):
        """Log security alerts"""
        alert_msg = f"[{severity}] {message} - Size: {len(packet)} bytes"
        print(alert_msg)
        
        with open("rl_ids_alerts.log", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {alert_msg}\n")
    
    def start_monitoring(self, interface="eth0"):
        """Start real-time network monitoring"""
        print(f"Starting RL-IDS monitoring on interface {interface}")
        
        try:
            sniff(iface=interface, prn=self.packet_callback, store=0, filter="ip")
        except Exception as e:
            print(f"Error starting packet capture: {e}")
    
    def save_model(self, path="rl_ids_model.pth"):
        """Save the trained model with scaler parameters"""
        torch.save({
            'q_network_state_dict': self.q_network.state_dict(),
            'target_network_state_dict': self.target_network.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'epsilon': self.epsilon,
            'scaler_mean': self.scaler.mean_,
            'scaler_scale': self.scaler.scale_,
            'feature_columns': self.feature_columns  # Save for verification
        }, path)
        print(f"Model saved to {path}")
    
    def load_model(self, path="rl_ids_model.pth"):
        """Load a trained model with scaler parameters"""
        try:
            checkpoint = torch.load(path,weights_only=False)
            self.q_network.load_state_dict(checkpoint['q_network_state_dict'])
            self.target_network.load_state_dict(checkpoint['target_network_state_dict'])
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
            self.epsilon = checkpoint['epsilon']
            
            # Reconstruct scaler from parameters
            self.scaler = StandardScaler()
            self.scaler.mean_ = checkpoint['scaler_mean']
            self.scaler.scale_ = checkpoint['scaler_scale']
            self.scaler.var_ = self.scaler.scale_**2  # Reconstruct variance
            
            # Verify feature columns match
            if 'feature_columns' in checkpoint:
                if checkpoint['feature_columns'] != self.feature_columns:
                    print("Warning: Feature columns mismatch between model and current configuration")
            
            self.is_trained = True
            print(f"Model loaded from {path}")
            return True
        except FileNotFoundError:
            print(f"No model found at {path}")
            return False

def main():
    # Initialize RL-IDS
    rl_ids = RLIDS()
    
    # Try to load existing model, otherwise pre-train
    if not rl_ids.load_model():
        print("No saved model found. Starting pre-training...")
        dataset_path = r'F:\data\filtered_dataset.csv'
        success = rl_ids.pretrain_with_dataset(dataset_path, epochs=5)
        if success:
            rl_ids.save_model()
        else:
            print("Pretraining failed, model not saved.")
    
    # Start monitoring
    # print("Starting real-time monitoring...")
    # Uncomment the line below to start monitoring
    # rl_ids.start_monitoring(interface="your_interface_name")

if __name__ == "__main__":
    main()