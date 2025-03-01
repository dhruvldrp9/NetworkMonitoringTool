import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import logging
from typing import List, Dict, Any
from collections import deque
import time

logger = logging.getLogger(__name__)

class MLAnalyzer:
    def __init__(self, window_size: int = 1000, contamination: float = 0.1):
        """Initialize ML-based analyzer with Isolation Forest"""
        self.window_size = window_size
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42
        )
        
        # Store recent packets for training
        self.packet_history = deque(maxlen=window_size)
        self.feature_history = deque(maxlen=window_size)
        
        # Training parameters
        self.last_training_time = 0
        self.training_interval = 300  # Train every 5 minutes
        self.min_samples_for_training = 100
        
        # Initialize baseline statistics
        self.baseline_stats = {
            'bytes_per_second': [],
            'packets_per_second': [],
            'unique_ips_per_minute': set(),
            'protocol_distribution': {}
        }

    def extract_features(self, packet_info: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from packet information"""
        features = [
            packet_info['length'],  # Packet size
            hash(packet_info['src_ip']) % 1000,  # Source IP hash
            hash(packet_info['dst_ip']) % 1000,  # Destination IP hash
            hash(packet_info['protocol']) % 100,  # Protocol hash
        ]
        
        # Add protocol-specific features
        if packet_info['protocol'] == 'TCP':
            features.extend([
                packet_info['details']['src_port'],
                packet_info['details']['dst_port'],
                int(packet_info['details']['flags']['SYN']),
                int(packet_info['details']['flags']['ACK']),
                int(packet_info['details']['flags']['FIN']),
                int(packet_info['details']['flags']['RST'])
            ])
        elif packet_info['protocol'] == 'UDP':
            features.extend([
                packet_info['details']['src_port'],
                packet_info['details']['dst_port'],
                0, 0, 0, 0  # Padding for consistent feature vector length
            ])
        else:
            features.extend([0, 0, 0, 0, 0, 0])  # Padding for other protocols
            
        return np.array(features, dtype=float)

    def update_baseline(self, packet_info: Dict[str, Any]):
        """Update baseline statistics"""
        current_time = time.time()
        
        # Update bytes per second
        self.baseline_stats['bytes_per_second'].append(packet_info['length'])
        if len(self.baseline_stats['bytes_per_second']) > 60:
            self.baseline_stats['bytes_per_second'].pop(0)
            
        # Update unique IPs
        self.baseline_stats['unique_ips_per_minute'].add(packet_info['src_ip'])
        self.baseline_stats['unique_ips_per_minute'].add(packet_info['dst_ip'])
        
        # Update protocol distribution
        proto = packet_info['protocol']
        self.baseline_stats['protocol_distribution'][proto] = \
            self.baseline_stats['protocol_distribution'].get(proto, 0) + 1

    def detect_anomalies(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies using ML and statistical analysis"""
        anomalies = []
        
        # Extract features and update history
        features = self.extract_features(packet_info)
        self.packet_history.append(packet_info)
        self.feature_history.append(features)
        self.update_baseline(packet_info)
        
        # Check if we need to retrain the model
        current_time = time.time()
        if (current_time - self.last_training_time > self.training_interval and 
            len(self.feature_history) >= self.min_samples_for_training):
            self._train_model()
            self.last_training_time = current_time
        
        # If model is trained, predict anomalies
        if len(self.feature_history) >= self.min_samples_for_training:
            # Prepare features for prediction
            X = np.array(list(self.feature_history))
            X_scaled = self.scaler.transform(X)
            
            # Get prediction for the latest packet
            prediction = self.isolation_forest.predict(X_scaled[-1:])
            
            if prediction[0] == -1:  # Anomaly detected
                anomalies.append({
                    'type': 'ML_ANOMALY',
                    'source': packet_info['src_ip'],
                    'details': 'Machine learning model detected anomalous traffic pattern',
                    'severity': 'medium',
                    'category': 'anomaly',
                    'confidence': self._calculate_anomaly_confidence(X_scaled[-1])
                })
        
        # Statistical anomaly detection
        stat_anomalies = self._detect_statistical_anomalies(packet_info)
        if stat_anomalies:
            anomalies.extend(stat_anomalies)
            
        return anomalies

    def _train_model(self):
        """Train the Isolation Forest model"""
        logger.info("Training ML model with %d samples", len(self.feature_history))
        try:
            X = np.array(list(self.feature_history))
            X_scaled = self.scaler.fit_transform(X)
            self.isolation_forest.fit(X_scaled)
            logger.info("ML model training completed successfully")
        except Exception as e:
            logger.error("Error training ML model: %s", str(e))

    def _calculate_anomaly_confidence(self, features: np.ndarray) -> float:
        """Calculate confidence score for anomaly detection"""
        score = self.isolation_forest.score_samples(features.reshape(1, -1))[0]
        # Convert score to probability-like value between 0 and 1
        confidence = 1 - (score + 0.5)  # Scores are typically between -0.5 and 0.5
        return min(max(confidence, 0), 1)  # Clamp between 0 and 1

    def _detect_statistical_anomalies(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies using statistical analysis"""
        anomalies = []
        
        # Calculate current statistics
        current_bytes_per_sec = np.mean(self.baseline_stats['bytes_per_second'])
        current_unique_ips = len(self.baseline_stats['unique_ips_per_minute'])
        
        # Check for sudden spikes in traffic volume
        if len(self.baseline_stats['bytes_per_second']) > 30:
            baseline_mean = np.mean(self.baseline_stats['bytes_per_second'][:-1])
            baseline_std = np.std(self.baseline_stats['bytes_per_second'][:-1])
            
            if current_bytes_per_sec > baseline_mean + (3 * baseline_std):
                anomalies.append({
                    'type': 'TRAFFIC_SPIKE',
                    'source': packet_info['src_ip'],
                    'details': f'Sudden increase in traffic volume detected: {current_bytes_per_sec:.2f} bytes/sec',
                    'severity': 'medium',
                    'category': 'anomaly'
                })
        
        # Check for unusual number of unique IPs
        if current_unique_ips > 100:  # Threshold for unique IPs per minute
            anomalies.append({
                'type': 'UNIQUE_IP_SURGE',
                'source': packet_info['src_ip'],
                'details': f'Unusual number of unique IPs detected: {current_unique_ips}',
                'severity': 'medium',
                'category': 'anomaly'
            })
            
        return anomalies
