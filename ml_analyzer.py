import numpy as np
import logging
from typing import List, Dict, Any
from collections import deque
import time
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

logger = logging.getLogger(__name__)

class MLAnalyzer:
    def __init__(self, window_size: int = 1000):
        """Initialize analyzer with ML and statistical detection"""
        self.window_size = window_size
        self.packet_history = deque(maxlen=window_size)

        # Initialize baseline statistics
        self.baseline_stats = {
            'bytes_per_second': [],
            'packets_per_second': [],
            'unique_ips': set(),
            'protocol_counts': {},
            'port_counts': {},
            'packet_sizes': []
        }

        # ML components
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,
            random_state=42
        )
        self.model_trained = False
        self.min_samples_for_training = 100

        # Load existing model if available
        self._load_model()

    def detect_anomalies(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies using ML and statistical analysis"""
        try:
            # Update packet history and stats
            self.packet_history.append(packet_info)
            self._update_stats(packet_info)

            # Extract features
            features = self.extract_features(packet_info)

            # Train model if enough data is collected
            if (len(self.packet_history) >= self.min_samples_for_training and 
                not self.model_trained):
                self._train_model()

            anomalies = []

            # ML-based detection if model is trained
            if self.model_trained:
                try:
                    # Scale features
                    scaled_features = self.scaler.transform(features.reshape(1, -1))
                    # Predict (-1 for anomaly, 1 for normal)
                    prediction = self.model.predict(scaled_features)

                    if prediction[0] == -1:  # Anomaly detected
                        score = self.model.score_samples(scaled_features)
                        confidence = 1 - (score[0] + 0.5)  # Convert to 0-1 scale

                        anomalies.append({
                            'type': 'ML_ANOMALY',
                            'source': packet_info['src_ip'],
                            'details': 'Machine Learning detected unusual pattern',
                            'confidence': float(confidence),
                            'severity': 'high' if confidence > 0.8 else 'medium',
                            'category': 'anomaly'
                        })
                except Exception as e:
                    logger.error(f"Error in ML prediction: {e}")
                    # Fall back to statistical analysis
                    anomalies.extend(self._statistical_analysis(packet_info))
            else:
                # Use statistical analysis until model is trained
                anomalies.extend(self._statistical_analysis(packet_info))

            return anomalies

        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return []

    def _statistical_analysis(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fallback statistical analysis"""
        anomalies = []
        anomalies.extend(self._check_packet_size_anomalies(packet_info))
        anomalies.extend(self._check_rate_anomalies(packet_info))
        anomalies.extend(self._check_protocol_anomalies(packet_info))
        return anomalies

    def _train_model(self):
        """Train the ML model on collected data"""
        try:
            # Extract features from historical data
            feature_matrix = np.array([
                self.extract_features(packet)
                for packet in self.packet_history
            ])

            # Fit scaler
            self.scaler.fit(feature_matrix)
            scaled_features = self.scaler.transform(feature_matrix)

            # Train model
            self.model.fit(scaled_features)
            self.model_trained = True

            # Save model
            self._save_model()

            logger.info("ML model successfully trained")
        except Exception as e:
            logger.error(f"Error training ML model: {e}")

    def extract_features(self, packet_info: Dict[str, Any]) -> np.ndarray:
        """Extract features for ML analysis"""
        features = [
            packet_info['length'],  # Packet size
            hash(packet_info['src_ip']) % 1000,  # Source IP hash
            hash(packet_info['dst_ip']) % 1000,  # Destination IP hash
            hash(packet_info['protocol']) % 100,  # Protocol hash
            len(self.baseline_stats['unique_ips']),  # Number of unique IPs
            len(self.baseline_stats['protocol_counts']),  # Number of protocols
            sum(self.baseline_stats['packets_per_second'][-10:]) / 10 if self.baseline_stats['packets_per_second'] else 0,  # Recent packet rate
            np.mean(self.baseline_stats['packet_sizes']) if self.baseline_stats['packet_sizes'] else 0  # Average packet size
        ]
        return np.array(features, dtype=float)

    def _save_model(self):
        """Save ML model and scaler"""
        try:
            if not os.path.exists('models'):
                os.makedirs('models')
            joblib.dump(self.model, 'models/anomaly_detector.joblib')
            joblib.dump(self.scaler, 'models/scaler.joblib')
        except Exception as e:
            logger.error(f"Error saving model: {e}")

    def _load_model(self):
        """Load existing ML model and scaler"""
        try:
            if os.path.exists('models/anomaly_detector.joblib'):
                self.model = joblib.load('models/anomaly_detector.joblib')
                self.scaler = joblib.load('models/scaler.joblib')
                self.model_trained = True
                logger.info("Loaded existing ML model")
        except Exception as e:
            logger.error(f"Error loading model: {e}")

    def _update_stats(self, packet_info: Dict[str, Any]) -> None:
        """Update statistical baselines"""
        try:
            # Update packet sizes
            self.baseline_stats['packet_sizes'].append(packet_info['length'])
            if len(self.baseline_stats['packet_sizes']) > self.window_size:
                self.baseline_stats['packet_sizes'].pop(0)

            # Update protocol counts
            proto = packet_info['protocol']
            self.baseline_stats['protocol_counts'][proto] = \
                self.baseline_stats['protocol_counts'].get(proto, 0) + 1

            # Update unique IPs
            self.baseline_stats['unique_ips'].add(packet_info['src_ip'])
            self.baseline_stats['unique_ips'].add(packet_info['dst_ip'])

            # Update port information
            if 'details' in packet_info and 'dst_port' in packet_info['details']:
                port = packet_info['details']['dst_port']
                self.baseline_stats['port_counts'][port] = \
                    self.baseline_stats['port_counts'].get(port, 0) + 1

        except Exception as e:
            logger.error(f"Error updating stats: {e}")

    def _check_packet_size_anomalies(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for unusually large packets"""
        try:
            if packet_info['length'] > 10000:  # Unusually large packet threshold
                return [{
                    'type': 'LARGE_PACKET',
                    'source': packet_info['src_ip'],
                    'details': f'Unusually large packet: {packet_info["length"]} bytes',
                    'confidence': 0.9,
                    'severity': 'medium',
                    'category': 'anomaly'
                }]
        except Exception as e:
            logger.error(f"Error checking packet sizes: {e}")
        return []

    def _check_rate_anomalies(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for abnormal packet rates"""
        try:
            recent_packets = list(self.packet_history)[-10:]
            src_ip = packet_info['src_ip']
            src_count = sum(1 for p in recent_packets if p['src_ip'] == src_ip)

            if src_count > 8:  # More than 8 packets in last 10
                return [{
                    'type': 'HIGH_RATE',
                    'source': src_ip,
                    'details': 'High packet rate from source',
                    'confidence': 0.8,
                    'severity': 'medium',
                    'category': 'anomaly'
                }]
        except Exception as e:
            logger.error(f"Error checking rates: {e}")
        return []

    def _check_protocol_anomalies(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for unusual protocols"""
        try:
            protocol = packet_info['protocol']
            if protocol not in ['TCP', 'UDP', 'ICMP', 'ARP']:
                return [{
                    'type': 'UNUSUAL_PROTOCOL',
                    'source': packet_info['src_ip'],
                    'details': f'Unusual protocol detected: {protocol}',
                    'confidence': 0.7,
                    'severity': 'low',
                    'category': 'anomaly'
                }]
        except Exception as e:
            logger.error(f"Error checking protocols: {e}")
        return []

    def get_baseline_stats(self):
        """Return current baseline statistics"""
        return self.baseline_stats