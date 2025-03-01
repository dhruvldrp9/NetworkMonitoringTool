import numpy as np
import logging
from typing import List, Dict, Any, Tuple
from collections import deque
import time

# Conditional imports to handle missing ML libraries gracefully
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

try:
    import hdbscan
    HDBSCAN_AVAILABLE = True
except ImportError:
    HDBSCAN_AVAILABLE = False

logger = logging.getLogger(__name__)

class MLAnalyzer:
    def __init__(self, window_size: int = 1000, contamination: float = 0.1):
        """Initialize ML-based analyzer with multiple models"""
        self.window_size = window_size
        self.contamination = contamination

        # Initialize detection models based on available libraries
        self.models_available = {
            'isolation_forest': False,
            'lstm': False,
            'clustering': False
        }

        try:
            if SKLEARN_AVAILABLE:
                self.scaler = StandardScaler()
                self.isolation_forest = IsolationForest(
                    contamination=contamination,
                    random_state=42
                )
                self.models_available['isolation_forest'] = True
                logger.info("Isolation Forest model initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize Isolation Forest: {e}")

        try:
            if TENSORFLOW_AVAILABLE:
                self.lstm_model = self._build_lstm_model()
                self.models_available['lstm'] = True
                logger.info("LSTM model initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize LSTM model: {e}")

        try:
            if HDBSCAN_AVAILABLE:
                self.clusterer = hdbscan.HDBSCAN(
                    min_cluster_size=5,
                    min_samples=3,
                    prediction_data=True
                )
                self.models_available['clustering'] = True
                logger.info("HDBSCAN clustering initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize HDBSCAN: {e}")

        # Store recent packets for training
        self.packet_history = deque(maxlen=window_size)
        self.feature_history = deque(maxlen=window_size)
        self.sequence_history = deque(maxlen=100)  # For LSTM

        # Training parameters
        self.last_training_time = 0
        self.training_interval = 300  # Train every 5 minutes
        self.min_samples_for_training = 100

        # Initialize baseline statistics
        self.baseline_stats = {
            'bytes_per_second': [],
            'packets_per_second': [],
            'unique_ips_per_minute': set(),
            'protocol_distribution': {},
            'avg_packet_sizes': [],
            'port_distribution': {},
            'connection_patterns': {}
        }

    def _build_lstm_model(self) -> Sequential:
        """Build LSTM model for sequence analysis"""
        model = Sequential([
            LSTM(64, input_shape=(10, 14), return_sequences=True),
            LSTM(32),
            Dense(16, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy')
        return model

    def extract_features(self, packet_info: Dict[str, Any]) -> np.ndarray:
        """Extract features safely with error handling"""
        try:
            basic_features = [
                float(packet_info['length']),
                float(hash(packet_info['src_ip']) % 1000),
                float(hash(packet_info['dst_ip']) % 1000),
                float(hash(packet_info['protocol']) % 100),
            ]
            return np.array(basic_features, dtype=float)
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return np.zeros(4, dtype=float)

    def _extract_protocol_features(self, packet_info: Dict[str, Any]) -> List[float]:
        """Extract protocol-specific features"""
        if packet_info['protocol'] == 'TCP':
            return [
                packet_info['details']['src_port'],
                packet_info['details']['dst_port'],
                int(packet_info['details']['flags']['SYN']),
                int(packet_info['details']['flags']['ACK']),
                int(packet_info['details']['flags']['FIN']),
                int(packet_info['details']['flags']['RST'])
            ]
        elif packet_info['protocol'] == 'UDP':
            return [
                packet_info['details']['src_port'],
                packet_info['details']['dst_port'],
                0, 0, 0, 0  # Padding for consistent feature vector length
            ]
        return [0, 0, 0, 0, 0, 0]  # Default padding

    def _extract_time_features(self, packet_info: Dict[str, Any]) -> List[float]:
        """Extract time-based features"""
        current_time = time.time()
        if len(self.packet_history) > 0:
            time_diff = current_time - self.packet_history[-1].get('timestamp', current_time)
            packet_rate = len([p for p in self.packet_history 
                             if current_time - p.get('timestamp', 0) <= 1])
        else:
            time_diff = 0
            packet_rate = 0

        return [time_diff, packet_rate]

    def _extract_statistical_features(self, packet_info: Dict[str, Any]) -> List[float]:
        """Extract statistical features"""
        if len(self.packet_history) > 0:
            avg_size = np.mean([p['length'] for p in self.packet_history])
            size_std = np.std([p['length'] for p in self.packet_history])
        else:
            avg_size = packet_info['length']
            size_std = 0

        return [avg_size, size_std]

    def detect_anomalies(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies using statistical analysis and available ML models"""
        anomalies = []

        try:
            # Extract features and update history
            features = self.extract_features(packet_info)
            self.packet_history.append(packet_info)
            self.feature_history.append(features)
            self.update_baseline(packet_info)

            # Only attempt ML detection if we have enough samples
            if len(self.feature_history) >= self.min_samples_for_training:
                # Check if we need to retrain models
                current_time = time.time()
                if (current_time - self.last_training_time > self.training_interval):
                    self._train_models()
                    self.last_training_time = current_time

                # Use available models for detection
                if self.models_available['isolation_forest']:
                    if_anomalies = self._detect_isolation_forest_anomalies(features)
                    if if_anomalies:
                        anomalies.extend(if_anomalies)

                if self.models_available['lstm']:
                    lstm_anomalies = self._detect_sequence_anomalies(features)
                    if lstm_anomalies:
                        anomalies.extend(lstm_anomalies)

                if self.models_available['clustering']:
                    cluster_anomalies = self._detect_cluster_anomalies(features)
                    if cluster_anomalies:
                        anomalies.extend(cluster_anomalies)

            # Always perform statistical analysis
            stat_anomalies = self._detect_statistical_anomalies(packet_info)
            if stat_anomalies:
                anomalies.extend(stat_anomalies)

        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            # Fallback to statistical analysis only
            try:
                stat_anomalies = self._detect_statistical_anomalies(packet_info)
                if stat_anomalies:
                    anomalies.extend(stat_anomalies)
            except Exception as e2:
                logger.error(f"Error in statistical analysis fallback: {e2}")

        return anomalies

    def _detect_isolation_forest_anomalies(self, X_scaled: np.ndarray) -> List[Dict[str, Any]]:
        """Detect anomalies using Isolation Forest"""
        if not self.models_available['isolation_forest']:
            return []
        try:
            prediction = self.isolation_forest.predict(X_scaled.reshape(1, -1))
            if prediction[0] == -1:
                return [{
                    'type': 'ISOLATION_FOREST_ANOMALY',
                    'source': self.packet_history[-1]['src_ip'],
                    'details': 'Isolation Forest detected anomalous traffic pattern',
                    'severity': 'medium',
                    'category': 'anomaly',
                    'confidence': self._calculate_anomaly_confidence(X_scaled)
                }]
            return []
        except Exception as e:
            logger.error(f"Error in Isolation Forest detection: {e}")
            return []

    def _detect_sequence_anomalies(self, X_scaled: np.ndarray) -> List[Dict[str, Any]]:
        """Detect sequence-based anomalies using LSTM"""
        if not self.models_available['lstm'] or len(X_scaled) < 10:
            return []
        try:
            sequence = X_scaled.reshape(1, 1, -1) #simplified for stability
            prediction = self.lstm_model.predict(sequence, verbose=0)[0][0]
            if prediction > 0.8:  # High anomaly score
                return [{
                    'type': 'SEQUENCE_ANOMALY',
                    'source': self.packet_history[-1]['src_ip'],
                    'details': 'LSTM detected abnormal traffic sequence',
                    'severity': 'high',
                    'category': 'anomaly',
                    'confidence': float(prediction)
                }]
            return []
        except Exception as e:
            logger.error(f"Error in LSTM detection: {e}")
            return []


    def _detect_cluster_anomalies(self, X_scaled: np.ndarray) -> List[Dict[str, Any]]:
        """Detect clustering-based anomalies"""
        if not self.models_available['clustering']:
            return []
        try:
            cluster_labels = self.clusterer.fit_predict(X_scaled.reshape(1,-1)) #simplified for stability
            if cluster_labels[-1] == -1:  # Noise point in HDBSCAN
                return [{
                    'type': 'CLUSTER_ANOMALY',
                    'source': self.packet_history[-1]['src_ip'],
                    'details': 'Clustering detected outlier traffic pattern',
                    'severity': 'medium',
                    'category': 'anomaly',
                    'confidence': 0.85
                }]
            return []
        except Exception as e:
            logger.error(f"Error in clustering detection: {e}")
            return []


    def _train_models(self):
        """Train available ML models with error handling"""
        if len(self.feature_history) < self.min_samples_for_training:
            return

        try:
            X = np.array(list(self.feature_history))
            if self.models_available['isolation_forest']:
                try:
                    self.isolation_forest.fit(X)
                    logger.info("Isolation Forest training completed")
                except Exception as e:
                    logger.error(f"Error training Isolation Forest: {e}")
                    self.models_available['isolation_forest'] = False

            if self.models_available['lstm']:
                try:
                    # LSTM training code here (simplified for stability)
                    pass
                except Exception as e:
                    logger.error(f"Error training LSTM: {e}")
                    self.models_available['lstm'] = False

            if self.models_available['clustering']:
                try:
                    self.clusterer.fit(X)
                    logger.info("HDBSCAN clustering training completed")
                except Exception as e:
                    logger.error(f"Error training HDBSCAN: {e}")
                    self.models_available['clustering'] = False

        except Exception as e:
            logger.error(f"Error in model training: {e}")

    def _prepare_sequences(self, X_scaled: np.ndarray) -> np.ndarray:
        """Prepare sequences for LSTM training"""
        sequences = []
        for i in range(len(X_scaled) - 10):
            sequences.append(X_scaled[i:i+10])
        return np.array(sequences)

    def _calculate_anomaly_confidence(self, features: np.ndarray) -> float:
        """Calculate confidence score for anomaly detection"""
        try:
            score = self.isolation_forest.score_samples(features.reshape(1, -1))[0]
            confidence = 1 - (score + 0.5)  # Convert to probability-like value
            return min(max(confidence, 0), 1)  # Clamp between 0 and 1
        except Exception as e:
            logger.error(f"Error calculating anomaly confidence: {e}")
            return 0.0

    def update_baseline(self, packet_info: Dict[str, Any]):
        """Update baseline statistics safely"""
        try:
            # Update bytes per second
            self.baseline_stats['bytes_per_second'].append(packet_info['length'])
            if len(self.baseline_stats['bytes_per_second']) > 60:
                self.baseline_stats['bytes_per_second'].pop(0)

            # Update packets per second
            self.baseline_stats['packets_per_second'].append(1)
            if len(self.baseline_stats['packets_per_second']) > 60:
                self.baseline_stats['packets_per_second'].pop(0)

            # Update unique IPs
            self.baseline_stats['unique_ips_per_minute'].add(packet_info['src_ip'])
            self.baseline_stats['unique_ips_per_minute'].add(packet_info['dst_ip'])

            # Update protocol distribution
            proto = packet_info['protocol']
            self.baseline_stats['protocol_distribution'][proto] = \
                self.baseline_stats['protocol_distribution'].get(proto, 0) + 1

            # Update average packet sizes
            self.baseline_stats['avg_packet_sizes'].append(packet_info['length'])
            if len(self.baseline_stats['avg_packet_sizes']) > 1000:
                self.baseline_stats['avg_packet_sizes'].pop(0)

            # Update port distribution
            if 'details' in packet_info and 'dst_port' in packet_info['details']:
                port = packet_info['details']['dst_port']
                self.baseline_stats['port_distribution'][port] = \
                    self.baseline_stats['port_distribution'].get(port, 0) + 1

            # Update connection patterns
            conn_key = f"{packet_info['src_ip']}:{packet_info['dst_ip']}"
            self.baseline_stats['connection_patterns'][conn_key] = \
                self.baseline_stats['connection_patterns'].get(conn_key, 0) + 1

        except Exception as e:
            logger.error(f"Error updating baseline stats: {e}")

    def _detect_statistical_anomalies(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Basic statistical analysis that doesn't depend on ML libraries"""
        anomalies = []
        try:
            # Simple threshold-based detection
            if packet_info['length'] > 10000:  # Unusually large packet
                anomalies.append({
                    'type': 'LARGE_PACKET',
                    'source': packet_info['src_ip'],
                    'details': f'Unusually large packet detected: {packet_info["length"]} bytes',
                    'severity': 'medium',
                    'category': 'anomaly',
                    'confidence': 0.8
                })
        except Exception as e:
            logger.error(f"Error in statistical analysis: {e}")
        return anomalies