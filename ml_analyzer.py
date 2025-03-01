import numpy as np
import logging
from typing import List, Dict, Any
from collections import deque
import time

logger = logging.getLogger(__name__)

class MLAnalyzer:
    def __init__(self, window_size: int = 1000):
        """Initialize analyzer with statistical detection"""
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

    def detect_anomalies(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies using simple statistical analysis"""
        try:
            # Update packet history and stats
            self.packet_history.append(packet_info)
            self._update_stats(packet_info)

            # Run anomaly checks
            anomalies = []
            anomalies.extend(self._check_packet_size_anomalies(packet_info))
            anomalies.extend(self._check_rate_anomalies(packet_info))
            anomalies.extend(self._check_protocol_anomalies(packet_info))
            return anomalies

        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return []

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
            # Count packets from same source in recent history
            recent_packets = list(self.packet_history)[-10:]  # Last 10 packets
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

    def extract_features(self, packet_info: Dict[str, Any]) -> np.ndarray:
        """Extract basic statistical features for analysis"""
        return np.array([
            packet_info['length'],
            hash(packet_info['src_ip']) % 1000,
            hash(packet_info['dst_ip']) % 1000,
            hash(packet_info['protocol']) % 100
        ], dtype=float)

    def get_baseline_stats(self):
        """Return current baseline statistics"""
        return self.baseline_stats