from dataclasses import dataclass
from typing import Dict, Set, DefaultDict, List, TypedDict, Optional
from collections import defaultdict
import logging
import time
import json
import os
from statistics import mean, stdev

logger = logging.getLogger(__name__)

class PacketTracker(TypedDict):
    count: int
    first_seen: float
    last_seen: float
    sizes: List[int]

class SignatureMatch(TypedDict):
    name: str
    description: str
    severity: str
    category: str

class ThreatDetector:
    def __init__(self):
        # Initialize detection thresholds
        self.syn_flood_threshold = 50  # packets per second
        self.port_scan_threshold = 15  # different ports
        self.icmp_flood_threshold = 30  # packets per second
        self.ddos_pps_threshold = 1000  # packets per second
        self.arp_cache_timeout = 300  # seconds

        # Statistical baseline parameters
        self.baseline_window = 300  # 5 minutes
        self.anomaly_std_threshold = 3  # Standard deviations

        # Tracking dictionaries
        self.syn_count: Dict[str, PacketTracker] = {}
        self.port_scan_track: DefaultDict[str, Set[int]] = defaultdict(set)
        self.icmp_count: DefaultDict[str, int] = defaultdict(int)
        self.ddos_track: Dict[str, PacketTracker] = {}
        self.arp_cache: Dict[str, Dict[str, float]] = {}  # IP to MAC mapping with timestamp

        # Load attack signatures
        self.signatures = self._load_signatures()

        # Traffic baseline statistics
        self.baseline_stats = {
            'pps': [],
            'bytes_per_sec': [],
            'packet_sizes': []
        }

        self.last_cleanup = time.time()
        self.cleanup_interval = 60  # seconds

    def _load_signatures(self) -> List[dict]:
        """Load known attack signatures"""
        signatures = [
            {
                "name": "NULL Scan",
                "pattern": {"TCP": {"flags": 0x00}},
                "description": "TCP packet with no flags set",
                "severity": "high",
                "category": "reconnaissance"
            },
            {
                "name": "XMAS Scan",
                "pattern": {"TCP": {"flags": 0x29}},
                "description": "TCP packet with FIN, PSH, URG flags",
                "severity": "high",
                "category": "reconnaissance"
            },
            {
                "name": "SMBBleed",
                "pattern": {"TCP": {"dport": 445}, "payload": b"\x00\x00\x00\x45"},
                "description": "Potential SMB vulnerability exploit",
                "severity": "critical",
                "category": "exploit"
            }
        ]
        return signatures

    def cleanup_old_data(self):
        """Clean up old tracking data"""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            # Cleanup various tracking dictionaries
            for tracker in [self.syn_count, self.ddos_track]:
                for ip in list(tracker.keys()):
                    if current_time - tracker[ip]['last_seen'] > self.cleanup_interval:
                        del tracker[ip]

            # Cleanup ARP cache
            for ip in list(self.arp_cache.keys()):
                if current_time - self.arp_cache[ip]['timestamp'] > self.arp_cache_timeout:
                    del self.arp_cache[ip]

            self.port_scan_track.clear()
            self.icmp_count.clear()
            self.last_cleanup = current_time
            logger.debug("Completed periodic cleanup of tracking data")

    def detect_threats(self, packet_info) -> List[dict]:
        """Detect potential threats in network traffic"""
        threats = []
        self.cleanup_old_data()
        self._update_baseline_stats(packet_info)

        # Basic attack detection
        if packet_info['protocol'] == 'TCP':
            threats.extend(self._detect_tcp_threats(packet_info))
        elif packet_info['protocol'] == 'ICMP':
            threats.extend(self._detect_icmp_threats(packet_info))
        elif packet_info['protocol'] == 'ARP':
            threats.extend(self._detect_arp_spoofing(packet_info))

        # Signature-based detection
        sig_threats = self._check_signatures(packet_info)
        if sig_threats:
            threats.extend(sig_threats)

        # Anomaly-based detection
        anomalies = self._detect_anomalies(packet_info)
        if anomalies:
            threats.extend(anomalies)

        # DDoS detection
        ddos_threats = self._detect_ddos(packet_info)
        if ddos_threats:
            threats.extend(ddos_threats)

        return threats

    def _detect_tcp_threats(self, packet_info) -> List[dict]:
        """Detect TCP-based threats"""
        threats = []

        # SYN flood detection
        if self._check_syn_flood(packet_info):
            threats.append({
                'type': 'SYN_FLOOD',
                'source': packet_info['src_ip'],
                'details': 'Possible SYN flood attack detected',
                'severity': 'high',
                'category': 'dos'
            })

        # Port scan detection
        if self._check_port_scan(packet_info):
            threats.append({
                'type': 'PORT_SCAN',
                'source': packet_info['src_ip'],
                'details': 'Possible port scanning detected',
                'severity': 'medium',
                'category': 'reconnaissance'
            })

        return threats

    def _detect_icmp_threats(self, packet_info) -> List[dict]:
        """Detect ICMP-based threats"""
        threats = []
        if self._check_icmp_flood(packet_info):
            threats.append({
                'type': 'ICMP_FLOOD',
                'source': packet_info['src_ip'],
                'details': 'Possible ICMP flood attack detected',
                'severity': 'medium',
                'category': 'dos'
            })
        return threats

    def _detect_arp_spoofing(self, packet_info) -> List[dict]:
        """Detect ARP spoofing attempts"""
        if 'arp' not in packet_info:
            return []

        ip = packet_info['arp']['src_ip']
        mac = packet_info['arp']['src_mac']
        current_time = time.time()

        if ip in self.arp_cache:
            if self.arp_cache[ip]['mac'] != mac:
                return [{
                    'type': 'ARP_SPOOFING',
                    'source': ip,
                    'details': f'ARP spoofing detected: IP {ip} changed MAC from {self.arp_cache[ip]["mac"]} to {mac}',
                    'severity': 'high',
                    'category': 'mitm'
                }]

        self.arp_cache[ip] = {'mac': mac, 'timestamp': current_time}
        return []

    def _detect_ddos(self, packet_info) -> List[dict]:
        """Detect DDoS attacks"""
        src_ip = packet_info['src_ip']
        current_time = time.time()

        if src_ip not in self.ddos_track:
            self.ddos_track[src_ip] = {
                'count': 0,
                'first_seen': current_time,
                'last_seen': current_time,
                'sizes': []
            }

        self.ddos_track[src_ip]['count'] += 1
        self.ddos_track[src_ip]['last_seen'] = current_time
        self.ddos_track[src_ip]['sizes'].append(packet_info['length'])

        # Calculate packet rate
        duration = current_time - self.ddos_track[src_ip]['first_seen']
        if duration > 0:
            pps = self.ddos_track[src_ip]['count'] / duration
            if pps > self.ddos_pps_threshold:
                return [{
                    'type': 'DDOS_ATTACK',
                    'source': src_ip,
                    'details': f'Possible DDoS attack detected: {pps:.2f} packets/second',
                    'severity': 'critical',
                    'category': 'dos'
                }]
        return []

    def _check_signatures(self, packet_info) -> List[dict]:
        """Check packet against known attack signatures"""
        threats = []
        for sig in self.signatures:
            if self._match_signature(packet_info, sig['pattern']):
                threats.append({
                    'type': 'SIGNATURE_MATCH',
                    'source': packet_info['src_ip'],
                    'details': f"Matched signature: {sig['name']} - {sig['description']}",
                    'severity': sig['severity'],
                    'category': sig['category']
                })
        return threats

    def _match_signature(self, packet_info, pattern) -> bool:
        """Match packet against a signature pattern"""
        for proto, checks in pattern.items():
            if proto not in packet_info:
                return False
            for key, value in checks.items():
                if key not in packet_info[proto] or packet_info[proto][key] != value:
                    return False
        return True

    def _update_baseline_stats(self, packet_info):
        """Update baseline statistics for anomaly detection"""
        current_time = time.time()
        self.baseline_stats['packet_sizes'].append(packet_info['length'])

        # Keep only recent statistics
        while len(self.baseline_stats['packet_sizes']) > 1000:
            self.baseline_stats['packet_sizes'].pop(0)

    def _detect_anomalies(self, packet_info) -> List[dict]:
        """Detect anomalies based on statistical analysis"""
        threats = []
        if len(self.baseline_stats['packet_sizes']) > 100:  # Need enough samples
            avg_size = mean(self.baseline_stats['packet_sizes'])
            std_size = stdev(self.baseline_stats['packet_sizes'])

            # Check for abnormal packet sizes
            if abs(packet_info['length'] - avg_size) > (std_size * self.anomaly_std_threshold):
                threats.append({
                    'type': 'ANOMALY',
                    'source': packet_info['src_ip'],
                    'details': f'Anomalous packet size detected: {packet_info["length"]} bytes',
                    'severity': 'medium',
                    'category': 'anomaly'
                })

        return threats

    def _check_syn_flood(self, packet_info) -> bool:
        """Check for SYN flood attacks"""
        if packet_info['details']['flags']['SYN'] and not packet_info['details']['flags']['ACK']:
            src_ip = packet_info['src_ip']
            current_time = time.time()

            if src_ip not in self.syn_count:
                self.syn_count[src_ip] = {
                    'count': 0,
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'sizes': []
                }

            self.syn_count[src_ip]['count'] += 1
            self.syn_count[src_ip]['last_seen'] = current_time
            self.syn_count[src_ip]['sizes'].append(packet_info['length'])

            interval = current_time - self.syn_count[src_ip]['first_seen']
            if interval > 0:
                rate = self.syn_count[src_ip]['count'] / interval
                logger.debug(f"SYN rate for {src_ip}: {rate:.2f} packets/sec")
                return rate > self.syn_flood_threshold
        return False

    def _check_port_scan(self, packet_info) -> bool:
        """Check for port scanning activity"""
        src_ip = packet_info['src_ip']
        dst_port = packet_info['details']['dst_port']

        self.port_scan_track[src_ip].add(dst_port)
        unique_ports = len(self.port_scan_track[src_ip])
        logger.debug(f"Port scan check for {src_ip}: {unique_ports} unique ports")
        return unique_ports > self.port_scan_threshold

    def _check_icmp_flood(self, packet_info) -> bool:
        """Check for ICMP flood attacks"""
        src_ip = packet_info['src_ip']
        self.icmp_count[src_ip] += 1
        count = self.icmp_count[src_ip]
        logger.debug(f"ICMP count for {src_ip}: {count} packets")
        return count > self.icmp_flood_threshold