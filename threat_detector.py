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
        self.syn_flood_threshold = 100  # SYN packets per second
        self.udp_flood_threshold = 1000  # UDP packets per second
        self.icmp_flood_threshold = 100  # ICMP packets per second
        self.port_scan_threshold = 10  # Different ports in 5 seconds
        self.port_scan_window = 5  # Time window for port scan detection
        self.brute_force_threshold = 10  # Login attempts per minute
        self.brute_force_window = 60  # Time window for brute force detection
        self.dns_spoof_check_enabled = True
        self.trusted_dns_servers = ["8.8.8.8", "8.8.4.4"]  # Google DNS
        self.trusted_dhcp_servers = ["192.168.1.1"]  # Default gateway
        self.data_exfil_threshold = 1000000  # 1MB per minute
        self.ransomware_file_ops_threshold = 100  # File operations per minute
        self.ddos_pps_threshold = 1000  # packets per second
        self.arp_cache_timeout = 300  # seconds

        # Initialize tracking dictionaries
        self.syn_flood_track: Dict[str, PacketTracker] = {}
        self.udp_flood_track: Dict[str, PacketTracker] = {}
        self.icmp_flood_track: Dict[str, PacketTracker] = {}
        self.port_scan_track: DefaultDict[str, Dict[float, Set[int]]] = defaultdict(lambda: defaultdict(set))
        self.mac_track: Dict[str, Set[str]] = defaultdict(set)  # MAC to IP mapping
        self.brute_force_track: Dict[str, List[float]] = defaultdict(list)
        self.data_exfil_track: Dict[str, Dict[str, float]] = defaultdict(lambda: {'bytes': 0, 'last_reset': time.time()})
        self.dns_response_track: Dict[str, str] = {}  # Query ID to expected responder mapping
        self.arp_cache: Dict[str, Dict[str, float]] = {}  # IP to MAC mapping with timestamp

        # Initialize baseline statistics
        self.baseline_stats = {
            'pps': [],
            'bytes_per_sec': [],
            'packet_sizes': []
        }

        # Load attack signatures
        self.signatures = self._load_signatures()

        self.last_cleanup = time.time()
        self.cleanup_interval = 60  # seconds

    def _load_signatures(self) -> List[dict]:
        """Load known attack signatures"""
        return [
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
                "name": "SMB Exploit Attempt",
                "pattern": {
                    "TCP": {"dport": 445},
                    "payload": b"\x00\x00\x00\x45"
                },
                "description": "Potential SMB vulnerability exploit",
                "severity": "critical",
                "category": "exploit"
            }
        ]

    def cleanup_old_data(self):
        """Clean up old tracking data"""
        current_time = time.time()
        if current_time - self.last_cleanup <= self.cleanup_interval:
            return

        for tracker in [self.syn_flood_track, self.udp_flood_track, self.icmp_flood_track]:
            for ip in list(tracker.keys()):
                if current_time - tracker[ip]['last_seen'] > self.cleanup_interval:
                    del tracker[ip]

        # Cleanup port scan tracking
        for ip in list(self.port_scan_track.keys()):
            for timestamp in list(self.port_scan_track[ip].keys()):
                if current_time - timestamp > self.port_scan_window:
                    del self.port_scan_track[ip][timestamp]
            if not self.port_scan_track[ip]:
                del self.port_scan_track[ip]

        # Cleanup brute force tracking
        for ip in list(self.brute_force_track.keys()):
            self.brute_force_track[ip] = [t for t in self.brute_force_track[ip] 
                                        if current_time - t <= self.brute_force_window]
            if not self.brute_force_track[ip]:
                del self.brute_force_track[ip]

        # Reset data exfiltration counters
        for ip in self.data_exfil_track:
            if current_time - self.data_exfil_track[ip]['last_reset'] > 60:
                self.data_exfil_track[ip] = {'bytes': 0, 'last_reset': current_time}

        self.last_cleanup = current_time

    def detect_threats(self, packet_info) -> List[dict]:
        """Detect potential threats in network traffic"""
        threats = []
        self.cleanup_old_data()

        # Basic attack detection
        if packet_info['protocol'] == 'TCP':
            threats.extend(self._detect_tcp_threats(packet_info))
        elif packet_info['protocol'] == 'UDP':
            threats.extend(self._detect_udp_threats(packet_info))
        elif packet_info['protocol'] == 'ICMP':
            threats.extend(self._detect_icmp_threats(packet_info))
        elif packet_info['protocol'] == 'DNS':
            threats.extend(self._detect_dns_spoofing(packet_info))

        # Check for MAC address spoofing
        if 'src_mac' in packet_info:
            mac_threats = self._detect_mac_spoofing(packet_info)
            if mac_threats:
                threats.extend(mac_threats)

        # Check for data exfiltration
        data_exfil_threats = self._detect_data_exfiltration(packet_info)
        if data_exfil_threats:
            threats.extend(data_exfil_threats)

        # Signature-based detection
        sig_threats = self._check_signatures(packet_info)
        if sig_threats:
            threats.extend(sig_threats)

        return threats

    def _detect_tcp_threats(self, packet_info) -> List[dict]:
        """Detect TCP-based threats"""
        threats = []
        src_ip = packet_info['src_ip']
        current_time = time.time()

        # SYN flood detection
        if self._check_syn_flood(packet_info):
            threats.append({
                'type': 'SYN_FLOOD',
                'source': src_ip,
                'details': 'Possible SYN flood attack detected',
                'severity': 'high',
                'category': 'dos'
            })

        # Port scan detection
        if self._check_port_scan(packet_info):
            threats.append({
                'type': 'PORT_SCAN',
                'source': src_ip,
                'details': 'Port scanning activity detected',
                'severity': 'medium',
                'category': 'reconnaissance'
            })

        return threats

    def _detect_udp_threats(self, packet_info) -> List[dict]:
        """Detect UDP-based threats"""
        threats = []
        src_ip = packet_info['src_ip']

        # UDP flood detection
        if self._check_udp_flood(packet_info):
            threats.append({
                'type': 'UDP_FLOOD',
                'source': src_ip,
                'details': 'UDP flood attack detected',
                'severity': 'high',
                'category': 'dos'
            })

        return threats

    def _detect_dns_spoofing(self, packet_info) -> List[dict]:
        """Detect DNS spoofing attempts"""
        if not self.dns_spoof_check_enabled:
            return []

        threats = []
        if packet_info['protocol'] == 'DNS' and 'response' in packet_info:
            src_ip = packet_info['src_ip']
            query_id = packet_info['dns']['id']

            if query_id in self.dns_response_track:
                expected_responder = self.dns_response_track[query_id]
                if src_ip != expected_responder and src_ip not in self.trusted_dns_servers:
                    threats.append({
                        'type': 'DNS_SPOOFING',
                        'source': src_ip,
                        'details': f'Unexpected DNS response from {src_ip}',
                        'severity': 'high',
                        'category': 'mitm'
                    })

        return threats

    def _detect_mac_spoofing(self, packet_info) -> List[dict]:
        """Detect MAC address spoofing"""
        threats = []
        mac = packet_info['src_mac']
        ip = packet_info['src_ip']

        # Track MAC-IP mappings
        self.mac_track[mac].add(ip)

        # Check if MAC is associated with multiple IPs
        if len(self.mac_track[mac]) > 1:
            threats.append({
                'type': 'MAC_SPOOFING',
                'source': ip,
                'details': f'MAC address {mac} associated with multiple IPs: {", ".join(self.mac_track[mac])}',
                'severity': 'high',
                'category': 'spoofing'
            })

        return threats

    def _detect_data_exfiltration(self, packet_info) -> List[dict]:
        """Detect potential data exfiltration"""
        threats = []
        src_ip = packet_info['src_ip']
        current_time = time.time()

        # Update byte count
        self.data_exfil_track[src_ip]['bytes'] += packet_info['length']

        # Check if byte count exceeds threshold
        if self.data_exfil_track[src_ip]['bytes'] > self.data_exfil_threshold:
            threats.append({
                'type': 'DATA_EXFILTRATION',
                'source': src_ip,
                'details': f'Excessive data transfer detected: {self.data_exfil_track[src_ip]["bytes"]} bytes/minute',
                'severity': 'high',
                'category': 'data_theft'
            })

        return threats

    def _check_syn_flood(self, packet_info) -> bool:
        """Check for SYN flood attacks"""
        if not (packet_info['details'].get('flags', {}).get('SYN') and 
                not packet_info['details'].get('flags', {}).get('ACK')):
            return False

        src_ip = packet_info['src_ip']
        current_time = time.time()

        if src_ip not in self.syn_flood_track:
            self.syn_flood_track[src_ip] = {
                'count': 0,
                'first_seen': current_time,
                'last_seen': current_time,
                'sizes': []
            }

        tracker = self.syn_flood_track[src_ip]
        tracker['count'] += 1
        tracker['last_seen'] = current_time
        tracker['sizes'].append(packet_info['length'])

        # Calculate rate over the interval
        interval = current_time - tracker['first_seen']
        if interval > 0:
            rate = tracker['count'] / interval
            return rate > self.syn_flood_threshold

        return False

    def _check_udp_flood(self, packet_info) -> bool:
        """Check for UDP flood attacks"""
        src_ip = packet_info['src_ip']
        current_time = time.time()

        if src_ip not in self.udp_flood_track:
            self.udp_flood_track[src_ip] = {
                'count': 0,
                'first_seen': current_time,
                'last_seen': current_time,
                'sizes': []
            }

        tracker = self.udp_flood_track[src_ip]
        tracker['count'] += 1
        tracker['last_seen'] = current_time
        tracker['sizes'].append(packet_info['length'])

        # Calculate rate over the interval
        interval = current_time - tracker['first_seen']
        if interval > 0:
            rate = tracker['count'] / interval
            return rate > self.udp_flood_threshold

        return False

    def _check_port_scan(self, packet_info) -> bool:
        """Check for port scanning activity"""
        src_ip = packet_info['src_ip']
        dst_port = packet_info['details']['dst_port']
        current_time = time.time()

        # Add port to current time window
        self.port_scan_track[src_ip][current_time].add(dst_port)

        # Count unique ports in the detection window
        unique_ports = set()
        for timestamp in list(self.port_scan_track[src_ip].keys()):
            if current_time - timestamp <= self.port_scan_window:
                unique_ports.update(self.port_scan_track[src_ip][timestamp])
            else:
                del self.port_scan_track[src_ip][timestamp]

        return len(unique_ports) > self.port_scan_threshold

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
            if proto == 'payload_length' and 'payload' in packet_info:
                if packet_info['payload']['length'] != checks:
                    return False
            elif proto == 'payload' and 'payload' in packet_info:
                if checks not in packet_info['payload']['raw']:
                    return False
            elif proto not in packet_info:
                return False
            elif isinstance(checks, dict):
                for key, value in checks.items():
                    if key not in packet_info[proto] or packet_info[proto][key] != value:
                        return False
        return True

    def _detect_icmp_threats(self, packet_info) -> List[dict]:
        """Detect ICMP-based threats"""
        threats = []
        src_ip = packet_info['src_ip']
        current_time = time.time()

        if src_ip not in self.icmp_flood_track:
            self.icmp_flood_track[src_ip] = {
                'count': 0,
                'first_seen': current_time,
                'last_seen': current_time,
                'sizes': []
            }

        tracker = self.icmp_flood_track[src_ip]
        tracker['count'] += 1
        tracker['last_seen'] = current_time
        tracker['sizes'].append(packet_info['length'])

        # Calculate rate over the interval
        interval = current_time - tracker['first_seen']
        if interval > 0:
            rate = tracker['count'] / interval
            if rate > self.icmp_flood_threshold:
                threats.append({
                    'type': 'ICMP_FLOOD',
                    'source': src_ip,
                    'details': f'Possible ICMP flood attack detected: {rate:.2f} packets/second',
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
            if current_time - self.arp_cache[ip]['timestamp'] > self.arp_cache_timeout:
                del self.arp_cache[ip]
            elif self.arp_cache[ip]['mac'] != mac:
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