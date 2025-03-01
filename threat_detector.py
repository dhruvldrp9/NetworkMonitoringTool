from dataclasses import dataclass
from typing import Dict, Set, DefaultDict, List, TypedDict
from collections import defaultdict
import logging
import time

logger = logging.getLogger(__name__)

class PacketTracker(TypedDict):
    count: int
    first_seen: float

class ThreatDetector:
    def __init__(self):
        # Initialize threat detection parameters with more realistic thresholds
        self.syn_flood_threshold = 50  # packets per second
        self.port_scan_threshold = 15  # different ports
        self.icmp_flood_threshold = 30  # packets per second

        # Tracking dictionaries with proper typing
        self.syn_count: Dict[str, PacketTracker] = {}
        self.port_scan_track: DefaultDict[str, Set[int]] = defaultdict(set)
        self.icmp_count: DefaultDict[str, int] = defaultdict(int)
        self.last_cleanup = time.time()
        self.cleanup_interval = 10  # seconds

    def cleanup_old_data(self):
        """Clean up old tracking data"""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            # Reset counters for sources that haven't been seen recently
            for ip in list(self.syn_count.keys()):
                if current_time - self.syn_count[ip]['first_seen'] > self.cleanup_interval:
                    logger.debug(f"Cleaning up SYN tracking for {ip}")
                    del self.syn_count[ip]

            self.port_scan_track.clear()
            self.icmp_count.clear()
            self.last_cleanup = current_time
            logger.debug("Completed periodic cleanup of tracking data")

    def detect_threats(self, packet_info) -> List[dict]:
        """Detect potential threats in network traffic"""
        threats = []
        self.cleanup_old_data()

        if packet_info['protocol'] == 'TCP':
            # Check for SYN flood with rate limiting
            if self._check_syn_flood(packet_info):
                threats.append({
                    'type': 'SYN_FLOOD',
                    'source': packet_info['src_ip'],
                    'details': 'Possible SYN flood attack detected'
                })
                logger.warning(f"SYN flood detected from {packet_info['src_ip']}")

            # Check for port scanning
            if self._check_port_scan(packet_info):
                threats.append({
                    'type': 'PORT_SCAN',
                    'source': packet_info['src_ip'],
                    'details': 'Possible port scanning detected'
                })
                logger.warning(
                    f"Port scan detected from {packet_info['src_ip']}, "
                    f"unique ports: {len(self.port_scan_track[packet_info['src_ip']])}"
                )

        elif packet_info['protocol'] == 'ICMP':
            if self._check_icmp_flood(packet_info):
                threats.append({
                    'type': 'ICMP_FLOOD',
                    'source': packet_info['src_ip'],
                    'details': 'Possible ICMP flood attack detected'
                })
                logger.warning(
                    f"ICMP flood detected from {packet_info['src_ip']}, "
                    f"count: {self.icmp_count[packet_info['src_ip']]}"
                )

        return threats

    def _check_syn_flood(self, packet_info) -> bool:
        """Check for SYN flood attacks with rate limiting"""
        if packet_info['details']['flags']['SYN'] and not packet_info['details']['flags']['ACK']:
            src_ip = packet_info['src_ip']
            current_time = time.time()

            # Initialize tracking for new sources
            if src_ip not in self.syn_count:
                self.syn_count[src_ip] = {'count': 0, 'first_seen': current_time}

            self.syn_count[src_ip]['count'] += 1

            # Calculate rate over the interval
            interval = current_time - self.syn_count[src_ip]['first_seen']
            if interval > 0:
                rate = self.syn_count[src_ip]['count'] / interval
                logger.debug(
                    f"SYN rate for {src_ip}: {rate:.2f} packets/sec "
                    f"(threshold: {self.syn_flood_threshold})"
                )
                return rate > self.syn_flood_threshold
        return False

    def _check_port_scan(self, packet_info) -> bool:
        """Check for port scanning activity with time window"""
        src_ip = packet_info['src_ip']
        dst_port = packet_info['details']['dst_port']

        self.port_scan_track[src_ip].add(dst_port)
        unique_ports = len(self.port_scan_track[src_ip])
        logger.debug(
            f"Port scan check for {src_ip}: {unique_ports} unique ports "
            f"(threshold: {self.port_scan_threshold})"
        )
        return unique_ports > self.port_scan_threshold

    def _check_icmp_flood(self, packet_info) -> bool:
        """Check for ICMP flood attacks"""
        src_ip = packet_info['src_ip']
        self.icmp_count[src_ip] += 1
        count = self.icmp_count[src_ip]
        logger.debug(
            f"ICMP count for {src_ip}: {count} packets "
            f"(threshold: {self.icmp_flood_threshold})"
        )
        return count > self.icmp_flood_threshold