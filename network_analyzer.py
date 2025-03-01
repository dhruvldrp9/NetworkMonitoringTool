#!/usr/bin/env python3
import os
import sys
import logging
import time
from scapy.all import IP, TCP, UDP, ICMP, Raw
from packet_analyzer import PacketAnalyzer
from threat_detector import ThreatDetector
from stats_collector import StatsCollector
from visualizer import Visualizer
import signal
import random
from ml_analyzer import MLAnalyzer
from database import DatabaseManager

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

        # Analyze packet
        packet_info = self.packet_analyzer.analyze_packet(packet)
        if packet_info:
            # Log packet to database
            self.db_manager.log_packet(packet_info)

            # Traditional threat detection
            threats = self.threat_detector.detect_threats(packet_info)
            if threats:
                for threat in threats:
                    logger.warning(f"Potential threat detected: {threat}")
                    self.db_manager.log_threat(threat)

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

            # Update statistics
            self.stats_collector.update_stats(packet_info)

            # Update visualization
            if self.stats_collector.packet_count % 100 == 0:
                self.visualizer.update_display(self.stats_collector.get_stats())

    def generate_sample_packet(self, protocol='TCP'):
        """Generate a sample packet for testing"""
        # Generate more realistic source and destination IPs
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        dst_ip = f"10.0.0.{random.randint(1, 254)}"

        if protocol == 'TCP':
            # Generate random ports for more realistic traffic
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 8080, 22, 21])  # Common service ports
            # Mix of different TCP flags
            flags = random.choice(['S', 'SA', 'A', 'PA', 'FA'])
            return IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags=flags)
        elif protocol == 'UDP':
            # Common UDP services
            sport = random.randint(1024, 65535)
            dport = random.choice([53, 67, 68, 123, 161])  # DNS, DHCP, NTP, SNMP
            return IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)/Raw(load='Sample payload')
        elif protocol == 'ICMP':
            # Different ICMP types
            icmp_type = random.choice([0, 8])  # Echo reply or request
            return IP(src=src_ip, dst=dst_ip)/ICMP(type=icmp_type)
        return None

    def simulate_traffic(self):
        """Simulate network traffic for testing"""
        logger.info("Starting traffic simulation...")
        protocols = ['TCP', 'UDP', 'ICMP']
        packet_count = 0

        # Add weights to make TCP more common
        protocol_weights = [0.6, 0.3, 0.1]  # 60% TCP, 30% UDP, 10% ICMP

        try:
            while self.running and packet_count < 1000:  # Simulate 1000 packets
                # Select protocol based on weights
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
    analyzer.simulate_traffic()

if __name__ == "__main__":
    main()