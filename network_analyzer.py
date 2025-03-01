#!/usr/bin/env python3
from security_integrations import SecurityToolIntegrator
import logging
import sys
import signal
import time
import random
import re
import json
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
    """Main network analysis class with optimized performance and clean code structure"""

    def __init__(self):
        """Initialize the network analyzer with all components"""
        self.running = True
        self.simulation_mode = True  # Default to simulation mode

        # Initialize components
        self._init_components()

        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        logger.info("Network Analyzer initialized successfully")

    def _init_components(self):
        """Initialize all analyzer components"""
        try:
            self.packet_analyzer = PacketAnalyzer()
            self.threat_detector = ThreatDetector()
            self.stats_collector = StatsCollector(
                performance_metrics=True,
                connection_tracking=True,
                attack_pattern_analysis=True
            )
            self.visualizer = Visualizer()
            self.ml_analyzer = MLAnalyzer()
            self.db_manager = DatabaseManager()
            self.notifier = NotificationManager()
            self.security_integrator = SecurityToolIntegrator()
            self.deep_inspector = DeepPacketInspector()
            logger.info("All components initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing components: {e}", exc_info=True)
            sys.exit(1)

    def set_simulation_mode(self, enabled: bool):
        """Set the simulation mode"""
        self.simulation_mode = enabled
        logger.info(f"Simulation mode {'enabled' if enabled else 'disabled'}")

    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info("Stopping packet analysis...")
        self.running = False
        sys.exit(0)

    def process_packet(self, packet_info):
        """Process each packet with enhanced analysis and optimized performance"""
        if not self.running:
            return

        try:
            # Deep packet inspection
            dpi_results = self.deep_inspector.inspect_packet(packet_info)

            # Handle threats
            if dpi_results['threats']:
                self._handle_threats(dpi_results['threats'], packet_info)

            # Handle anomalies from DPI
            if dpi_results['anomalies']:
                self._handle_anomalies(dpi_results['anomalies'], packet_info)

            # ML analysis
            self._perform_ml_analysis(packet_info)

            # Update statistics
            self.stats_collector.update_stats(packet_info)

        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)

    def _handle_threats(self, threats, packet_info):
        """Handle detected threats"""
        try:
            for threat in threats:
                logger.warning(f"DPI detected threat: {threat}")
                self.db_manager.log_threat(threat)

                if threat['severity'] in ['high', 'critical']:
                    self.notifier.send_alert(threat, channels=['webhook', 'email'])

                packet_info['is_attack'] = True
                packet_info['attack_type'] = threat['type']
        except Exception as e:
            logger.error(f"Error handling threats: {e}", exc_info=True)

    def _handle_anomalies(self, anomalies, packet_info):
        """Handle detected anomalies"""
        try:
            for anomaly in anomalies:
                logger.warning(f"DPI detected anomaly: {anomaly}")
                packet_info['is_attack'] = True
                packet_info['attack_type'] = 'anomaly'
        except Exception as e:
            logger.error(f"Error handling anomalies: {e}", exc_info=True)

    def _perform_ml_analysis(self, packet_info):
        """Perform machine learning analysis"""
        try:
            anomalies = self.ml_analyzer.detect_anomalies(packet_info)
            if anomalies:
                for anomaly in anomalies:
                    logger.warning(f"ML anomaly detected: {anomaly}")
                    features = self.ml_analyzer.extract_features(packet_info)
                    baseline_stats = self.ml_analyzer.get_baseline_stats()

                    # Log anomaly with features and stats
                    self.db_manager.log_anomaly(
                        anomaly,
                        features=features.tolist() if hasattr(features, 'tolist') else features,
                        baseline_stats=baseline_stats
                    )

                    if anomaly.get('confidence', 0) > 0.8:
                        self.notifier.send_alert(anomaly, channels=['webhook'])

                    packet_info['is_attack'] = True
                    packet_info['attack_type'] = 'ML_ANOMALY'
        except Exception as e:
            logger.error(f"Error in ML analysis: {e}", exc_info=True)

    def _generate_packet_info(self):
        """Generate realistic packet information for simulation"""
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        dst_ip = f"10.0.0.{random.randint(1, 254)}"
        protocol = random.choice(['TCP', 'UDP', 'ICMP'])

        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'length': random.randint(64, 1500),
            'details': {
                'src_port': random.randint(1024, 65535),
                'dst_port': random.randint(1, 65535)
            }
        }

    def _simulate_attack(self, attack_type):
        """Simulate a specific type of attack with optimized patterns"""
        attack_patterns = {
            'sql_injection': lambda: {
                'payload': "SELECT * FROM users WHERE id = 1 OR '1'='1'",
                'dst_port': 3306
            },
            'xss': lambda: {
                'payload': "<script>alert('xss')</script>",
                'dst_port': 80
            },
            'command_injection': lambda: {
                'payload': "; cat /etc/passwd; echo 'pwned'",
                'dst_port': 80
            }
        }

        for _ in range(random.randint(5, 15)):
            packet_info = self._generate_packet_info()
            if attack_type in attack_patterns:
                pattern = attack_patterns[attack_type]()
                packet_info['payload'] = pattern['payload']
                packet_info['details']['dst_port'] = pattern['dst_port']

            self.process_packet(packet_info)
            time.sleep(0.05)

    def simulate_attack_patterns(self):
        """Simulate various attack patterns with realistic timing"""
        logger.info("Starting attack pattern simulation...")
        try:
            while self.running and self.simulation_mode:
                # Mix of normal and attack traffic
                for _ in range(random.randint(10, 30)):
                    packet_info = self._generate_packet_info()
                    self.process_packet(packet_info)
                    time.sleep(0.1)

                # Periodically inject attack patterns
                if random.random() < 0.3:  # 30% chance of attack
                    attack_type = random.choice([
                        'sql_injection', 'xss', 'port_scan',
                        'syn_flood', 'ddos', 'command_injection'
                    ])
                    self._simulate_attack(attack_type)

        except Exception as e:
            logger.error(f"Error during attack simulation: {e}", exc_info=True)
            sys.exit(1)

class DeepPacketInspector:
    """Deep Packet Inspection module with optimized detection capabilities"""

    def __init__(self, rules_file=None):
        """Initialize the Deep Packet Inspector with detection rules"""
        self.rules = self._load_rules(rules_file)
        self.connection_tracker = {}
        self.anomaly_thresholds = {
            'port_scan': 15,
            'syn_flood': 50,
            'icmp_flood': 20,
            'payload_size': 10000
        }
        logger.info("Deep Packet Inspector initialized")

    def _load_rules(self, rules_file):
        """Load detection rules from file or use defaults"""
        default_rules = {
            'patterns': {
                'sql_injection': [
                    r'SELECT.+FROM.+WHERE',
                    r'DROP\s+TABLE',
                    r'UNION\s+SELECT',
                    r'--\s',
                    r'OR\s+1=1'
                ],
                'xss': [
                    r'<script>',
                    r'javascript:',
                    r'onerror=',
                    r'eval\(',
                    r'document\.cookie'
                ],
                'command_injection': [
                    r'`.*`',
                    r'\b(bash|sh|ksh|csh)\s+-c\s+',
                    r'\bsystem\(',
                    r'\bexec\(',
                    r'\|.*(bash|sh)'
                ]
            },
            'suspicious_ports': [
                '31337',  # Back Orifice
                '5554',   # Sasser worm
                '9996',   # Common botnet port
                '4444',   # Metasploit default
                '6667'    # IRC (often used by botnets)
            ]
        }

        if rules_file:
            try:
                with open(rules_file, 'r') as f:
                    custom_rules = json.load(f)
                    for category, rules in custom_rules.items():
                        if category in default_rules:
                            default_rules[category].extend(rules)
                        else:
                            default_rules[category] = rules
            except Exception as e:
                logger.error(f"Failed to load rules from {rules_file}: {e}")

        return default_rules

    def inspect_packet(self, packet):
        """Inspect a packet for security threats with optimized detection"""
        result = {
            'threats': [],
            'anomalies': [],
            'info': {}
        }

        try:
            if 'details' in packet:
                self._check_ports(packet, result)

            if 'payload' in packet:
                self._check_patterns(packet, result)

            self._check_anomalies(packet, result)

        except Exception as e:
            logger.error(f"Error in packet inspection: {e}")

        return result

    def _check_ports(self, packet, result):
        """Check for suspicious ports"""
        dst_port = packet['details'].get('dst_port')
        if str(dst_port) in self.rules['suspicious_ports']:
            result['anomalies'].append(f"Connection to suspicious port {dst_port}")

    def _check_patterns(self, packet, result):
        """Check payload for attack patterns"""
        payload = packet['payload']
        for attack_type, patterns in self.rules['patterns'].items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    result['threats'].append({
                        'type': attack_type,
                        'source': packet['src_ip'],
                        'details': f"Matched pattern: {pattern}",
                        'severity': 'high',
                        'category': 'pattern_match'
                    })

    def _check_anomalies(self, packet, result):
        """Check for traffic anomalies"""
        conn_key = f"{packet['src_ip']}:{packet['details'].get('src_port', '')}"

        if conn_key not in self.connection_tracker:
            self.connection_tracker[conn_key] = {
                'ports': set(),
                'syn_count': 0,
                'last_seen': time.time()
            }

        tracker = self.connection_tracker[conn_key]
        tracker['ports'].add(packet['details'].get('dst_port'))

        # Check for port scanning
        if len(tracker['ports']) > self.anomaly_thresholds['port_scan']:
            result['threats'].append({
                'type': 'port_scan',
                'source': packet['src_ip'],
                'details': f"Accessed {len(tracker['ports'])} different ports",
                'severity': 'high',
                'category': 'anomaly'
            })
            tracker['ports'].clear()

        # Check packet size
        if packet['length'] > self.anomaly_thresholds['payload_size']:
            result['anomalies'].append({
                'type': 'large_packet',
                'source': packet['src_ip'],
                'details': f"Unusually large packet: {packet['length']} bytes",
                'severity': 'medium',
                'category': 'anomaly'
            })

def main():
    """Main entry point"""
    analyzer = NetworkAnalyzer()
    analyzer.simulate_attack_patterns()

if __name__ == "__main__":
    main()