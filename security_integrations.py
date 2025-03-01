import json
import logging
import os
from typing import List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurityToolIntegrator:
    def __init__(self):
        """Initialize security tool integration"""
        self.suricata_rules = []
        self.snort_rules = []
        self.zeek_signatures = []
        self.load_default_rules()

    def load_default_rules(self):
        """Load default detection rules"""
        try:
            # Load built-in rules
            rules_dir = Path(__file__).parent / 'rules'
            if rules_dir.exists():
                # Load Suricata rules
                suricata_file = rules_dir / 'suricata-rules.json'
                if suricata_file.exists():
                    with open(suricata_file) as f:
                        self.suricata_rules = json.load(f)

                # Load Snort rules
                snort_file = rules_dir / 'snort-rules.json'
                if snort_file.exists():
                    with open(snort_file) as f:
                        self.snort_rules = json.load(f)

                # Load Zeek signatures
                zeek_file = rules_dir / 'zeek-signatures.json'
                if zeek_file.exists():
                    with open(zeek_file) as f:
                        self.zeek_signatures = json.load(f)

            logger.info("Loaded default security rules")
        except Exception as e:
            logger.error(f"Error loading security rules: {e}")

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze packet using external security tool rules"""
        threats = []
        
        # Apply Suricata rules
        threats.extend(self._check_suricata_rules(packet_info))
        
        # Apply Snort rules
        threats.extend(self._check_snort_rules(packet_info))
        
        # Apply Zeek signatures
        threats.extend(self._check_zeek_signatures(packet_info))
        
        return threats

    def _check_suricata_rules(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check packet against Suricata rules"""
        threats = []
        for rule in self.suricata_rules:
            if self._match_rule(packet_info, rule['pattern']):
                threats.append({
                    'type': 'SURICATA_MATCH',
                    'source': packet_info['src_ip'],
                    'details': f"Matched Suricata rule: {rule['name']} - {rule['description']}",
                    'severity': rule['severity'],
                    'category': 'ids'
                })
        return threats

    def _check_snort_rules(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check packet against Snort rules"""
        threats = []
        for rule in self.snort_rules:
            if self._match_rule(packet_info, rule['pattern']):
                threats.append({
                    'type': 'SNORT_MATCH',
                    'source': packet_info['src_ip'],
                    'details': f"Matched Snort rule: {rule['name']} - {rule['description']}",
                    'severity': rule['severity'],
                    'category': 'ids'
                })
        return threats

    def _check_zeek_signatures(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check packet against Zeek signatures"""
        threats = []
        for sig in self.zeek_signatures:
            if self._match_rule(packet_info, sig['pattern']):
                threats.append({
                    'type': 'ZEEK_MATCH',
                    'source': packet_info['src_ip'],
                    'details': f"Matched Zeek signature: {sig['name']} - {sig['description']}",
                    'severity': sig['severity'],
                    'category': 'ids'
                })
        return threats

    def _match_rule(self, packet_info: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
        """Match packet against a rule pattern"""
        for field, value in pattern.items():
            if field not in packet_info:
                return False
            if isinstance(value, dict):
                if not all(packet_info[field].get(k) == v for k, v in value.items()):
                    return False
            elif packet_info[field] != value:
                return False
        return True
