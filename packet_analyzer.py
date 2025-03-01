from scapy.all import IP, TCP, UDP, ICMP, ARP, Raw
import logging
import time
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class PacketAnalyzer:
    def __init__(self):
        self.supported_protocols = {
            'TCP': self.analyze_tcp,
            'UDP': self.analyze_udp,
            'ICMP': self.analyze_icmp,
            'ARP': self.analyze_arp
        }

    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze a network packet and return relevant information"""
        try:
            # Initialize packet info with current timestamp
            packet_info = {
                'timestamp': time.time(),
                'length': 0,
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'details': {}
            }

            # Handle dictionary input
            if isinstance(packet, dict):
                packet_info.update({
                    'timestamp': packet.get('timestamp', time.time()),
                    'length': packet.get('length', 0),
                    'protocol': packet.get('protocol'),
                    'src_ip': packet.get('src_ip'),
                    'dst_ip': packet.get('dst_ip'),
                    'details': packet.get('details', {})
                })
                return packet_info

            # Handle Scapy packet
            if hasattr(packet, 'time'):
                packet_info['timestamp'] = float(packet.time)
            packet_info['length'] = len(packet)

            # Handle ARP packets
            if packet.haslayer(ARP):
                packet_info['protocol'] = 'ARP'
                packet_info['details'] = self.analyze_arp(packet)
                return packet_info

            # Handle IP packets
            if packet.haslayer(IP):
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst
                })

                # Determine protocol and analyze accordingly
                if packet.haslayer(TCP):
                    packet_info['protocol'] = 'TCP'
                    packet_info['details'] = self.analyze_tcp(packet)
                elif packet.haslayer(UDP):
                    packet_info['protocol'] = 'UDP'
                    packet_info['details'] = self.analyze_udp(packet)
                elif packet.haslayer(ICMP):
                    packet_info['protocol'] = 'ICMP'
                    packet_info['details'] = self.analyze_icmp(packet)

                # Add payload analysis if present
                if packet.haslayer(Raw):
                    packet_info['payload'] = self.analyze_payload(packet)

                return packet_info

            return None

        except Exception as e:
            logger.error(f"Error analyzing packet: {e}", exc_info=True)
            return None

    def analyze_tcp(self, packet) -> Dict[str, Any]:
        """Analyze TCP packet details"""
        if isinstance(packet, dict):
            return packet.get('details', {})

        tcp_info = {
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'flags': {
                'SYN': packet[TCP].flags.S,
                'ACK': packet[TCP].flags.A,
                'FIN': packet[TCP].flags.F,
                'RST': packet[TCP].flags.R,
                'PSH': packet[TCP].flags.P,
                'URG': packet[TCP].flags.U
            },
            'seq': packet[TCP].seq,
            'ack': packet[TCP].ack,
            'window': packet[TCP].window
        }
        tcp_info['raw_flags'] = packet[TCP].flags.value
        return tcp_info

    def analyze_udp(self, packet) -> Dict[str, Any]:
        """Analyze UDP packet details"""
        if isinstance(packet, dict):
            return packet.get('details', {})

        return {
            'src_port': packet[UDP].sport,
            'dst_port': packet[UDP].dport,
            'length': packet[UDP].len
        }

    def analyze_icmp(self, packet) -> Dict[str, Any]:
        """Analyze ICMP packet details"""
        if isinstance(packet, dict):
            return packet.get('details', {})

        return {
            'type': packet[ICMP].type,
            'code': packet[ICMP].code,
            'id': packet[ICMP].id if hasattr(packet[ICMP], 'id') else None,
            'seq': packet[ICMP].seq if hasattr(packet[ICMP], 'seq') else None
        }

    def analyze_arp(self, packet) -> Dict[str, Any]:
        """Analyze ARP packet details"""
        if isinstance(packet, dict):
            return packet.get('details', {})

        return {
            'op': packet[ARP].op,
            'src_mac': packet[ARP].hwsrc,
            'dst_mac': packet[ARP].hwdst,
            'src_ip': packet[ARP].psrc,
            'dst_ip': packet[ARP].pdst
        }

    def analyze_payload(self, packet) -> Dict[str, Any]:
        """Analyze packet payload"""
        if isinstance(packet, dict):
            return packet.get('payload', {'raw': b'', 'length': 0, 'hex': ''})

        payload_info = {
            'raw': bytes(packet[Raw].load),
            'length': len(packet[Raw].load)
        }
        payload_info['hex'] = payload_info['raw'].hex()
        return payload_info

    def get_protocol_name(self, packet) -> str:
        """Get the protocol name from a packet"""
        if isinstance(packet, dict):
            return packet.get('protocol', 'UNKNOWN')

        for protocol in self.supported_protocols:
            if packet.haslayer(protocol):
                return protocol
        return "UNKNOWN"