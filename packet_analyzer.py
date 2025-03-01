from scapy.all import IP, TCP, UDP, ICMP
import logging

logger = logging.getLogger(__name__)

class PacketAnalyzer:
    def __init__(self):
        self.supported_protocols = {
            'TCP': self.analyze_tcp,
            'UDP': self.analyze_udp,
            'ICMP': self.analyze_icmp
        }

    def analyze_packet(self, packet):
        """Analyze a network packet and return relevant information"""
        if not packet.haslayer(IP):
            return None

        packet_info = {
            'timestamp': packet.time,
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': None,
            'length': len(packet),
            'details': {}
        }

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

        return packet_info

    def analyze_tcp(self, packet):
        """Analyze TCP packet details"""
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
            'ack': packet[TCP].ack
        }
        return tcp_info

    def analyze_udp(self, packet):
        """Analyze UDP packet details"""
        udp_info = {
            'src_port': packet[UDP].sport,
            'dst_port': packet[UDP].dport,
            'length': packet[UDP].len
        }
        return udp_info

    def analyze_icmp(self, packet):
        """Analyze ICMP packet details"""
        icmp_info = {
            'type': packet[ICMP].type,
            'code': packet[ICMP].code
        }
        return icmp_info
