from collections import defaultdict
import time

class StatsCollector:
    def __init__(self):
        self.reset_stats()
        
    def reset_stats(self):
        """Reset all statistics"""
        self.start_time = time.time()
        self.packet_count = 0
        self.byte_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.packet_rates = []
        self.last_update = time.time()

    def update_stats(self, packet_info):
        """Update statistics with new packet information"""
        self.packet_count += 1
        self.byte_count += packet_info['length']
        
        # Update protocol statistics
        self.protocol_stats[packet_info['protocol']] += 1
        
        # Update IP statistics
        self.ip_stats[packet_info['src_ip']] += 1
        self.ip_stats[packet_info['dst_ip']] += 1
        
        # Update port statistics for TCP and UDP
        if packet_info['protocol'] in ['TCP', 'UDP']:
            self.port_stats[packet_info['details']['src_port']] += 1
            self.port_stats[packet_info['details']['dst_port']] += 1
        
        # Calculate packet rate
        current_time = time.time()
        if current_time - self.last_update >= 1.0:  # Update every second
            rate = self.packet_count / (current_time - self.start_time)
            self.packet_rates.append(rate)
            self.last_update = current_time
            
            # Keep only last 60 seconds of rate history
            if len(self.packet_rates) > 60:
                self.packet_rates.pop(0)

    def get_stats(self):
        """Return current statistics"""
        current_time = time.time()
        elapsed_time = current_time - self.start_time
        
        stats = {
            'general': {
                'total_packets': self.packet_count,
                'total_bytes': self.byte_count,
                'elapsed_time': elapsed_time,
                'packets_per_second': self.packet_count / elapsed_time if elapsed_time > 0 else 0
            },
            'protocols': dict(self.protocol_stats),
            'top_ips': dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ports': dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            'packet_rates': self.packet_rates
        }
        
        return stats
