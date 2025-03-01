from collections import defaultdict
import time

class StatsCollector:
    def __init__(self, performance_metrics=False, connection_tracking=False, attack_pattern_analysis=False):
        """Initialize stats collector with optional features"""
        self.performance_metrics_enabled = performance_metrics
        self.connection_tracking_enabled = connection_tracking
        self.attack_pattern_analysis_enabled = attack_pattern_analysis
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

        # Connection tracking for heatmap
        self.connection_matrix = {
            'src_ips': [],
            'dst_ips': [],
            'counts': []
        }
        self.unique_connections = defaultdict(int)

        # Attack pattern analysis
        self.attack_timestamps = []
        self.attack_counts = []

        # Performance metrics
        self.performance_metrics = {
            'packet_loss': [],
            'latency': [],
            'bandwidth': []
        }

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

        # Update connection matrix for heatmap if enabled
        if self.connection_tracking_enabled:
            conn_key = f"{packet_info['src_ip']}->{packet_info['dst_ip']}"
            self.unique_connections[conn_key] += 1

            # Update matrix periodically
            current_time = time.time()
            if current_time - self.last_update >= 1.0:  # Update every second
                # Convert connection data to matrix format
                connections = sorted(self.unique_connections.items())
                if connections:
                    src_ips = list(set([c.split('->')[0] for c in self.unique_connections.keys()]))
                    dst_ips = list(set([c.split('->')[1] for c in self.unique_connections.keys()]))
                    counts = [[self.unique_connections.get(f"{src}->{dst}", 0) 
                             for dst in dst_ips] for src in src_ips]

                    self.connection_matrix = {
                        'src_ips': src_ips,
                        'dst_ips': dst_ips,
                        'counts': counts
                    }

        # Calculate packet rate
        current_time = time.time()
        if current_time - self.last_update >= 1.0:  # Update every second
            rate = self.packet_count / (current_time - self.start_time)
            self.packet_rates.append(rate)
            self.last_update = current_time

            # Keep only last 60 seconds of rate history
            if len(self.packet_rates) > 60:
                self.packet_rates.pop(0)

        # Update attack pattern data if enabled
        if self.attack_pattern_analysis_enabled and hasattr(packet_info, 'is_attack'):
            self.attack_timestamps.append(time.time())
            self.attack_counts.append(self.packet_count)

            # Keep only recent attack history
            if len(self.attack_timestamps) > 100:
                self.attack_timestamps.pop(0)
                self.attack_counts.pop(0)

    def get_stats(self):
        """Return current statistics"""
        current_time = time.time()
        elapsed_time = current_time - self.start_time

        stats = {
            'general': {
                'total_packets': self.packet_count,
                'total_bytes': self.byte_count,
                'elapsed_time': elapsed_time,
                'packets_per_second': self.packet_count / elapsed_time if elapsed_time > 0 else 0,
                'unique_ips': len(set(self.ip_stats.keys())),
                'avg_packet_size': self.byte_count / self.packet_count if self.packet_count > 0 else 0
            },
            'protocols': dict(self.protocol_stats),
            'top_ips': dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ports': dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            'packet_rates': self.packet_rates,
            'connections': self.connection_matrix if self.connection_tracking_enabled else None,
            'attacks': {
                'timestamps': self.attack_timestamps,
                'counts': self.attack_counts
            } if self.attack_pattern_analysis_enabled else None
        }

        if self.performance_metrics_enabled:
            stats['performance'] = self.performance_metrics

        return stats