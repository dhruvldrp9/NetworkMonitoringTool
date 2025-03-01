import os
import sys
import time
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import numpy as np

class Visualizer:
    def __init__(self):
        self.last_update = time.time()
        self.update_interval = 1.0  # Update every second
        
    def clear_screen(self):
        """Clear the console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def update_display(self, stats):
        """Update the console display with current statistics"""
        current_time = time.time()
        if current_time - self.last_update < self.update_interval:
            return

        self.clear_screen()
        self.display_header()
        self.display_general_stats(stats['general'])
        self.display_protocol_stats(stats['protocols'])
        self.display_top_ips(stats['top_ips'])
        self.display_top_ports(stats['top_ports'])
        
        self.last_update = current_time

    def display_header(self):
        """Display the header information"""
        print("=" * 80)
        print(f"Network Traffic Analyzer - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)

    def display_general_stats(self, general_stats):
        """Display general statistics"""
        print("\nGeneral Statistics:")
        print("-" * 40)
        print(f"Total Packets: {general_stats['total_packets']}")
        print(f"Total Bytes: {self.format_bytes(general_stats['total_bytes'])}")
        print(f"Elapsed Time: {general_stats['elapsed_time']:.2f} seconds")
        print(f"Current Rate: {general_stats['packets_per_second']:.2f} packets/second")

    def display_protocol_stats(self, protocol_stats):
        """Display protocol statistics"""
        print("\nProtocol Distribution:")
        print("-" * 40)
        total = sum(protocol_stats.values())
        for protocol, count in protocol_stats.items():
            percentage = (count / total * 100) if total > 0 else 0
            print(f"{protocol}: {count} ({percentage:.1f}%)")

    def display_top_ips(self, ip_stats):
        """Display top IP statistics"""
        print("\nTop 5 IP Addresses:")
        print("-" * 40)
        for i, (ip, count) in enumerate(list(ip_stats.items())[:5], 1):
            print(f"{i}. {ip}: {count} packets")

    def display_top_ports(self, port_stats):
        """Display top port statistics"""
        print("\nTop 5 Ports:")
        print("-" * 40)
        for i, (port, count) in enumerate(list(port_stats.items())[:5], 1):
            print(f"{i}. Port {port}: {count} packets")

    def format_bytes(self, bytes):
        """Format bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"

    def show_final_stats(self, stats):
        """Display final statistics with graphs"""
        # Create packet rate graph
        plt.figure(figsize=(10, 6))
        plt.plot(stats['packet_rates'])
        plt.title('Packet Rate Over Time')
        plt.xlabel('Time (seconds)')
        plt.ylabel('Packets per Second')
        plt.grid(True)
        
        # Create protocol distribution pie chart
        plt.figure(figsize=(8, 8))
        protocols = stats['protocols']
        plt.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
        plt.title('Protocol Distribution')
        
        plt.show()
