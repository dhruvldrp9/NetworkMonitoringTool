import socket
import struct
import logging

logger = logging.getLogger(__name__)

def get_protocol_name(protocol_number):
    """Convert protocol number to name"""
    try:
        protocol_name = socket.getprotobynum(protocol_number)
        return protocol_name.upper()
    except (socket.error, OSError):
        return str(protocol_number)

def format_mac_address(mac_bytes):
    """Format MAC address bytes to string"""
    return ':'.join('%02x' % b for b in mac_bytes)

def ip_to_str(ip_bytes):
    """Convert IP bytes to string representation"""
    try:
        return socket.inet_ntoa(ip_bytes)
    except Exception as e:
        logger.error(f"Error converting IP address: {e}")
        return None

def calculate_checksum(data):
    """Calculate IP/TCP/UDP checksum"""
    if len(data) % 2 == 1:
        data += b'\0'
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    checksum = sum(words)
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF

def is_private_ip(ip_address):
    """Check if an IP address is private"""
    ip_parts = ip_address.split('.')
    if len(ip_parts) != 4:
        return False
    
    # Convert to integers
    ip_parts = [int(part) for part in ip_parts]
    
    # Check private IP ranges
    if ip_parts[0] == 10:  # 10.0.0.0 to 10.255.255.255
        return True
    elif ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:  # 172.16.0.0 to 172.31.255.255
        return True
    elif ip_parts[0] == 192 and ip_parts[1] == 168:  # 192.168.0.0 to 192.168.255.255
        return True
    
    return False

def get_service_name(port, protocol='tcp'):
    """Get service name for a port number"""
    try:
        return socket.getservbyport(port, protocol)
    except (socket.error, OSError):
        return str(port)

def format_timestamp(timestamp):
    """Format timestamp to human-readable format"""
    from datetime import datetime
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
