#!/usr/bin/env python3
import os
import sys
import socket
import struct
import time
import math
import argparse
import hashlib
import random
from ctypes import *
from array import array
import csv

# Constants
PORT = 8888
BUFFER_SIZE = 65536
MAX_FILE_SIZE = 100000

# Encoding modes
ENCODING_BINARY = 'binary'  # Use full window size range for binary data
ENCODING_ASCII = 'ascii'    # Use window size for direct ASCII encoding
ENCODING_CUSTOM = 'custom'  # Use a custom encoding scheme

def checksum(data):
    """Calculate checksum of the given data"""
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(array('H', data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return socket.ntohs(s & 0xffff)

class IP(Structure):
    _fields_ = [
        ("ihl", c_uint, 4),
        ("version", c_uint, 4),
        ("tos", c_uint8),
        ("len", c_uint16),
        ("id", c_uint16),
        ("offset", c_uint16),
        ("ttl", c_uint8),
        ("protocol_num", c_uint8),
        ("sum", c_uint16),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]
    
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)
        
    def __init__(self, socket_buffer=None):
        self.socket_buffer = socket_buffer
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class PseudoHeader(Structure):
    _fields_ = [
        ("src_addr", c_uint32),
        ("dst_addr", c_uint32),
        ("placeholder", c_uint8),
        ("protocol", c_uint8),
        ("tcp_len", c_uint16)
    ]

def decode_xor_window_size(window_size, seq_number, packet_index=0, mode='xor', use_current_seq=False):
    """
    Decode multi-round XOR-encoded window size back to ASCII character
    
    Args:
        window_size: Received window size
        seq_number: Sequence number (initial_seq for fixed modes, current_seq for random mode)
        packet_index: Current packet index (unused, kept for compatibility)
        mode: XOR mode ('xor'/'xor1', 'xor2', 'xor3', 'random', 'random3')
        use_current_seq: Whether to use the current packet's sequence number (for random mode)
        
    Returns:
        Decoded ASCII character value
    """
    # Extract the encoded 3-digit value from window size
    encoded_value = window_size % 1000
    
    # Convert sequence number to string and pad with zeros if needed
    seq_str = str(seq_number).zfill(9)  # Ensure at least 9 digits
    
    # Extract XOR keys (same as encoding)
    xor_key1 = int(seq_str[-3:]) % 1000    # Rightmost 3 digits (bits 0-2)
    xor_key2 = int(seq_str[-6:-3]) % 1000  # Next 3 digits (bits 3-5)
    xor_key3 = int(seq_str[-9:-6]) % 1000  # Next 3 digits (bits 6-8)
    
    # Decode by reversing XOR operations (XOR is self-inverse)
    ascii_value = encoded_value
    
    if mode in ['xor', 'xor1']:
        # Single XOR decode
        ascii_value = ascii_value ^ xor_key1
    elif mode == 'xor2':
        # Two XOR decode (reverse order)
        ascii_value = ascii_value ^ xor_key2
        ascii_value = ascii_value ^ xor_key1
    elif mode == 'xor3':
        # Three XOR decode (reverse order)
        ascii_value = ascii_value ^ xor_key3
        ascii_value = ascii_value ^ xor_key2
        ascii_value = ascii_value ^ xor_key1
    elif mode == 'random':
        # Random mode: single XOR with current packet's sequence number
        ascii_value = ascii_value ^ xor_key1
    elif mode == 'random3':
        # Enhanced random mode: reverse triple XOR (reverse order)
        ascii_value = ascii_value ^ xor_key3
        ascii_value = ascii_value ^ xor_key2
        ascii_value = ascii_value ^ xor_key1
    
    # Ensure valid byte range (0-255)
    ascii_value = ascii_value % 256
    
    return ascii_value

def decode_dynamic_window_size(window_size, mode='ascii', initial_seq=None, packet_index=0, current_seq=None):
    """
    Decode window size using the specified mode
    
    Args:
        window_size: TCP window size to decode
        mode: Decoding mode ('ascii', 'xor', 'xor1', 'xor2', 'xor3', 'random', 'random3')
        initial_seq: Initial sequence number for XOR mode
        packet_index: Current packet index
        current_seq: Current packet sequence number for random XOR mode
        
    Returns:
        Decoded ASCII character value
    """
    if mode in ['xor', 'xor1', 'xor2', 'xor3']:
        if initial_seq is None:
            raise ValueError("initial_seq is required for XOR mode")
        return decode_xor_window_size(window_size, initial_seq, packet_index, mode)
    elif mode in ['random', 'random3']:
        if current_seq is None:
            raise ValueError("current_seq is required for random XOR mode")
        return decode_xor_window_size(window_size, current_seq, packet_index, mode, use_current_seq=True)
    else:
        # Default to ASCII mode
        return decode_ascii_window_size(window_size)

def decode_ascii_window_size(window_size):
    """
    Decode ASCII value from the last 3 digits of window size
    
    Args:
        window_size: Encoded window size
        
    Returns:
        Decoded ASCII value
    """
    # Extract last 3 digits
    ascii_value = window_size % 1000
    
    # Special case: EOF marker (4) is allowed
    if ascii_value == 4:
        return 4  # EOF marker
    
    # Validate range - if outside ASCII printable range, might be corrupted
    if ascii_value < 32 or ascii_value > 126:
        # Try to recover or mark as potentially corrupted
        if ascii_value > 126 and ascii_value < 200:
            # Might be extended ASCII, map to printable range
            ascii_value = ((ascii_value - 127) % 95) + 32
        elif ascii_value < 32:
            # Too low, might be corruption - use minimum printable
            ascii_value = 32
        else:
            # Very high value, likely corruption
            ascii_value = 63  # '?' character
    
    return ascii_value

class CovertChannelDecoder:
    def __init__(self, mode=ENCODING_ASCII, window_base=1000, bit_pattern=None):
        """
        Initialize the covert channel decoder
        
        Args:
            mode: Encoding mode (ascii, binary, custom)
            window_base: Base window size for binary/custom modes
            bit_pattern: Custom bit pattern for encoding in binary mode
        """
        self.mode = mode
        self.window_base = window_base
        self.bit_pattern = bit_pattern or [1, 2, 4, 8, 16, 32, 64, 128]
        # Track recent values for error correction
        self.recent_values = {}
        self.value_counts = {}
        self.sequence_tracker = {}
    
    def decode_window_size(self, window_size):
        """
        Decode a window size back to original byte value
        
        Args:
            window_size: Window size value
            
        Returns:
            Original byte value
        """
        if self.mode == ENCODING_ASCII:
            return window_size
            
        elif self.mode == ENCODING_BINARY:
            # Inverse of the encoding operation
            window_size -= self.window_base
            byte_value = 0
            for i in range(8):
                if window_size & self.bit_pattern[i]:
                    byte_value |= (1 << i)
            return byte_value
            
        elif self.mode == ENCODING_CUSTOM:
            # Inverse of custom transform
            # Find the value that when transformed gives this window size
            for i in range(256):
                if ((i * 167) % 251) + self.window_base == window_size:
                    return i
            return 0  # Unable to decode
            
        return window_size  # Fallback
    
    def track_sequence(self, seq, value):
        """
        Track sequence numbers and values for error correction
        
        Args:
            seq: Sequence number
            value: Decoded value
            
        Returns:
            Corrected value if possible, otherwise original value
        """
        # Store the value for this sequence number
        if seq not in self.sequence_tracker:
            self.sequence_tracker[seq] = []
        
        if len(self.sequence_tracker[seq]) < 3:  # Store up to 3 values per sequence
            self.sequence_tracker[seq].append(value)
        
        # If we have multiple values for this sequence, use majority voting
        if len(self.sequence_tracker[seq]) > 1:
            counts = {}
            for v in self.sequence_tracker[seq]:
                counts[v] = counts.get(v, 0) + 1
            
            # Find the most common value
            max_count = 0
            most_common = value
            for v, count in counts.items():
                if count > max_count:
                    max_count = count
                    most_common = v
            
            return most_common
        
        return value
    
    def error_correction(self, seq, value):
        """
        Apply error correction to the decoded value
        
        Args:
            seq: Sequence number
            value: Decoded value
            
        Returns:
            Corrected value if possible, otherwise original value
        """
        # Only use sequence-specific tracking for retransmissions
        # Disable context-based correction as it causes false corrections
        corrected = self.track_sequence(seq, value)
        
        # Don't apply context-based heuristics as they cause wrong corrections
        # Each sequence number should have a unique character, not repeated patterns
        
        return corrected

def log_packet(packet_info, logfile_name="all_packets_log.csv"):
    """Log all received packets to CSV file"""
    try:
        with open(logfile_name, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                time.time(),
                packet_info.get('packet_index', 0),
                packet_info.get('src_ip', ''),
                packet_info.get('dst_ip', ''),
                packet_info.get('src_port', 0),
                packet_info.get('dst_port', 0),
                packet_info.get('protocol', 'Unknown'),
                packet_info.get('packet_size', 0),
                packet_info.get('ip_header_length', 0),
                packet_info.get('protocol_header_length', 0),
                packet_info.get('payload_size', 0),
                packet_info.get('tcp_seq', 0),
                packet_info.get('tcp_ack', 0),
                packet_info.get('tcp_window', 0),
                packet_info.get('tcp_flags', 0),
                packet_info.get('tcp_flags_hex', ''),
                packet_info.get('window_base', 0),
                packet_info.get('window_covert', 0),
                packet_info.get('checksum_ip_valid', False),
                packet_info.get('checksum_protocol_valid', False),
                packet_info.get('checksum_ip_received', 0),
                packet_info.get('checksum_protocol_received', 0),
                packet_info.get('is_corrupted', False),
                packet_info.get('ttl', 0),
                packet_info.get('ip_version', 0),
                packet_info.get('ip_tos', 0),
                packet_info.get('ip_id', 0),
                packet_info.get('ip_fragment_offset', 0),
                packet_info.get('tcp_urgent_ptr', 0),
                packet_info.get('tcp_options_length', 0),
                packet_info.get('flow_id', ''),
                packet_info.get('inter_arrival_time_us', 0),
                packet_info.get('flow_packet_count', 0),
                packet_info.get('flow_duration', 0),
                packet_info.get('payload_preview', '')
            ])
    except Exception as e:
        print(f"[ERROR] Failed to log packet: {e}")

def receive_covert_data(mode='ascii', window_base=1000, port=PORT, 
                       logfile_name="recv_log.csv", output_prefix="saved",
                       all_packets_log="all_packets_log.csv"):
    """Receive covert data from TCP window size covert channel"""
    # Initialize all packets log file with headers
    try:
        with open(all_packets_log, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            headers = [
                'timestamp', 'packet_index', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'protocol', 'packet_size', 'ip_header_length', 'protocol_header_length',
                'payload_size', 'tcp_seq', 'tcp_ack', 'tcp_window', 'tcp_flags',
                'tcp_flags_hex', 'window_base', 'window_covert', 'checksum_ip_valid',
                'checksum_protocol_valid', 'checksum_ip_received', 'checksum_protocol_received',
                'is_corrupted', 'is_duplicate', 'is_out_of_order', 'ttl', 'ip_version', 'ip_tos', 
                'ip_id', 'ip_fragment_offset', 'tcp_urgent_ptr', 'tcp_options_length', 
                'flow_id', 'inter_arrival_time_us', 'flow_packet_count', 'flow_duration', 
                'payload_preview'
            ]
            writer.writerow(headers)
    except Exception as e:
        print(f"[ERROR] Failed to initialize all packets log: {e}")

    # Initialize flow tracking
    flow_stats = {}
    packet_index = 0
    last_packet_time = time.time()
    received_seqs = {}  # Track received sequence numbers per flow
    last_seq = {}  # Track last sequence number per flow

    def is_packet_corrupted(packet_info):
        """Check if packet is corrupted based on checksums and header validation"""
        # Check IP checksum
        if not packet_info.get('checksum_ip_valid', False):
            return True
            
        # Check TCP checksum if it's a TCP packet
        if packet_info.get('protocol') == 'TCP' and not packet_info.get('checksum_protocol_valid', False):
            return True
            
        # Check for invalid header lengths
        if packet_info.get('ip_header_length', 0) < 20 or packet_info.get('ip_header_length', 0) > 60:
            return True
            
        if packet_info.get('protocol') == 'TCP' and packet_info.get('protocol_header_length', 0) < 20:
            return True
            
        return False

    def is_packet_duplicate(packet_info):
        """Check if packet is a duplicate based on sequence number"""
        flow_id = packet_info.get('flow_id', '')
        seq = packet_info.get('tcp_seq', 0)
        
        if flow_id not in received_seqs:
            received_seqs[flow_id] = set()
            return False
            
        if seq in received_seqs[flow_id]:
            return True
            
        received_seqs[flow_id].add(seq)
        return False

    def is_packet_out_of_order(packet_info):
        """Check if packet is out of order based on sequence number"""
        flow_id = packet_info.get('flow_id', '')
        seq = packet_info.get('tcp_seq', 0)
        
        if flow_id not in last_seq:
            last_seq[flow_id] = seq
            return False
            
        # For TCP, sequence numbers should increase
        if seq < last_seq[flow_id]:
            return True
            
        last_seq[flow_id] = seq
        return False

    def process_packet(data, addr):
        nonlocal packet_index, last_packet_time, flow_stats
        
        try:
            # Extract packet information
            packet_info = extract_packet_info(data)
            if not packet_info:
                return
                
            # Update packet tracking
            packet_index += 1
            packet_info['packet_index'] = packet_index
            
            # Calculate inter-arrival time
            current_time = time.time()
            inter_arrival_time = (current_time - last_packet_time) * 1000000  # microseconds
            packet_info['inter_arrival_time_us'] = int(inter_arrival_time)
            last_packet_time = current_time
            
            # Update flow statistics
            flow_id = packet_info.get('flow_id', '')
            if flow_id not in flow_stats:
                flow_stats[flow_id] = {
                    'start_time': current_time,
                    'packet_count': 0
                }
            flow_stats[flow_id]['packet_count'] += 1
            flow_stats[flow_id]['last_time'] = current_time
            
            # Check packet status
            packet_info['is_corrupted'] = is_packet_corrupted(packet_info)
            packet_info['is_duplicate'] = is_packet_duplicate(packet_info)
            packet_info['is_out_of_order'] = is_packet_out_of_order(packet_info)
            
            # Update flow statistics in packet info
            packet_info['flow_packet_count'] = flow_stats[flow_id]['packet_count']
            packet_info['flow_duration'] = current_time - flow_stats[flow_id]['start_time']
            
            # Log all received packets
            log_packet(packet_info, all_packets_log)
            
            # Continue with existing covert channel processing
            if packet_info['protocol'] == 'TCP':
                # Process TCP packet for covert channel
                pass  # Add your existing TCP processing code here
                
        except Exception as e:
            print(f"[ERROR] Failed to process packet: {e}")
            return

    host_ip = os.getenv('INSECURENET_HOST_IP')
    if not host_ip:
        print("Error: INSECURENET_HOST_IP environment variable not set")
        return
    
    # Create decoder
    decoder = CovertChannelDecoder(mode=mode, window_base=window_base)
    
    # Initialize CSV logging
    csv_log = []
    # Enhanced CSV headers with comprehensive logging
    csv_headers = [
        'timestamp', 'timestamp_us', 'seq_num', 'ack_num', 'raw_window_size', 'window_base', 'window_covert',
        'decoded_value', 'original_char', 'decoded_char', 'encoding_mode', 'initial_seq', 'xor_key',
        'sender_ip', 'sender_port', 'receiver_ip', 'receiver_port', 'tcp_flags', 'tcp_flags_hex',
        'payload_size', 'total_packet_size', 'ip_header_length', 'tcp_header_length',
        'is_corrupted', 'corruption_reasons', 'was_corrected', 'correction_method',
        'is_duplicate', 'is_out_of_order', 'expected_seq', 'sequence_gap',
        'packet_buffer_size', 'missing_packets', 'retransmission_detected',
        'checksum_ip_valid', 'checksum_tcp_valid', 'checksum_ip_received', 'checksum_tcp_received',
        'inter_arrival_time_us', 'cumulative_delay_ms', 'processing_time_us',
        'congestion_window_hint', 'cover_traffic_preview', 'run_number'
    ]
    
    print(f"[+] CSV logging enabled: {logfile_name}")
    
    # Create a raw socket for receiving
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print(f"Error creating receive socket: {e}")
        print("Note: This script requires root privileges")
        sys.exit(1)
    
    # Create a raw socket for sending ACKs
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except socket.error as e:
        print(f"Error creating send socket: {e}")
        recv_sock.close()
        sys.exit(1)
    
    # Additional socket options to prevent kernel interference
    try:
        # Disable automatic TCP RST generation for received packets
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Set socket buffer sizes
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    except Exception as e:
        print(f"[!] Warning: Could not set all socket options: {e}")
        print(f"[!] This may cause packet drops, but continuing...")
    
    def send_ack(sender_ip, sender_port, ack_seq):
        """Send ACK packet back to sender"""
        try:
            # Create IP header
            ip_ihl = 5
            ip_ver = 4
            ip_tos = 0
            ip_tot_len = 20 + 20  # IP header + TCP header
            ip_id = random.randint(0, 65535)
            ip_frag_off = 0
            ip_ttl = 64
            ip_proto = socket.IPPROTO_TCP
            ip_check = 0  # Will be calculated below
            ip_saddr = socket.inet_aton(host_ip)  # Our IP
            ip_daddr = socket.inet_aton(sender_ip)  # Sender's IP
            
            ip_ihl_ver = (ip_ver << 4) + ip_ihl
            
            # Pack IP header with checksum = 0 first
            ip_header = struct.pack('!BBHHHBBH4s4s',
                ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
                ip_proto, ip_check, ip_saddr, ip_daddr)
            
            # Calculate IP header checksum
            ip_check = checksum(ip_header)
            
            # Reconstruct IP header with correct checksum
            ip_header = struct.pack('!BBHHHBBH4s4s',
                ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
                ip_proto, ip_check, ip_saddr, ip_daddr)
            
            # Debug: Show checksum info
            print(f"[ACK CHECKSUM] ACK IP checksum: 0x{ip_check:04x}, total_len: {ip_tot_len}")
            
            # TCP header fields for ACK
            tcp_source = port
            tcp_dest = sender_port
            tcp_seq = 1000  # Our sequence number
            tcp_ack_seq = ack_seq  # This should be sender's seq + 1
            tcp_doff = 5  # Header length in 32-bit words
            tcp_flags = 0x10  # ACK flag
            tcp_window = 64240  # Standard window size
            tcp_check = 0
            tcp_urg_ptr = 0
            
            # TCP header packing (excluding checksum)
            tcp_offset_res = (tcp_doff << 4) + 0
            
            tcp_header = struct.pack('!HHLLBBHHH',
                tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
            
            # TCP pseudo header for checksum calculation
            src_addr = socket.inet_aton(host_ip)
            dst_addr = socket.inet_aton(sender_ip)
            placeholder = 0
            protocol = socket.IPPROTO_TCP
            tcp_length = len(tcp_header)
            
            # Create pseudo packet for checksum calculation
            psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
            pseudo_packet = psh + tcp_header
            
            # Calculate TCP checksum
            tcp_check = checksum(pseudo_packet)
            
            # Debug: Show TCP checksum info
            print(f"[ACK CHECKSUM] ACK TCP checksum: 0x{tcp_check:04x}, tcp_len: {tcp_length}")
            
            # Construct TCP header again with correct checksum
            tcp_header = struct.pack('!HHLLBBHHH',
                tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
            
            # Final packet
            packet = ip_header + tcp_header
            
            # Send ACK packet
            send_sock.sendto(packet, (sender_ip, 0))
            print(f"[<] Sent ACK for seq {ack_seq - 1} (ack_num={ack_seq})")
            
        except Exception as e:
            print(f"[!] Error sending ACK: {e}")
    
    def send_syn_ack(sender_ip, sender_port, client_seq):
        """Send SYN-ACK packet in response to SYN"""
        try:
            # Generate our own random sequence number
            server_seq = random.randint(1000000, 4000000000)
            
            # Create IP header
            ip_ihl = 5
            ip_ver = 4
            ip_tos = 0
            ip_tot_len = 20 + 20  # IP header + TCP header
            ip_id = random.randint(0, 65535)
            ip_frag_off = 0
            ip_ttl = 64
            ip_proto = socket.IPPROTO_TCP
            ip_check = 0  # Will be calculated below
            ip_saddr = socket.inet_aton(host_ip)  # Our IP
            ip_daddr = socket.inet_aton(sender_ip)  # Sender's IP
            
            ip_ihl_ver = (ip_ver << 4) + ip_ihl
            
            # Pack IP header with checksum = 0 first
            ip_header = struct.pack('!BBHHHBBH4s4s',
                ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
                ip_proto, ip_check, ip_saddr, ip_daddr)
            
            # Calculate IP header checksum
            ip_check = checksum(ip_header)
            
            # Reconstruct IP header with correct checksum
            ip_header = struct.pack('!BBHHHBBH4s4s',
                ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
                ip_proto, ip_check, ip_saddr, ip_daddr)
            
            # Debug: Show checksum info
            print(f"[HANDSHAKE CHECKSUM] SYN-ACK IP checksum: 0x{ip_check:04x}, total_len: {ip_tot_len}")
            
            # TCP header fields for SYN-ACK
            tcp_source = port
            tcp_dest = sender_port
            tcp_seq = server_seq  # Our sequence number
            tcp_ack_seq = client_seq + 1  # ACK the client's SYN
            tcp_doff = 5  # Header length in 32-bit words
            tcp_flags = 0x12  # SYN+ACK flags
            tcp_window = 65535  # Large window size for SYN-ACK
            tcp_check = 0
            tcp_urg_ptr = 0
            
            # TCP header packing (excluding checksum)
            tcp_offset_res = (tcp_doff << 4) + 0
            
            tcp_header = struct.pack('!HHLLBBHHH',
                tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
            
            # TCP pseudo header for checksum calculation
            src_addr = socket.inet_aton(host_ip)
            dst_addr = socket.inet_aton(sender_ip)
            placeholder = 0
            protocol = socket.IPPROTO_TCP
            tcp_length = len(tcp_header)
            
            # Create pseudo packet for checksum calculation
            psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
            pseudo_packet = psh + tcp_header
            
            # Calculate TCP checksum
            tcp_check = checksum(pseudo_packet)
            
            # Debug: Show TCP checksum info
            print(f"[HANDSHAKE CHECKSUM] SYN-ACK TCP checksum: 0x{tcp_check:04x}, tcp_len: {tcp_length}")
            
            # Construct TCP header again with correct checksum
            tcp_header = struct.pack('!HHLLBBHHH',
                tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
            
            # Final packet
            packet = ip_header + tcp_header
            
            # Send SYN-ACK packet
            send_sock.sendto(packet, (sender_ip, 0))
            print(f"[HANDSHAKE] Sent SYN-ACK (server_seq={server_seq}, ack={tcp_ack_seq})")
            
            # Debug: Show what we sent
            print(f"[HANDSHAKE DEBUG] Sent SYN-ACK: src_port={tcp_source}, dst_port={tcp_dest}, flags=0x{tcp_flags:02x}, seq={tcp_seq}, ack={tcp_ack_seq}")
            
            # Small delay to ensure packet gets sent before function returns
            time.sleep(0.1)
            
            return server_seq
            
        except Exception as e:
            print(f"[!] Error sending SYN-ACK: {e}")
            return None
    
    def process_buffered_packets():
        """Process any buffered packets that are now in sequence"""
        nonlocal expected_seq, covert_buffer, cover_traffic_buffer, last_usec, sum_ia, sum_sq_ia, count_ia
        nonlocal error_corrected, eof_received, current_time, sender_info
        
        # Keep processing until we can't find the next expected sequence
        while expected_seq in packet_buffer:
            # Get the buffered packet
            secret, packet_time, was_corrected, is_corrupted, buffered_payload = packet_buffer[expected_seq]
            
            # Add buffered cover traffic to buffer
            if buffered_payload:
                cover_traffic_buffer.extend(buffered_payload)
            
            # Remove from buffer and mark as processed
            del packet_buffer[expected_seq]
            processed_sequences.add(expected_seq)
            
            # Clean up missing sequence tracking for this processed sequence
            if expected_seq in missing_seq_timeout:
                del missing_seq_timeout[expected_seq]
                print(f"[i] Removed seq {expected_seq} from missing sequence tracking")
            
            # Send ACK for this buffered packet
            if sender_info:
                send_ack(sender_info[0], sender_info[1], expected_seq + 1)
                print(f"[<] Sent ACK for buffered seq {expected_seq} (ack_num={expected_seq + 1})")
            
            # Update timing
            current_usec = int(packet_time * 1000000)
            if last_usec > 0:
                delta = current_usec - last_usec
                sum_ia += delta
                sum_sq_ia += delta * delta
                count_ia += 1
            last_usec = current_usec
            
            # Check if this is EOF marker
            if secret == 0x04 and not eof_received and not is_corrupted:  # EOF marker
                print(f"[✔] Processing buffered EOF marker - seq {expected_seq}")
                eof_received = True
                eof_timeout = packet_time + 10.0
                # Don't process the EOF here - let the main logic handle it
                # Just mark that we found EOF and return
                expected_seq += 1  # Move past the EOF
                return True  # Signal that EOF was found
                
            elif secret == 0x04 and is_corrupted:
                # Corrupted EOF - treat as data
                print(f"[!] Processing buffered corrupted EOF - seq {expected_seq} - treating as '?'")
                secret = ord('?')
                # Add to buffer as regular data
                if len(covert_buffer) < MAX_FILE_SIZE:
                    covert_buffer.append(secret)
            
            else:
                # Regular data packet - add to buffer if not EOF received yet
                if not eof_received and len(covert_buffer) < MAX_FILE_SIZE:
                    covert_buffer.append(secret)
                    
                    if 32 <= secret <= 126:
                        correction_info = " (corrected)" if was_corrected else ""
                        corruption_info = " [CORRUPTED]" if is_corrupted else ""
                        print(f"[<] Processed buffered '{chr(secret)}' ({secret}) - seq {expected_seq}{correction_info}{corruption_info}")
                    else:
                        correction_info = " (corrected)" if was_corrected else ""
                        corruption_info = " [CORRUPTED]" if is_corrupted else ""
                        print(f"[<] Processed buffered byte {secret:#04x} - seq {expected_seq}{correction_info}{corruption_info}")
                elif eof_received:
                    # We've already received EOF, so this packet came after EOF - ignore it
                    print(f"[i] Ignoring buffered packet seq {expected_seq} - received after EOF")
            
            # Move to next expected sequence
            expected_seq += 1
        
        return False  # No EOF processed
    
    # Missing sequence recovery
    missing_seq_timeout = {}  # Track when we first detected missing sequences
    
    # Variables to track state
    covert_buffer = bytearray()
    cover_traffic_buffer = bytearray()  # Store legitimate TCP payload data
    file_index = 1
    run_number = 1
    expected_seq = 2000  # Expected sequence number for next packet
    out_of_order = 0
    missing = 0
    last_usec = 0
    sum_ia = 0
    sum_sq_ia = 0
    count_ia = 0
    duplicate_count = 0
    error_corrected = 0
    total_packets = 0
    reliable_packets = 0
    dropped_packets = 0  # Track packets dropped due to checksum failures
    run_number = 1
    
    # XOR mode specific variables
    initial_seq_number = None  # Store initial sequence number for XOR key
    xor_mode_active = (mode in ['xor', 'xor1', 'xor2', 'xor3', 'random', 'random3'])
    
    # Packet deduplication tracking
    last_packets = {}  # Dictionary to track recent packets by sequence number
    processed_sequences = set()  # Track all processed sequence numbers
    
    # Packet reordering buffer - store out-of-order packets
    packet_buffer = {}  # {seq_num: (secret, timestamp, was_corrected, is_corrupted, tcp_payload)}
    
    # EOF handling
    eof_received = False  # Flag to track if we've already received an EOF
    eof_timeout = 0       # Timeout to prevent processing multiple EOFs
    
    # Reliability tracking
    total_packets = 0
    reliable_packets = 0
    
    # Sender information for ACKs
    sender_info = None  # (sender_ip, sender_port)
        
    # Disable file logging - just print to console
    print(f"Listening for TCP packets on {host_ip}:{port}...")
    print(f"Decoding mode: {mode.upper()}")
    print("[i] File creation enabled - output will be saved to files")
        
    while True:
        # Receive packet
        packet = recv_sock.recvfrom(BUFFER_SIZE)[0]
        
        # Extract IP header
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # IP header length
        ihl = (iph[0] & 0xF)
        version = (iph[0] >> 4)
        iph_length = ihl * 4
        
        # Check protocol
        protocol = iph[6]
        if protocol != socket.IPPROTO_TCP:
            continue
        
        # Extract source and destination IP
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        # Extract TCP header
        tcp_header = packet[iph_length:iph_length+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        
        # === CHECKSUM VALIDATION ===
        # Validate IP header checksum first
        ip_header_for_check = packet[0:iph_length]
        # Zero out the checksum field for verification (create copy)
        ip_header_check = bytearray(ip_header_for_check)
        ip_header_check[10:12] = b'\x00\x00'  # Zero out checksum field
        calculated_ip_checksum = checksum(bytes(ip_header_check))
        received_ip_checksum = iph[7]  # Checksum from header
        
        if calculated_ip_checksum != received_ip_checksum:
            print(f"[DROP] IP checksum mismatch: calculated=0x{calculated_ip_checksum:04x}, received=0x{received_ip_checksum:04x} - dropping packet")
            dropped_packets += 1
            continue  # Drop packet, sender will retransmit when no ACK received
        
        # Validate TCP header checksum  
        tcp_source = tcph[0]
        tcp_dest = tcph[1]
        tcp_seq = tcph[2] 
        tcp_ack = tcph[3]
        tcp_flags = tcph[5]
        received_tcp_checksum = tcph[7]
        
        # Create TCP pseudo header for checksum validation
        src_addr = socket.inet_aton(s_addr)
        dst_addr = socket.inet_aton(d_addr)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(packet) - iph_length  # Total TCP segment length
        
        # Zero out the TCP checksum field for verification
        tcp_header_check = bytearray(tcp_header)
        if len(tcp_header_check) >= 18:  # Ensure we have enough bytes
            tcp_header_check[16:18] = b'\x00\x00'  # Zero out checksum field
        
        # Add any TCP payload for checksum calculation
        tcp_payload_for_check = packet[iph_length+20:] if len(packet) > iph_length+20 else b''
        tcp_segment_for_check = bytes(tcp_header_check) + tcp_payload_for_check
        
        # Create pseudo packet for checksum calculation
        psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, len(tcp_segment_for_check))
        pseudo_packet = psh + tcp_segment_for_check
        calculated_tcp_checksum = checksum(pseudo_packet)
        
        if calculated_tcp_checksum != received_tcp_checksum:
            print(f"[DROP] TCP checksum mismatch: calculated=0x{calculated_tcp_checksum:04x}, received=0x{received_tcp_checksum:04x} - dropping packet")
            dropped_packets += 1
            continue  # Drop packet, sender will retransmit when no ACK received
        
        # === PACKET PASSED CHECKSUM VALIDATION ===
        
        # TCP header fields
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcp_flags = tcph[5]
        window = tcph[6]
        
        # Skip packets not destined for our port
        if dest_port != port:
            continue
        
        # If we've received an EOF, ignore packets for a while to prevent duplicates
        current_time = time.time()
        if eof_received and current_time < eof_timeout:
            continue
        
        # If EOF timeout has passed, reset state for potential new transmission
        if eof_received and current_time >= eof_timeout:
            print(f"[i] EOF timeout passed, resetting state for new transmission")
            # Reset all state variables
            covert_buffer = bytearray()
            cover_traffic_buffer = bytearray()
            run_number += 1
            expected_seq = 2000
            out_of_order = 0
            missing = 0
            last_usec = 0
            sum_ia = 0
            sum_sq_ia = 0
            count_ia = 0
            duplicate_count = 0
            error_corrected = 0
            total_packets = 0
            reliable_packets = 0
            dropped_packets = 0
            last_packets.clear()
            packet_buffer.clear()
            processed_sequences.clear()
            eof_received = False
        
            print(f"[+] Reset state for new transmission (run {run_number})")
        
        # Handle SYN packets (connection setup) - now with proper handshake
        if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN flag but not ACK
            print(f"[HANDSHAKE] Step 1/3: Received SYN from {s_addr}:{source_port} (seq={sequence})")
            
            # Capture initial sequence number for XOR mode
            if xor_mode_active and initial_seq_number is None:
                initial_seq_number = sequence
                print(f"[HANDSHAKE] {mode.upper()} Mode: Captured initial seq {initial_seq_number} for key derivation")
            
            # Only reset if we haven't received data recently or this is a new connection
            current_time = time.time()
            time_since_last_data = current_time - (last_usec / 1000000.0) if last_usec > 0 else float('inf')
            
            # Reset state for new connection (always reset on SYN if EOF was received)
            if eof_received or time_since_last_data > 10.0 or len(covert_buffer) == 0:
                # Reset state for new transmission
                old_expected = expected_seq
                if len(covert_buffer) > 0:
                    print(f"[!] SYN reset - had {len(covert_buffer)} bytes in buffer, expected seq was {old_expected}")
                
                # Reset all state variables
                covert_buffer = bytearray()
                cover_traffic_buffer = bytearray()
                run_number += 1
                expected_seq = sequence + 1  # Next expected sequence after handshake
                out_of_order = 0
                missing = 0
                last_usec = 0
                sum_ia = 0
                sum_sq_ia = 0
                count_ia = 0
                duplicate_count = 0
                error_corrected = 0
                total_packets = 0
                reliable_packets = 0
                dropped_packets = 0
                last_packets.clear()
                packet_buffer.clear()
                processed_sequences.clear()
                eof_received = False
                
                print(f"[+] Reset state for new transmission (run {run_number})")
                
                # Send SYN-ACK response
                server_seq = send_syn_ack(s_addr, source_port, sequence)
                if server_seq:
                    print(f"[HANDSHAKE] Step 2/3: SYN-ACK sent, waiting for final ACK...")
                    
                    # Update expected sequence to account for data transmission
                    # Data will start after the handshake sequence
                    expected_seq = sequence + 1
                else:
                    print(f"[!] Failed to send SYN-ACK")
            else:
                print(f"[i] Ignoring SYN - active transmission in progress (last data {time_since_last_data:.1f}s ago)")
        
        # Handle final ACK of handshake (ACK without SYN, no payload)
        elif (tcp_flags & 0x10 and not (tcp_flags & 0x02) and 
              len(packet) - iph_length <= 20):  # ACK flag, no SYN, header-only packet
            # Check if this looks like the final handshake ACK
            if sequence == expected_seq and acknowledgement > 0:
                print(f"[HANDSHAKE] Step 3/3: Received final ACK (seq={sequence}, ack={acknowledgement})")
                print(f"[HANDSHAKE] ✅ TCP handshake completed! Ready for data transmission")
                # Don't process this as data, just acknowledge the handshake completion
                continue
        
        # Handle ACK packets with potential covert data in window size
        elif tcp_flags & 0x10:  # ACK flag
            try:
                # Update sender information for ACKs
                sender_info = (s_addr, source_port)
                
                # Only process packets from expected sequence range or close to it
                # Tighten the range to avoid processing heavily corrupted packets
                if sequence < expected_seq - 50 or sequence > expected_seq + 50:
                    # This might be a regular TCP packet or heavily corrupted, ignore
                    continue
                
                # Assign seq variable first
                seq = sequence
                
                # Extract TCP payload data (the legitimate cover traffic)
                tcp_header_len = ((doff_reserved >> 4) * 4)  # Data offset in bytes
                total_tcp_len = len(packet) - iph_length  # Total TCP length
                payload_len = total_tcp_len - tcp_header_len
                
                tcp_payload = b""
                if payload_len > 0:
                    payload_start = iph_length + tcp_header_len
                    tcp_payload = packet[payload_start:payload_start + payload_len]
                
                # Log the legitimate traffic for analysis
                if payload_len > 0:
                    # Store the cover traffic data
                    cover_traffic_buffer.extend(tcp_payload)
                    
                    if payload_len < 100:  # Show small payloads completely
                        try:
                            payload_preview = tcp_payload.decode('utf-8', errors='replace')[:100]
                            print(f"[COVER] seq {seq}: {payload_len}B payload: \"{payload_preview}\"")
                        except:
                            payload_preview = tcp_payload.hex()[:100]
                            print(f"[COVER] seq {seq}: {payload_len}B binary payload: {payload_preview}")
                    else:  # Show preview for large payloads
                        try:
                            payload_preview = tcp_payload[:50].decode('utf-8', errors='replace')
                            print(f"[COVER] seq {seq}: {payload_len}B payload preview: \"{payload_preview}...\"")
                        except:
                            payload_preview = tcp_payload[:20].hex()
                            print(f"[COVER] seq {seq}: {payload_len}B binary payload preview: {payload_preview}...")
                else:
                    print(f"[COVER] seq {seq}: No payload (header-only packet)")
                
                # Check for duplicate packets first - before any processing
                if seq in processed_sequences:
                    duplicate_count += 1
                    # IMPORTANT: Re-send ACK for already processed packets
                    # This handles the case where our original ACK was corrupted
                    send_ack(s_addr, source_port, seq + 1)
                    if duplicate_count % 10 == 0:
                        print(f"[i] Re-sent ACK for duplicate seq {seq} - total duplicates: {duplicate_count}")
                    else:
                        print(f"[<] Re-sent ACK for duplicate seq {seq} (original ACK likely corrupted)")
                    continue  # Skip all other processing for this duplicate
                
                # Decode window size with corruption detection - use dynamic decoding
                packet_index = seq - expected_seq if seq >= expected_seq else 0  # Calculate packet index
                if mode in ['xor', 'xor1', 'xor2', 'xor3'] and initial_seq_number is not None:
                    secret = decode_dynamic_window_size(window, mode, initial_seq_number, packet_index)
                elif mode in ['random', 'random3']:
                    secret = decode_dynamic_window_size(window, mode, initial_seq_number, packet_index, sequence)
                else:
                    secret = decode_dynamic_window_size(window, mode)
                total_packets += 1
                
                # DEBUG: Show exact window size and decoded value with dynamic info
                window_base = window // 1000  # Show the realistic base
                covert_part = window % 1000   # Show the covert part
                if secret == 4:
                    print(f"[DEBUG] seq {seq}: window={window} (base={window_base}000+{covert_part:03d}) -> decoded=EOF marker (4) in {mode} mode")
                elif mode == 'ascii' and 32 <= secret <= 126:
                    print(f"[DEBUG] seq {seq}: window={window} (base={window_base}000+{covert_part:03d}) -> decoded='{chr(secret)}' ({secret}) in {mode} mode")
                elif mode in ['xor', 'xor1', 'xor2', 'xor3']:
                    if 32 <= secret <= 126:
                        print(f"[DEBUG] seq {seq}: window={window} (XOR key from seq {initial_seq_number}) -> decoded='{chr(secret)}' ({secret}) in {mode} mode")
                    else:
                        print(f"[DEBUG] seq {seq}: window={window} (XOR key from seq {initial_seq_number}) -> decoded={secret} (0x{secret:02x}) in {mode} mode")
                elif mode == 'random':
                    if 32 <= secret <= 126:
                        print(f"[DEBUG] seq {seq}: window={window} (XOR key from current seq {sequence}) -> decoded='{chr(secret)}' ({secret}) in {mode} mode")
                    else:
                        print(f"[DEBUG] seq {seq}: window={window} (XOR key from current seq {sequence}) -> decoded={secret} (0x{secret:02x}) in {mode} mode")
                elif mode == 'random3':
                    if 32 <= secret <= 126:
                        print(f"[DEBUG] seq {seq}: window={window} (Enhanced XOR keys from seq {sequence}) -> decoded='{chr(secret)}' ({secret}) in {mode} mode")
                    else:
                        print(f"[DEBUG] seq {seq}: window={window} (Enhanced XOR keys from seq {sequence}) -> decoded={secret} (0x{secret:02x}) in {mode} mode")
                else:
                    print(f"[DEBUG] seq {seq}: window={window} (base={window_base}000+{covert_part:03d}) -> decoded={secret} (0x{secret:02x}) in {mode} mode")
                
                # Detect potential corruption - updated for different encoding modes
                is_likely_corrupted = False
                corruption_reasons = []
                
                # Check for corruption indicators with dynamic encoding
                if window == 0 or window > 65535:
                    is_likely_corrupted = True
                    corruption_reasons.append("invalid_window")
                
                # With dynamic encoding, window should be at least 8000 
                if window < 8000:
                    is_likely_corrupted = True
                    corruption_reasons.append("window_too_small")
                
                # Mode-specific corruption detection
                if mode in ['xor', 'xor1', 'xor2', 'xor3', 'random', 'random3']:
                    # For XOR mode, we can't easily validate the covert part since
                    # any 3-digit value could be valid after XOR encoding
                    # Instead, check if decoded value is reasonable
                    if secret > 255:  # Beyond byte range
                        is_likely_corrupted = True
                        corruption_reasons.append("decoded_out_of_range")
                elif mode == 'ascii':
                    # For ASCII mode, check covert part range
                    covert_part = window % 1000
                    # Allow EOF marker (4) as special case, otherwise check ASCII range
                    if covert_part != 4 and (covert_part < 32 or covert_part > 126):
                        is_likely_corrupted = True
                        corruption_reasons.append("invalid_covert_range")
                
                # Check if decoded secret makes sense (common to all modes)
                if secret == 0 and window % 1000 != 0:
                    is_likely_corrupted = True
                    corruption_reasons.append("zero_decode")
                
                # Additional checks for extremely unusual window sizes
                if window > 65000 and covert_part > 126 and covert_part != 4:
                    is_likely_corrupted = True
                    corruption_reasons.append("suspicious_high_values")
                
                # Apply error correction
                original_secret = secret
                secret = decoder.error_correction(seq, secret)
                
                # Track if correction was applied
                was_corrected = (original_secret != secret)
                if was_corrected:
                    error_corrected += 1
                    reliable_packets += 1
                    is_likely_corrupted = False  # Correction fixed it
                else:
                    reliable_packets += 1
                
                # Calculate additional logging variables
                # XOR key extraction for logging
                xor_key1 = xor_key2 = xor_key3 = 0
                xor_key_info = ""
                if mode in ['xor', 'xor1', 'xor2', 'xor3'] and initial_seq_number is not None:
                    seq_str = str(initial_seq_number).zfill(9)
                    xor_key1 = int(seq_str[-3:]) % 1000
                    xor_key2 = int(seq_str[-6:-3]) % 1000
                    xor_key3 = int(seq_str[-9:-6]) % 1000
                    xor_key_info = f"{xor_key1}, {xor_key2}, {xor_key3}"
                elif mode == 'random':
                    # For random mode, XOR key comes from current sequence number
                    seq_str = str(sequence).zfill(9)
                    xor_key1 = int(seq_str[-3:]) % 1000
                    xor_key_info = f"{xor_key1} (from seq {sequence})"
                elif mode == 'random3':
                    # For random3 mode, enhanced XOR keys from current sequence number
                    seq_str = str(sequence).zfill(9)
                    xor_key1 = int(seq_str[-3:]) % 1000
                    xor_key2 = int(seq_str[-6:-3]) % 1000
                    xor_key3 = int(seq_str[-9:-6]) % 1000
                    xor_key_info = f"{xor_key1},{xor_key2},{xor_key3} (enhanced from seq {sequence})"
                
                # Extract checksum values for logging (these were calculated earlier)
                # received_ip_checksum and received_tcp_checksum are already available
                # calculated_ip_checksum and calculated_tcp_checksum are already available
                
                # Calculate payload preview for logging
                payload_preview = ""
                if tcp_payload and len(tcp_payload) > 0:
                    try:
                        if len(tcp_payload) <= 50:
                            payload_preview = tcp_payload.decode('utf-8', errors='replace')
                        else:
                            payload_preview = tcp_payload[:30].decode('utf-8', errors='replace') + "..."
                    except:
                        payload_preview = tcp_payload[:20].hex() + "..." if len(tcp_payload) > 20 else tcp_payload.hex()
                else:
                    payload_preview = "(no payload)"
                
                # Calculate timing values
                delta = 0
                if last_usec > 0:
                    current_usec = int(current_time * 1000000)
                    delta = current_usec - last_usec
                
                # Calculate sequence gap
                sequence_gap = max(0, seq - expected_seq)
                
                # Additional calculated values for comprehensive logging
                tcp_header_len = ((doff_reserved >> 4) * 4) if 'doff_reserved' in locals() else 20
                is_duplicate = seq in processed_sequences
                is_out_of_order = seq > expected_seq
                retransmission_detected = seq in last_packets  # Check if we've seen this sequence before
                
                # === CSV LOGGING ===
                # Log this packet to CSV for analysis
                current_time = time.time()
                decoded_char = chr(secret) if 32 <= secret <= 126 else '?'
                csv_log.append({
                    'timestamp': current_time,
                    'timestamp_us': int(current_time * 1000000),
                    'seq_num': seq,
                    'ack_num': acknowledgement,
                    'raw_window_size': window,
                    'window_base': window_base,
                    'window_covert': covert_part,
                    'decoded_value': secret,
                    'original_char': chr(original_secret) if 32 <= original_secret <= 126 else '?',
                    'decoded_char': decoded_char,
                    'encoding_mode': mode,
                    'initial_seq': initial_seq_number,
                    'xor_key': xor_key_info,
                    'sender_ip': s_addr,
                    'sender_port': source_port,
                    'receiver_ip': d_addr,
                    'receiver_port': dest_port,
                    'tcp_flags': f"0x{tcp_flags:02x}",
                    'tcp_flags_hex': f"{tcp_flags:02x}",
                    'payload_size': len(tcp_payload) if 'tcp_payload' in locals() else 0,
                    'total_packet_size': len(packet),
                    'ip_header_length': iph_length,
                    'tcp_header_length': tcp_header_len,
                    'is_corrupted': is_likely_corrupted,
                    'corruption_reasons': ', '.join(corruption_reasons),
                    'was_corrected': was_corrected,
                    'correction_method': 'dynamic' if mode in ['xor', 'xor1', 'xor2', 'xor3', 'random', 'random3'] else 'ascii',
                    'is_duplicate': is_duplicate,
                    'is_out_of_order': is_out_of_order,
                    'expected_seq': expected_seq,
                    'sequence_gap': sequence_gap,
                    'packet_buffer_size': len(packet_buffer),
                    'missing_packets': missing,
                    'retransmission_detected': retransmission_detected,
                    'checksum_ip_valid': calculated_ip_checksum == received_ip_checksum,
                    'checksum_tcp_valid': calculated_tcp_checksum == received_tcp_checksum,
                    'checksum_ip_received': received_ip_checksum,
                    'checksum_tcp_received': received_tcp_checksum,
                    'inter_arrival_time_us': delta if seq > expected_seq else 0,
                    'cumulative_delay_ms': sum_ia / 1000 if seq > expected_seq else 0,
                    'processing_time_us': 0,
                    'congestion_window_hint': 0,
                    'cover_traffic_preview': payload_preview,
                    'run_number': run_number
                })
                
                # Check if this is the expected sequence number
                if seq == expected_seq:
                    # Mark this sequence as processed BEFORE sending ACK
                    processed_sequences.add(seq)
                    
                    # Send ACK acknowledging the packet we just received (seq + 1)
                    send_ack(s_addr, source_port, seq + 1)
                    
                    # Process in-order packet immediately
                    current_time = time.time()
                    current_usec = int(current_time * 1000000)
                    
                    # Calculate interarrival time
                    if last_usec > 0:
                        delta = current_usec - last_usec
                        sum_ia += delta
                        sum_sq_ia += delta * delta
                        count_ia += 1
                    
                    last_usec = current_usec
                    
                    # Move to next expected sequence
                    expected_seq += 1
                    
                    # Clean up missing sequence tracking for the processed sequence
                    if (seq in missing_seq_timeout):
                        del missing_seq_timeout[seq]
                    
                    # Handle EOF marker
                    if secret == 0x04 and not eof_received and not is_likely_corrupted:  # EOF marker - only if not corrupted
                        print(f"[✔] Received EOF marker - seq {seq}")
                        eof_received = True
                        eof_timeout = current_time + 10.0  # Ignore packets for next 10 seconds (increased from 5)
                        
                        # IMPORTANT: Process all remaining buffered packets before completing transmission
                        print(f"[i] Processing all remaining buffered packets before completing transmission...")
                        
                        # First, process any buffered packets that are now in sequence
                        process_buffered_packets()
                        
                        # Then, process any remaining buffered packets even if they're out of order
                        # This ensures we don't lose any data that arrived before EOF
                        remaining_packets = sorted(packet_buffer.keys())
                        if remaining_packets:
                            print(f"[i] Found {len(remaining_packets)} remaining buffered packets: {remaining_packets}")
                            
                            for buffered_seq in remaining_packets:
                                if buffered_seq < seq:  # Only process packets that came before EOF
                                    secret_buf, packet_time, was_corrected, is_corrupted, buffered_payload = packet_buffer[buffered_seq]
                                    
                                    # Remove from buffer
                                    del packet_buffer[buffered_seq]
                                    processed_sequences.add(buffered_seq)
                                    
                                    # Send ACK for this buffered packet
                                    if sender_info:
                                        send_ack(sender_info[0], sender_info[1], buffered_seq + 1)
                                        print(f"[<] Sent ACK for remaining buffered seq {buffered_seq}")
                                    
                                    # Add to buffer if it's not EOF and not corrupted beyond repair
                                    if secret_buf != 0x04 and len(covert_buffer) < MAX_FILE_SIZE:
                                        if is_corrupted and secret_buf == 0:
                                            secret_buf = ord('?')  # Substitute corrupted zero bytes
                                        
                                        covert_buffer.append(secret_buf)
                                        
                                        if 32 <= secret_buf <= 126:
                                            correction_info = " (corrected)" if was_corrected else ""
                                            corruption_info = " [CORRUPTED]" if is_corrupted else ""
                                            print(f"[<] Processed remaining '{chr(secret_buf)}' ({secret_buf}) - seq {buffered_seq}{correction_info}{corruption_info}")
                                        else:
                                            correction_info = " (corrected)" if was_corrected else ""
                                            corruption_info = " [CORRUPTED]" if is_corrupted else ""
                                            print(f"[<] Processed remaining byte {secret_buf:#04x} - seq {buffered_seq}{correction_info}{corruption_info}")
                                else:
                                    print(f"[i] Ignoring buffered packet seq {buffered_seq} - arrived after EOF seq {seq}")
                        
                        # Clear any remaining buffer entries
                        packet_buffer.clear()
                        
                        print(f"[✔] All buffered packets processed, completing transmission...")
                        
                        # Process the complete message (no file writing)
                        # Verify if this is a checksum-protected transmission
                        valid_checksum = False
                        try_checksums = [4, 5]  # Try both 4 and 5 byte checksums
                        
                        for checksum_size in try_checksums:
                            if len(covert_buffer) >= checksum_size:
                                try:
                                    # Extract message and digest
                                    message_data = covert_buffer[:-checksum_size]
                                    received_digest = covert_buffer[-checksum_size:]
                                    
                                    # Calculate digest for verification
                                    calculated_digest = hashlib.md5(message_data).digest()[:checksum_size]
                                    
                                    if received_digest == calculated_digest:
                                        print(f"[✔] Checksum verification passed (using {checksum_size} bytes)")
                                        covert_buffer = message_data  # Remove checksum from data
                                        valid_checksum = True
                                        break
                                except Exception as e:
                                    print(f"[!] Error verifying checksum: {e}")
                        
                        if not valid_checksum and len(covert_buffer) >= 4:
                            print(f"[✘] Checksum verification failed!")
                        
                        # Post-processing: Fix common errors in text
                        
                        print(f"[✔] Transmission complete ({len(covert_buffer)} bytes received)")
                        print(f"[i] Deduplicated {duplicate_count} packets during reception")
                        print(f"[i] Corrected {error_corrected} errors during reception")
                        
                        reliability = (reliable_packets / total_packets * 100) if total_packets > 0 else 0
                        print(f"[i] Transmission reliability: {reliability:.2f}% ({reliable_packets}/{total_packets} packets)")
                        print(f"[i] Packets dropped due to checksum failures: {dropped_packets}")
                        
                        # Display received covert content
                        print(f"\n{'='*60}")
                        print(f"🔴 COVERT DATA (Hidden in TCP Window Sizes)")
                        print(f"{'='*60}")
                        try:
                            text_content = covert_buffer.decode('utf-8', errors='replace')
                            if all(32 <= ord(c) <= 126 or ord(c) in [9, 10, 13] for c in text_content[:100]):
                                print("--- Start of received covert text ---")
                                print(text_content)
                                print("--- End of received covert text ---")
                            else:
                                print(f"--- Received covert binary data ({len(covert_buffer)} bytes) ---")
                                # Show hex dump for binary data
                                hex_data = covert_buffer[:100].hex()
                                print(' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2)))
                                if len(covert_buffer) > 100:
                                    print("... (truncated)")
                                print("--- End of covert binary data ---")
                                
                                # Also show as characters with substitution for non-printable
                                print(f"--- As characters (non-printable shown as '?') ---")
                                char_output = ""
                                for byte_val in covert_buffer:
                                    if 32 <= byte_val <= 126:
                                        char_output += chr(byte_val)
                                    else:
                                        char_output += '?'
                                print(char_output)
                                print("--- End of character representation ---")
                                
                        except Exception:
                            print(f"--- Received covert data ({len(covert_buffer)} bytes) ---")
                            print("Unable to decode as text")
                            print("--- End of covert data ---")
                        
                        # Display received cover traffic
                        print(f"\n{'='*60}")
                        print(f"🟢 COVER TRAFFIC (Legitimate TCP Payload Data)")
                        print(f"{'='*60}")
                        if len(cover_traffic_buffer) > 0:
                            try:
                                cover_text = cover_traffic_buffer.decode('utf-8', errors='replace')
                                # Check if it looks like text
                                if all(32 <= ord(c) <= 126 or ord(c) in [9, 10, 13] for c in cover_text[:200]):
                                    print("--- Start of received cover traffic ---")
                                    print(cover_text)
                                    print("--- End of received cover traffic ---")
                                else:
                                    print(f"--- Received cover binary data ({len(cover_traffic_buffer)} bytes) ---")
                                    # Show hex dump for binary data
                                    hex_data = cover_traffic_buffer[:200].hex()
                                    print(' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2)))
                                    if len(cover_traffic_buffer) > 200:
                                        print("... (truncated)")
                                    print("--- End of cover binary data ---")
                                    
                                    # Also show as characters
                                    print(f"--- As characters (non-printable shown as '?') ---")
                                    char_output = ""
                                    for byte_val in cover_traffic_buffer[:500]:  # Limit to 500 chars
                                        if 32 <= byte_val <= 126:
                                            char_output += chr(byte_val)
                                        else:
                                            char_output += '?'
                                    print(char_output)
                                    if len(cover_traffic_buffer) > 500:
                                        print("... (truncated)")
                                    print("--- End of character representation ---")
                                    
                            except Exception:
                                print(f"--- Received cover data ({len(cover_traffic_buffer)} bytes) ---")
                                print("Unable to decode cover traffic")
                                print("--- End of cover data ---")
                        else:
                            print("--- No cover traffic received (header-only packets) ---")
                        
                        # Save to files
                        try:
                            # Extract directory from output_prefix if it contains a path
                            output_dir = os.path.dirname(output_prefix) if output_prefix and os.path.dirname(output_prefix) else ""
                            output_base = os.path.basename(output_prefix) if output_prefix else "received_data"
                            
                            # Save covert data
                            if output_dir:
                                covert_filename = os.path.join(output_dir, f"{output_base}_covert_run_{run_number}.txt")
                            else:
                                covert_filename = f"received_covert_run_{run_number}.txt"
                            with open(covert_filename, 'wb') as f:
                                f.write(covert_buffer)
                            print(f"\n[✔] Saved covert data to {covert_filename}")
                            
                            # Save cover traffic  
                            if len(cover_traffic_buffer) > 0:
                                if output_dir:
                                    cover_filename = os.path.join(output_dir, f"{output_base}_cover_run_{run_number}.txt")
                                else:
                                    cover_filename = f"received_cover_run_{run_number}.txt"
                                with open(cover_filename, 'wb') as f:
                                    f.write(cover_traffic_buffer)
                                print(f"[✔] Saved cover traffic to {cover_filename}")
                            
                            # Also save readable versions
                            try:
                                # Readable covert text
                                if output_dir:
                                    covert_readable_filename = os.path.join(output_dir, f"{output_base}_covert_run_{run_number}_readable.txt")
                                else:
                                    covert_readable_filename = f"received_covert_run_{run_number}_readable.txt"
                                readable_covert = ""
                                for byte_val in covert_buffer:
                                    if 32 <= byte_val <= 126 or byte_val in [9, 10, 13]:
                                        readable_covert += chr(byte_val)
                                    else:
                                        readable_covert += '?'
                                
                                with open(covert_readable_filename, 'w', encoding='utf-8') as f:
                                    f.write(readable_covert)
                                print(f"[✔] Saved readable covert text to {covert_readable_filename}")
                                
                                # Readable cover text
                                if len(cover_traffic_buffer) > 0:
                                    if output_dir:
                                        cover_readable_filename = os.path.join(output_dir, f"{output_base}_cover_run_{run_number}_readable.txt")
                                    else:
                                        cover_readable_filename = f"received_cover_run_{run_number}_readable.txt"
                                    readable_cover = ""
                                    for byte_val in cover_traffic_buffer:
                                        if 32 <= byte_val <= 126 or byte_val in [9, 10, 13]:
                                            readable_cover += chr(byte_val)
                                        else:
                                            readable_cover += '?'
                                    
                                    with open(cover_readable_filename, 'w', encoding='utf-8') as f:
                                        f.write(readable_cover)
                                    print(f"[✔] Saved readable cover text to {cover_readable_filename}")
                                
                            except Exception as e:
                                print(f"[!] Error saving readable versions: {e}")
                                
                        except Exception as e:
                            print(f"[!] Error saving to files: {e}")
                        
                        # Print summary instead of writing to file
                        print(f"[i] Summary - Run: {run_number}")
                        print(f"[i] Encoding mode: {mode.upper()}")
                        print(f"[i] Out-of-order packets: {out_of_order}")
                        print(f"[i] Missing packets: {missing}")
                        print(f"[i] Duplicate packets detected: {duplicate_count}")
                        print(f"[i] Errors corrected: {error_corrected}")
                        print(f"[i] Reliability: {reliability:.2f}%")
                        print(f"[i] Total bytes received: {len(covert_buffer)}")
                        
                        if count_ia > 1:
                            mean = sum_ia / count_ia
                            std = math.sqrt((sum_sq_ia / count_ia) - (mean * mean))
                            snr = mean / std if std > 0 else float('inf')
                            print(f"[i] Interarrival mean: {mean:.2f} µs")
                            print(f"[i] Interarrival stddev: {std:.2f} µs")
                            print(f"[i] SNR: {snr:.2f}")
                        
                        print(f"[✔] Transmission complete. Exiting receiver...")
                        
                        # Clean up and exit gracefully
                        recv_sock.close()
                        send_sock.close()
                        print(f"[✔] TCP Covert Channel Receiver shutdown complete.")
                        
                        # === WRITE CSV LOG ===
                        # Save CSV log to file
                        try:
                            with open(logfile_name, 'w', newline='', encoding='utf-8') as csvfile:
                                if csv_log:
                                    writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
                                    writer.writeheader()
                                    writer.writerows(csv_log)
                                    print(f"[✔] Saved CSV log with {len(csv_log)} entries to {logfile_name}")
                                else:
                                    # Write empty CSV with headers
                                    writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
                                    writer.writeheader()
                                    print(f"[✔] Saved empty CSV log to {logfile_name}")
                        except Exception as e:
                            print(f"[!] Error writing CSV log: {e}")
                        
                        return  # Exit the function and terminate the program
                    
                    elif secret == 0x04 and is_likely_corrupted:
                        # Corrupted EOF - treat as regular corrupted data
                        print(f"[!] Corrupted EOF marker detected - seq {seq} (reasons: {','.join(corruption_reasons)}) - treating as data")
                        secret = ord('?')  # Substitute with question mark
                        if len(covert_buffer) < MAX_FILE_SIZE:
                            covert_buffer.append(secret)
                            print(f"[<] Received '?' (corrupted EOF) - seq {seq} [CORRUPTED]")
                        
                        # After processing in-order packet, check for buffered packets
                        if process_buffered_packets():
                            # EOF was found in buffered packets - trigger transmission completion
                            print(f"[✔] EOF found in buffered packets during regular processing, transmission complete. Exiting receiver...")
                            
                            # Clean up and exit gracefully
                            recv_sock.close()
                            send_sock.close()
                            print(f"[✔] TCP Covert Channel Receiver shutdown complete.")
                            
                            # === WRITE CSV LOG ===
                            # Save CSV log to file
                            try:
                                with open(logfile_name, 'w', newline='', encoding='utf-8') as csvfile:
                                    if csv_log:
                                        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
                                        writer.writeheader()
                                        writer.writerows(csv_log)
                                        print(f"[✔] Saved CSV log with {len(csv_log)} entries to {logfile_name}")
                                    else:
                                        # Write empty CSV with headers
                                        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
                                        writer.writeheader()
                                        print(f"[✔] Saved empty CSV log to {logfile_name}")
                            except Exception as e:
                                print(f"[!] Error writing CSV log: {e}")
                            
                            return  # Exit the function and terminate the program
                    
                    elif not eof_received:  # Regular data
                        if len(covert_buffer) < MAX_FILE_SIZE:
                            # Handle corrupted data
                            if is_likely_corrupted:
                                # Try to recover or substitute
                                if secret == 0:
                                    # Substitute with a placeholder or skip
                                    print(f"[!] Corrupted packet seq {seq} (reasons: {','.join(corruption_reasons)}) - substituting with '?'")
                                    secret = ord('?')  # Substitute with question mark
                                else:
                                    print(f"[!] Possibly corrupted packet seq {seq} (reasons: {','.join(corruption_reasons)}) - using value {secret}")
                            
                            covert_buffer.append(secret)
                            
                            if 32 <= secret <= 126:  # Printable ASCII
                                correction_info = " (corrected)" if was_corrected else ""
                                corruption_info = " [CORRUPTED]" if is_likely_corrupted else ""
                                print(f"[<] Received '{chr(secret)}' ({secret}) - seq {seq}{correction_info}{corruption_info}")
                            else:
                                correction_info = " (corrected)" if was_corrected else ""
                                corruption_info = " [CORRUPTED]" if is_likely_corrupted else ""
                                print(f"[<] Received byte {secret:#04x} - seq {seq}{correction_info}{corruption_info}")
                        else:
                            print("[!] Buffer overflow — dropping data")
                        
                        # After processing in-order packet, check for buffered packets
                        if process_buffered_packets():
                            # EOF was found in buffered packets - trigger transmission completion
                            print(f"[✔] EOF found in buffered packets during regular processing, transmission complete. Exiting receiver...")
                            
                            # Clean up and exit gracefully
                            recv_sock.close()
                            send_sock.close()
                            print(f"[✔] TCP Covert Channel Receiver shutdown complete.")
                            
                            # === WRITE CSV LOG ===
                            # Save CSV log to file
                            try:
                                with open(logfile_name, 'w', newline='', encoding='utf-8') as csvfile:
                                    if csv_log:
                                        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
                                        writer.writeheader()
                                        writer.writerows(csv_log)
                                        print(f"[✔] Saved CSV log with {len(csv_log)} entries to {logfile_name}")
                                    else:
                                        # Write empty CSV with headers
                                        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
                                        writer.writeheader()
                                        print(f"[✔] Saved empty CSV log to {logfile_name}")
                            except Exception as e:
                                print(f"[!] Error writing CSV log: {e}")
                            
                            return  # Exit the function and terminate the program
                
                elif seq < expected_seq:
                    # Old packet that arrived late - likely duplicate or retransmission
                    # This happens when our ACK was corrupted and sender retransmitted
                    if seq in processed_sequences:
                        duplicate_count += 1
                        # IMPORTANT: Re-send ACK for already processed packets
                        # This handles the case where our original ACK was corrupted
                        send_ack(s_addr, source_port, seq + 1)
                        if duplicate_count % 10 == 0:
                            print(f"[i] Re-sent ACK for duplicate packet seq {seq} (expected {expected_seq}) - total duplicates: {duplicate_count}")
                        else:
                            print(f"[<] Re-sent ACK for duplicate seq {seq} (original ACK likely corrupted)")
                    else:
                        # This is an old packet we haven't seen before (very rare)
                        # Still send ACK to help sender progress
                        send_ack(s_addr, source_port, seq + 1)
                        print(f"[i] Sent ACK for old unseen packet seq {seq} (expected {expected_seq}) - likely retransmission")
                    continue
                
                elif seq > expected_seq:
                    # Future packet - buffer it for later processing
                    missing_count = seq - expected_seq
                    
                    # Track missing sequences for recovery
                    current_time = time.time()
                    for missing_seq in range(expected_seq, seq):
                        if missing_seq not in missing_seq_timeout:
                            missing_seq_timeout[missing_seq] = current_time
                            print(f"[!] Started tracking missing seq {missing_seq}")
                    
                    # Only buffer if the gap is reasonable (not due to corruption)
                    if missing_count <= 10:  # Reduced from 50 to be more conservative
                        print(f"[!] Received future packet seq {seq}, expected {expected_seq} (missing {missing_count} packets) - buffering")
                        missing += missing_count
                        
                        # Buffer the out-of-order packet (don't send ACK yet)
                        if seq not in packet_buffer:  # Avoid duplicates
                            packet_buffer[seq] = (secret, current_time, was_corrected, is_likely_corrupted, tcp_payload)
                            print(f"[i] Buffered packet seq {seq} for later processing (no ACK sent)")
                            
                            # Send NACK (duplicate ACK) for the last successfully received sequence
                            # This helps the sender know we're missing packets
                            if expected_seq > 2000:  # Only if we've received at least one packet
                                last_good_seq = expected_seq - 1
                                send_ack(s_addr, source_port, last_good_seq + 1)
                                print(f"[<] Sent NACK (duplicate ACK) for last good seq {last_good_seq} to signal missing packets")
                        else:
                            print(f"[i] Duplicate future packet seq {seq} - ignoring")
                    else:
                        # Large gap, probably corruption in sequence number
                        print(f"[!] Large sequence gap detected ({missing_count}), likely sequence corruption - ignoring")
                
                # Check for timed-out missing sequences and request retransmission
                current_time = time.time()
                timeout_threshold = 2.0  # Reduced from 5.0 to 2.0 seconds for faster recovery in high corruption
                sequences_to_remove = []
                
                for missing_seq, first_detected in missing_seq_timeout.items():
                    if current_time - first_detected > timeout_threshold:
                        if missing_seq < expected_seq:
                            # This sequence should have been processed by now, remove from tracking
                            sequences_to_remove.append(missing_seq)
                        else:
                            # Still missing and timed out - send NACK request
                            if expected_seq > 2000:
                                last_good_seq = expected_seq - 1
                                send_ack(s_addr, source_port, last_good_seq + 1)
                                print(f"[!] Missing seq {missing_seq} timed out - sending NACK for retransmission")
                            # Update timeout to avoid spam
                            missing_seq_timeout[missing_seq] = current_time
                
                # Remove processed missing sequences from tracking
                for seq_to_remove in sequences_to_remove:
                    del missing_seq_timeout[seq_to_remove]
                
            except Exception as e:
                # This might be a regular packet or heavily corrupted packet
                if window > 1000:  # Likely a regular packet
                    pass  # Silently ignore
                else:
                    print(f"[!] Error processing packet (seq: {sequence}, window: {window}): {e}")
                    # Don't send ACK for corrupted packets that cause exceptions
    
    recv_sock.close()
    send_sock.close()

def main():
    parser = argparse.ArgumentParser(description="TCP Covert Channel Receiver")
    
    parser.add_argument("--mode", type=str, choices=['ascii', 'xor', 'xor1', 'xor2', 'xor3', 'random', 'random3'], 
                       default='ascii', 
                       help="Encoding mode (ascii, xor, xor1, xor2, xor3, random, random3) [default: ascii]")
    parser.add_argument("--window-base", type=int, default=1000,
                        help="Base window size for binary/custom modes (legacy)")
    parser.add_argument("--port", type=int, default=PORT,
                        help="TCP port to listen on")
    parser.add_argument("--logfile", default="recv_log.csv",
                        help="Log file name")
    parser.add_argument("--output", default="received_data",
                       help="Output file prefix")
    parser.add_argument("--logdir", type=str, default=None,
                       help="Directory for all logs and output files")
    
    args = parser.parse_args()
    
    # Create log directory if specified
    if args.logdir:
        os.makedirs(args.logdir, exist_ok=True)
        # Update paths to include directory
        logfile_path = os.path.join(args.logdir, args.logfile)
        output_prefix_path = os.path.join(args.logdir, args.output)
        print(f"[+] Using log directory: {args.logdir}")
        print(f"[+] Log file: {logfile_path}")
        print(f"[+] Output prefix: {output_prefix_path}")
    else:
        logfile_path = args.logfile
        output_prefix_path = args.output
    
    print(f"[+] Starting TCP Covert Channel Receiver")
    print(f"[+] Mode: {args.mode.upper()}")
    if args.mode == 'ascii':
        print(f"[+] ASCII mode: Decoding printable characters (32-126)")
    elif args.mode in ['xor', 'xor1', 'xor2', 'xor3']:
        print(f"[+] {args.mode.upper()} mode: Using initial sequence number from handshake as XOR key")
    elif args.mode == 'random':
        print(f"[+] RANDOM mode: Using current packet sequence number as dynamic XOR key")
    elif args.mode == 'random3':
        print(f"[+] RANDOM3 mode: Enhanced triple XOR using different parts of current packet sequence number")
    
    # Start receiving
    receive_covert_data(
        mode=args.mode,
        window_base=args.window_base,
        port=args.port,
        logfile_name=logfile_path,
        output_prefix=output_prefix_path
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0) 