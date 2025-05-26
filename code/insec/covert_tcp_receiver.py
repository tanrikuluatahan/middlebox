#!/usr/bin/env python3
import os
import sys
import socket
import struct
import time
import math
import argparse
import hashlib
from ctypes import *
from array import array

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

def receive_covert_data(mode=ENCODING_ASCII, window_base=1000, port=PORT, 
                       logfile_name="recv_log.csv", output_prefix="saved"):
    """
    Receive and decode covert data from TCP window size
    
    Args:
        mode (str): Encoding mode (ascii, binary, custom)
        window_base (int): Base window size for binary/custom modes
        port (int): TCP port to listen on
        logfile_name (str): Log file to write
        output_prefix (str): Prefix for saved files
    """
    host_ip = os.getenv('INSECURENET_HOST_IP')
    if not host_ip:
        print("INSECURENET_HOST_IP not set")
        sys.exit(1)
    
    # Create decoder
    decoder = CovertChannelDecoder(mode=mode, window_base=window_base)
    
    # Create a raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print(f"Error creating socket: {e}")
        print("Note: This script requires root privileges")
        sys.exit(1)
    
    # Variables to track state
    covert_buffer = bytearray()
    file_index = 1
    run_number = 1
    last_seq = 0
    out_of_order = 0
    missing = 0
    last_usec = 0
    sum_ia = 0
    sum_sq_ia = 0
    count_ia = 0
    
    # Packet deduplication tracking
    last_packets = {}  # Dictionary to track recent packets by sequence number
    duplicate_count = 0
    
    # EOF handling
    eof_received = False  # Flag to track if we've already received an EOF
    eof_timeout = 0       # Timeout to prevent processing multiple EOFs
    
    # Open log file
    with open(logfile_name, "w") as logfile:
        logfile.write("run,index,byte,encoded,time_us\n")
        
        print(f"Listening for TCP packets on {host_ip}:{port}...")
        print(f"Decoding mode: {mode}, Window base: {window_base}")
        
        while True:
            # Receive packet
            packet = sock.recvfrom(BUFFER_SIZE)[0]
            
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
            
            # Handle SYN packets (connection setup)
            if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN flag but not ACK
                print(f"[+] Received SYN from {s_addr}:{source_port}")
                
                # Create SYN+ACK response
                # First, create IP header
                ip_ihl = 5
                ip_ver = 4
                ip_tos = 0
                ip_tot_len = 20 + 20  # IP header + TCP header
                ip_id = random.randint(0, 65535)
                ip_frag_off = 0
                ip_ttl = 64
                ip_proto = socket.IPPROTO_TCP
                ip_check = 0
                ip_saddr = socket.inet_aton(d_addr)  # Swap src/dst
                ip_daddr = socket.inet_aton(s_addr)
                
                ip_ihl_ver = (ip_ver << 4) + ip_ihl
                
                # Pack IP header
                ip_header = struct.pack('!BBHHHBBH4s4s',
                    ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
                    ip_proto, ip_check, ip_saddr, ip_daddr)
                
                # TCP header fields for SYN+ACK
                tcp_source = dest_port
                tcp_dest = source_port
                tcp_seq = 1000
                tcp_ack_seq = sequence + 1
                tcp_doff = 5  # Header length in 32-bit words
                tcp_flags = 0x12  # SYN + ACK flag
                tcp_window = 64240
                tcp_check = 0
                tcp_urg_ptr = 0
                
                # TCP header packing (excluding checksum)
                tcp_offset_res = (tcp_doff << 4) + 0
                
                tcp_header = struct.pack('!HHLLBBHHH',
                    tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                    tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
                
                # TCP pseudo header for checksum calculation
                src_addr = socket.inet_aton(d_addr)
                dst_addr = socket.inet_aton(s_addr)
                placeholder = 0
                protocol = socket.IPPROTO_TCP
                tcp_length = len(tcp_header)
                
                # Create pseudo packet for checksum calculation
                psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
                pseudo_packet = psh + tcp_header
                
                # Calculate TCP checksum
                tcp_check = checksum(pseudo_packet)
                
                # Construct TCP header again with correct checksum
                tcp_header = struct.pack('!HHLLBBHHH',
                    tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                    tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
                
                # Final packet
                packet = ip_header + tcp_header
                
                # Create a raw socket for sending
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                send_sock.sendto(packet, (s_addr, 0))
                send_sock.close()
                
                print(f"[+] Sent SYN-ACK to {s_addr}:{source_port}")
                
            # Handle ACK packets with potential covert data in window size
            elif tcp_flags & 0x10:  # ACK flag
                try:
                    # Decode window size
                    secret = decoder.decode_window_size(window)
                    seq = sequence
                    
                    # Packet deduplication: Check if we've seen this packet recently
                    packet_key = f"{seq}:{secret}:{source_port}"
                    current_time = time.time()
                    
                    # Skip if this is a duplicate packet (same seq, window size, and port)
                    if packet_key in last_packets:
                        if current_time - last_packets[packet_key] < 2.0:  # Within 2 seconds
                            duplicate_count += 1
                            if duplicate_count % 10 == 0:  # Only print occasionally
                                print(f"[i] Skipped {duplicate_count} duplicate packets so far")
                            continue
                    
                    # Add to recent packets cache
                    last_packets[packet_key] = current_time
                    
                    # Clean up old entries from the cache (older than 5 seconds)
                    for k in list(last_packets.keys()):
                        if current_time - last_packets[k] > 5.0:
                            del last_packets[k]
                    
                    # Get current time
                    current_usec = int(time.time() * 1000000)
                    
                    # Calculate interarrival time
                    if last_usec > 0:
                        delta = current_usec - last_usec
                        sum_ia += delta
                        sum_sq_ia += delta * delta
                        count_ia += 1
                    
                    last_usec = current_usec
                    
                    # Check for packet ordering issues
                    if last_seq != 0:
                        if seq < last_seq:
                            out_of_order += 1
                            print(f"[!] Out-of-order packet: {seq} < {last_seq}")
                        elif seq > last_seq + 1:
                            gap = seq - last_seq - 1
                            if gap > 0:
                                missing += gap
                                print(f"[!] Missing packets: {gap} packets lost")
                    
                    last_seq = seq
                    
                    # Handle EOF marker
                    if secret == 0x04 and not eof_received:  # EOF marker (only process if not already received)
                        print(f"[✔] Received EOF marker")
                        eof_received = True
                        eof_timeout = current_time + 5.0  # Ignore packets for next 5 seconds
                        
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
                        
                        filename = f"{output_prefix}_{file_index}.bin"
                        file_index += 1
                        
                        with open(filename, "wb") as fout:
                            fout.write(covert_buffer)
                        
                        print(f"[✔] Saved file: {filename} ({len(covert_buffer)} bytes)")
                        print(f"[i] Deduplicated {duplicate_count} packets during reception")
                        
                        # Try to detect text files and print content
                        try:
                            text_content = covert_buffer.decode('utf-8', errors='replace')
                            if all(32 <= ord(c) <= 126 or ord(c) in [9, 10, 13] for c in text_content[:100]):
                                print("\n--- Start of received text ---")
                                print(text_content[:500] + ('...' if len(text_content) > 500 else ''))
                                print("--- End of received text ---\n")
                        except Exception:
                            pass  # Not a text file, ignore
                        
                        # Write summary
                        with open(f"{output_prefix}_summary_{run_number}.txt", "w") as summary:
                            summary.write(f"Run: {run_number}\n")
                            summary.write(f"Encoding mode: {mode}\n")
                            summary.write(f"Window base: {window_base}\n")
                            summary.write(f"Out-of-order packets: {out_of_order}\n")
                            summary.write(f"Missing packets: {missing}\n")
                            summary.write(f"Duplicate packets detected: {duplicate_count}\n")
                            summary.write(f"Total bytes received: {len(covert_buffer)}\n")
                            summary.write("EOF received: yes\n")
                            
                            if count_ia > 1:
                                mean = sum_ia / count_ia
                                std = math.sqrt((sum_sq_ia / count_ia) - (mean * mean))
                                snr = mean / std if std > 0 else float('inf')
                                summary.write(f"Interarrival mean: {mean:.2f} µs\n")
                                summary.write(f"Interarrival stddev: {std:.2f} µs\n")
                                summary.write(f"SNR: {snr:.2f}\n")
                        
                        # Reset state for next run
                        covert_buffer = bytearray()
                        run_number += 1
                        last_seq = 0
                        out_of_order = 0
                        missing = 0
                        last_usec = 0
                        sum_ia = 0
                        sum_sq_ia = 0
                        count_ia = 0
                        duplicate_count = 0
                        last_packets.clear()
                        eof_received = False
                        
                        print(f"[i] Ready for next transmission (run {run_number})")
                    
                    elif secret == 0x04 and eof_received:
                        # Already received EOF marker, ignore
                        print(f"[i] Ignoring duplicate EOF marker")
                    
                    elif not eof_received:  # Regular data (only if we haven't received EOF)
                        if len(covert_buffer) < MAX_FILE_SIZE:
                            covert_buffer.append(secret)
                            logfile.write(f"{run_number},{len(covert_buffer)-1},{secret},{window},{current_usec}\n")
                            
                            if 32 <= secret <= 126:  # Printable ASCII
                                print(f"[<] Received '{chr(secret)}' ({secret}) - Decoded from window {window}")
                            else:
                                print(f"[<] Received byte {secret:#04x} - Decoded from window {window}")
                        else:
                            print("[!] Buffer overflow — dropping data")
                
                except Exception as e:
                    # This might be a regular packet or noise packet
                    if window > 1000:  # Likely a regular packet
                        pass  # Silently ignore
                    else:
                        print(f"[!] Error decoding window size {window}: {e}")

def main():
    parser = argparse.ArgumentParser(description="TCP Covert Channel Receiver")
    
    parser.add_argument("--mode", choices=[ENCODING_ASCII, ENCODING_BINARY, ENCODING_CUSTOM],
                        default=ENCODING_ASCII, help="Encoding mode")
    parser.add_argument("--window-base", type=int, default=1000,
                        help="Base window size for binary/custom modes")
    parser.add_argument("--port", type=int, default=PORT,
                        help="TCP port to listen on")
    parser.add_argument("--logfile", default="recv_log.csv",
                        help="Log file name")
    parser.add_argument("--output", default="received_data",
                       help="Output file prefix")
    
    args = parser.parse_args()
    
    # Start receiving
    receive_covert_data(
        mode=args.mode,
        window_base=args.window_base,
        port=args.port,
        logfile_name=args.logfile,
        output_prefix=args.output
    )

if __name__ == "__main__":
    try:
        import random
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0) 