#!/usr/bin/env python3
import os
import sys
import socket
import struct
import time
import math
import argparse
import hashlib
import threading
import queue
from ctypes import *
from array import array
from collections import OrderedDict, defaultdict
import random

# Constants
PORT = 8888
BUFFER_SIZE = 65536
MAX_FILE_SIZE = 100000
WINDOW_SIZE = 32  # Sliding window size
ACK_TIMEOUT = 2.0  # Timeout for ACK packets
MAX_RETRIES = 3    # Maximum retransmission attempts

# Encoding modes
ENCODING_BINARY = 'binary'
ENCODING_ASCII = 'ascii'
ENCODING_CUSTOM = 'custom'

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

class HammingCode:
    """Simple Hamming(7,4) error correction code"""
    
    @staticmethod
    def encode_nibble(nibble):
        """Encode 4-bit nibble to 7-bit Hamming code"""
        # Generator matrix for Hamming(7,4)
        d = [0] * 4
        for i in range(4):
            d[i] = (nibble >> i) & 1
        
        # Calculate parity bits
        p1 = d[0] ^ d[1] ^ d[3]
        p2 = d[0] ^ d[2] ^ d[3]  
        p3 = d[1] ^ d[2] ^ d[3]
        
        # Return 7-bit codeword: p1 p2 d0 p3 d1 d2 d3
        return (p1) | (p2 << 1) | (d[0] << 2) | (p3 << 3) | (d[1] << 4) | (d[2] << 5) | (d[3] << 6)
    
    @staticmethod
    def decode_hamming(codeword):
        """Decode 7-bit Hamming code to 4-bit nibble with error correction"""
        # Extract bits
        p1 = codeword & 1
        p2 = (codeword >> 1) & 1
        d0 = (codeword >> 2) & 1
        p3 = (codeword >> 3) & 1
        d1 = (codeword >> 4) & 1
        d2 = (codeword >> 5) & 1
        d3 = (codeword >> 6) & 1
        
        # Calculate syndrome
        s1 = p1 ^ d0 ^ d1 ^ d3
        s2 = p2 ^ d0 ^ d2 ^ d3
        s3 = p3 ^ d1 ^ d2 ^ d3
        
        syndrome = s1 | (s2 << 1) | (s3 << 2)
        
        # Error correction
        if syndrome != 0:
            # Single bit error - correct it
            error_pos = syndrome - 1
            if 0 <= error_pos < 7:
                codeword ^= (1 << error_pos)
                # Re-extract corrected bits
                d0 = (codeword >> 2) & 1
                d1 = (codeword >> 4) & 1
                d2 = (codeword >> 5) & 1
                d3 = (codeword >> 6) & 1
        
        # Return 4-bit data
        return d0 | (d1 << 1) | (d2 << 2) | (d3 << 3)
    
    @staticmethod
    def encode_byte(byte_val):
        """Encode a byte using Hamming codes"""
        low_nibble = byte_val & 0x0F
        high_nibble = (byte_val >> 4) & 0x0F
        
        encoded_low = HammingCode.encode_nibble(low_nibble)
        encoded_high = HammingCode.encode_nibble(high_nibble)
        
        return encoded_low, encoded_high
    
    @staticmethod
    def decode_byte(encoded_low, encoded_high):
        """Decode a byte from Hamming codes with error correction"""
        low_nibble = HammingCode.decode_hamming(encoded_low)
        high_nibble = HammingCode.decode_hamming(encoded_high)
        
        return low_nibble | (high_nibble << 4)

class SlidingWindowBuffer:
    """Sliding window buffer for handling out-of-order packets"""
    
    def __init__(self, window_size=WINDOW_SIZE):
        self.window_size = window_size
        self.base_seq = None  # Will be set when first packet arrives
        self.next_seq = None  # Will be set when first packet arrives
        self.buffer = {}  # seq_num -> data
        self.received = set()  # set of received sequence numbers
        self.delivered = OrderedDict()  # ordered delivery buffer
        self.initialized = False
        
    def add_packet(self, seq_num, data):
        """Add packet to buffer"""
        # Initialize on first packet
        if not self.initialized:
            self.base_seq = seq_num
            self.next_seq = seq_num
            self.initialized = True
            print(f"[SLIDING WINDOW] Initialized with base_seq={seq_num}")
        
        # Check if this is a duplicate
        if seq_num in self.received:
            print(f"[DUPLICATE] Packet seq={seq_num} already received, skipping")
            return False, []  # Duplicate packet
        
        # Add to buffer
        self.buffer[seq_num] = data
        self.received.add(seq_num)
        print(f"[RECV] Adding packet seq={seq_num}, data={data}")
        
        # Try to deliver consecutive packets
        delivered_data = []
        
        # Deliver consecutive packets starting from next_seq
        while self.next_seq in self.buffer:
            delivered_data.append(self.buffer[self.next_seq])
            self.delivered[self.next_seq] = self.buffer[self.next_seq]
            del self.buffer[self.next_seq]
            self.next_seq += 1
        
        # Update base sequence
        if delivered_data:
            self.base_seq = self.next_seq
            
        if len(self.buffer) > 0:
            print(f"[RECV] Window buffer: {sorted(self.buffer.keys())}")
        
        return True, delivered_data
    
    def get_expected_seq(self):
        """Get the next expected sequence number"""
        return self.next_seq if self.next_seq is not None else 0
    
    def get_missing_sequences(self):
        """Get list of missing sequence numbers within window"""
        missing = []
        for i in range(self.base_seq, self.next_seq + self.window_size):
            if i not in self.received and i < self.next_seq + self.window_size:
                missing.append(i)
        return missing
    
    def is_in_window(self, seq_num):
        """Check if sequence number is within the current window"""
        return self.base_seq <= seq_num < self.base_seq + self.window_size

class ReliableCovertChannelDecoder:
    def __init__(self, mode=ENCODING_ASCII, window_base=1000, enable_fec=True):
        """
        Initialize the reliable covert channel decoder
        
        Args:
            mode: Encoding mode (ascii, binary, custom)
            window_base: Base window size for binary/custom modes
            enable_fec: Enable Forward Error Correction
        """
        self.mode = mode
        self.window_base = window_base
        self.enable_fec = enable_fec
        self.sliding_window = SlidingWindowBuffer()
        
        # Statistics
        self.total_packets = 0
        self.corrected_packets = 0
        self.duplicate_packets = 0
        self.out_of_order_packets = 0
        
        # ACK management
        self.ack_socket = None
        self.pending_acks = queue.Queue()
        self.last_ack_sent = None  # Track last ACK to avoid duplicates
        
    def setup_ack_socket(self, src_ip, dest_ip):
        """Setup socket for sending ACK packets"""
        try:
            self.ack_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.ack_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.src_ip = src_ip
            self.dest_ip = dest_ip
            
            # Start ACK sender thread
            self.ack_thread = threading.Thread(target=self._ack_sender_worker, daemon=True)
            self.ack_thread.start()
            
        except Exception as e:
            print(f"Warning: Could not setup ACK socket: {e}")
    
    def _ack_sender_worker(self):
        """Worker thread to send ACK packets"""
        while True:
            try:
                ack_info = self.pending_acks.get(timeout=1.0)
                if ack_info is None:  # Shutdown signal
                    break
                self._send_ack_packet(**ack_info)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in ACK sender: {e}")
    
    def _send_ack_packet(self, seq_num, ack_seq, window_size=65535):
        """Send an ACK packet"""
        if not self.ack_socket:
            return
            
        try:
            # Create ACK packet
            packet = self._create_ack_packet(seq_num, ack_seq, window_size)
            self.ack_socket.sendto(packet, (self.dest_ip, 0))
            print(f"[ACK] Sent ACK for seq {ack_seq}")
        except Exception as e:
            print(f"Error sending ACK: {e}")
    
    def _create_ack_packet(self, seq_num, ack_seq, window_size):
        """Create a TCP ACK packet"""
        # IP header
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20 + 20  # IP + TCP headers
        ip_id = 54321
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(self.src_ip)
        ip_daddr = socket.inet_aton(self.dest_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
            ip_proto, ip_check, ip_saddr, ip_daddr)
        
        # TCP header
        tcp_source = PORT
        tcp_dest = PORT
        tcp_seq = seq_num
        tcp_ack_seq = ack_seq
        tcp_doff = 5
        tcp_flags = 0x10  # ACK flag
        tcp_window = window_size
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
            tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
        
        # Calculate checksum
        psh = struct.pack('!4s4sBBH', 
            ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header))
        tcp_check = checksum(psh + tcp_header)
        
        # Repack with correct checksum
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
            tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
        
        return ip_header + tcp_header
    
    def send_ack(self, seq_num, ack_seq):
        """Queue an ACK packet to be sent"""
        # Avoid sending duplicate ACKs
        if self.last_ack_sent == ack_seq:
            return
            
        print(f"[SEND ACK] seq_num={seq_num}, ack_seq={ack_seq}")
        self.last_ack_sent = ack_seq
        
        if self.ack_socket:
            ack_info = {
                'seq_num': seq_num,
                'ack_seq': ack_seq,
                'window_size': 65535
            }
            try:
                self.pending_acks.put_nowait(ack_info)
            except queue.Full:
                pass  # ACK queue is full, skip this ACK
    
    def decode_window_size(self, window_size):
        """Decode a window size back to original byte value"""
        if self.mode == ENCODING_ASCII:
            return window_size
            
        elif self.mode == ENCODING_BINARY:
            # Inverse of the encoding operation
            window_size -= self.window_base
            byte_value = 0
            for i in range(8):
                if window_size & (1 << i):
                    byte_value |= (1 << i)
            return byte_value
            
        elif self.mode == ENCODING_CUSTOM:
            # Inverse of custom transform
            for i in range(256):
                if ((i * 167) % 251) + self.window_base == window_size:
                    return i
            return 0
            
        return window_size
    
    def process_packet(self, seq_num, window_size, use_fec=False):
        # Print window size as character if it's printable
        if 32 <= window_size <= 126:
            print(f"[RECV] seq={seq_num}, window={window_size} = '{chr(window_size)}'")
        else:
            print(f"[RECV] seq={seq_num}, window={window_size} (non-printable)")
            
        self.total_packets += 1
        
        # Decode window size
        if use_fec and self.enable_fec:
            # For FEC mode, we expect the data to be Hamming encoded
            # Split the window size into two parts for low and high nibbles
            if window_size >= 128:  # High nibble packet
                encoded_high = window_size - 128
                return None, False  # Wait for corresponding low nibble
            else:  # Low nibble packet
                encoded_low = window_size
                # For now, just decode without pairing
                # In a full implementation, you'd pair high/low nibbles
                decoded_byte = HammingCode.decode_hamming(encoded_low) & 0x0F
        else:
            decoded_byte = self.decode_window_size(window_size)
            
        # Add to sliding window buffer
        is_new, delivered_data = self.sliding_window.add_packet(seq_num, decoded_byte)
        
        if not is_new:
            self.duplicate_packets += 1
            return None, True  # Duplicate packet
        
        # Send ACK for this packet
        self.send_ack(seq_num + 1, seq_num + 1)
        
        # Check if packet was out of order
        if seq_num != self.sliding_window.get_expected_seq() - len(delivered_data):
            self.out_of_order_packets += 1
        
        return delivered_data, False

def receive_covert_data_reliable(mode=ENCODING_ASCII, window_base=1000, port=PORT, 
                                logfile_name="recv_log.csv", output_prefix="received_data",
                                enable_fec=True, enable_ack=True):
    """
    Receive and decode covert data with reliability mechanisms
    """
    host_ip = os.getenv('INSECURENET_HOST_IP')
    if not host_ip:
        print("INSECURENET_HOST_IP not set")
        sys.exit(1)
    
    dest_ip = os.getenv('SECURENET_HOST_IP')
    if not dest_ip:
        print("SECURENET_HOST_IP not set")
        enable_ack = False
    
    # Create decoder
    decoder = ReliableCovertChannelDecoder(mode=mode, window_base=window_base, enable_fec=enable_fec)
    
    # Setup ACK socket if enabled
    if enable_ack and dest_ip:
        decoder.setup_ack_socket(host_ip, dest_ip)
    
    # Create a raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print(f"Error creating socket: {e}")
        print("Note: This script requires root privileges")
        sys.exit(1)
    
    # State variables
    covert_buffer = bytearray()
    file_index = 1
    run_number = 1
    processed_packets = set()  # Track processed packets globally
    
    # Handshake state
    TCP_CLOSED = 0
    TCP_SYN_RECEIVED = 1
    TCP_ESTABLISHED = 2
    tcp_state = TCP_CLOSED
    sender_seq = None
    receiver_seq = None
    handshake_ack = None
    
    # Statistics
    start_time = time.time()
    last_progress_time = start_time
    
    # Open log file
    with open(logfile_name, "w") as logfile:
        logfile.write("run,seq,byte,encoded,time_us,corrected,duplicate\n")
        
        print(f"Listening for TCP packets on {host_ip}:{port}...")
        print(f"Decoding mode: {mode}, Window base: {window_base}")
        print(f"FEC enabled: {enable_fec}, ACK enabled: {enable_ack}")
        
        print("[RECV] Ready to accept any initial sequence number.")
        
        try:
            while True:
                # Receive packet
                packet = sock.recvfrom(BUFFER_SIZE)[0]
                
                # Extract IP header
                ip_header = packet[0:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                # IP header length
                ihl = (iph[0] & 0xF)
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
                tcp_flags = tcph[5]
                window = tcph[6]
                
                # Skip packets not destined for our port
                if dest_port != port:
                    continue
                
                # --- Handshake state machine ---
                if tcp_state == TCP_CLOSED:
                    if tcp_flags & 0x02:  # SYN
                        sender_seq = sequence
                        receiver_seq = random.randint(10000, 65000)
                        print(f"[HANDSHAKE] SYN received from sender_seq={sender_seq}")
                        # Send SYN-ACK
                        if decoder.ack_socket:
                            decoder._send_ack_packet(seq_num=receiver_seq, ack_seq=sender_seq+1)
                        tcp_state = TCP_SYN_RECEIVED
                        continue
                elif tcp_state == TCP_SYN_RECEIVED:
                    print(f"[HANDSHAKE] Waiting for ACK. Got ack={acknowledgement}, flags={tcp_flags:02x}")
                    if tcp_flags & 0x10:  # Any ACK packet
                        handshake_ack = acknowledgement
                        print(f"[HANDSHAKE] ACK received, handshake complete. Connection ESTABLISHED.")
                        tcp_state = TCP_ESTABLISHED
                        continue
                elif tcp_state == TCP_ESTABLISHED:
                    # Only process data packets from sender, not our own ACKs
                    if tcp_flags & 0x10 and not (tcp_flags & 0x02):  # ACK but not SYN
                        # Filter out our own ACK packets by checking source IP
                        if s_addr == host_ip:
                            continue  # Skip our own ACK packets
                        
                        # Additional global duplicate filter
                        packet_id = (sequence, window, s_addr)
                        if packet_id in processed_packets:
                            continue  # Skip already processed packets
                        processed_packets.add(packet_id)
                            
                        current_time = time.time()
                        current_usec = int(current_time * 1000000)
                        try:
                            delivered_data, is_duplicate = decoder.process_packet(
                                sequence, window, use_fec=enable_fec
                            )
                            if is_duplicate:
                                continue  # Skip duplicate packets
                            if delivered_data:
                                for data_byte in delivered_data:
                                    if data_byte == 0x04:
                                        print(f"[✔] Received EOF marker")
                                        
                                        # Determine file extension based on content
                                        try:
                                            text_content = covert_buffer.decode('utf-8', errors='strict')
                                            if all(32 <= ord(c) <= 126 or ord(c) in [9, 10, 13] for c in text_content):
                                                filename = f"{output_prefix}_{file_index}.txt"
                                            else:
                                                filename = f"{output_prefix}_{file_index}.bin"
                                        except UnicodeDecodeError:
                                            filename = f"{output_prefix}_{file_index}.bin"
                                        
                                        file_index += 1
                                        with open(filename, "wb") as fout:
                                            fout.write(covert_buffer)
                                        print(f"[✔] Saved file: {filename} ({len(covert_buffer)} bytes)")
                                        total_time = current_time - start_time
                                        print(f"[i] Total packets: {decoder.total_packets}")
                                        print(f"[i] Duplicate packets: {decoder.duplicate_packets}")
                                        print(f"[i] Out-of-order packets: {decoder.out_of_order_packets}")
                                        print(f"[i] Corrected packets: {decoder.corrected_packets}")
                                        print(f"[i] Reception time: {total_time:.2f} seconds")
                                        reliability = ((decoder.total_packets - decoder.duplicate_packets) / 
                                                     decoder.total_packets * 100) if decoder.total_packets > 0 else 0
                                        print(f"[i] Reliability: {reliability:.2f}%")
                                        
                                        # Display received text content
                                        try:
                                            text_content = covert_buffer.decode('utf-8', errors='replace')
                                            print("\n--- Start of received text ---")
                                            print(text_content)
                                            print("--- End of received text ---\n")
                                        except Exception:
                                            print("\n--- Received binary data ---")
                                            print(f"Content: {covert_buffer[:100]}{'...' if len(covert_buffer) > 100 else ''}")
                                            print("--- End of binary data ---\n")
                                        
                                        with open(f"{output_prefix}_summary_{run_number}.txt", "w") as summary:
                                            summary.write(f"Run: {run_number}\n")
                                            summary.write(f"Encoding mode: {mode}\n")
                                            summary.write(f"Window base: {window_base}\n")
                                            summary.write(f"FEC enabled: {enable_fec}\n")
                                            summary.write(f"ACK enabled: {enable_ack}\n")
                                            summary.write(f"Total packets: {decoder.total_packets}\n")
                                            summary.write(f"Duplicate packets: {decoder.duplicate_packets}\n")
                                            summary.write(f"Out-of-order packets: {decoder.out_of_order_packets}\n")
                                            summary.write(f"Corrected packets: {decoder.corrected_packets}\n")
                                            summary.write(f"Reliability: {reliability:.2f}%\n")
                                            summary.write(f"Total bytes received: {len(covert_buffer)}\n")
                                            summary.write(f"Reception time: {total_time:.2f} seconds\n")
                                        
                                        print(f"[✔] Message reception complete! Check {filename} for the received message.")
                                        return  # Exit after receiving complete message
                                    else:
                                        if len(covert_buffer) < MAX_FILE_SIZE:
                                            covert_buffer.append(data_byte)
                                            # Log with proper sequence tracking
                                            logfile.write(f"{run_number},{sequence},{data_byte},{window},"
                                                        f"{current_usec},false,false\n")
                                            if 32 <= data_byte <= 126:
                                                print(f"[RECV DATA] byte={data_byte} char='{chr(data_byte)}' buffer_pos={len(covert_buffer)}")
                                            else:
                                                print(f"[RECV DATA] byte={data_byte} (non-printable) buffer_pos={len(covert_buffer)}")
                                            if current_time - last_progress_time > 5.0:
                                                print(f"[i] Progress: {len(covert_buffer)} bytes received, "
                                                    f"{decoder.total_packets} total packets")
                                                last_progress_time = current_time
                                        else:
                                            print("[!] Buffer overflow — dropping data")
                        except Exception as e:
                            print(f"[!] Error processing packet: {e}")
                            continue
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        finally:
            if decoder.ack_socket:
                decoder.pending_acks.put_nowait(None)
                decoder.ack_socket.close()
            sock.close()

def main():
    parser = argparse.ArgumentParser(description="Reliable TCP Covert Channel Receiver")
    
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
    parser.add_argument("--no-fec", action="store_true",
                       help="Disable Forward Error Correction")
    parser.add_argument("--no-ack", action="store_true",
                       help="Disable ACK responses")
    
    args = parser.parse_args()
    
    # Start receiving
    receive_covert_data_reliable(
        mode=args.mode,
        window_base=args.window_base,
        port=args.port,
        logfile_name=args.logfile,
        output_prefix=args.output,
        enable_fec=not args.no_fec,
        enable_ack=not args.no_ack
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0) 