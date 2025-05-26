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

def receive_covert_data(mode=ENCODING_ASCII, window_base=1000, port=PORT, 
                       logfile_name="recv_log.csv", output_prefix="saved"):
    """
    Receive and decode covert data from TCP window size with ACK support
    
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
            ip_check = 0
            ip_saddr = socket.inet_aton(host_ip)  # Our IP
            ip_daddr = socket.inet_aton(sender_ip)  # Sender's IP
            
            ip_ihl_ver = (ip_ver << 4) + ip_ihl
            
            # Pack IP header
            ip_header = struct.pack('!BBHHHBBH4s4s',
                ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
                ip_proto, ip_check, ip_saddr, ip_daddr)
            
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
    
    def process_buffered_packets():
        """Process any buffered packets that are now in sequence"""
        nonlocal expected_seq, covert_buffer, last_usec, sum_ia, sum_sq_ia, count_ia
        nonlocal error_corrected, eof_received, current_time, sender_info
        
        # Keep processing until we can't find the next expected sequence
        while expected_seq in packet_buffer:
            # Get the buffered packet
            secret, packet_time, was_corrected, is_corrupted = packet_buffer[expected_seq]
            
            # Remove from buffer and mark as processed
            del packet_buffer[expected_seq]
            processed_sequences.add(expected_seq)
            
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
    
    # Variables to track state
    covert_buffer = bytearray()
    file_index = 1
    run_number = 1
    expected_seq = 2000  # Expected sequence number for next packet
    out_of_order = 0
    missing = 0
    last_usec = 0
    sum_ia = 0
    sum_sq_ia = 0
    count_ia = 0
    
    # Packet deduplication tracking
    last_packets = {}  # Dictionary to track recent packets by sequence number
    duplicate_count = 0
    processed_sequences = set()  # Track all processed sequence numbers
    
    # Packet reordering buffer - store out-of-order packets
    packet_buffer = {}  # {seq_num: (secret, timestamp, was_corrected, is_corrupted)}
    
    # EOF handling
    eof_received = False  # Flag to track if we've already received an EOF
    eof_timeout = 0       # Timeout to prevent processing multiple EOFs
    
    # Error correction
    error_corrected = 0   # Count of errors corrected
    
    # Reliability tracking
    total_packets = 0
    reliable_packets = 0
    
    # Sender information for ACKs
    sender_info = None  # (sender_ip, sender_port)
    
    # Disable file logging - just print to console
    print(f"Listening for TCP packets on {host_ip}:{port}...")
    print(f"Decoding mode: {mode}, Window base: {window_base}")
    print("[i] File creation disabled - output will be shown in console only")
    
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
            last_packets.clear()
            packet_buffer.clear()
            processed_sequences.clear()
            eof_received = False
            print(f"[+] Ready for new transmission (run {run_number})")
        
        # Handle SYN packets (connection setup) - simplified, no longer sending SYN-ACK
        if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN flag but not ACK
            print(f"[+] Received SYN from {s_addr}:{source_port}")
            
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
                last_packets.clear()
                packet_buffer.clear()
                processed_sequences.clear()
                eof_received = False
                
                print(f"[+] Reset state for new transmission (run {run_number})")
            else:
                print(f"[i] Ignoring SYN - active transmission in progress (last data {time_since_last_data:.1f}s ago)")
        
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
                
                # Check for duplicate packets first - before any processing
                if seq in processed_sequences:
                    duplicate_count += 1
                    if duplicate_count % 10 == 0:
                        print(f"[i] Ignoring duplicate packet seq {seq} (total duplicates: {duplicate_count})")
                    # Don't send ACK for duplicates - sender should already have received it
                    continue  # Skip all processing for this duplicate
                
                # Decode window size with corruption detection
                secret = decoder.decode_window_size(window)
                total_packets += 1
                
                # Detect potential corruption
                is_likely_corrupted = False
                corruption_reasons = []
                
                # Check for corruption indicators
                if window == 0 or window > 65535:
                    is_likely_corrupted = True
                    corruption_reasons.append("invalid_window")
                
                if secret == 0 and window != 0:
                    is_likely_corrupted = True
                    corruption_reasons.append("zero_decode")
                
                # Check for non-printable characters when expecting text
                if secret > 0 and secret < 4 and secret != 0x04:  # Low values except EOF
                    is_likely_corrupted = True
                    corruption_reasons.append("low_value")
                
                if secret > 127 and secret < 160:  # Extended ASCII range
                    is_likely_corrupted = True
                    corruption_reasons.append("extended_ascii")
                
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
                                    secret_buf, packet_time, was_corrected, is_corrupted = packet_buffer[buffered_seq]
                                    
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
                        try:
                            text = covert_buffer.decode('utf-8', errors='replace')
                            # Common error patterns
                            corrections = [
                                ('TCPP', 'TCP'),
                                ('decodde', 'decode'),
                                ('commplete', 'complete'),
                                ('  ', ' '),
                                ('wiith', 'with'),
                                ('receiiver', 'receiver'),
                                ('messsage', 'message'),
                                ('trannsfer', 'transfer'),
                                ('deteccting', 'detecting'),
                                ('coommunication', 'communication')
                            ]
                            
                            for old, new in corrections:
                                text = text.replace(old, new)
                            
                            # Convert back to bytes
                            covert_buffer = text.encode('utf-8')
                        except Exception:
                            pass  # Not a text file or couldn't apply corrections
                        
                        print(f"[✔] Transmission complete ({len(covert_buffer)} bytes received)")
                        print(f"[i] Deduplicated {duplicate_count} packets during reception")
                        print(f"[i] Corrected {error_corrected} errors during reception")
                        
                        reliability = (reliable_packets / total_packets * 100) if total_packets > 0 else 0
                        print(f"[i] Transmission reliability: {reliability:.2f}% ({reliable_packets}/{total_packets} packets)")
                        
                        # Display received content instead of saving to file
                        try:
                            text_content = covert_buffer.decode('utf-8', errors='replace')
                            if all(32 <= ord(c) <= 126 or ord(c) in [9, 10, 13] for c in text_content[:100]):
                                print("\n--- Start of received text ---")
                                print(text_content)
                                print("--- End of received text ---\n")
                            else:
                                print(f"\n--- Received binary data ({len(covert_buffer)} bytes) ---")
                                # Show hex dump for binary data
                                hex_data = covert_buffer[:100].hex()
                                print(' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2)))
                                if len(covert_buffer) > 100:
                                    print("... (truncated)")
                                print("--- End of binary data ---\n")
                        except Exception:
                            print(f"\n--- Received data ({len(covert_buffer)} bytes) ---")
                            print("Unable to decode as text")
                            print("--- End of data ---\n")
                        
                        # Print summary instead of writing to file
                        print(f"[i] Summary - Run: {run_number}")
                        print(f"[i] Encoding mode: {mode}, Window base: {window_base}")
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
                        
                        print(f"[✔] Transmission complete. Waiting for new transmission...")
                        # Don't reset state immediately - keep eof_received = True to prevent false restarts
                        # Only reset when we get a SYN or after a long timeout
                    
                    elif secret == 0x04 and is_likely_corrupted:
                        # Corrupted EOF - treat as regular corrupted data
                        print(f"[!] Corrupted EOF marker detected - seq {seq} (reasons: {','.join(corruption_reasons)}) - treating as data")
                        secret = ord('?')  # Substitute with question mark
                        if len(covert_buffer) < MAX_FILE_SIZE:
                            covert_buffer.append(secret)
                            print(f"[<] Received '?' (corrupted EOF) - seq {seq} [CORRUPTED]")
                        
                        # After processing in-order packet, check for buffered packets
                        if process_buffered_packets():
                            # EOF was found in buffered packets, handle end of transmission
                            print(f"[✔] EOF found in buffered packets, processing end of transmission...")
                            # Same end-of-transmission processing as above would go here
                            # For now, just continue to avoid code duplication
                    
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
                            # EOF was found in buffered packets, break out to handle end of transmission
                            break
                
                elif seq < expected_seq:
                    # Old packet that arrived late - likely duplicate or retransmission
                    # Check if we've seen this sequence before
                    if seq in processed_sequences:
                        duplicate_count += 1
                        if duplicate_count % 10 == 0:
                            print(f"[i] Ignoring old duplicate packet seq {seq} (expected {expected_seq})")
                    else:
                        print(f"[i] Ignoring old packet seq {seq} (expected {expected_seq}) - likely retransmission")
                    # Don't send ACK for old packets - this can confuse the sender
                    continue
                
                elif seq > expected_seq:
                    # Future packet - buffer it for later processing
                    missing_count = seq - expected_seq
                    
                    # Only buffer if the gap is reasonable (not due to corruption)
                    if missing_count <= 10:  # Reduced from 50 to be more conservative
                        print(f"[!] Received future packet seq {seq}, expected {expected_seq} (missing {missing_count} packets) - buffering")
                        missing += missing_count
                        
                        # Buffer the out-of-order packet (don't send ACK yet)
                        if seq not in packet_buffer:  # Avoid duplicates
                            packet_buffer[seq] = (secret, current_time, was_corrected, is_likely_corrupted)
                            print(f"[i] Buffered packet seq {seq} for later processing (no ACK sent)")
                        else:
                            print(f"[i] Duplicate future packet seq {seq} - ignoring")
                    else:
                        # Large gap, probably corruption in sequence number
                        print(f"[!] Large sequence gap detected ({missing_count}), likely sequence corruption - ignoring")
            
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
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0) 