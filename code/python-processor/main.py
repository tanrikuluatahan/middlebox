import asyncio
import argparse
import os
import random
import traceback
import time
import statistics
import collections
import json
import csv
from datetime import datetime
from nats.aio.client import Client as NATS
from scapy.all import Ether, IP, TCP, UDP, ICMP
import numpy as np
from scipy import stats

class CovertChannelDetector:
    """
    Advanced covert channel detection system for TCP window size covert channels
    """
    
    def __init__(self, detection_enabled=True, log_file="detection_log.csv", alert_threshold=0.7, packet_log_file=None):
        """
        Initialize the covert channel detector
        
        Args:
            detection_enabled: Whether to perform detection
            log_file: File to log detection results
            alert_threshold: Threshold for triggering alerts (0.0-1.0)
            packet_log_file: File to log all packet information
        """
        self.detection_enabled = detection_enabled
        self.alert_threshold = alert_threshold
        
        # Create logs directory if it doesn't exist
        logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Set up log file paths
        timestamp = int(time.time())
        self.log_file = os.path.join(logs_dir, f"detection_log_{timestamp}.csv")
        self.packet_log_file = os.path.join(logs_dir, f"packet_log_{timestamp}.csv") if packet_log_file is None else packet_log_file
        
        # Traffic analysis data structures
        self.window_sizes = collections.deque(maxlen=1000)  # Recent window sizes
        self.packet_count = 0
        self.tcp_flows = {}  # Track individual TCP flows
        self.detection_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'suspicious_packets': 0,
            'alerts_triggered': 0,
            'covert_probability_sum': 0.0
        }
        
        # Detection algorithms - Realistic window size covert channel detection
        self.detection_methods = {
            'entropy': self._detect_entropy_anomaly,
            'ascii_encoding': self._detect_ascii_encoding,
            'ascii_3digit_pattern': self._detect_ascii_3digit_pattern,
            'xor_encoding': self._detect_xor_encoding,
            'window_legitimacy': self._detect_window_legitimacy,
            'oscillation_patterns': self._detect_oscillation_patterns,
            'frequency_domain': self._detect_frequency_domain,
            'benford_law': self._detect_benford_law,
            'timing_correlation': self._detect_timing_correlation,
            'payload_correlation': self._detect_payload_correlation
        }
        
        # Packet statistics
        self.packet_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'corrupted_packets': 0,
            'bytes_processed': 0
        }
        
        # Initialize CSV logging
        if self.detection_enabled:
            self._init_csv_logging()
        self._init_packet_csv_logging()
        
        print(f"[MIDDLEBOX] Covert channel detector initialized")
        print(f"[MIDDLEBOX] Detection: {'ENABLED' if detection_enabled else 'DISABLED'}")
        print(f"[MIDDLEBOX] Detection log: {self.log_file}")
        print(f"[MIDDLEBOX] Packet log: {self.packet_log_file}")
        print(f"[MIDDLEBOX] Alert threshold: {alert_threshold}")
    
    def _init_csv_logging(self):
        """Initialize CSV logging for detection results"""
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            
            with open(self.log_file, 'w', newline='') as csvfile:
                headers = [
                    'timestamp', 'packet_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                    'window_size', 'window_base', 'window_covert', 'sequence_num', 'ack_num',
                    'flags', 'payload_size', 'flow_id', 'detection_score', 'alert_triggered',
                    'entropy_score', 'ascii_encoding_score', 'xor_encoding_score',
                    'window_legitimacy_score', 'oscillation_patterns_score', 'frequency_domain_score', 
                    'benford_law_score', 'timing_correlation_score', 'payload_correlation_score',
                    'detected_methods', 'potential_decoded_chars', 'confidence_level'
                ]
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                print(f"[MIDDLEBOX] Detection log initialized: {self.log_file}")
        except Exception as e:
            print(f"[DETECTOR] Error initializing detection log: {e}")
            traceback.print_exc()
    
    def _init_packet_csv_logging(self):
        """Initialize CSV logging for all packets"""
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.packet_log_file), exist_ok=True)
            
            with open(self.packet_log_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Comprehensive packet log headers
                headers = [
                    'timestamp', 'timestamp_us', 'packet_index', 'direction',
                    'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                    'packet_size', 'ip_header_length', 'protocol_header_length',
                    'payload_size', 'tcp_seq', 'tcp_ack', 'tcp_window',
                    'tcp_flags', 'tcp_flags_hex', 'window_base', 'window_covert',
                    'checksum_ip_valid', 'checksum_protocol_valid',
                    'checksum_ip_received', 'checksum_protocol_received',
                    'is_corrupted', 'corruption_applied', 'ttl', 'ip_version',
                    'ip_tos', 'ip_id', 'ip_fragment_offset', 'tcp_urgent_ptr',
                    'tcp_options_length', 'flow_id', 'inter_arrival_time_us',
                    'detection_enabled', 'detection_score', 'alert_triggered',
                    'high_risk_methods', 'decoded_char_candidate',
                    'suspected_encoding_mode', 'flow_packet_count', 'flow_duration',
                    'mitigation_triggered', 'mitigation_strategies', 'mitigation_action',
                    'packet_dropped', 'packet_delayed_ms', 'window_modified',
                    'original_window', 'new_window', 'payload_preview'
                ]
                writer.writerow(headers)
                print(f"[MIDDLEBOX] Packet log initialized: {self.packet_log_file}")
        except Exception as e:
            print(f"[ERROR] Failed to initialize packet log: {e}")
            traceback.print_exc()
    
    def analyze_packet(self, packet):
        """
        Analyze packet for covert channel indicators
        
        Args:
            packet: Scapy packet object
            
        Returns:
            tuple: (alert_triggered, detection_score, detection_results)
        """
        if not self.detection_enabled:
            return False, 0.0, {}
        
        # Extract comprehensive packet information
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return False, 0.0, {}
        
        # Update packet statistics
        self.packet_stats['total_packets'] += 1
        self.packet_stats['bytes_processed'] += packet_info['packet_size']
        
        protocol = packet_info['protocol']
        if protocol == 'TCP':
            self.packet_stats['tcp_packets'] += 1
        elif protocol == 'UDP':
            self.packet_stats['udp_packets'] += 1
        elif protocol == 'ICMP':
            self.packet_stats['icmp_packets'] += 1
        else:
            self.packet_stats['other_packets'] += 1
        
        if packet_info['is_corrupted']:
            self.packet_stats['corrupted_packets'] += 1
        
        # Only perform covert channel detection on TCP packets
        detection_results = {}
        detection_score = 0.0
        alert_triggered = False
        
        if packet.haslayer(TCP):
            # Update flow tracking for TCP packets
            flow_id = packet_info['flow_id']
            if flow_id not in self.tcp_flows:
                self.tcp_flows[flow_id] = {
                    'window_history': collections.deque(maxlen=100),
                    'packet_count': 0,
                    'start_time': time.time(),
                    'last_packet_time': time.time()
                }
            
            flow_data = self.tcp_flows[flow_id]
            
            # Calculate inter-arrival time
            current_time = time.time()
            inter_arrival_time = (current_time - flow_data['last_packet_time']) * 1000000  # microseconds
            packet_info['inter_arrival_time_us'] = int(inter_arrival_time)
            flow_data['last_packet_time'] = current_time
            
            # Update flow statistics
            flow_data['window_history'].append(packet_info['tcp_window'])
            flow_data['packet_count'] += 1
            
            # Update global window size tracking
            self.window_sizes.append(packet_info['tcp_window'])
            self.packet_count += 1
            
            # Run all detection algorithms
            for method_name, method_func in self.detection_methods.items():
                try:
                    score = method_func(packet_info)
                    detection_results[method_name] = score
                except Exception as e:
                    print(f"[DETECTOR] Error in {method_name}: {e}")
                    detection_results[method_name] = 0.0
            
            # Calculate overall detection score (weighted average with emphasis on ASCII detection)
            if detection_results:
                # Define weights for each detection method
                method_weights = {
                    'ascii_encoding': 3.0,      # 3x weight - most important for ASCII covert channels
                    'ascii_3digit_pattern': 3.5, # 3.5x weight - highest for your specific 3-digit ASCII setup
                    'xor_encoding': 2.5,        # 2.5x weight - important for XOR-based channels
                    'entropy': 1.5,             # 1.5x weight - good general indicator
                    'window_legitimacy': 2.0,   # 2x weight - important for window-based channels
                    'oscillation_patterns': 1.0, # 1x weight - baseline
                    'frequency_domain': 1.0,    # 1x weight - baseline
                    'benford_law': 1.0,         # 1x weight - baseline
                    'timing_correlation': 0.8,  # 0.8x weight - less reliable
                    'payload_correlation': 1.2  # 1.2x weight - moderately important
                }
                
                # Calculate weighted score
                weighted_sum = 0.0
                total_weight = 0.0
                
                for method_name, score in detection_results.items():
                    weight = method_weights.get(method_name, 1.0)  # Default weight 1.0
                    weighted_sum += score * weight
                    total_weight += weight
                
                # Calculate weighted average
                detection_score = weighted_sum / total_weight if total_weight > 0 else 0.0
                
                # Cap the score at 1.0 to prevent over-scoring
                detection_score = min(detection_score, 1.0)
            
            # Update detection statistics
            self.detection_stats['tcp_packets'] += 1
            self.detection_stats['covert_probability_sum'] += detection_score
            
            # Check if alert should be triggered
            alert_triggered = detection_score >= self.alert_threshold
            if alert_triggered:
                self.detection_stats['alerts_triggered'] += 1
                if self.detection_enabled:  # Only print alerts if detection is enabled
                    self._print_alert(packet_info, detection_results, detection_score)
            
            # Log detection results
            self._log_detection(packet_info, detection_results, detection_score, alert_triggered)
        
        return alert_triggered, detection_score, detection_results
    
    def _extract_packet_info(self, packet):
        """Extract comprehensive packet information for analysis and logging"""
        current_time = time.time()
        packet_info = {
            'timestamp': current_time,
            'packet_id': self.packet_stats['total_packets'],
            'packet_size': len(packet),
            'ip_version': 0,
            'ip_header_length': 0,
            'protocol': 'Unknown',
            'protocol_header_length': 0,
            'payload_size': 0,
            'src_ip': '',
            'dst_ip': '',
            'src_port': 0,
            'dst_port': 0,
            'ttl': 0,
            'ip_tos': 0,
            'ip_id': 0,
            'ip_fragment_offset': 0,
            'checksum_ip_valid': False,
            'checksum_protocol_valid': False,
            'checksum_ip_received': 0,
            'checksum_protocol_received': 0,
            'is_corrupted': False,
            'payload': b'',
            'inter_arrival_time_us': 0,
            'sequence_num': 0,
            'ack_num': 0,
            'flags': 0,
            'window_size': 0,
            'window_base': 0,
            'window_covert': 0
        }
        
        # Extract IP layer information
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            packet_info.update({
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'ip_version': ip_layer.version,
                'ip_header_length': ip_layer.ihl * 4,  # IHL is in 4-byte units
                'ttl': ip_layer.ttl,
                'ip_tos': ip_layer.tos,
                'ip_id': ip_layer.id,
                'ip_fragment_offset': ip_layer.frag,
                'checksum_ip_received': ip_layer.chksum,
                'protocol': {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ip_layer.proto, f'Proto-{ip_layer.proto}')
            })
            
            # Basic IP checksum validation (simplified)
            packet_info['checksum_ip_valid'] = (ip_layer.chksum != 0)
        
        # Extract TCP-specific information
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_info.update({
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'tcp_seq': tcp_layer.seq,
                'tcp_ack': tcp_layer.ack,
                'tcp_window': tcp_layer.window,
                'tcp_flags': int(tcp_layer.flags),
                'tcp_flags_hex': f"0x{int(tcp_layer.flags):02x}",
                'tcp_urgent_ptr': tcp_layer.urgptr,
                'protocol_header_length': tcp_layer.dataofs * 4,  # Data offset in 4-byte units
                'checksum_protocol_received': tcp_layer.chksum,
                'protocol': 'TCP'
            })
            
            # Calculate TCP options length
            tcp_options_length = (tcp_layer.dataofs * 4) - 20  # 20 bytes is standard TCP header
            packet_info['tcp_options_length'] = max(0, tcp_options_length)
            
            # Basic TCP checksum validation (simplified)
            packet_info['checksum_protocol_valid'] = (tcp_layer.chksum != 0)
            
            # Extract window size details for covert channel analysis
            window_size = tcp_layer.window
            packet_info.update({
                'window_base': (window_size // 1000) * 1000,
                'window_covert': window_size % 1000
            })
            
            # Extract payload
            if hasattr(tcp_layer, 'payload') and tcp_layer.payload:
                payload_data = bytes(tcp_layer.payload)
                packet_info['payload'] = payload_data
                packet_info['payload_size'] = len(payload_data)
            
            # Calculate flow ID for tracking
            src_ip = packet_info['src_ip']
            dst_ip = packet_info['dst_ip']
            src_port = packet_info['src_port']
            dst_port = packet_info['dst_port']
            
            # Create consistent flow ID (normalize direction)
            if (src_ip, src_port) < (dst_ip, dst_port):
                flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            else:
                flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            packet_info['flow_id'] = flow_id
            
        # Extract UDP-specific information
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_info.update({
                'src_port': udp_layer.sport,
                'dst_port': udp_layer.dport,
                'protocol_header_length': 8,  # UDP header is always 8 bytes
                'checksum_protocol_received': udp_layer.chksum,
                'protocol': 'UDP'
            })
            
            # Extract payload
            if hasattr(udp_layer, 'payload') and udp_layer.payload:
                payload_data = bytes(udp_layer.payload)
                packet_info['payload'] = payload_data
                packet_info['payload_size'] = len(payload_data)
            
            # Create flow ID for UDP
            src_ip = packet_info['src_ip']
            dst_ip = packet_info['dst_ip']
            src_port = packet_info['src_port']
            dst_port = packet_info['dst_port']
            
            if (src_ip, src_port) < (dst_ip, dst_port):
                flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-UDP"
            else:
                flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-UDP"
            packet_info['flow_id'] = flow_id
            
        # Extract ICMP information
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            packet_info.update({
                'protocol': 'ICMP',
                'protocol_header_length': 8,  # ICMP header is typically 8 bytes
                'checksum_protocol_received': icmp_layer.chksum
            })
            
            # Extract payload
            if hasattr(icmp_layer, 'payload') and icmp_layer.payload:
                payload_data = bytes(icmp_layer.payload)
                packet_info['payload'] = payload_data
                packet_info['payload_size'] = len(payload_data)
                
            packet_info['flow_id'] = f"{packet_info['src_ip']}-{packet_info['dst_ip']}-ICMP"
        
        # Calculate actual payload size if not set
        if packet_info['payload_size'] == 0:
            total_header_size = packet_info['ip_header_length'] + packet_info['protocol_header_length']
            packet_info['payload_size'] = max(0, packet_info['packet_size'] - total_header_size)
        
        # Simple corruption detection (look for unusual patterns)
        packet_info['is_corrupted'] = self._detect_corruption(packet, packet_info)
        
        return packet_info
    
    def _detect_corruption(self, packet, packet_info):
        """Simple corruption detection based on packet characteristics"""
        try:
            # Check for invalid header lengths
            if packet_info['ip_header_length'] < 20 or packet_info['ip_header_length'] > 60:
                return True
                
            # Check for TCP-specific corruption indicators
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                # Check for invalid TCP header length
                if packet_info['protocol_header_length'] < 20:
                    return True
                # Check for reserved bits set inappropriately
                if hasattr(tcp_layer, 'reserved') and tcp_layer.reserved != 0:
                    return True
                    
            # Check for extremely large payload sizes that don't match packet size
            expected_size = packet_info['ip_header_length'] + packet_info['protocol_header_length'] + packet_info['payload_size']
            if abs(expected_size - packet_info['packet_size']) > 20:  # Allow some tolerance
                return True
                
            return False
            
        except Exception:
            # If we can't analyze it properly, consider it potentially corrupted
            return True
    
    def _detect_entropy_anomaly(self, packet_info):
        """Detect low entropy in window sizes (indicating structured data)"""
        if len(self.window_sizes) < 10:
            return 0.0
            
        try:
            # Calculate entropy of recent window sizes
            window_list = list(self.window_sizes)[-50:]  # Last 50 packets
            unique_windows = len(set(window_list))
            total_windows = len(window_list)
            
            # Entropy score (lower entropy = higher suspicion)
            if total_windows == 0:
                return 0.0
                
            entropy_ratio = unique_windows / total_windows
            
            # Normal TCP should have varied window sizes
            if entropy_ratio < 0.3:  # Less than 30% unique values
                return 0.8
            elif entropy_ratio < 0.5:
                return 0.5
            else:
                return 0.1
                
        except Exception:
            return 0.0
    
    def _detect_ascii_encoding(self, packet_info):
        """Specifically detect ASCII encoding patterns in the least 3 digits of window size"""
        try:
            window_covert = packet_info['window_covert']  # Last 3 digits (% 1000)
            window_size = packet_info.get('window_size', 0)
            window_base = packet_info.get('window_base', 0)
            flow_id = packet_info['flow_id']
            
            # DEBUG: Print window analysis for all packets to understand the pattern
            if self.detection_enabled:
                print(f"[ASCII DEBUG] Window: {window_size}, Base: {window_base}, Covert: {window_covert}")
                if 32 <= window_covert <= 126:
                    print(f"[ASCII DEBUG] Potential ASCII: '{chr(window_covert)}' (value {window_covert})")
            
            # Base ASCII detection score
            ascii_score = 0.0
            
            # Check if window base is in realistic TCP congestion window range (8KB-65KB)
            window_base_kb = window_base // 1000
            realistic_base = 8 <= window_base_kb <= 65
            
            if not realistic_base:
                # If base is not realistic, lower the confidence
                base_penalty = 0.3
            else:
                base_penalty = 0.0
            
            # Primary ASCII range detection (stronger scoring for your use case)
            if 65 <= window_covert <= 90:  # Uppercase letters A-Z
                ascii_score = 0.9 - base_penalty  # Very high confidence
            elif 97 <= window_covert <= 122:  # Lowercase letters a-z
                ascii_score = 0.9 - base_penalty  # Very high confidence
            elif 48 <= window_covert <= 57:  # Numbers 0-9
                ascii_score = 0.8 - base_penalty  # High confidence
            elif 32 <= window_covert <= 47:  # Space and punctuation
                ascii_score = 0.7 - base_penalty  # Good confidence
            elif window_covert == 10:  # Newline
                ascii_score = 0.8 - base_penalty
            elif window_covert == 13:  # Carriage return
                ascii_score = 0.8 - base_penalty
            elif window_covert == 9:   # Tab
                ascii_score = 0.7 - base_penalty
            elif window_covert == 4:   # EOF marker
                ascii_score = 0.95 - base_penalty  # Very high confidence for EOF
            elif 58 <= window_covert <= 64:  # :;<=>?@
                ascii_score = 0.6 - base_penalty
            elif 91 <= window_covert <= 96:  # [\]^_`
                ascii_score = 0.6 - base_penalty
            elif 123 <= window_covert <= 126:  # {|}~
                ascii_score = 0.6 - base_penalty
            elif 1 <= window_covert <= 31:  # Control characters (less common but possible)
                ascii_score = 0.4 - base_penalty
            else:
                ascii_score = 0.05  # Very low for non-ASCII values
            
            # Bonus for realistic congestion window behavior
            if realistic_base and ascii_score > 0.3:
                ascii_score = min(ascii_score + 0.1, 1.0)  # Bonus for realistic base
            
            # DEBUG: Print base score
            if self.detection_enabled and ascii_score > 0.3:
                print(f"[ASCII DEBUG] Base ASCII score: {ascii_score:.3f} (realistic_base: {realistic_base})")
            
            # Flow-based pattern analysis for ASCII sequences
            if flow_id in self.tcp_flows and ascii_score > 0.3:
                flow_data = self.tcp_flows[flow_id]
                windows = list(flow_data['window_history'])
                
                if len(windows) >= 3:
                    # Extract recent covert values (last 10 packets)
                    recent_covert = [w % 1000 for w in windows[-10:]]
                    recent_bases = [(w // 1000) * 1000 for w in windows[-10:]]
                    ascii_chars = []
                    
                    # Convert to ASCII characters where possible
                    for val in recent_covert:
                        if 32 <= val <= 126:  # Printable ASCII
                            ascii_chars.append(chr(val))
                        elif val == 10:
                            ascii_chars.append('\\n')
                        elif val == 13:
                            ascii_chars.append('\\r')
                        elif val == 9:
                            ascii_chars.append('\\t')
                        elif val == 4:
                            ascii_chars.append('EOF')
                    
                    # DEBUG: Print flow analysis
                    if self.detection_enabled and len(ascii_chars) > 0:
                        print(f"[ASCII DEBUG] Flow chars: {''.join(ascii_chars[:10])}")
                        # Show base progression to verify congestion window simulation
                        base_kbs = [b//1000 for b in recent_bases[-5:]]
                        print(f"[ASCII DEBUG] Recent bases (KB): {base_kbs}")
                    
                    # Check for realistic congestion window progression
                    if len(recent_bases) >= 5:
                        base_changes = []
                        for i in range(1, len(recent_bases)):
                            change = (recent_bases[i] - recent_bases[i-1]) // 1000
                            base_changes.append(change)
                        
                        # Realistic congestion window should have gradual changes
                        large_changes = sum(1 for change in base_changes if abs(change) > 10)
                        if large_changes < len(base_changes) * 0.3:  # Less than 30% large changes
                            ascii_score = min(ascii_score + 0.1, 1.0)  # Bonus for realistic progression
                    
                    # Bonus scoring for ASCII text patterns
                    if len(ascii_chars) >= 3:
                        ascii_text = ''.join(c for c in ascii_chars if len(c) == 1)
                        
                        # Check for common English text patterns
                        if len(ascii_text) >= 3:
                            # Common English letter combinations
                            common_patterns = ['the', 'and', 'ing', 'ion', 'tion', 'er', 'ed', 'es', 'en', 'al']
                            text_lower = ascii_text.lower()
                            
                            pattern_matches = sum(1 for pattern in common_patterns if pattern in text_lower)
                            if pattern_matches > 0:
                                ascii_score = min(ascii_score + 0.1 * pattern_matches, 1.0)
                        
                        # Check for word-like patterns (alternating consonants/vowels)
                        vowels = set('aeiouAEIOU')
                        consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
                        
                        if len(ascii_text) >= 4:
                            vowel_consonant_pattern = 0
                            for i in range(len(ascii_text) - 1):
                                if ((ascii_text[i] in vowels and ascii_text[i+1] in consonants) or 
                                    (ascii_text[i] in consonants and ascii_text[i+1] in vowels)):
                                    vowel_consonant_pattern += 1
                            
                            if vowel_consonant_pattern >= 2:
                                ascii_score = min(ascii_score + 0.05, 1.0)
                        
                        # Check for sentence-like patterns (capital letter followed by lowercase)
                        if len(ascii_text) >= 2:
                            sentence_patterns = 0
                            for i in range(len(ascii_text) - 1):
                                if ascii_text[i].isupper() and ascii_text[i+1].islower():
                                    sentence_patterns += 1
                            
                            if sentence_patterns > 0:
                                ascii_score = min(ascii_score + 0.05 * sentence_patterns, 1.0)
                    
                    # Check for sequential ASCII patterns (like typing alphabet)
                    if len(recent_covert) >= 3:
                        sequential_count = 0
                        for i in range(len(recent_covert) - 1):
                            if abs(recent_covert[i] - recent_covert[i+1]) == 1:  # Sequential ASCII values
                                sequential_count += 1
                        
                        if sequential_count >= 2:
                            ascii_score = min(ascii_score + 0.1, 1.0)
                    
                    # Penalty for too many non-ASCII values in the flow
                    non_ascii_count = sum(1 for val in recent_covert if not (32 <= val <= 126 or val in [4, 9, 10, 13]))
                    if len(recent_covert) > 0:
                        non_ascii_ratio = non_ascii_count / len(recent_covert)
                        if non_ascii_ratio > 0.5:  # More than 50% non-ASCII
                            ascii_score *= (1.0 - non_ascii_ratio * 0.5)  # Reduce score
            
            # DEBUG: Print final score
            if self.detection_enabled and ascii_score > 0.3:
                print(f"[ASCII DEBUG] Final ASCII score: {ascii_score:.3f}")
            
            return min(ascii_score, 1.0)
                
        except Exception as e:
            print(f"[ASCII DEBUG] Error in ASCII detection: {e}")
            return 0.0
    
    def _detect_ascii_3digit_pattern(self, packet_info):
        """Detect patterns specific to 3-digit ASCII covert channels in window sizes"""
        try:
            window_covert = packet_info['window_covert']  # Last 3 digits (% 1000)
            window_size = packet_info.get('window_size', 0)
            window_base = packet_info.get('window_base', 0)
            flow_id = packet_info['flow_id']
            
            # This method focuses on detecting patterns specific to 3-digit ASCII encoding
            # where the covert channel uses the last 3 digits of window size for ASCII chars
            
            score = 0.0
            
            # Check if window base is in realistic TCP congestion window range (8KB-65KB)
            window_base_kb = window_base // 1000
            realistic_base = 8 <= window_base_kb <= 65
            
            # DEBUG: Print 3-digit pattern analysis
            if self.detection_enabled:
                print(f"[3DIGIT DEBUG] Window: {window_size}, Base: {window_base_kb}KB, Covert: {window_covert:03d}")
                if realistic_base:
                    print(f"[3DIGIT DEBUG] Realistic congestion window base detected")
            
            # Check if the value is in valid ASCII range
            if 32 <= window_covert <= 126:  # Printable ASCII
                score = 0.8
            elif window_covert in [9, 10, 13]:  # Tab, newline, carriage return
                score = 0.7
            elif window_covert == 4:  # EOF marker
                score = 0.9
            elif 1 <= window_covert <= 31:  # Control characters
                score = 0.5
            else:
                score = 0.1  # Non-ASCII values are suspicious in ASCII covert channel
            
            # Bonus for realistic congestion window base
            if realistic_base and score > 0.3:
                score = min(score + 0.15, 1.0)  # Significant bonus for realistic base
                if self.detection_enabled:
                    print(f"[3DIGIT DEBUG] Realistic base bonus applied: +0.15")
            
            # Flow-based analysis for 3-digit ASCII patterns
            if flow_id in self.tcp_flows and score > 0.3:
                flow_data = self.tcp_flows[flow_id]
                windows = list(flow_data['window_history'])
                
                if len(windows) >= 5:
                    # Extract recent covert values (last 15 packets)
                    recent_covert = [w % 1000 for w in windows[-15:]]
                    recent_bases = [(w // 1000) for w in windows[-15:]]  # Base in KB
                    
                    # Count ASCII vs non-ASCII values in the flow
                    ascii_count = sum(1 for val in recent_covert if 32 <= val <= 126 or val in [4, 9, 10, 13])
                    total_count = len(recent_covert)
                    ascii_ratio = ascii_count / total_count if total_count > 0 else 0
                    
                    # DEBUG: Print flow statistics
                    if self.detection_enabled:
                        print(f"[3DIGIT DEBUG] Flow ASCII ratio: {ascii_ratio:.2f} ({ascii_count}/{total_count})")
                        # Show recent bases to verify congestion window simulation
                        print(f"[3DIGIT DEBUG] Recent bases (KB): {recent_bases[-5:]}")
                    
                    # High ASCII ratio suggests ASCII covert channel
                    if ascii_ratio > 0.8:  # More than 80% ASCII
                        score = min(score + 0.2, 1.0)
                        if self.detection_enabled:
                            print(f"[3DIGIT DEBUG] High ASCII ratio bonus: +0.2")
                    elif ascii_ratio > 0.6:  # More than 60% ASCII
                        score = min(score + 0.1, 1.0)
                        if self.detection_enabled:
                            print(f"[3DIGIT DEBUG] Medium ASCII ratio bonus: +0.1")
                    
                    # Check for realistic congestion window progression
                    if len(recent_bases) >= 5:
                        base_changes = []
                        for i in range(1, len(recent_bases)):
                            change = recent_bases[i] - recent_bases[i-1]
                            base_changes.append(change)
                        
                        # Realistic congestion window should have gradual changes (±1-5KB typically)
                        realistic_changes = sum(1 for change in base_changes if abs(change) <= 5)
                        realistic_ratio = realistic_changes / len(base_changes) if base_changes else 0
                        
                        if realistic_ratio > 0.7:  # More than 70% realistic changes
                            score = min(score + 0.1, 1.0)
                            if self.detection_enabled:
                                print(f"[3DIGIT DEBUG] Realistic congestion progression bonus: +0.1")
                    
                    # Check for text-like patterns in the ASCII sequence
                    ascii_chars = []
                    for val in recent_covert:
                        if 32 <= val <= 126:
                            ascii_chars.append(chr(val))
                        elif val == 10:
                            ascii_chars.append('\n')
                        elif val == 13:
                            ascii_chars.append('\r')
                        elif val == 9:
                            ascii_chars.append('\t')
                    
                    if len(ascii_chars) >= 4:
                        text = ''.join(ascii_chars)
                        
                        # DEBUG: Print decoded text
                        if self.detection_enabled:
                            printable_text = text.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                            print(f"[3DIGIT DEBUG] Decoded text: '{printable_text[:20]}{'...' if len(printable_text) > 20 else ''}'")
                        
                        # Check for English-like patterns
                        letter_count = sum(1 for c in text if c.isalpha())
                        if letter_count > len(text) * 0.6:  # More than 60% letters
                            score = min(score + 0.1, 1.0)
                            if self.detection_enabled:
                                print(f"[3DIGIT DEBUG] English-like pattern bonus: +0.1")
                        
                        # Check for common English words
                        text_lower = text.lower()
                        common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use']
                        word_matches = sum(1 for word in common_words if word in text_lower)
                        if word_matches > 0:
                            score = min(score + 0.05 * word_matches, 1.0)
                            if self.detection_enabled:
                                print(f"[3DIGIT DEBUG] Common words bonus: +{0.05 * word_matches:.2f}")
                    
                    # Check for consistent 3-digit encoding (values consistently in 100-999 range)
                    three_digit_count = sum(1 for val in recent_covert if 100 <= val <= 999)
                    if three_digit_count > total_count * 0.7:  # More than 70% are 3-digit
                        score = min(score + 0.15, 1.0)
                        if self.detection_enabled:
                            print(f"[3DIGIT DEBUG] Consistent 3-digit encoding bonus: +0.15")
                    
                    # Penalty for too many values outside typical ASCII range
                    non_typical_count = sum(1 for val in recent_covert if val > 126 or (val < 32 and val not in [4, 9, 10, 13]))
                    if total_count > 0:
                        non_typical_ratio = non_typical_count / total_count
                        if non_typical_ratio > 0.3:  # More than 30% non-typical
                            penalty = non_typical_ratio * 0.5
                            score *= (1.0 - penalty)
                            if self.detection_enabled:
                                print(f"[3DIGIT DEBUG] Non-typical values penalty: -{penalty:.2f}")
            
            # DEBUG: Print final score
            if self.detection_enabled and score > 0.3:
                print(f"[3DIGIT DEBUG] Final 3-digit pattern score: {score:.3f}")
            
            return min(score, 1.0)
                
        except Exception as e:
            print(f"[3DIGIT DEBUG] Error in 3-digit pattern detection: {e}")
            return 0.0
    
    def _detect_xor_encoding(self, packet_info):
        """Detect generic XOR encoding patterns in window sizes without overfitting to specific implementations"""
        try:
            flow_id = packet_info['flow_id']
            window_covert = packet_info.get('window_covert', 0)
            payload = packet_info.get('payload', b'')
            
            if flow_id not in self.tcp_flows:
                return 0.0
                
            flow_data = self.tcp_flows[flow_id]
            windows = list(flow_data['window_history'])
            
            if len(windows) < 8:
                return 0.0
            
            score = 0.0
            covert_values = [w % 1000 for w in windows[-20:]]  # Last 20 covert values
            
            # Test 1: Bit distribution analysis for XOR patterns
            score += self._analyze_bit_distribution(covert_values) * 0.25
            
            # Test 2: XOR correlation with sequential data
            score += self._detect_xor_sequential_correlation(covert_values) * 0.25
            
            # Test 3: XOR key detection (repeating patterns)
            score += self._detect_xor_key_patterns(covert_values) * 0.25
            
            # Test 4: Payload-window XOR correlation
            if payload:
                score += self._detect_payload_xor_correlation(window_covert, payload) * 0.25
            
            return min(score, 1.0)
                 
        except Exception:
            return 0.0
    
    def _analyze_bit_distribution(self, covert_values):
        """Analyze bit distribution patterns typical of XOR encoding"""
        if len(covert_values) < 8:
            return 0.0
        
        try:
            # Calculate bit statistics for each bit position
            bit_positions = 8  # Analyze up to 8 bits
            bit_stats = []
            
            for bit_pos in range(bit_positions):
                bit_mask = 1 << bit_pos
                ones_count = sum(1 for val in covert_values if val & bit_mask)
                bit_ratio = ones_count / len(covert_values)
                bit_stats.append(bit_ratio)
            
            # XOR encoding often creates more uniform bit distribution
            # Calculate variance in bit ratios - lower variance = more uniform = suspicious
            if len(bit_stats) > 1:
                bit_variance = statistics.variance(bit_stats)
                
                # Also check if distribution is too uniform (close to 0.5 for all bits)
                uniformity_score = 0.0
                for ratio in bit_stats:
                    if 0.4 <= ratio <= 0.6:  # Close to 50/50 distribution
                        uniformity_score += 0.1
                
                # Low variance + high uniformity = likely XOR
                if bit_variance < 0.05 and uniformity_score > 0.5:
                    return 0.8
                elif bit_variance < 0.1 and uniformity_score > 0.3:
                    return 0.6
                elif uniformity_score > 0.4:
                    return 0.4
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _detect_xor_sequential_correlation(self, covert_values):
        """Detect XOR correlation with sequential/incremental patterns"""
        if len(covert_values) < 6:
            return 0.0
        
        try:
            max_correlation = 0.0
            
            # Test against common XOR key patterns
            test_patterns = [
                list(range(256)),  # Sequential bytes 0-255
                [i % 256 for i in range(len(covert_values))],  # Modulo pattern
                [ord('A') + (i % 26) for i in range(len(covert_values))],  # Alphabet pattern
                [i % 128 for i in range(len(covert_values))],  # ASCII range pattern
            ]
            
            for pattern in test_patterns:
                if len(pattern) >= len(covert_values):
                    # Test XOR correlation
                    correlations = []
                    for key_candidate in range(256):
                        correlation_score = 0
                        for i in range(len(covert_values)):
                            expected_xor = pattern[i] ^ key_candidate
                            if abs(expected_xor - covert_values[i]) <= 2:  # Allow small variance
                                correlation_score += 1
                        
                        correlation_ratio = correlation_score / len(covert_values)
                        correlations.append(correlation_ratio)
                    
                    max_pattern_correlation = max(correlations) if correlations else 0
                    max_correlation = max(max_correlation, max_pattern_correlation)
            
            # High correlation suggests XOR encoding
            if max_correlation > 0.8:
                return 0.9
            elif max_correlation > 0.6:
                return 0.7
            elif max_correlation > 0.4:
                return 0.5
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _detect_xor_key_patterns(self, covert_values):
        """Detect repeating XOR key patterns"""
        if len(covert_values) < 10:
            return 0.0
        
        try:
            # Look for repeating XOR key patterns of different lengths
            for key_length in range(1, min(8, len(covert_values) // 3)):
                pattern_score = 0
                total_comparisons = 0
                
                # Compare values that should use the same key byte
                for i in range(len(covert_values) - key_length):
                    val1 = covert_values[i]
                    val2 = covert_values[i + key_length]
                    
                    # If XOR key repeats, the XOR difference should be consistent
                    # with the plaintext difference
                    xor_diff = val1 ^ val2
                    
                    # Check if this difference makes sense for text/data
                    if xor_diff == 0:  # Same plaintext character
                        pattern_score += 1
                    elif 0 < xor_diff < 128:  # Reasonable ASCII difference
                        pattern_score += 0.5
                    
                    total_comparisons += 1
                
                if total_comparisons > 0:
                    pattern_ratio = pattern_score / total_comparisons
                    if pattern_ratio > 0.7:  # Strong repeating pattern
                        return 0.8
                    elif pattern_ratio > 0.5:
                        return 0.6
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _detect_payload_xor_correlation(self, window_covert, payload):
        """Detect correlation between window covert value and payload XOR patterns"""
        if not payload or len(payload) < 2:
            return 0.0
        
        try:
            correlations = []
            
            # Test if window_covert could be an XOR key for payload
            for i in range(len(payload) - 1):
                # Test adjacent byte XOR
                byte_xor = payload[i] ^ payload[i + 1]
                if abs(byte_xor - window_covert) <= 5:  # Close match
                    correlations.append(1)
                else:
                    correlations.append(0)
            
            if correlations:
                correlation_ratio = sum(correlations) / len(correlations)
                if correlation_ratio > 0.5:
                    return 0.8
                elif correlation_ratio > 0.3:
                    return 0.5
            
            # Test if window_covert XOR with a constant gives ASCII
            for test_byte in payload[:min(10, len(payload))]:
                xor_result = test_byte ^ window_covert
                if 32 <= xor_result <= 126:  # Results in printable ASCII
                    return 0.6
            
            # Test if window_covert appears to be derived from payload
            if len(payload) >= 4:
                payload_sum = sum(payload[:4]) % 256
                payload_xor = payload[0] ^ payload[1] if len(payload) >= 2 else 0
                
                if abs(window_covert - payload_sum) <= 3:
                    return 0.5
                if abs(window_covert - payload_xor) <= 3:
                    return 0.7
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _detect_window_legitimacy(self, packet_info):
        """Check if window size follows legitimate TCP behavior"""
        try:
            window_size = packet_info['window_size']
            flow_id = packet_info['flow_id']
            
            # Get flow history for this flow
            if flow_id not in self.tcp_flows:
                return 0.0
                
            flow_data = self.tcp_flows[flow_id]
            windows = list(flow_data['window_history'])
            
            if len(windows) < 5:
                return 0.0
            
            score = 0.0
            
            # Check 1: Window size too precise (always ends in specific digits)
            if len(windows) >= 10:
                last_digits = [w % 10 for w in windows[-10:]]
                unique_last_digits = len(set(last_digits))
                if unique_last_digits <= 3:  # Too few unique last digits
                    score += 0.4
            
            # Check 2: Window size progression analysis 
            if len(windows) >= 5:
                differences = [abs(windows[i] - windows[i-1]) for i in range(1, len(windows))]
                if len(differences) > 1:
                    std_diff = statistics.stdev(differences)
                    # Legitimate TCP should have varying differences
                    if std_diff < 50:  # Too uniform changes
                        score += 0.5
            
            # Check 3: Window values in suspicious encoding ranges
            window_base = packet_info.get('window_base', 0)
            if 8000 <= window_base <= 65000:  # Common covert channel range
                score += 0.3
            
            # Check 4: Zero window should be rare in normal TCP
            zero_windows = sum(1 for w in windows if w == 0)
            if zero_windows > len(windows) * 0.1:  # More than 10% zero windows
                score += 0.3
                
            return min(score, 1.0)
            
        except Exception:
            return 0.0
    
    def _detect_oscillation_patterns(self, packet_info):
        """Analyze window size oscillation patterns - covert channels often create artificial oscillations"""
        try:
            flow_id = packet_info['flow_id']
            
            if flow_id not in self.tcp_flows:
                return 0.0
                
            flow_data = self.tcp_flows[flow_id]
            windows = list(flow_data['window_history'])
            
            if len(windows) < 8:
                return 0.0
            
            # Look for artificial oscillation patterns
            changes = []
            for i in range(1, len(windows)):
                if windows[i] > windows[i-1]:
                    changes.append(1)  # Increase
                elif windows[i] < windows[i-1]:
                    changes.append(-1)  # Decrease
                else:
                    changes.append(0)  # No change
            
            if len(changes) < 6:
                return 0.0
            
            score = 0.0
            
            # Check for regular alternating patterns (e.g., +1, -1, +1, -1)
            pattern_length = 2
            repeats = 0
            for i in range(len(changes) - pattern_length + 1):
                if i + 2 * pattern_length <= len(changes):
                    if changes[i:i+pattern_length] == changes[i+pattern_length:i+2*pattern_length]:
                        repeats += 1
            
            if repeats > len(changes) / 4:  # Too many pattern repeats
                score += 0.6
            
            # Check for too many "no change" patterns (indicating structured data)
            no_change_count = changes.count(0)
            if no_change_count > len(changes) * 0.3:  # More than 30% no change
                score += 0.4
            
            # Check for extremely regular increases/decreases
            increases = changes.count(1)
            decreases = changes.count(-1)
            total_changes = increases + decreases
            
            if total_changes > 0:
                change_ratio = abs(increases - decreases) / total_changes
                if change_ratio < 0.2:  # Very balanced increases/decreases - suspicious
                    score += 0.3
                    
            return min(score, 1.0)
                 
        except Exception:
            return 0.0
    
    def _detect_frequency_domain(self, packet_info):
        """Analyze window sizes in frequency domain using FFT - hidden data often creates spectral anomalies"""
        try:
            flow_id = packet_info['flow_id']
            
            if flow_id not in self.tcp_flows:
                return 0.0
                
            flow_data = self.tcp_flows[flow_id]
            windows = list(flow_data['window_history'])
            
            if len(windows) < 16:
                return 0.0
            
            # Perform FFT on window size sequence
            fft_result = np.fft.fft(windows)
            frequencies = np.fft.fftfreq(len(windows))
            
            # Analyze power spectrum
            power_spectrum = np.abs(fft_result) ** 2
            
            # Look for dominant frequencies (indicating regular patterns)
            # Skip DC component (index 0)
            if len(power_spectrum) > 1:
                max_power = np.max(power_spectrum[1:])
                total_power = np.sum(power_spectrum[1:])
                
                if total_power > 0:
                    power_ratio = max_power / total_power
                    # High power concentration in single frequency = suspicious
                    if power_ratio > 0.5:
                        return 0.7
                    elif power_ratio > 0.3:
                        return 0.4
                    elif power_ratio > 0.2:
                        return 0.2
            
            return 0.0
                 
        except Exception:
            return 0.0
    
    def _detect_benford_law(self, packet_info):
        """Apply Benford's Law to detect artificial data patterns - natural data often follows Benford's Law"""
        try:
            flow_id = packet_info['flow_id']
            
            if flow_id not in self.tcp_flows:
                return 0.0
                
            flow_data = self.tcp_flows[flow_id]
            windows = list(flow_data['window_history'])
            
            if len(windows) < 20:
                return 0.0
            
            # Extract first digits from window sizes
            first_digits = []
            for w in windows:
                if w > 0:
                    first_digit = int(str(w)[0])
                    if 1 <= first_digit <= 9:
                        first_digits.append(first_digit)
            
            if len(first_digits) < 10:
                return 0.0
            
            # Count occurrences of each digit
            digit_counts = [0] * 10
            for digit in first_digits:
                digit_counts[digit] += 1
            
            # Expected frequencies according to Benford's Law
            benford_expected = [0, 0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046]
            
            # Calculate observed frequencies
            total = len(first_digits)
            observed_freq = [count / total for count in digit_counts]
            
            # Chi-square test for goodness of fit
            chi_square = 0
            valid_comparisons = 0
            for i in range(1, 10):
                expected = benford_expected[i] * total
                if expected > 5:  # Valid for chi-square test
                    chi_square += ((digit_counts[i] - expected) ** 2) / expected
                    valid_comparisons += 1
            
            if valid_comparisons < 5:  # Need enough valid comparisons
                return 0.0
            
            # Critical value for chi-square test (varies by degrees of freedom)
            # For 8 degrees of freedom at 0.05 significance: 15.507
            if chi_square > 15.507:
                return min(0.6, chi_square / 30.0)  # Scale the score
            elif chi_square > 10.0:
                return 0.3
            
            return 0.0
                 
        except Exception:
            return 0.0
    
    def _detect_timing_correlation(self, packet_info):
        """Detect correlation between covert data and packet timing"""
        try:
            flow_id = packet_info['flow_id']
            
            if flow_id not in self.tcp_flows:
                return 0.0
                
            flow_data = self.tcp_flows[flow_id]
            windows = list(flow_data['window_history'])
            
            if len(windows) < 10:
                return 0.0
            
            # Get inter-arrival time (if available)
            inter_arrival = packet_info.get('inter_arrival_time_us', 0)
            
            # Simple correlation check between window covert value and timing
            covert_values = [w % 1000 for w in windows[-10:]]
            
            # Check if covert values correlate with packet ordering
            # (Real covert channels sometimes use timing as a secondary channel)
            if len(covert_values) >= 5:
                # Look for correlation with sequence position
                positions = list(range(len(covert_values)))
                try:
                    correlation, p_value = stats.pearsonr(covert_values, positions)
                    if abs(correlation) > 0.7 and p_value < 0.05:  # Strong correlation
                        return 0.8
                    elif abs(correlation) > 0.5:
                        return 0.4
                    elif abs(correlation) > 0.3:
                        return 0.2
                except:
                    pass
            
            # Check for timing-based encoding patterns
            if inter_arrival > 0:
                window_covert = packet_info.get('window_covert', 0)
                # Look for correlation between timing and covert value
                timing_mod = int(inter_arrival) % 1000
                if abs(window_covert - timing_mod) < 50:  # Close correlation
                    return 0.5
            
            return 0.0
                 
        except Exception:
            return 0.0
    
    def _detect_payload_correlation(self, packet_info):
        """Detect correlation between window sizes and payload characteristics"""
        try:
            payload = packet_info.get('payload', b'')
            window_covert = packet_info.get('window_covert', 0)
            
            if not payload or len(payload) == 0:
                return 0.0
            
            score = 0.0
            
            # Check 1: Window size correlates with payload size
            if len(payload) < 256:  # Small payload
                if window_covert == len(payload):
                    score += 0.5  # Suspicious correlation
                elif abs(window_covert - len(payload)) < 5:
                    score += 0.3  # Close correlation
            
            # Check 2: Window size correlates with payload content
            if len(payload) > 0:
                payload_sum = sum(payload) % 1000
                if abs(window_covert - payload_sum) < 10:
                    score += 0.4  # Potential encoding correlation
                    
                # Check if payload has ASCII characters matching window covert
                if 32 <= window_covert <= 126:
                    if chr(window_covert).encode() in payload:
                        score += 0.6  # Character appears in payload
            
            # Check 3: Payload entropy vs window entropy
            if len(payload) >= 10:
                try:
                    # Calculate payload entropy
                    payload_bytes = list(payload)
                    unique_bytes = len(set(payload_bytes))
                    payload_entropy = unique_bytes / len(payload_bytes)
                    
                    # If payload has low entropy and window covert is in ASCII range
                    if payload_entropy < 0.5 and 32 <= window_covert <= 126:
                        score += 0.3
                except:
                    pass
            
            # Check 4: Window covert matches payload patterns
            if len(payload) >= 4:
                # Check if window covert appears as bytes in payload
                window_bytes = window_covert.to_bytes(2, byteorder='big', signed=False)
                if window_bytes in payload:
                    score += 0.4
            
            return min(score, 1.0)
                 
        except Exception:
            return 0.0
    
    def _log_detection(self, packet_info, detection_results, overall_score, alert_triggered):
        """Log detection results to CSV file"""
        try:
            if not self.log_file:  # Skip if no log file specified
                return
                
            # Ensure the directory exists
            log_dir = os.path.dirname(self.log_file)
            if log_dir:  # Only create directory if path is not empty
                os.makedirs(log_dir, exist_ok=True)
            
            # Analyze potential decoded characters
            window_covert = packet_info.get('window_covert', 0)
            potential_chars = []
            
            if 32 <= window_covert <= 126:
                potential_chars.append(chr(window_covert))
            if window_covert == 4:
                potential_chars.append('EOF')
            
            # Determine detected methods
            detected_methods = [name for name, score in detection_results.items() if score > 0.5]
            
            # Determine confidence level
            if overall_score >= 0.8:
                confidence = "HIGH"
            elif overall_score >= 0.5:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
            
            # Write to CSV
            with open(self.log_file, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)
                row = [
                    datetime.fromtimestamp(packet_info['timestamp']).isoformat(),
                    packet_info.get('packet_id', 0),
                    packet_info.get('src_ip', ''),
                    packet_info.get('dst_ip', ''),
                    packet_info.get('src_port', 0),
                    packet_info.get('dst_port', 0),
                    packet_info.get('window_size', 0),
                    packet_info.get('window_base', 0),
                    packet_info.get('window_covert', 0),
                    packet_info.get('sequence_num', 0),
                    packet_info.get('ack_num', 0),
                    packet_info.get('flags', 0),
                    packet_info.get('payload_size', 0),
                    packet_info.get('flow_id', ''),
                    f"{overall_score:.3f}",
                    alert_triggered,
                    f"{detection_results.get('entropy', 0):.3f}",
                    f"{detection_results.get('ascii_encoding', 0):.3f}",
                    f"{detection_results.get('xor_encoding', 0):.3f}",
                    f"{detection_results.get('window_legitimacy', 0):.3f}",
                    f"{detection_results.get('oscillation_patterns', 0):.3f}",
                    f"{detection_results.get('frequency_domain', 0):.3f}",
                    f"{detection_results.get('benford_law', 0):.3f}",
                    f"{detection_results.get('timing_correlation', 0):.3f}",
                    f"{detection_results.get('payload_correlation', 0):.3f}",
                    ';'.join(detected_methods),
                    ';'.join(potential_chars),
                    confidence
                ]
                writer.writerow(row)
                
        except Exception as e:
            print(f"[DETECTOR] Error logging detection: {e}")
            traceback.print_exc()
    
    def _print_alert(self, packet_info, detection_results, overall_score):
        """Print alert information to console"""
        print("\n" + "="*80)
        print("!!! COVERT CHANNEL ALERT DETECTED! !!!")
        print("="*80)
        print(f"Timestamp: {datetime.fromtimestamp(packet_info['timestamp'])}")
        print(f"Flow: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")
        print(f"Window Size: {packet_info['window_size']} (Base: {packet_info['window_base']}, Covert: {packet_info['window_covert']})")
        print(f"Overall Detection Score: {overall_score:.3f}")
        
        # Show potential decoded character
        window_covert = packet_info['window_covert']
        if 32 <= window_covert <= 126:
            print(f"Potential ASCII Character: '{chr(window_covert)}' ({window_covert})")
        elif window_covert == 4:
            print(f"Potential EOF Marker: {window_covert}")
        
        print("\n DETAILED DETECTION ANALYSIS (with weighted scoring):")
        print("-" * 50)
        
        # Define the same weights as in the scoring calculation
        method_weights = {
            'ascii_encoding': 3.0,      # 3x weight - most important for ASCII covert channels
            'ascii_3digit_pattern': 3.5, # 3.5x weight - highest for your specific 3-digit ASCII setup
            'xor_encoding': 2.5,        # 2.5x weight - important for XOR-based channels
            'entropy': 1.5,             # 1.5x weight - good general indicator
            'window_legitimacy': 2.0,   # 2x weight - important for window-based channels
            'oscillation_patterns': 1.0, # 1x weight - baseline
            'frequency_domain': 1.0,    # 1x weight - baseline
            'benford_law': 1.0,         # 1x weight - baseline
            'timing_correlation': 0.8,  # 0.8x weight - less reliable
            'payload_correlation': 1.2  # 1.2x weight - moderately important
        }
        
        # Enhanced method analysis with explanations
        method_details = {
            'entropy': {
                'name': 'Entropy Analysis',
                'high': 'Low entropy detected - indicates structured/repeated data patterns',
                'medium': 'Moderate entropy - some structure detected in window sizes',
                'low': 'Normal entropy - window sizes appear random as expected'
            },
            'ascii_encoding': {
                'name': 'ASCII Encoding Detection',
                'high': 'Strong ASCII character patterns - likely text-based covert channel',
                'medium': 'Some ASCII patterns - possible text encoding',
                'low': 'No ASCII patterns detected'
            },
            'ascii_3digit_pattern': {
                'name': 'ASCII 3-Digit Pattern Detection',
                'high': 'Strong 3-digit ASCII patterns detected - matches your covert channel setup',
                'medium': 'Some 3-digit ASCII patterns - possible specialized encoding',
                'low': 'No 3-digit ASCII patterns detected'
            },
            'xor_encoding': {
                'name': 'XOR Encoding Detection',
                'high': 'XOR patterns detected - uniform bit distribution, sequential correlations, or repeating keys',
                'medium': 'Some XOR indicators - possible encoding detected',
                'low': 'No XOR encoding patterns detected'
            },
            'window_legitimacy': {
                'name': 'Window Legitimacy',
                'high': 'Window base in suspicious range (8K-65K) commonly used by covert channels',
                'medium': 'Unusual base range detected - investigate further',
                'low': 'Normal window base range for legitimate TCP traffic'
            },
            'oscillation_patterns': {
                'name': 'Oscillation Patterns',
                'high': 'Artificial oscillation patterns detected - suggests structured data',
                'medium': 'Some oscillation patterns detected - could indicate covert encoding',
                'low': 'No obvious oscillation patterns - appears random'
            },
            'frequency_domain': {
                'name': 'Frequency Domain Analysis',
                'high': 'Dominant frequencies detected - indicates regular patterns',
                'medium': 'Some frequency domain anomalies detected - could indicate covert encoding',
                'low': 'Normal frequency domain for TCP windows'
            },
            'benford_law': {
                'name': 'Benford\'s Law',
                'high': 'Benford\'s Law violations detected - unnatural digit distribution',
                'medium': 'Some Benford\'s Law anomalies detected - could indicate artificial data',
                'low': 'Normal digit distribution following Benford\'s Law'
            },
            'timing_correlation': {
                'name': 'Timing Correlation',
                'high': 'Strong correlation between timing and window values detected',
                'medium': 'Some timing correlation detected - possible secondary channel',
                'low': 'Normal timing patterns - no correlation detected'
            },
            'payload_correlation': {
                'name': 'Payload Correlation',
                'high': 'Window values correlate with payload characteristics',
                'medium': 'Some payload correlation detected - could indicate encoding',
                'low': 'Normal payload correlation for TCP windows'
            }
        }
        
        for method, score in detection_results.items():
            if score > 0.2:  # Only show methods that contributed meaningfully
                details = method_details.get(method, {'name': method, 'high': '', 'medium': '', 'low': ''})
                weight = method_weights.get(method, 1.0)
                weighted_score = score * weight
                
                if score > 0.6:
                    level = 'HIGH'
                    explanation = details['high']
                    icon = "🔴"
                elif score > 0.3:
                    level = 'MEDIUM' 
                    explanation = details['medium']
                    icon = "🟡"
                else:
                    level = 'LOW'
                    explanation = details['low']
                    icon = "🟢"
                
                weight_indicator = "+++" if weight >= 3.0 else "++" if weight >= 2.0 else "+" if weight >= 1.0 else "○"
                print(f"{icon} {details['name']:20} | Score: {score:.3f} (×{weight:.1f}) = {weighted_score:.3f} {weight_indicator} ({level})")
                if explanation:
                    print(f"   └─ {explanation}")
        
        print(f"\n  WEIGHTED TOTAL SCORE: {overall_score:.3f} (capped at 1.0)")
        print("   +++ = High weight (3.0x) | ++ = Medium weight (2.0x) | + = Normal weight (1.0x) | ○ = Low weight (0.8x)")
        
        # Provide overall assessment
        print(f"\n OVERALL ASSESSMENT:")
        if overall_score >= 0.8:
            print("   VERY HIGH CONFIDENCE - Strong indicators of covert channel activity")
        elif overall_score >= 0.6:
            print("   HIGH CONFIDENCE - Multiple indicators suggest covert channel")
        elif overall_score >= 0.4:
            print("   MEDIUM CONFIDENCE - Some suspicious patterns detected")
        else:
            print("   LOW CONFIDENCE - Minimal suspicious activity")
        
        # Show flow statistics if available
        flow_id = packet_info['flow_id']
        if flow_id in self.tcp_flows:
            flow_stats = self.tcp_flows[flow_id]
            print(f"\n FLOW STATISTICS:")
            print(f"   Packets in flow: {flow_stats['packet_count']}")
            print(f"   Flow duration: {time.time() - flow_stats['start_time']:.1f} seconds")
            if len(flow_stats['window_history']) > 1:
                windows = list(flow_stats['window_history'])
                covert_parts = [w % 1000 for w in windows]
                unique_covert = len(set(covert_parts))
                print(f"   Unique covert values: {unique_covert}/{len(covert_parts)} ({unique_covert/len(covert_parts)*100:.1f}%)")
        
        print("="*80 + "\n")
    
    def get_statistics(self):
        """Get detection statistics"""
        stats = self.detection_stats.copy()
        if stats['tcp_packets'] > 0:
            stats['average_covert_probability'] = stats['covert_probability_sum'] / stats['tcp_packets']
            stats['alert_rate'] = stats['alerts_triggered'] / stats['tcp_packets']
        else:
            stats['average_covert_probability'] = 0.0
            stats['alert_rate'] = 0.0
        return stats

    def _log_packet(self, packet_info, detection_results=None, detection_score=0.0, alert_triggered=False, direction="UNKNOWN", corruption_applied=False, mitigation_actions=None):
        """Log comprehensive packet information to CSV"""
        try:
            if not self.packet_log_file:  # Skip if no log file specified
                return
                
            # Ensure the directory exists
            log_dir = os.path.dirname(self.packet_log_file)
            if log_dir:  # Only create directory if path is not empty
                os.makedirs(log_dir, exist_ok=True)
            
            # Determine high-risk detection methods
            high_risk_methods = []
            suspected_encoding = "unknown"
            if detection_results:
                high_risk_methods = [name for name, score in detection_results.items() if score > 0.5]
                
                # Guess encoding mode based on detection patterns
                if detection_results.get('ascii_encoding', 0) > 0.6:
                    suspected_encoding = "ascii"
                elif detection_results.get('window_legitimacy', 0) > 0.6:
                    suspected_encoding = "structured"
            
            # Determine decoded character candidate
            decoded_char = ""
            window_covert = packet_info.get('window_covert', 0)
            if 32 <= window_covert <= 126:
                decoded_char = chr(window_covert)
            elif window_covert == 4:
                decoded_char = "EOF"
            
            # Calculate flow statistics
            flow_id = packet_info.get('flow_id', '')
            flow_packet_count = 0
            flow_duration = 0
            if flow_id in self.tcp_flows:
                flow_data = self.tcp_flows[flow_id]
                flow_packet_count = flow_data['packet_count']
                flow_duration = time.time() - flow_data['start_time']
            
            # Prepare payload preview (first 20 chars, printable only)
            payload_preview = ""
            if 'payload' in packet_info and packet_info['payload']:
                payload_bytes = packet_info['payload'][:20]
                payload_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload_bytes)
            
            # Extract mitigation information
            mitigation_info = mitigation_actions or {}
            mitigation_triggered = mitigation_info.get('triggered', False)
            mitigation_strategies = ','.join(mitigation_info.get('strategies_applied', []))
            mitigation_action = mitigation_info.get('primary_action', 'none')
            packet_dropped = mitigation_info.get('packet_dropped', False)
            packet_delayed_ms = mitigation_info.get('delay_ms', 0)
            window_modified = mitigation_info.get('new_window', 0) != mitigation_info.get('original_window', 0)
            original_window = mitigation_info.get('original_window', packet_info.get('tcp_window', 0))
            new_window = mitigation_info.get('new_window', packet_info.get('tcp_window', 0))
            
            row_data = [
                packet_info.get('timestamp', time.time()),
                int(packet_info.get('timestamp', time.time()) * 1000000),
                self.packet_stats['total_packets'],
                direction,
                packet_info.get('protocol', 'Unknown'),
                packet_info.get('src_ip', ''),
                packet_info.get('src_port', 0),
                packet_info.get('dst_ip', ''),
                packet_info.get('dst_port', 0),
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
                corruption_applied,
                packet_info.get('ttl', 0),
                packet_info.get('ip_version', 0),
                packet_info.get('ip_tos', 0),
                packet_info.get('ip_id', 0),
                packet_info.get('ip_fragment_offset', 0),
                packet_info.get('tcp_urgent_ptr', 0),
                packet_info.get('tcp_options_length', 0),
                flow_id,
                packet_info.get('inter_arrival_time_us', 0),
                self.detection_enabled,
                detection_score,
                alert_triggered,
                ','.join(high_risk_methods) if high_risk_methods else '',
                decoded_char,
                suspected_encoding,
                flow_packet_count,
                flow_duration,
                mitigation_triggered,
                mitigation_strategies,
                mitigation_action,
                packet_dropped,
                packet_delayed_ms,
                window_modified,
                original_window,
                new_window,
                payload_preview
            ]
            
            with open(self.packet_log_file, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(row_data)
                
        except Exception as e:
            print(f"[ERROR] Failed to log packet: {e}")
            traceback.print_exc()

def parse_packet(data):
    # Try to parse with Ether or IP, raise Python exception if fails
    pkt = Ether(data)
    if IP in pkt:
        return pkt
    return IP(data)  # fallback to raw IP layer if Ether not present

def corrupt_packet(pkt, corruption_rate=0.0):
    if random.random() > corruption_rate:
        return pkt
    raw_bytes = bytearray(bytes(pkt))
    if len(raw_bytes) > 0:
        index = random.randint(0, len(raw_bytes) - 1)
        raw_bytes[index] ^= 0xFF
    return raw_bytes

async def run(corruption_rate, detection_enabled, detection_threshold, verbose_detection,
              mitigation_enabled, mitigation_threshold, mitigation_strategies, mitigation_aggressiveness):
    nc = NATS()
    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)
    
    # Initialize covert channel detector with comprehensive logging
    detector = CovertChannelDetector(
        detection_enabled=detection_enabled,
        alert_threshold=detection_threshold,
        log_file=f"detection_log_{int(time.time())}.csv",
        packet_log_file=f"middlebox_packet_log_{int(time.time())}.csv"
    )
    
    # Initialize covert channel mitigator
    mitigator = CovertChannelMitigator(
        mitigation_enabled=mitigation_enabled,
        mitigation_threshold=mitigation_threshold,
        strategies=mitigation_strategies,
        aggressiveness=mitigation_aggressiveness
    )

    async def message_handler(msg):
        subject = msg.subject
        try:
            pkt = parse_packet(msg.data)
            
            # Extract packet information for logging (regardless of detection state)
            packet_info = detector._extract_packet_info(pkt)
            direction = "SEC->INSEC" if subject == "inpktsec" else "INSEC->SEC"
            
            # Initialize detection and mitigation variables
            alert_triggered = False
            detection_score = 0.0
            detection_results = {}
            mitigation_actions = {'triggered': False, 'strategies_applied': [], 'primary_action': 'none'}
            should_forward = True
            
            # Perform covert channel detection if enabled and packet is TCP
            # ONLY analyze SEC->INSEC traffic (sender to receiver) for covert channels
            if detection_enabled and pkt.haslayer(TCP) and direction == "SEC->INSEC":
                alert_triggered, detection_score, detection_results = detector.analyze_packet(pkt)
                
                # Apply mitigation if enabled and detection score warrants it
                if mitigation_enabled:
                    pkt, mitigation_actions, should_forward = mitigator.analyze_and_mitigate(
                        pkt, detection_results, detection_score, packet_info
                    )
                
                # Enhanced console output with individual method scores
                window_size = pkt[TCP].window
                window_base = (window_size // 1000) * 1000
                window_covert = window_size % 1000
                
                # DEBUG: Always show window analysis for sender traffic
                print(f"[COVERT DEBUG] {direction} | Window: {window_size} (Base: {window_base}, Covert: {window_covert}) | Score: {detection_score:.3f}")
                if 32 <= window_covert <= 126:
                    print(f"[COVERT DEBUG] Potential ASCII: '{chr(window_covert)}' (value {window_covert})")
                
                if verbose_detection:
                    # Show detailed detection breakdown for all TCP packets
                    print(f"\n[DETECTION] {direction} | Window: {window_size} (Base: {window_base}, Covert: {window_covert})")
                    print(f"[TOTAL SCORE] {detection_score:.3f} | Alert: {'!!! YES' if alert_triggered else ' NO'}")
                    
                    # Show individual method scores with interpretation and weights
                    print("[METHOD SCORES] (with weights)")
                    method_explanations = {
                        'entropy': 'Entropy (low=structured data)',
                        'ascii_encoding': 'ASCII (direct encoding)',
                        'ascii_3digit_pattern': 'ASCII 3-digit pattern (your setup)',
                        'xor_encoding': 'XOR (bit patterns & correlations)',
                        'window_legitimacy': 'Window Legitimacy',
                        'oscillation_patterns': 'Oscillation Patterns',
                        'frequency_domain': 'Frequency Domain Analysis',
                        'benford_law': 'Benford\'s Law',
                        'timing_correlation': 'Timing Correlation',
                        'payload_correlation': 'Payload Correlation'
                    }
                    
                    # Define the same weights as in the scoring calculation
                    method_weights = {
                        'ascii_encoding': 3.0,      # 3x weight - most important for ASCII covert channels
                        'ascii_3digit_pattern': 3.5, # 3.5x weight - highest for your specific 3-digit ASCII setup
                        'xor_encoding': 2.5,        # 2.5x weight - important for XOR-based channels
                        'entropy': 1.5,             # 1.5x weight - good general indicator
                        'window_legitimacy': 2.0,   # 2x weight - important for window-based channels
                        'oscillation_patterns': 1.0, # 1x weight - baseline
                        'frequency_domain': 1.0,    # 1x weight - baseline
                        'benford_law': 1.0,         # 1x weight - baseline
                        'timing_correlation': 0.8,  # 0.8x weight - less reliable
                        'payload_correlation': 1.2  # 1.2x weight - moderately important
                    }
                    
                    for method, score in detection_results.items():
                        explanation = method_explanations.get(method, method)
                        weight = method_weights.get(method, 1.0)
                        weighted_score = score * weight
                        status = "🔴" if score > 0.6 else "🟡" if score > 0.3 else "🟢"
                        weight_indicator = "+++" if weight >= 3.0 else "++" if weight >= 2.0 else "+" if weight >= 1.0 else "○"
                        print(f"  {status} {explanation:25}: {score:.3f} (×{weight:.1f}) = {weighted_score:.3f} {weight_indicator}")
                    
                    print(f"[WEIGHTED TOTAL] Final score: {detection_score:.3f} (capped at 1.0)")
                    
                    # Show potential decoded character if in ASCII range
                    if 32 <= window_covert <= 126:
                        print(f"[POTENTIAL CHAR] '{chr(window_covert)}' (ASCII {window_covert})")
                    elif window_covert == 4:
                        print(f"[POTENTIAL CHAR] EOF marker (value {window_covert})")
                    
                    # Show high-scoring detection reasons
                    high_scoring_methods = [name for name, score in detection_results.items() if score > 0.5]
                    if high_scoring_methods:
                        print(f"[HIGH SUSPICION] Methods: {', '.join(high_scoring_methods)}")
                    
                    print("-" * 60)
                else:
                    # Summary mode - only show significant detections
                    if detection_score > 0.3:
                        high_methods = [name for name, score in detection_results.items() if score > 0.5]
                        char_info = f" → '{chr(window_covert)}'" if 32 <= window_covert <= 126 else f" → EOF" if window_covert == 4 else ""
                        print(f"[DETECT] {direction} | Score: {detection_score:.3f} | Win: {window_size}{char_info} | Methods: {','.join(high_methods) if high_methods else 'multiple'}")
            elif detection_enabled and pkt.haslayer(TCP) and direction == "INSEC->SEC":
                # Just log receiver traffic without detection
                window_size = pkt[TCP].window
                print(f"[RECEIVER] {direction} | Window: {window_size} (ignored for detection)")
                # Set empty detection results for logging
                detection_results = {}
                detection_score = 0.0
                alert_triggered = False
            
            # Apply corruption if specified
            corruption_applied = False
            corrupted = pkt
            if corruption_rate > 0.0:
                corrupted = corrupt_packet(pkt, corruption_rate=corruption_rate)
                corruption_applied = (corrupted != pkt)
                if corruption_applied:
                    detector.packet_stats['corrupted_packets'] += 1
            
            # Log comprehensive packet information to CSV (enhanced with mitigation info)
            detector._log_packet(
                packet_info=packet_info,
                detection_results=detection_results,
                detection_score=detection_score,
                alert_triggered=alert_triggered,
                direction=direction,
                corruption_applied=corruption_applied,
                mitigation_actions=mitigation_actions
            )
            
            # Show packet info (reduced verbosity for console)
            if pkt.haslayer(TCP):
                if not detection_enabled or not verbose_detection:
                    # Enhanced console output with mitigation info
                    tcp_info = f"TCP {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} | Win: {pkt[TCP].window}"
                    mitigation_info = ""
                    if mitigation_enabled and mitigation_actions['triggered']:
                        action_str = mitigation_actions['primary_action']
                        forward_str = "DROPPED" if not should_forward else "FORWARDED"
                        mitigation_info = f" |  {action_str.upper()} ({forward_str})"
                    print(f"[PACKET] {tcp_info}{mitigation_info}")
            elif not verbose_detection:
                # Show basic info for non-TCP packets
                protocol = packet_info.get('protocol', 'Unknown')
                src = f"{packet_info.get('src_ip', '')}:{packet_info.get('src_port', '')}" if packet_info.get('src_port') else packet_info.get('src_ip', '')
                dst = f"{packet_info.get('dst_ip', '')}:{packet_info.get('dst_port', '')}" if packet_info.get('dst_port') else packet_info.get('dst_ip', '')
                print(f"[PACKET] {protocol} {src} -> {dst} | Size: {packet_info.get('packet_size', 0)}")
            
            await asyncio.sleep(random.expovariate(1 / 1e-8))
            
            # Apply delay if mitigation requested it
            if mitigation_actions.get('delay_ms', 0) > 0:
                delay_seconds = mitigation_actions['delay_ms'] / 1000.0
                print(f"[MITIGATOR]  Applying {mitigation_actions['delay_ms']}ms delay")
                await asyncio.sleep(delay_seconds)
            
            # Forward packet to destination (only if not dropped by mitigation)
            if should_forward:
                out_topic = "outpktinsec" if subject == "inpktsec" else "outpktsec"
                await nc.publish(out_topic, bytes(corrupted))
            else:
                print(f"[MITIGATOR]  Packet DROPPED - not forwarded")
            
        except Exception:
            traceback.print_exc()  # ⬅️ Native Python traceback
            os._exit(1)

    await nc.subscribe("inpktsec", cb=message_handler)
    await nc.subscribe("inpktinsec", cb=message_handler)

    print(f"Subscribed to inpktsec and inpktinsec topics with corruption rate: {corruption_rate}")
    if detection_enabled:
        print(f" Covert Channel Detection ENABLED (threshold: {detection_threshold})")
        print(f" Detection verbosity: {'DETAILED' if verbose_detection else 'SUMMARY'}")
        print(f"  Weighted Scoring: ASCII 3-digit pattern (3.5x), ASCII encoding (3.0x), XOR encoding (2.5x)")
        print(f"   Other methods: Window legitimacy (2.0x), Entropy (1.5x), Payload correlation (1.2x), Others (1.0x), Timing (0.8x)")
    else:
        print(" Covert Channel Detection DISABLED")
    
    if mitigation_enabled:
        print(f"  Covert Channel Mitigation ENABLED (threshold: {mitigation_threshold})")
        print(f" Mitigation strategies: {', '.join(mitigation_strategies)}")
        print(f" Aggressiveness level: {mitigation_aggressiveness.upper()}")
        print(f" Log file: {mitigator.log_file}")
    else:
        print(" Covert Channel Mitigation DISABLED")

    try:
        # Periodic statistics reporting
        stats_interval = 30  # seconds
        last_stats_time = time.time()
        
        while True:
            await asyncio.sleep(1)
            
            # Report detection and mitigation statistics periodically
            if (detection_enabled or mitigation_enabled) and time.time() - last_stats_time > stats_interval:
                packet_stats = detector.packet_stats
                print(f"\n[STATS] === MIDDLEBOX STATISTICS ===")
                print(f"[STATS] Total Packets: {packet_stats['total_packets']} | TCP: {packet_stats['tcp_packets']} | UDP: {packet_stats['udp_packets']} | ICMP: {packet_stats['icmp_packets']} | Other: {packet_stats['other_packets']}")
                print(f"[STATS] Bytes Processed: {packet_stats['bytes_processed']:,} | Corrupted: {packet_stats['corrupted_packets']}")
                
                if detection_enabled:
                    stats = detector.get_statistics()
                    print(f"[STATS] Detection Alerts: {stats['alerts_triggered']} | Avg Score: {stats['average_covert_probability']:.3f}")
                
                if mitigation_enabled:
                    mitigation_stats = mitigator.get_statistics()
                    print(f"[STATS] Mitigation: Analyzed: {mitigation_stats['total_analyzed']} | Triggered: {mitigation_stats['mitigation_triggered']} | Rate: {mitigation_stats['mitigation_rate']:.3f}")
                    print(f"[STATS] Actions: Sanitized: {mitigation_stats['packets_sanitized']} | Dropped: {mitigation_stats['packets_dropped']} | Reset: {mitigation_stats['connections_reset']} | Delayed: {mitigation_stats['packets_delayed']}")
                
                last_stats_time = time.time()
                
    except KeyboardInterrupt:
        if detection_enabled or mitigation_enabled:
            final_packet_stats = detector.packet_stats
            print(f"\n[FINAL STATS] === MIDDLEBOX FINAL STATISTICS ===")
            print(f"[FINAL STATS] Packet Summary:")
            print(f"  Total Packets: {final_packet_stats['total_packets']}")
            print(f"  TCP: {final_packet_stats['tcp_packets']} | UDP: {final_packet_stats['udp_packets']} | ICMP: {final_packet_stats['icmp_packets']} | Other: {final_packet_stats['other_packets']}")
            print(f"[FINAL STATS] Bytes Processed: {final_packet_stats['bytes_processed']:,}")
            print(f"[FINAL STATS] Corrupted Packets: {final_packet_stats['corrupted_packets']}")
            
            if detection_enabled:
                final_stats = detector.get_statistics()
                print(f"[FINAL STATS] Detection Summary:")
                print(f"  Total TCP Packets: {final_stats['tcp_packets']}")
                print(f"  Alerts Triggered: {final_stats['alerts_triggered']}")
                print(f"  Alert Rate: {final_stats['alert_rate']:.3f}")
                print(f"  Average Detection Score: {final_stats['average_covert_probability']:.3f}")
            
            if mitigation_enabled:
                final_mitigation_stats = mitigator.get_statistics()
                print(f"[FINAL STATS] Mitigation Summary:")
                print(f"  Total Analyzed: {final_mitigation_stats['total_analyzed']}")
                print(f"  Mitigation Triggered: {final_mitigation_stats['mitigation_triggered']}")
                print(f"  Mitigation Rate: {final_mitigation_stats['mitigation_rate']:.3f}")
                print(f"  Packets Sanitized: {final_mitigation_stats['packets_sanitized']}")
                print(f"  Packets Dropped: {final_mitigation_stats['packets_dropped']}")
                print(f"  Connections Reset: {final_mitigation_stats['connections_reset']}")
                print(f"  Packets Delayed: {final_mitigation_stats['packets_delayed']}")
            
            print(f"[FINAL STATS] Log Files:")
            print(f"  Detection Log: {detector.log_file}")
            print(f"  Packet Log: {detector.packet_log_file}")
            if mitigation_enabled:
                print(f"  Mitigation Log: {mitigator.log_file}")
        
        print("Disconnecting...")
        await nc.close()

class CovertChannelMitigator:
    """
    Advanced covert channel mitigation system
    """
    
    def __init__(self, mitigation_enabled=True, mitigation_threshold=0.6, strategies=['sanitize_window'], 
                 aggressiveness='medium', log_file=None):
        """
        Initialize the covert channel mitigator
        
        Args:
            mitigation_enabled: Whether to perform mitigation
            mitigation_threshold: Threshold for triggering mitigation (0.0-1.0)
            strategies: List of mitigation strategies to apply
            aggressiveness: Mitigation aggressiveness level ('conservative', 'medium', 'aggressive')
            log_file: File to log mitigation actions
        """
        self.mitigation_enabled = mitigation_enabled
        self.mitigation_threshold = mitigation_threshold
        self.aggressiveness = aggressiveness
        
        # Available mitigation strategies
        self.available_strategies = {
            'sanitize_window': self._sanitize_window_size,
            'drop_packet': self._drop_packet,
            'reset_connection': self._reset_connection,
            'delay_packet': self._delay_packet,
            'randomize_window': self._randomize_window,
            'normalize_window': self._normalize_window
        }
        
        # Validate and set strategies
        self.strategies = []
        for strategy in strategies:
            if strategy in self.available_strategies:
                self.strategies.append(strategy)
            else:
                print(f"[MITIGATOR] Warning: Unknown strategy '{strategy}', skipping")
        
        if not self.strategies:
            self.strategies = ['sanitize_window']  # Default fallback
        
        # Set aggressiveness parameters
        self.aggressiveness_params = self._get_aggressiveness_params(aggressiveness)
        
        # Create logs directory if it doesn't exist
        logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Set up log file paths
        timestamp = int(time.time())
        self.log_file = os.path.join(logs_dir, f"mitigation_log_{timestamp}.csv") if log_file is None else log_file
        
        # Mitigation statistics
        self.mitigation_stats = {
            'total_analyzed': 0,
            'mitigation_triggered': 0,
            'packets_dropped': 0,
            'packets_sanitized': 0,
            'connections_reset': 0,
            'packets_delayed': 0,
            'strategy_usage': {strategy: 0 for strategy in self.strategies}
        }
        
        # Flow-level tracking for connection resets
        self.reset_flows = set()  # Flows that have been marked for reset
        
        # Initialize CSV logging
        if self.mitigation_enabled:
            self._init_csv_logging()
        
        print(f"[MITIGATOR] Covert channel mitigator initialized")
        print(f"[MITIGATOR] Mitigation: {'ENABLED' if mitigation_enabled else 'DISABLED'}")
        print(f"[MITIGATOR] Threshold: {mitigation_threshold}")
        print(f"[MITIGATOR] Strategies: {', '.join(self.strategies)}")
        print(f"[MITIGATOR] Aggressiveness: {aggressiveness}")
        print(f"[MITIGATOR] Log file: {self.log_file}")
    
    def _get_aggressiveness_params(self, level):
        """Get parameters based on aggressiveness level"""
        params = {
            'conservative': {
                'sanitize_probability': 0.3,  # Only sanitize 30% of detected packets
                'drop_threshold_bonus': 0.2,  # Need higher score to drop
                'reset_threshold_bonus': 0.3, # Need even higher score to reset
                'delay_max_ms': 50,           # Short delays
                'randomization_range': 0.1    # Small randomization
            },
            'medium': {
                'sanitize_probability': 0.7,  # Sanitize 70% of detected packets
                'drop_threshold_bonus': 0.1,  # Moderate score needed to drop
                'reset_threshold_bonus': 0.2, # Higher score needed to reset
                'delay_max_ms': 200,          # Medium delays
                'randomization_range': 0.2    # Medium randomization
            },
            'aggressive': {
                'sanitize_probability': 1.0,  # Sanitize all detected packets
                'drop_threshold_bonus': 0.0,  # Drop at base threshold
                'reset_threshold_bonus': 0.1, # Reset with small bonus
                'delay_max_ms': 500,          # Longer delays
                'randomization_range': 0.3    # Higher randomization
            }
        }
        return params.get(level, params['medium'])
    
    def _init_csv_logging(self):
        """Initialize CSV logging for mitigation actions"""
        try:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            
            with open(self.log_file, 'w', newline='') as csvfile:
                headers = [
                    'timestamp', 'packet_id', 'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                    'detection_score', 'mitigation_threshold', 'threshold_exceeded',
                    'original_window', 'window_base', 'window_covert', 'mitigation_triggered',
                    'strategies_applied', 'primary_action', 'new_window_size', 'packet_dropped',
                    'connection_reset', 'delay_applied_ms', 'aggressiveness_level',
                    'detected_methods', 'confidence_level', 'flow_already_reset',
                    'sanitization_method', 'randomization_applied', 'notes'
                ]
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                print(f"[MITIGATOR] Mitigation log initialized: {self.log_file}")
        except Exception as e:
            print(f"[MITIGATOR] Error initializing mitigation log: {e}")
            traceback.print_exc()
    
    def analyze_and_mitigate(self, packet, detection_results, detection_score, packet_info):
        """
        Analyze detection results and apply mitigation if necessary
        
        Args:
            packet: Scapy packet object
            detection_results: Dictionary of detection method results
            detection_score: Overall detection score (0.0-1.0)
            packet_info: Extracted packet information
            
        Returns:
            tuple: (mitigated_packet, mitigation_actions, should_forward)
        """
        self.mitigation_stats['total_analyzed'] += 1
        
        # Initialize mitigation actions
        mitigation_actions = {
            'triggered': False,
            'strategies_applied': [],
            'primary_action': 'none',
            'packet_dropped': False,
            'connection_reset': False,
            'delay_ms': 0,
            'original_window': packet_info.get('tcp_window', 0) if packet.haslayer(TCP) else 0,
            'new_window': packet_info.get('tcp_window', 0) if packet.haslayer(TCP) else 0,
            'sanitization_method': 'none',
            'randomization_applied': False,
            'notes': []
        }
        
        # Check if mitigation should be triggered
        threshold_exceeded = detection_score >= self.mitigation_threshold
        should_forward = True
        mitigated_packet = packet
        
        if not self.mitigation_enabled or not threshold_exceeded or not packet.haslayer(TCP):
            # Log the decision even if no mitigation applied
            self._log_mitigation(packet_info, detection_results, detection_score, mitigation_actions)
            return mitigated_packet, mitigation_actions, should_forward
        
        # Mitigation is triggered
        mitigation_actions['triggered'] = True
        self.mitigation_stats['mitigation_triggered'] += 1
        
        flow_id = packet_info.get('flow_id', '')
        flow_already_reset = flow_id in self.reset_flows
        
        print(f"[MITIGATOR]   MITIGATION TRIGGERED | Score: {detection_score:.3f} | Flow: {flow_id}")
        
        # Apply mitigation strategies in order
        for strategy_name in self.strategies:
            if strategy_name in self.available_strategies:
                try:
                    strategy_func = self.available_strategies[strategy_name]
                    mitigated_packet, action_result = strategy_func(
                        mitigated_packet, detection_results, detection_score, 
                        packet_info, mitigation_actions, flow_already_reset
                    )
                    
                    # Update mitigation actions based on strategy result
                    if action_result.get('applied', False):
                        mitigation_actions['strategies_applied'].append(strategy_name)
                        self.mitigation_stats['strategy_usage'][strategy_name] += 1
                        
                        # Set primary action if not already set
                        if mitigation_actions['primary_action'] == 'none':
                            mitigation_actions['primary_action'] = action_result.get('action', strategy_name)
                        
                        # Update specific action flags
                        if action_result.get('packet_dropped'):
                            mitigation_actions['packet_dropped'] = True
                            should_forward = False
                        
                        if action_result.get('connection_reset'):
                            mitigation_actions['connection_reset'] = True
                            self.reset_flows.add(flow_id)
                        
                        if action_result.get('delay_ms', 0) > 0:
                            mitigation_actions['delay_ms'] = max(
                                mitigation_actions['delay_ms'], 
                                action_result['delay_ms']
                            )
                        
                        # Update window information
                        if action_result.get('new_window') is not None:
                            mitigation_actions['new_window'] = action_result['new_window']
                        
                        if action_result.get('sanitization_method'):
                            mitigation_actions['sanitization_method'] = action_result['sanitization_method']
                        
                        if action_result.get('randomization_applied'):
                            mitigation_actions['randomization_applied'] = True
                        
                        if action_result.get('notes'):
                            mitigation_actions['notes'].extend(action_result['notes'])
                        
                        print(f"[MITIGATOR]    Applied {strategy_name}: {action_result.get('action', 'modified')}")
                    
                except Exception as e:
                    print(f"[MITIGATOR] Error applying strategy {strategy_name}: {e}")
                    mitigation_actions['notes'].append(f"Error in {strategy_name}: {str(e)}")
        
        # Log the mitigation action
        self._log_mitigation(packet_info, detection_results, detection_score, mitigation_actions)
        
        # Print mitigation summary
        if mitigation_actions['strategies_applied']:
            actions_str = ', '.join(mitigation_actions['strategies_applied'])
            result_str = "DROPPED" if not should_forward else f"MODIFIED ({mitigation_actions['primary_action']})"
            print(f"[MITIGATOR]  Result: {result_str} | Strategies: {actions_str}")
        
        return mitigated_packet, mitigation_actions, should_forward
    
    def _sanitize_window_size(self, packet, detection_results, detection_score, packet_info, mitigation_actions, flow_already_reset):
        """Sanitize TCP window size by removing covert data"""
        if not packet.haslayer(TCP):
            return packet, {'applied': False}
        
        # Check sanitization probability based on aggressiveness
        if random.random() > self.aggressiveness_params['sanitize_probability']:
            return packet, {'applied': False, 'notes': ['Sanitization skipped due to probability']}
        
        tcp_layer = packet[TCP]
        original_window = tcp_layer.window
        window_base = (original_window // 1000) * 1000
        window_covert = original_window % 1000
        
        # Choose sanitization method based on detection results and aggressiveness
        sanitization_method = 'base_only'
        new_window = window_base
        
        # If base window is too small or unrealistic, set a reasonable default
        if window_base < 8000:
            new_window = random.randint(8000, 16000)  # Conservative default
            sanitization_method = 'realistic_default'
        elif window_base > 65000:
            new_window = random.randint(32000, 65000)  # Cap at reasonable max
            sanitization_method = 'capped_realistic'
        else:
            # Base is reasonable, just remove covert part
            new_window = window_base
            sanitization_method = 'base_only'
        
        # Apply some randomization to avoid creating new patterns
        if self.aggressiveness_params['randomization_range'] > 0:
            randomization = int(new_window * self.aggressiveness_params['randomization_range'])
            new_window += random.randint(-randomization, randomization)
            new_window = max(1024, min(65535, new_window))  # Keep within valid TCP window range
            mitigation_actions['randomization_applied'] = True
        
        # Modify the packet
        tcp_layer.window = new_window
        
        # Recalculate checksums
        del packet[IP].chksum
        del packet[TCP].chksum
        packet = packet.__class__(bytes(packet))  # Force recalculation
        
        self.mitigation_stats['packets_sanitized'] += 1
        
        return packet, {
            'applied': True,
            'action': 'sanitize_window',
            'new_window': new_window,
            'sanitization_method': sanitization_method,
            'randomization_applied': mitigation_actions['randomization_applied'],
            'notes': [f'Window sanitized: {original_window} -> {new_window} (method: {sanitization_method})']
        }
    
    def _drop_packet(self, packet, detection_results, detection_score, packet_info, mitigation_actions, flow_already_reset):
        """Drop packet if detection score is very high"""
        # Apply threshold bonus based on aggressiveness
        drop_threshold = self.mitigation_threshold + self.aggressiveness_params['drop_threshold_bonus']
        
        if detection_score >= drop_threshold:
            self.mitigation_stats['packets_dropped'] += 1
            return packet, {
                'applied': True,
                'action': 'drop',
                'packet_dropped': True,
                'notes': [f'Packet dropped due to high suspicion score: {detection_score:.3f} >= {drop_threshold:.3f}']
            }
        
        return packet, {'applied': False, 'notes': [f'Drop threshold not met: {detection_score:.3f} < {drop_threshold:.3f}']}
    
    def _reset_connection(self, packet, detection_results, detection_score, packet_info, mitigation_actions, flow_already_reset):
        """Reset TCP connection for very suspicious flows"""
        if flow_already_reset:
            return packet, {'applied': False, 'notes': ['Flow already marked for reset']}
        
        # Apply threshold bonus based on aggressiveness
        reset_threshold = self.mitigation_threshold + self.aggressiveness_params['reset_threshold_bonus']
        
        if detection_score >= reset_threshold:
            self.mitigation_stats['connections_reset'] += 1
            # Note: Actual RST packet sending would be implemented here
            # For now, we just mark the connection for reset
            return packet, {
                'applied': True,
                'action': 'reset_connection',
                'connection_reset': True,
                'notes': [f'Connection marked for reset due to very high suspicion: {detection_score:.3f} >= {reset_threshold:.3f}']
            }
        
        return packet, {'applied': False, 'notes': [f'Reset threshold not met: {detection_score:.3f} < {reset_threshold:.3f}']}
    
    def _delay_packet(self, packet, detection_results, detection_score, packet_info, mitigation_actions, flow_already_reset):
        """Apply artificial delay to suspicious packets"""
        # Calculate delay based on detection score and aggressiveness
        max_delay = self.aggressiveness_params['delay_max_ms']
        delay_ms = int((detection_score - self.mitigation_threshold) * max_delay / (1.0 - self.mitigation_threshold))
        delay_ms = max(10, min(max_delay, delay_ms))  # Ensure reasonable bounds
        
        if delay_ms > 0:
            self.mitigation_stats['packets_delayed'] += 1
            # Note: Actual delay would be implemented in the packet forwarding logic
            return packet, {
                'applied': True,
                'action': 'delay',
                'delay_ms': delay_ms,
                'notes': [f'Packet scheduled for {delay_ms}ms delay']
            }
        
        return packet, {'applied': False, 'notes': ['No delay calculated']}
    
    def _randomize_window(self, packet, detection_results, detection_score, packet_info, mitigation_actions, flow_already_reset):
        """Randomize window size to disrupt covert channel"""
        if not packet.haslayer(TCP):
            return packet, {'applied': False}
        
        tcp_layer = packet[TCP]
        original_window = tcp_layer.window
        
        # Generate a realistic random window size
        new_window = random.randint(8192, 65535)  # Common TCP window range
        
        tcp_layer.window = new_window
        
        # Recalculate checksums
        del packet[IP].chksum
        del packet[TCP].chksum
        packet = packet.__class__(bytes(packet))
        
        return packet, {
            'applied': True,
            'action': 'randomize_window',
            'new_window': new_window,
            'randomization_applied': True,
            'notes': [f'Window randomized: {original_window} -> {new_window}']
        }
    
    def _normalize_window(self, packet, detection_results, detection_score, packet_info, mitigation_actions, flow_already_reset):
        """Normalize window size to common values"""
        if not packet.haslayer(TCP):
            return packet, {'applied': False}
        
        tcp_layer = packet[TCP]
        original_window = tcp_layer.window
        
        # Common TCP window sizes
        common_windows = [8192, 16384, 32768, 65535]
        
        # Choose the closest common window size
        new_window = min(common_windows, key=lambda x: abs(x - original_window))
        
        tcp_layer.window = new_window
        
        # Recalculate checksums
        del packet[IP].chksum
        del packet[TCP].chksum
        packet = packet.__class__(bytes(packet))
        
        return packet, {
            'applied': True,
            'action': 'normalize_window', 
            'new_window': new_window,
            'sanitization_method': 'common_value',
            'notes': [f'Window normalized: {original_window} -> {new_window}']
        }
    
    def _log_mitigation(self, packet_info, detection_results, detection_score, mitigation_actions):
        """Log mitigation actions to CSV file"""
        try:
            if not self.log_file:
                return
                
            # Determine confidence level
            if detection_score >= 0.8:
                confidence = "HIGH"
            elif detection_score >= 0.5:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
            
            # Get detected methods
            detected_methods = [name for name, score in detection_results.items() if score > 0.5] if detection_results else []
            
            # Prepare row data
            row_data = [
                datetime.fromtimestamp(packet_info.get('timestamp', time.time())).isoformat(),
                packet_info.get('packet_id', 0),
                packet_info.get('flow_id', ''),
                packet_info.get('src_ip', ''),
                packet_info.get('dst_ip', ''),
                packet_info.get('src_port', 0),
                packet_info.get('dst_port', 0),
                f"{detection_score:.3f}",
                f"{self.mitigation_threshold:.3f}",
                detection_score >= self.mitigation_threshold,
                mitigation_actions['original_window'],
                (mitigation_actions['original_window'] // 1000) * 1000,
                mitigation_actions['original_window'] % 1000,
                mitigation_actions['triggered'],
                ';'.join(mitigation_actions['strategies_applied']),
                mitigation_actions['primary_action'],
                mitigation_actions['new_window'],
                mitigation_actions['packet_dropped'],
                mitigation_actions['connection_reset'],
                mitigation_actions['delay_ms'],
                self.aggressiveness,
                ';'.join(detected_methods),
                confidence,
                packet_info.get('flow_id', '') in self.reset_flows,
                mitigation_actions['sanitization_method'],
                mitigation_actions['randomization_applied'],
                '; '.join(mitigation_actions['notes'])
            ]
            
            with open(self.log_file, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(row_data)
                
        except Exception as e:
            print(f"[MITIGATOR] Error logging mitigation: {e}")
            traceback.print_exc()
    
    def get_statistics(self):
        """Get mitigation statistics"""
        stats = self.mitigation_stats.copy()
        if stats['total_analyzed'] > 0:
            stats['mitigation_rate'] = stats['mitigation_triggered'] / stats['total_analyzed']
        else:
            stats['mitigation_rate'] = 0.0
        return stats

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Python packet processor with covert channel detection and mitigation')
    parser.add_argument('--corruption-rate', '-c', type=float, default=0.0,
                       help='Packet corruption rate (0.0 to 1.0, default: 0.0)')
    parser.add_argument('--detect', '-d', action='store_true',
                       help='Enable covert channel detection (default: disabled)')
    parser.add_argument('--detection-threshold', '-t', type=float, default=0.7,
                       help='Detection alert threshold (0.0 to 1.0, default: 0.7)')
    parser.add_argument('--verbose-detection', '-v', action='store_true',
                       help='Enable verbose detection output showing all method scores (default: summary mode)')
    
    # Mitigation arguments
    parser.add_argument('--mitigate', '-m', action='store_true',
                       help='Enable covert channel mitigation (default: disabled)')
    parser.add_argument('--mitigation-threshold', '-mt', type=float, default=0.6,
                       help='Mitigation activation threshold (0.0 to 1.0, default: 0.6)')
    parser.add_argument('--mitigation-strategy', '-ms', nargs='+', 
                       choices=['sanitize_window', 'drop_packet', 'reset_connection', 'delay_packet', 'randomize_window', 'normalize_window'],
                       default=['sanitize_window'],
                       help='Mitigation strategies to apply (can specify multiple, default: sanitize_window)')
    parser.add_argument('--mitigation-aggressiveness', '-ma', 
                       choices=['conservative', 'medium', 'aggressive'], 
                       default='medium',
                       help='Mitigation aggressiveness level (default: medium)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not 0.0 <= args.corruption_rate <= 1.0:
        print("Error: Corruption rate must be between 0.0 and 1.0")
        exit(1)
        
    if not 0.0 <= args.detection_threshold <= 1.0:
        print("Error: Detection threshold must be between 0.0 and 1.0")
        exit(1)
        
    if not 0.0 <= args.mitigation_threshold <= 1.0:
        print("Error: Mitigation threshold must be between 0.0 and 1.0")
        exit(1)
    
    asyncio.run(run(args.corruption_rate, args.detect, args.detection_threshold, args.verbose_detection,
                   args.mitigate, args.mitigation_threshold, args.mitigation_strategy, args.mitigation_aggressiveness)) 