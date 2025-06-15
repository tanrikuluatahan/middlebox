import os
import socket
import time
import random
import json
import string
from datetime import datetime

def generate_dynamic_data():
    """Generate highly diverse and random data with many different patterns"""
    
    # Expand data generation types significantly
    data_generators = [
        # 1. JSON-like data with varied structures
        lambda: json.dumps({
            'timestamp': datetime.now().isoformat(),
            'value': random.uniform(-1000, 1000),
            'status': random.choice(['active', 'idle', 'processing', 'error', 'warning', 'success', 'pending']),
            'counter': random.randint(1, 100000),
            'metadata': {
                'source': random.choice(['sensor1', 'sensor2', 'api', 'user', 'system']),
                'priority': random.choice(['low', 'medium', 'high', 'critical'])
            }
        }),
        
        # 2. Log entries with various formats
        lambda: f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {random.choice(['INFO', 'WARN', 'ERROR', 'DEBUG', 'TRACE'])}: {random.choice(['User', 'System', 'Service'])} {random.choice(['authenticated', 'failed', 'connected', 'disconnected', 'processed', 'queued'])} - ID:{random.randint(10000, 99999)}",
        
        # 3. CSV-like data
        lambda: f"{random.randint(1, 1000)},{random.uniform(0, 100):.2f},{random.choice(['A', 'B', 'C', 'D'])},{random.randint(2020, 2024)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
        
        # 4. XML-like data
        lambda: f"<data><id>{random.randint(1, 10000)}</id><value>{random.uniform(0, 1000):.3f}</value><type>{random.choice(['measurement', 'event', 'alert'])}</type></data>",
        
        # 5. Base64-like encoded data
        lambda: ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=random.randint(20, 80))),
        
        # 6. Binary data patterns
        lambda: bytes([random.randint(0, 255) for _ in range(random.randint(5, 100))]),
        
        # 7. Hex dump style data
        lambda: ' '.join([f'{random.randint(0, 255):02x}' for _ in range(random.randint(8, 32))]),
        
        # 8. Network protocol-like data
        lambda: f"PROTO:{random.choice(['HTTP', 'FTP', 'SMTP', 'TCP', 'UDP'])}:{random.randint(1000, 65535)}:{random.choice(['GET', 'POST', 'PUT', 'DELETE'])}:/path/{random.randint(1, 100)}",
        
        # 9. Database query-like data
        lambda: f"SELECT * FROM table_{random.randint(1, 20)} WHERE id={random.randint(1, 10000)} AND status='{random.choice(['active', 'inactive', 'pending'])}'",
        
        # 10. Configuration data
        lambda: f"config.{random.choice(['database', 'network', 'security'])}.{random.choice(['timeout', 'retries', 'buffer_size'])}={random.randint(1, 1000)}",
        
        # 11. Random text with natural language patterns
        lambda: ' '.join([random.choice(['The', 'A', 'This', 'That', 'Some', 'Every']), 
                         random.choice(['quick', 'lazy', 'brown', 'red', 'fast', 'slow']),
                         random.choice(['fox', 'dog', 'cat', 'bird', 'system', 'process']),
                         random.choice(['jumps', 'runs', 'walks', 'flies', 'executes', 'processes']),
                         random.choice(['over', 'under', 'through', 'around', 'with', 'without']),
                         random.choice(['the', 'a', 'some', 'many', 'few', 'several']),
                         random.choice(['fence', 'wall', 'data', 'packets', 'requests', 'responses'])]),
        
        # 12. Mixed alphanumeric patterns
        lambda: ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?', k=random.randint(15, 80))),
        
        # 13. Structured data with separators
        lambda: '|'.join([str(random.randint(1, 1000)), 
                         random.choice(['success', 'failure', 'timeout', 'retry']),
                         str(random.uniform(0, 100)),
                         datetime.now().strftime('%H:%M:%S')]),
        
        # 14. URL-like data
        lambda: f"https://{random.choice(['api', 'www', 'cdn', 'static'])}.{random.choice(['example', 'test', 'demo'])}.{random.choice(['com', 'org', 'net'])}/v{random.randint(1, 3)}/{random.choice(['users', 'data', 'files'])}/{random.randint(1, 10000)}?param={random.randint(1, 100)}",
        
        # 15. Email-like data
        lambda: f"{random.choice(['user', 'admin', 'test', 'demo'])}{random.randint(1, 999)}@{random.choice(['company', 'org', 'test'])}.{random.choice(['com', 'org', 'net'])}",
        
        # 16. Version/build info
        lambda: f"v{random.randint(1, 10)}.{random.randint(0, 20)}.{random.randint(0, 100)}-{random.choice(['alpha', 'beta', 'rc', 'stable'])}.{random.randint(1, 50)}",
        
        # 17. Hash-like data
        lambda: ''.join(random.choices('0123456789abcdef', k=random.choice([32, 40, 64]))),
        
        # 18. Performance metrics
        lambda: f"cpu:{random.uniform(0, 100):.1f}% mem:{random.uniform(0, 100):.1f}% disk:{random.uniform(0, 100):.1f}% net:{random.randint(0, 1000)}kb/s",
        
        # 19. Error codes and messages
        lambda: f"ERROR_{random.randint(1000, 9999)}: {random.choice(['Connection failed', 'Timeout occurred', 'Invalid input', 'Resource not found', 'Permission denied'])} at line {random.randint(1, 1000)}",
        
        # 20. Random repeated patterns (to test pattern detection)
        lambda: (random.choice(['A', 'B', 'C', '1', '2', '3']) * random.randint(3, 15)) + str(random.randint(100, 999)),
        
        # 21. Mixed case with numbers
        lambda: ''.join([random.choice([str.upper, str.lower])(c) if c.isalpha() else c 
                        for c in ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(20, 60)))]),
        
        # 22. Tab and space separated data
        lambda: '\t'.join([str(random.randint(1, 100)), 
                          f"{random.uniform(0, 1000):.2f}",
                          random.choice(['pass', 'fail', 'skip']),
                          str(random.randint(2000, 2024))]),
        
        # 23. Mathematical expressions
        lambda: f"{random.randint(1, 100)} {random.choice(['+', '-', '*', '/', '%'])} {random.randint(1, 100)} = {random.randint(1, 1000)}",
        
        # 24. File path-like data
        lambda: f"/{random.choice(['home', 'usr', 'var', 'etc'])}/{random.choice(['user', 'log', 'bin', 'data'])}/{random.choice(['file', 'document', 'script'])}{random.randint(1, 100)}.{random.choice(['txt', 'log', 'dat', 'tmp'])}",
        
        # 25. Random punctuation heavy data
        lambda: ''.join(random.choices('.,!?;:()[]{}"\'-_+=<>/@#$%^&*', k=random.randint(10, 30))),
    ]
    
    # Randomly select a generator and create data
    generator = random.choice(data_generators)
    return generator()

def tcp_sender():
    # Use TCP proxy on middlebox - explicitly set to middlebox IP
    host = '10.1.0.2'  # middlebox IP on routed network (mitm container)
    port = 8118
    packet_count = 0
    start_time = time.time()

    print(f"Connecting to TCP proxy at {host}:{port}")
    print("This will be forwarded to the insec container")

    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # 10 second connection timeout
        
        print(f"Connecting to {host}:{port}...")
        sock.connect((host, port))
        print("Connected successfully to TCP proxy!")
        
        # Set socket timeout for data operations
        sock.settimeout(5)  # 5 second timeout for send/receive
        
        print(f"Starting TCP sender through proxy to insec container")
        print("Generating highly diverse random traffic patterns...")

        # Traffic pattern variables
        burst_mode = False
        burst_remaining = 0
        quiet_mode = False
        quiet_remaining = 0
        last_pattern_change = time.time()

        while True:
            try:
                # Change traffic patterns periodically (every 30-120 seconds)
                if time.time() - last_pattern_change > random.uniform(30, 120):
                    pattern_choice = random.choice(['normal', 'burst', 'quiet', 'mixed'])
                    
                    if pattern_choice == 'burst':
                        burst_mode = True
                        burst_remaining = random.randint(20, 100)  # Send 20-100 packets in burst
                        quiet_mode = False
                        print(f"Switching to BURST mode ({burst_remaining} packets)")
                    elif pattern_choice == 'quiet':
                        quiet_mode = True
                        quiet_remaining = random.randint(10, 30)  # Send fewer packets
                        burst_mode = False
                        print(f"Switching to QUIET mode ({quiet_remaining} packets)")
                    else:
                        burst_mode = False
                        quiet_mode = False
                        print("Switching to NORMAL mode")
                    
                    last_pattern_change = time.time()

                # Generate multiple data packets sometimes
                packets_this_round = 1
                if burst_mode and burst_remaining > 0:
                    packets_this_round = random.randint(1, 5)  # Send 1-5 packets in burst
                    burst_remaining -= packets_this_round
                    if burst_remaining <= 0:
                        burst_mode = False
                        print("Burst mode ended")
                elif quiet_mode and quiet_remaining > 0:
                    packets_this_round = 1 if random.random() < 0.3 else 0  # 30% chance to send
                    quiet_remaining -= 1
                    if quiet_remaining <= 0:
                        quiet_mode = False
                        print("Quiet mode ended")

                # Send the packets for this round
                for _ in range(packets_this_round):
                    # Generate diverse data
                    data = generate_dynamic_data()
                    if isinstance(data, str):
                        data = data.encode()
                    
                    # Randomly modify packet characteristics
                    if random.random() < 0.1:  # 10% chance to send larger packets
                        extra_data = generate_dynamic_data()
                        if isinstance(extra_data, str):
                            extra_data = extra_data.encode()
                        data = data + b'\n' + extra_data
                    
                    # Send data to the server through proxy
                    sock.send(data)
                    packet_count += 1
                
                # Calculate and display statistics every 200 packets
                if packet_count % 200 == 0:
                    elapsed_time = time.time() - start_time
                    rate = packet_count / elapsed_time
                    mode_str = "BURST" if burst_mode else "QUIET" if quiet_mode else "NORMAL"
                    print(f"Sent {packet_count} TCP packets ({rate:.2f} pkt/sec) - Mode: {mode_str}")

                # Try to receive response from the server
                try:
                    sock.settimeout(0.05)  # Very short timeout for response
                    response = sock.recv(8192)  # Larger receive buffer
                    if response:
                        # Print fewer responses to avoid spam, but show variety
                        if random.random() < 0.005:  # Print ~0.5% of responses
                            try:
                                resp_preview = response[:100]  # First 100 bytes
                                print(f"Sample response ({len(response)} bytes): {resp_preview}")
                            except:
                                print(f"Sample response: {len(response)} bytes (binary)")
                except socket.timeout:
                    pass  # Ignore timeout, continue sending
                except Exception:
                    pass  # Ignore other receive errors

                # Dynamic sleep time based on current mode
                if burst_mode:
                    sleep_time = random.uniform(0.01, 0.05)  # 10-50ms for burst mode
                elif quiet_mode:
                    sleep_time = random.uniform(0.5, 2.0)    # 500ms-2s for quiet mode
                else:
                    sleep_time = random.uniform(0.03, 0.2)   # 30-200ms for normal mode
                
                # Occasionally add random delays to simulate network conditions
                if random.random() < 0.02:  # 2% chance
                    extra_delay = random.uniform(0.1, 1.0)
                    sleep_time += extra_delay
                
                time.sleep(sleep_time)

            except (ConnectionResetError, BrokenPipeError):
                print("Connection lost. Attempting to reconnect...")
                sock.close()
                
                # Retry connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((host, port))
                print("Reconnected successfully!")
                
            except Exception as e:
                print(f"An error occurred: {e}")
                time.sleep(1)  # Wait before retrying

    except ConnectionRefusedError:
        print(f"Connection refused to {host}:{port}")
        print("Make sure the TCP proxy is running on the middlebox")
    except socket.timeout:
        print(f"Connection timed out to {host}:{port}")
        print("Check that the middlebox TCP proxy is accessible")
    except KeyboardInterrupt:
        print("\nStopping TCP sender...")
        elapsed_time = time.time() - start_time
        rate = packet_count / elapsed_time if elapsed_time > 0 else 0
        print(f"Final statistics:")
        print(f"  Total packets sent: {packet_count}")
        print(f"  Average rate: {rate:.2f} packets/sec")
        print(f"  Total duration: {elapsed_time:.2f} seconds")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    tcp_sender()