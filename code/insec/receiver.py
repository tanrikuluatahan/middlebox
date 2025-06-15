import socket
import os
import time
import json
import random
import threading
from datetime import datetime

def generate_response(data, client_addr):
    """Generate appropriate response based on received data"""
    try:
        # Try to parse as JSON
        if isinstance(data, bytes):
            data_str = data.decode()
            if data_str.startswith('{'):
                return json.dumps({
                    'status': 'received',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'json',
                    'size': len(data),
                    'from': f"{client_addr[0]}:{client_addr[1]}"
                }).encode()
        
        # Handle structured data
        if isinstance(data, bytes):
            data_str = data.decode()
            if data_str.startswith('DATA:'):
                return f"ACK:{data_str.split(':')[1]}".encode()
            elif data_str.startswith('LOG:'):
                return f"LOG_RECEIVED:{data_str.split(':')[1]}".encode()
        
        # Default response for binary or unknown data
        return f"RECEIVED:{len(data)}_bytes_from_{client_addr[0]}".encode()
    except:
        # Fallback response
        return f"RECEIVED:{len(data)}_bytes_from_{client_addr[0]}".encode()

def handle_client(client_socket, address, stats):
    """Handle individual client connection"""
    try:
        print(f"New TCP connection from {address}")
        packet_count = 0
        start_time = time.time()
        
        while True:
            try:
                # Receive data
                data = client_socket.recv(4096)
                if not data:
                    break
                    
                packet_count += 1
                stats['total_packets'] += 1
                
                # Track packets per client
                client_key = f"{address[0]}:{address[1]}"
                if client_key not in stats['clients']:
                    stats['clients'][client_key] = 0
                stats['clients'][client_key] += 1
                
                # Generate and send response
                response = generate_response(data, address)
                client_socket.send(response)
                
                # Optional: Print packet details for debugging
                if random.random() < 0.01:  # Print ~1% of packets
                    print(f"\nSample TCP packet from {address}:")
                    try:
                        print(f"  Data: {data.decode()[:100]}...")  # Limit output length
                    except:
                        print(f"  Binary data: {len(data)} bytes")
                    try:
                        print(f"  Response: {response.decode()[:100]}...")
                    except:
                        print(f"  Response: {len(response)} bytes")
                        
            except ConnectionResetError:
                print(f"Client {address} disconnected (connection reset)")
                break
            except Exception as e:
                print(f"Error handling data from {address}: {e}")
                break
                
    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        client_socket.close()
        elapsed = time.time() - start_time
        print(f"Connection from {address} closed. Received {packet_count} packets in {elapsed:.1f}s")

def start_tcp_listener():
    # Create a TCP socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind the socket to the port
    server_address = ('', 8118)
    server.bind(server_address)
    server.listen(5)
    
    print("TCP server started on port 8118")
    print("Waiting for TCP connections...")
    
    # Statistics tracking
    stats = {
        'total_packets': 0,
        'start_time': time.time(),
        'last_stats_time': time.time(),
        'clients': {},  # Track packets per client
        'active_connections': 0,
        'total_connections': 0
    }
    
    # Start statistics display thread
    def display_stats():
        while True:
            time.sleep(5)
            current_time = time.time()
            elapsed = current_time - stats['start_time']
            rate = stats['total_packets'] / elapsed if elapsed > 0 else 0
            print(f"\nTCP Server Statistics:")
            print(f"  Total packets received: {stats['total_packets']}")
            print(f"  Average rate: {rate:.2f} packets/sec")
            print(f"  Active connections: {stats['active_connections']}")
            print(f"  Total connections: {stats['total_connections']}")
            print(f"  Running time: {elapsed:.1f} seconds")
            
            # Show top clients
            if stats['clients']:
                sorted_clients = sorted(stats['clients'].items(), key=lambda x: x[1], reverse=True)[:3]
                print(f"  Top clients:")
                for addr, count in sorted_clients:
                    print(f"    {addr}: {count} packets")
            
            stats['last_stats_time'] = current_time
    
    stats_thread = threading.Thread(target=display_stats, daemon=True)
    stats_thread.start()
    
    try:
        while True:
            # Accept new connection
            client_socket, address = server.accept()
            
            stats['active_connections'] += 1
            stats['total_connections'] += 1
            
            # Handle client in a new thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, address, stats)
            )
            client_thread.daemon = True
            client_thread.start()
            
            # Decrement active connections when thread finishes
            def cleanup_connection():
                client_thread.join()
                stats['active_connections'] -= 1
            
            cleanup_thread = threading.Thread(target=cleanup_connection, daemon=True)
            cleanup_thread.start()
            
    except KeyboardInterrupt:
        print("\nStopping TCP server...")
        elapsed_time = time.time() - stats['start_time']
        rate = stats['total_packets'] / elapsed_time if elapsed_time > 0 else 0
        print(f"Final statistics:")
        print(f"  Total packets received: {stats['total_packets']}")
        print(f"  Average rate: {rate:.2f} packets/sec")
        print(f"  Total duration: {elapsed_time:.2f} seconds")
        print(f"  Total connections: {stats['total_connections']}")
        print(f"  Unique clients: {len(stats['clients'])}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    start_tcp_listener()