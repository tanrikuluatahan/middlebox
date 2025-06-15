#!/usr/bin/env python3
"""
TCP Proxy for Middlebox - Forwards TCP connections between sec and insec networks
"""
import socket
import threading
import time
import argparse
import os

class TCPProxy:
    def __init__(self, listen_host='0.0.0.0', listen_port=8888, 
                 target_host='10.0.0.21', target_port=8888):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.active_connections = 0
        self.total_connections = 0
        self.bytes_forwarded = 0
        self.start_time = time.time()
        
    def handle_client(self, client_socket, client_address):
        """Handle a client connection by forwarding to target"""
        target_socket = None
        try:
            self.active_connections += 1
            self.total_connections += 1
            
            print(f"[PROXY] New connection from {client_address} -> {self.target_host}:{self.target_port}")
            
            # Connect to target server
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)  # 10 second timeout
            target_socket.connect((self.target_host, self.target_port))
            
            # Start forwarding threads
            client_to_target = threading.Thread(
                target=self.forward_data,
                args=(client_socket, target_socket, f"{client_address} -> target")
            )
            target_to_client = threading.Thread(
                target=self.forward_data,
                args=(target_socket, client_socket, f"target -> {client_address}")
            )
            
            client_to_target.daemon = True
            target_to_client.daemon = True
            
            client_to_target.start()
            target_to_client.start()
            
            # Wait for threads to complete
            client_to_target.join()
            target_to_client.join()
            
        except Exception as e:
            print(f"[PROXY] Error handling client {client_address}: {e}")
        finally:
            self.active_connections -= 1
            if target_socket:
                target_socket.close()
            client_socket.close()
            print(f"[PROXY] Connection from {client_address} closed")
    
    def forward_data(self, source_socket, dest_socket, direction):
        """Forward data from source to destination socket"""
        try:
            while True:
                data = source_socket.recv(4096)
                if not data:
                    break
                    
                dest_socket.send(data)
                self.bytes_forwarded += len(data)
                
        except Exception as e:
            print(f"[PROXY] Forwarding error ({direction}): {e}")
        finally:
            # Close both sockets to signal end of connection
            try:
                source_socket.shutdown(socket.SHUT_RD)
                dest_socket.shutdown(socket.SHUT_WR)
            except:
                pass
    
    def start(self):
        """Start the TCP proxy server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.listen_host, self.listen_port))
            server_socket.listen(10)
            
            print(f"[PROXY] TCP Proxy started on {self.listen_host}:{self.listen_port}")
            print(f"[PROXY] Forwarding to {self.target_host}:{self.target_port}")
            print(f"[PROXY] Waiting for connections...")
            
            # Start statistics thread
            stats_thread = threading.Thread(target=self.print_stats, daemon=True)
            stats_thread.start()
            
            while True:
                client_socket, client_address = server_socket.accept()
                
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print(f"\n[PROXY] Shutting down...")
        except Exception as e:
            print(f"[PROXY] Server error: {e}")
        finally:
            server_socket.close()
            self.print_final_stats()
    
    def print_stats(self):
        """Print periodic statistics"""
        while True:
            time.sleep(30)  # Print stats every 30 seconds
            uptime = time.time() - self.start_time
            print(f"\n[PROXY STATS] Uptime: {uptime:.1f}s | Active: {self.active_connections} | Total: {self.total_connections} | Bytes: {self.bytes_forwarded:,}")
    
    def print_final_stats(self):
        """Print final statistics"""
        uptime = time.time() - self.start_time
        print(f"\n[PROXY FINAL] Total connections: {self.total_connections}")
        print(f"[PROXY FINAL] Total bytes forwarded: {self.bytes_forwarded:,}")
        print(f"[PROXY FINAL] Uptime: {uptime:.1f} seconds")

def main():
    parser = argparse.ArgumentParser(description='TCP Proxy for Middlebox')
    parser.add_argument('--listen-host', default='0.0.0.0', 
                       help='Host to listen on (default: 0.0.0.0)')
    parser.add_argument('--listen-port', type=int, default=8888,
                       help='Port to listen on (default: 8888)')
    parser.add_argument('--target-host', default='10.0.0.21',
                       help='Target host to forward to (default: 10.0.0.21)')
    parser.add_argument('--target-port', type=int, default=8888,
                       help='Target port to forward to (default: 8888)')
    
    args = parser.parse_args()
    
    # Create and start proxy
    proxy = TCPProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        target_host=args.target_host,
        target_port=args.target_port
    )
    
    proxy.start()

if __name__ == '__main__':
    main() 