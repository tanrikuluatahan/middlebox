#!/usr/bin/env python3
"""
Test script to verify TCP proxy functionality
"""
import socket
import time
import threading
import subprocess

def test_connectivity():
    """Test basic network connectivity"""
    print("=== NETWORK CONNECTIVITY TEST ===")
    
    # Test targets
    targets = [
        ("10.0.0.21", "insec container"),
        ("10.1.0.2", "middlebox on routed network"),
        ("10.1.0.21", "sec container"),
    ]
    
    for ip, description in targets:
        print(f"\nTesting {description} ({ip}):")
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '2', ip], 
                                   capture_output=True, text=True)
            if result.returncode == 0:
                print(f"  ✅ {ip} is reachable")
            else:
                print(f"  ❌ {ip} is NOT reachable")
        except Exception as e:
            print(f"  ❌ Error pinging {ip}: {e}")

def test_tcp_port(host, port, timeout=5):
    """Test if a TCP port is open and accepting connections"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def test_proxy_ports():
    """Test if proxy ports are accessible"""
    print("\n=== TCP PORT TEST ===")
    
    ports_to_test = [
        ("10.1.0.2", 8888, "TCP proxy for normal_tcp (port 8888)"),
        ("10.1.0.2", 8118, "TCP proxy for sender/receiver (port 8118)"),
        ("10.0.0.21", 8888, "Direct insec container (port 8888)"),
        ("10.0.0.21", 8118, "Direct insec container (port 8118)"),
    ]
    
    for host, port, description in ports_to_test:
        print(f"\nTesting {description}:")
        print(f"  Connecting to {host}:{port}...")
        
        if test_tcp_port(host, port):
            print(f"  ✅ Port {port} is open and accepting connections")
        else:
            print(f"  ❌ Port {port} is NOT accessible")

def test_proxy_forwarding():
    """Test if the proxy actually forwards data correctly"""
    print("\n=== PROXY FORWARDING TEST ===")
    
    proxy_host = "10.1.0.2"
    proxy_port = 8118
    
    print(f"Testing data forwarding through proxy {proxy_host}:{proxy_port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        print("  Connecting to proxy...")
        sock.connect((proxy_host, proxy_port))
        print("  ✅ Connected successfully!")
        
        # Send test data
        test_message = b"TEST_PROXY_FORWARDING_12345"
        print(f"  Sending test message: {test_message}")
        sock.send(test_message)
        
        # Try to receive response
        sock.settimeout(5)
        try:
            response = sock.recv(1024)
            print(f"  ✅ Received response: {response}")
            return True
        except socket.timeout:
            print("  ⚠️ No response received (timeout)")
            return False
        except Exception as e:
            print(f"  ❌ Error receiving response: {e}")
            return False
            
    except ConnectionRefusedError:
        print(f"  ❌ Connection refused - proxy not listening on {proxy_host}:{proxy_port}")
        return False
    except socket.timeout:
        print(f"  ❌ Connection timeout - proxy not accessible")
        return False
    except Exception as e:
        print(f"  ❌ Connection error: {e}")
        return False
    finally:
        try:
            sock.close()
        except:
            pass

def check_proxy_process():
    """Check if TCP proxy process is running"""
    print("\n=== PROCESS CHECK ===")
    
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        if 'tcp_proxy.py' in result.stdout:
            print("  ✅ tcp_proxy.py process is running")
            # Show the process
            lines = result.stdout.split('\n')
            for line in lines:
                if 'tcp_proxy.py' in line and not 'grep' in line:
                    print(f"    {line}")
        else:
            print("  ❌ tcp_proxy.py process is NOT running")
            
        # Check for any python processes
        if 'python' in result.stdout:
            print("\n  Python processes running:")
            lines = result.stdout.split('\n')
            for line in lines:
                if 'python' in line and not 'grep' in line:
                    print(f"    {line}")
                    
    except Exception as e:
        print(f"  ❌ Error checking processes: {e}")

def check_netstat():
    """Check what's listening on ports"""
    print("\n=== PORT LISTENING CHECK ===")
    
    try:
        result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
        print("  TCP ports currently listening:")
        
        lines = result.stdout.split('\n')
        for line in lines:
            if ':8888' in line or ':8118' in line:
                print(f"    {line}")
                
    except Exception as e:
        print(f"  ❌ Error checking netstat: {e}")

def main():
    print("TCP Proxy Diagnostic Tool")
    print("=" * 50)
    
    # Run all tests
    test_connectivity()
    check_proxy_process()
    check_netstat()
    test_proxy_ports()
    test_proxy_forwarding()
    
    print("\n" + "=" * 50)
    print("DIAGNOSTIC COMPLETE")
    print("\nTroubleshooting tips:")
    print("1. Make sure tcp_proxy.py is running in middlebox container")
    print("2. Make sure receiver.py is running in insec container")
    print("3. Check that ports 8888 and 8118 are not blocked")
    print("4. Verify network connectivity between containers")

if __name__ == "__main__":
    main() 