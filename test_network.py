#!/usr/bin/env python3
"""
Network Functionality Test for HomeNetMon
Tests ping, nmap, and network discovery capabilities
"""

import subprocess
import sys
import socket
from ping3 import ping
import nmap

def test_basic_ping():
    """Test basic ping functionality"""
    print("🏓 Testing basic ping functionality...")
    
    targets = ['127.0.0.1', '192.168.86.1', '8.8.8.8']
    
    for target in targets:
        try:
            result = ping(target, timeout=3)
            if result:
                print(f"✅ ping3: {target} -> {result*1000:.1f}ms")
            else:
                print(f"❌ ping3: {target} -> No response")
        except PermissionError:
            print(f"❌ ping3: {target} -> Permission denied (need sudo or capabilities)")
        except Exception as e:
            print(f"❌ ping3: {target} -> Error: {e}")

def test_system_ping():
    """Test system ping command"""
    print("\n🖥️  Testing system ping command...")
    
    targets = ['192.168.86.1']
    
    for target in targets:
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '3', target], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ system ping: {target} -> Success")
            else:
                print(f"❌ system ping: {target} -> Failed")
        except Exception as e:
            print(f"❌ system ping: {target} -> Error: {e}")

def test_nmap_scan():
    """Test nmap scanning functionality"""
    print("\n🔍 Testing nmap scanning...")
    
    try:
        nm = nmap.PortScanner()
        # Test a small range first
        result = nm.scan('192.168.86.1-2', arguments='-sn -T4 --max-retries=1 --host-timeout=5s')
        
        hosts_found = []
        for host in result['scan']:
            if result['scan'][host]['status']['state'] == 'up':
                hosts_found.append(host)
        
        if hosts_found:
            print(f"✅ nmap scan: Found {len(hosts_found)} hosts: {', '.join(hosts_found)}")
        else:
            print("⚠️  nmap scan: No hosts found (may need sudo for some scan types)")
            
    except Exception as e:
        print(f"❌ nmap scan: Error: {e}")

def test_arp_table():
    """Test ARP table parsing"""
    print("\n🗂️  Testing ARP table access...")
    
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            print(f"✅ ARP table: Found {len(lines)} entries")
            
            # Show first few entries
            for i, line in enumerate(lines[:3]):
                if '(' in line and ')' in line:
                    print(f"   {i+1}. {line.strip()}")
        else:
            print("❌ ARP table: No entries or command failed")
            
    except Exception as e:
        print(f"❌ ARP table: Error: {e}")

def test_raw_socket():
    """Test raw socket creation (for ping)"""
    print("\n🔌 Testing raw socket capabilities...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.close()
        print("✅ Raw socket: Can create ICMP socket")
    except PermissionError:
        print("❌ Raw socket: Permission denied - need sudo or CAP_NET_RAW capability")
    except Exception as e:
        print(f"❌ Raw socket: Error: {e}")

def test_network_connectivity():
    """Test basic network connectivity"""
    print("\n🌐 Testing network connectivity...")
    
    try:
        # Test local network gateway
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex(('192.168.86.1', 80))
        sock.close()
        
        if result == 0:
            print("✅ Network: Can reach gateway (192.168.86.1:80)")
        else:
            print("⚠️  Network: Gateway not reachable on port 80 (normal for many routers)")
            
    except Exception as e:
        print(f"❌ Network: Error testing connectivity: {e}")

def main():
    print("🏠 HomeNetMon Network Functionality Test")
    print("=" * 50)
    
    test_basic_ping()
    test_system_ping()
    test_nmap_scan()
    test_arp_table()
    test_raw_socket()
    test_network_connectivity()
    
    print("\n" + "=" * 50)
    print("📋 Summary:")
    print("If you see 'Permission denied' errors for ping3 or raw sockets:")
    print("1. Run: sudo setcap cap_net_raw+ep $(which python3)")
    print("2. Or run HomeNetMon with: sudo python3 app.py")
    print("")
    print("If nmap doesn't find devices:")
    print("1. Check if devices are actually on the network")
    print("2. Some devices may not respond to ping sweeps")
    print("3. Try running nmap with sudo for better detection")

if __name__ == "__main__":
    main()