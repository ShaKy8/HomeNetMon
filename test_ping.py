#!/usr/bin/env python3
import subprocess
import re
import time

def test_ping(ip):
    print(f"Testing ping to {ip}")
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '3', ip], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        
        print(f"Return code: {result.returncode}")
        print(f"Stdout: {result.stdout}")
        print(f"Stderr: {result.stderr}")
        
        if result.returncode == 0:
            time_match = re.search(r'time=([0-9.]+)\s*ms', result.stdout)
            response_time = float(time_match.group(1)) if time_match else 0.0
            print(f"Parsed response time: {response_time}ms")
            return True, response_time
        else:
            print("Ping failed")
            return False, None
            
    except Exception as e:
        print(f"Exception: {e}")
        return False, None

if __name__ == "__main__":
    # Test a few devices
    test_ips = ['192.168.86.1', '192.168.86.64', '192.168.86.24']
    
    for ip in test_ips:
        success, response_time = test_ping(ip)
        print(f"Result: {ip} -> Success: {success}, Time: {response_time}")
        print("-" * 50)