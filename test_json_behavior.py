#!/usr/bin/env python3
"""
Test what Flask's request.get_json() returns for different request types
"""

import requests

def test_json_behavior():
    """Test how Flask handles different JSON content type scenarios"""

    url = "http://geekom1:5000/api/monitoring/alerts/1"

    print("Testing Flask JSON behavior:")
    print("=" * 50)

    # Test what we're sending
    print("\n1. DELETE with Content-Type: application/json but no body:")
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.delete(url, headers=headers, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
    except Exception as e:
        print(f"   ERROR: {e}")

    print("\n2. DELETE with no headers:")
    try:
        response = requests.delete(url, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
    except Exception as e:
        print(f"   ERROR: {e}")

if __name__ == '__main__':
    test_json_behavior()