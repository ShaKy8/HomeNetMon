#!/usr/bin/env python3
"""
Direct test of DELETE request to isolate the issue
"""

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_delete_request():
    """Test DELETE request with various configurations"""

    url = "http://geekom1:5000/api/monitoring/alerts/1"

    print(f"Testing DELETE request to: {url}")
    print("=" * 50)

    # Test 1: Simple DELETE request
    print("\n1. Simple DELETE request:")
    try:
        response = requests.delete(url, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")
        print(f"   Body: {response.text}")
    except Exception as e:
        print(f"   ERROR: {e}")

    # Test 2: DELETE with JSON content type
    print("\n2. DELETE with JSON content type:")
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.delete(url, headers=headers, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")
        print(f"   Body: {response.text}")
    except Exception as e:
        print(f"   ERROR: {e}")

    # Test 3: DELETE with empty JSON body
    print("\n3. DELETE with empty JSON body:")
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.delete(url, headers=headers, json={}, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")
        print(f"   Body: {response.text}")
    except Exception as e:
        print(f"   ERROR: {e}")

    # Test 4: GET request to same endpoint (to verify server is running)
    print("\n4. GET request to alerts endpoint (for comparison):")
    try:
        get_url = "http://geekom1:5000/api/monitoring/alerts"
        response = requests.get(get_url, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Response length: {len(response.text)} chars")
    except Exception as e:
        print(f"   ERROR: {e}")

if __name__ == '__main__':
    test_delete_request()