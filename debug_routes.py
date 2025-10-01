#!/usr/bin/env python3
"""
Debug script to check Flask route registration
"""

import os
import sys

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set minimal environment variables
os.environ.setdefault('NETWORK_RANGE', '192.168.86.0/24')
os.environ.setdefault('DEBUG', 'true')

from app import create_app

app, socketio = create_app()

def list_routes():
    """List all registered routes"""
    print("=== REGISTERED ROUTES ===")

    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods - {'OPTIONS', 'HEAD'})
        print(f"{rule.rule:<40} {methods:<20} {rule.endpoint}")

def check_alerts_routes():
    """Check specifically for alerts routes"""
    print("\n=== ALERTS ROUTES ===")

    for rule in app.url_map.iter_rules():
        if 'alert' in rule.rule:
            methods = ','.join(rule.methods - {'OPTIONS', 'HEAD'})
            print(f"{rule.rule:<40} {methods:<20} {rule.endpoint}")

if __name__ == '__main__':
    print("Flask App URL Map Debug")
    print("=" * 50)

    list_routes()
    check_alerts_routes()

    # Check if DELETE method is supported for alerts endpoint
    print("\n=== TESTING DELETE ROUTE MATCH ===")

    with app.test_request_context('/api/monitoring/alerts/1', method='DELETE'):
        try:
            rule, _ = app.url_map.bind('localhost:5000').match('/api/monitoring/alerts/1', method='DELETE')
            print(f"DELETE /api/monitoring/alerts/1 matches: {rule}")
        except Exception as e:
            print(f"DELETE /api/monitoring/alerts/1 ERROR: {e}")