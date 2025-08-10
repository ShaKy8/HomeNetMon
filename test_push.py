#!/usr/bin/env python3

import sys
import os
sys.path.append('/home/kyle/ClaudeCode/HomeNetMon')

from services.push_notifications import push_service

def test_push_notifications():
    """Test push notification functionality"""
    
    print("🧪 Testing Push Notification Service")
    print("====================================")
    
    # Test with sample configuration
    push_service.enabled = True
    push_service.server = "https://ntfy.sh"
    push_service.topic = "test-topic"
    
    print(f"Server: {push_service.server}")
    print(f"Topic: {push_service.topic}")
    print(f"Configured: {push_service.is_configured()}")
    
    if push_service.is_configured():
        print("\n📱 Sending test notification...")
        
        success = push_service.send_test_notification()
        
        if success:
            print("✅ Test notification sent successfully!")
            print("🔔 Check your phone if you've subscribed to 'test-topic'")
        else:
            print("❌ Failed to send test notification")
    else:
        print("❌ Push service not properly configured")

if __name__ == '__main__':
    test_push_notifications()