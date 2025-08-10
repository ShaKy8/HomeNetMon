#!/usr/bin/env python3
"""
Startup notification script for HomeNetMon
Sends a push notification when the service starts
"""

import sys
import os
import time

# Add the project directory to Python path
sys.path.insert(0, '/home/kyle/ClaudeCode/HomeNetMon')

def send_startup_notification():
    """Send a push notification when HomeNetMon starts"""
    try:
        # Import after adding to path
        from services.push_notifications import push_service
        from config import Config
        
        # Wait a moment for the service to fully initialize
        time.sleep(3)
        
        # Check if push notifications are configured
        if not push_service.is_configured():
            print("Push notifications not configured, skipping startup notification")
            return
        
        # Send startup notification
        dashboard_url = f"http://{Config.HOST}:{Config.PORT}"
        
        success = push_service.send_notification(
            title="🚀 HomeNetMon Started",
            message=f"HomeNetMon network monitoring service has successfully started and is now monitoring your network at {dashboard_url}",
            priority="default",
            tags="green_circle,rocket,white_check_mark",
            click_url=dashboard_url
        )
        
        if success:
            print("Startup notification sent successfully")
        else:
            print("Failed to send startup notification")
            
    except Exception as e:
        print(f"Error sending startup notification: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    send_startup_notification()