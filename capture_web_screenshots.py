#!/usr/bin/env python3
"""
HomeNetMon Web Screenshot Capture Tool
======================================

This script automatically captures screenshots of HomeNetMon pages using Selenium.
Requires: pip install selenium pillow
And: Download chromedriver or install via package manager

Usage:
    python3 capture_web_screenshots.py

Prerequisites:
    sudo apt install chromium-chromedriver  # or
    pip install selenium pillow
"""

import os
import time
import sys
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from PIL import Image
except ImportError as e:
    print(f"❌ Missing required package: {e}")
    print("Install with: pip install selenium pillow")
    print("And: sudo apt install chromium-chromedriver")
    sys.exit(1)

# Configuration
BASE_URL = "http://192.168.86.64:5000"
SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"
WINDOW_SIZE = (1920, 1080)

# Pages to capture
PAGES = [
    {
        'name': '01_dashboard',
        'url': f'{BASE_URL}/',
        'title': 'Main Dashboard',
        'wait_for': 'device-grid',  # CSS class to wait for
        'description': 'Real-time device monitoring with status grid'
    },
    {
        'name': '02_monitored_hosts',
        'url': f'{BASE_URL}/monitored-hosts',
        'title': 'Monitored Hosts',
        'wait_for': 'hosts-table',
        'description': 'Device management with MAC addresses and vendor info'
    },
    {
        'name': '03_analytics',
        'url': f'{BASE_URL}/analytics',
        'title': 'Analytics Dashboard',
        'wait_for': 'analytics-content',
        'description': 'Network performance analytics and health scores'
    },
    {
        'name': '04_health_overview',
        'url': f'{BASE_URL}/health-overview',
        'title': 'Health Overview',
        'wait_for': 'health-content',
        'description': 'Network health monitoring and metrics'
    },
    {
        'name': '05_alerts',
        'url': f'{BASE_URL}/alerts',
        'title': 'Alert Management',
        'wait_for': 'alerts-content',
        'description': 'Active alert monitoring and management'
    }
]

def setup_driver():
    """Setup Chrome webdriver with appropriate options"""
    chrome_options = Options()
    chrome_options.add_argument('--headless')  # Run in background
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument(f'--window-size={WINDOW_SIZE[0]},{WINDOW_SIZE[1]}')
    chrome_options.add_argument('--hide-scrollbars')
    chrome_options.add_argument('--disable-web-security')
    chrome_options.add_argument('--allow-running-insecure-content')
    
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_window_size(*WINDOW_SIZE)
        return driver
    except Exception as e:
        print(f"❌ Failed to start Chrome driver: {e}")
        print("Try: sudo apt install chromium-chromedriver")
        return None

def capture_page(driver, page_info):
    """Capture screenshot of a specific page"""
    try:
        print(f"📷 Capturing: {page_info['title']}")
        
        # Navigate to page
        driver.get(page_info['url'])
        
        # Wait for page to load
        time.sleep(3)
        
        # Try to wait for specific element (with fallback)
        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CLASS_NAME, page_info['wait_for']))
            )
        except:
            print(f"   ⚠️  Warning: Could not find element '{page_info['wait_for']}', continuing anyway")
        
        # Additional wait for dynamic content
        time.sleep(2)
        
        # Scroll to top to ensure consistent screenshots
        driver.execute_script("window.scrollTo(0, 0);")
        time.sleep(1)
        
        # Take screenshot
        screenshot_path = SCREENSHOTS_DIR / f"{page_info['name']}.png"
        driver.save_screenshot(str(screenshot_path))
        
        # Verify screenshot was created and has reasonable size
        if screenshot_path.exists() and screenshot_path.stat().st_size > 10000:
            print(f"   ✅ Saved: {screenshot_path}")
            return True
        else:
            print(f"   ❌ Failed to save screenshot or file too small")
            return False
            
    except Exception as e:
        print(f"   ❌ Error capturing {page_info['title']}: {e}")
        return False

def optimize_screenshot(image_path):
    """Optimize screenshot size and quality"""
    try:
        with Image.open(image_path) as img:
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Resize if too large (max width 1200px)
            if img.width > 1200:
                ratio = 1200 / img.width
                new_height = int(img.height * ratio)
                img = img.resize((1200, new_height), Image.Resampling.LANCZOS)
            
            # Save optimized version
            img.save(image_path, 'PNG', optimize=True)
            
    except Exception as e:
        print(f"   ⚠️  Could not optimize {image_path}: {e}")

def main():
    """Main screenshot capture process"""
    print("🏠 HomeNetMon Screenshot Capture Tool")
    print("=" * 40)
    
    # Create screenshots directory
    SCREENSHOTS_DIR.mkdir(exist_ok=True)
    
    # Check if HomeNetMon is accessible
    try:
        import requests
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code != 200:
            print(f"❌ HomeNetMon not accessible at {BASE_URL}")
            print("   Make sure HomeNetMon is running first")
            return False
    except Exception as e:
        print(f"❌ Could not connect to HomeNetMon: {e}")
        return False
    
    print(f"✅ HomeNetMon accessible at {BASE_URL}")
    
    # Setup browser driver
    driver = setup_driver()
    if not driver:
        return False
    
    print(f"✅ Chrome driver initialized")
    print(f"📁 Screenshots will be saved to: {SCREENSHOTS_DIR}")
    print()
    
    # Capture screenshots
    successful_captures = 0
    total_pages = len(PAGES)
    
    try:
        for page in PAGES:
            if capture_page(driver, page):
                # Optimize the screenshot
                screenshot_path = SCREENSHOTS_DIR / f"{page['name']}.png"
                optimize_screenshot(screenshot_path)
                successful_captures += 1
            print()  # Empty line for readability
            
    finally:
        driver.quit()
    
    # Summary
    print(f"🎉 Screenshot capture complete!")
    print(f"   Successfully captured: {successful_captures}/{total_pages} pages")
    
    if successful_captures > 0:
        print()
        print("📝 Next steps:")
        print("   1. Review screenshots in screenshots/ directory")
        print("   2. Add to git: git add screenshots/")
        print("   3. Commit: git commit -m 'Add HomeNetMon screenshots'")
        print("   4. Push: git push")
        
        # List captured files
        print()
        print("📁 Captured files:")
        for png_file in sorted(SCREENSHOTS_DIR.glob("*.png")):
            size_kb = png_file.stat().st_size // 1024
            print(f"   {png_file.name} ({size_kb} KB)")
    
    return successful_captures == total_pages

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)