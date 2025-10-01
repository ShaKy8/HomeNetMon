#!/usr/bin/env python3
"""
Debug analytics frontend issues - check for JavaScript errors and button functionality
"""

import requests
import re
from bs4 import BeautifulSoup

def check_analytics_page():
    """Check the analytics page for common frontend issues"""
    print("=" * 60)
    print("ANALYTICS FRONTEND DEBUG")
    print("=" * 60)

    try:
        response = requests.get("http://geekom1:5000/analytics", timeout=10)
        if response.status_code != 200:
            print(f"❌ Page not accessible: HTTP {response.status_code}")
            return False

        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        print("✅ Page loaded successfully")
        print(f"📄 Page size: {len(html):,} characters")

        # Check for JavaScript files
        print("\n🔍 CHECKING JAVASCRIPT INCLUDES:")
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src')
            if src:
                print(f"  📜 {src}")
                # Test if script is accessible
                try:
                    if src.startswith('/'):
                        script_url = f"http://geekom1:5000{src}"
                        script_resp = requests.get(script_url, timeout=5)
                        if script_resp.status_code == 200:
                            print(f"     ✅ Accessible")
                        else:
                            print(f"     ❌ Not accessible: {script_resp.status_code}")
                except Exception as e:
                    print(f"     ⚠️  Error checking: {e}")

        # Check for inline JavaScript
        print("\n🔍 CHECKING INLINE JAVASCRIPT:")
        inline_scripts = soup.find_all('script', src=False)
        total_js_lines = 0
        for i, script in enumerate(inline_scripts):
            if script.string:
                lines = len(script.string.strip().split('\n'))
                total_js_lines += lines
                print(f"  📝 Inline script {i+1}: {lines} lines")

        print(f"📊 Total inline JS: {total_js_lines} lines")

        # Check for common button elements
        print("\n🔍 CHECKING BUTTON ELEMENTS:")
        buttons = soup.find_all(['button', 'input'], type=['button', 'submit'])
        for button in buttons[:10]:  # Show first 10
            btn_id = button.get('id', 'no-id')
            btn_class = button.get('class', [])
            btn_text = button.get_text(strip=True)[:30]
            print(f"  🔘 {btn_id}: '{btn_text}' (classes: {btn_class})")

        if len(buttons) > 10:
            print(f"  ... and {len(buttons) - 10} more buttons")

        # Check for specific analytics buttons
        print("\n🔍 CHECKING SPECIFIC ANALYTICS BUTTONS:")
        key_buttons = [
            'refresh-analytics',
            'speedtest-btn',
            'cancel-speedtest-btn',
            'refresh-rating-btn'
        ]

        for btn_id in key_buttons:
            element = soup.find(id=btn_id)
            if element:
                print(f"  ✅ Found: {btn_id}")
            else:
                print(f"  ❌ Missing: {btn_id}")

        # Check for tab elements
        print("\n🔍 CHECKING TAB NAVIGATION:")
        tabs = soup.find_all(['button', 'a'], attrs={'data-bs-target': True})
        for tab in tabs:
            target = tab.get('data-bs-target')
            text = tab.get_text(strip=True)
            print(f"  📑 Tab: '{text}' → {target}")

        # Check for form elements with time ranges
        print("\n🔍 CHECKING TIME RANGE CONTROLS:")
        time_inputs = soup.find_all('input', attrs={'name': 'global-time-range'})
        for inp in time_inputs:
            value = inp.get('value')
            print(f"  ⏰ Time range option: {value}")

        # Check for potential JavaScript errors in inline scripts
        print("\n🔍 CHECKING FOR POTENTIAL JS ISSUES:")
        all_js = ""
        for script in inline_scripts:
            if script.string:
                all_js += script.string

        # Look for common issues
        issues = []
        if 'addEventListener' in all_js:
            print("  ✅ Event listeners found")
        else:
            issues.append("No event listeners found")

        if 'loadAllAnalytics' in all_js:
            print("  ✅ loadAllAnalytics function found")
        else:
            issues.append("loadAllAnalytics function missing")

        if 'Chart.js' in all_js or 'Chart(' in all_js:
            print("  ✅ Chart.js usage found")
        else:
            issues.append("Chart.js usage not found")

        if issues:
            print("\n⚠️  POTENTIAL ISSUES:")
            for issue in issues:
                print(f"    - {issue}")

        return True

    except Exception as e:
        print(f"❌ Error checking analytics page: {e}")
        return False

def test_api_endpoints():
    """Test key API endpoints that buttons call"""
    print("\n" + "=" * 60)
    print("API ENDPOINT TESTS")
    print("=" * 60)

    endpoints = [
        "/api/analytics/network-health-score",
        "/api/analytics/device-insights",
        "/api/analytics/usage-patterns",
        "/api/speedtest/status",
        "/api/devices"
    ]

    for endpoint in endpoints:
        try:
            response = requests.get(f"http://geekom1:5000{endpoint}", timeout=5)
            if response.status_code == 200:
                print(f"✅ {endpoint}: Working")
            else:
                print(f"❌ {endpoint}: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ {endpoint}: Error - {e}")

if __name__ == '__main__':
    success = check_analytics_page()
    if success:
        test_api_endpoints()

    print("\n" + "=" * 60)
    print("NEXT STEPS:")
    print("1. Check browser console for JavaScript errors")
    print("2. Verify CSRF tokens are working")
    print("3. Test button click events manually")
    print("4. Check if Bootstrap JS is loading correctly")
    print("=" * 60)