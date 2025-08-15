#!/bin/bash

# HomeNetMon Screenshot Capture Script
# This script helps you take screenshots of key HomeNetMon pages

echo "🏠 HomeNetMon Screenshot Capture Tool"
echo "======================================"
echo ""
echo "Make sure your HomeNetMon is running at http://192.168.86.64:5000"
echo "Open your web browser to the HomeNetMon interface before running this."
echo ""

SCREENSHOTS_DIR="/home/kyle/ClaudeCode/HomeNetMon/screenshots"

# Function to take a screenshot with delay
take_screenshot() {
    local filename="$1"
    local description="$2"
    
    echo "📸 Preparing to capture: $description"
    echo "   Navigate to the appropriate page in your browser..."
    echo "   Press ENTER when ready (5 second delay will follow)"
    read -r
    
    echo "   Taking screenshot in 5 seconds..."
    sleep 5
    
    # Take screenshot using gnome-screenshot (most user-friendly)
    gnome-screenshot -f "$SCREENSHOTS_DIR/$filename" 2>/dev/null || {
        # Fallback to scrot if gnome-screenshot fails
        scrot "$SCREENSHOTS_DIR/$filename" 2>/dev/null || {
            echo "   ❌ Screenshot failed - please take manually"
            return 1
        }
    }
    
    echo "   ✅ Screenshot saved as: $filename"
    echo ""
}

# Create screenshots directory if it doesn't exist
mkdir -p "$SCREENSHOTS_DIR"

echo "📋 We'll capture these key pages:"
echo "   1. Main Dashboard"
echo "   2. Monitored Hosts" 
echo "   3. Analytics"
echo "   4. Health Overview"
echo "   5. Alerts"
echo ""

# Take screenshots
take_screenshot "01_dashboard.png" "Main Dashboard (http://192.168.86.64:5000)"

take_screenshot "02_monitored_hosts.png" "Monitored Hosts page (http://192.168.86.64:5000/monitored-hosts)"

take_screenshot "03_analytics.png" "Analytics Dashboard (http://192.168.86.64:5000/analytics)"

take_screenshot "04_health_overview.png" "Health Overview (http://192.168.86.64:5000/health-overview)"

take_screenshot "05_alerts.png" "Alerts page (http://192.168.86.64:5000/alerts)"

echo "🎉 Screenshot capture complete!"
echo ""
echo "📁 Screenshots saved in: $SCREENSHOTS_DIR"
echo "📝 File list:"
ls -la "$SCREENSHOTS_DIR"/*.png 2>/dev/null || echo "   No PNG files found"

echo ""
echo "💡 Next steps:"
echo "   1. Review the screenshots in $SCREENSHOTS_DIR"
echo "   2. Resize/edit them if needed (recommended: 800-1200px wide)"
echo "   3. Add them to git: git add screenshots/"
echo "   4. Update README.md with the screenshots"