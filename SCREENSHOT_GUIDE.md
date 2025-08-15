# 📸 HomeNetMon Screenshot Guide

Follow these steps to capture professional screenshots for your GitHub repository.

## 🚀 Quick Start

1. **Run the screenshot script:**
   ```bash
   cd /home/kyle/ClaudeCode/HomeNetMon
   ./take_screenshots.sh
   ```

2. **Follow the prompts** - the script will guide you through each page

3. **Add to git and commit:**
   ```bash
   git add screenshots/
   git commit -m "Add HomeNetMon application screenshots"
   git push
   ```

## 📋 Pages to Capture

### 1. Main Dashboard (`01_dashboard.png`)
- **URL:** http://192.168.86.64:5000
- **What to show:** Device grid with mix of online/offline devices
- **Tips:** 
  - Make sure you have a good variety of device statuses
  - Include the navigation bar and status overview cards

### 2. Monitored Hosts (`02_monitored_hosts.png`)
- **URL:** http://192.168.86.64:5000/monitored-hosts
- **What to show:** The new monitored hosts page with MAC/vendor info
- **Tips:**
  - Show the status overview cards at the top
  - Include devices with different statuses
  - Make sure MAC addresses and vendor info are visible

### 3. Analytics Dashboard (`03_analytics.png`)
- **URL:** http://192.168.86.64:5000/analytics
- **What to show:** Health score, charts, and analytics data
- **Tips:**
  - Capture the health score prominently
  - Include any charts or graphs
  - Show device insights and recommendations

### 4. Health Overview (`04_health_overview.png`)
- **URL:** http://192.168.86.64:5000/health-overview
- **What to show:** Network health metrics and overview
- **Tips:**
  - Show the health score and status
  - Include performance metrics
  - Capture any trend data or charts

### 5. Alert Management (`05_alerts.png`)
- **URL:** http://192.168.86.64:5000/alerts
- **What to show:** Active alerts and alert management interface
- **Tips:**
  - Show some active alerts (you have 229!)
  - Include alert details and severity levels
  - Show alert management buttons

## 🎨 Screenshot Best Practices

### Browser Setup
- **Use Chrome or Firefox** for best compatibility
- **Set zoom to 100%** (no zoom)
- **Use 1920x1080 resolution** or similar wide screen
- **Hide browser bookmarks bar** for cleaner screenshots

### Content Preparation
- **Clear browser cache** to ensure fresh data
- **Wait for page to fully load** before taking screenshot
- **Make sure real data is showing** (not loading states)
- **Check for any error messages** and fix them first

### Image Quality
- **Capture full page** including navigation
- **Avoid cutting off important content**
- **Ensure text is readable** 
- **Use consistent browser window size** for all screenshots

## 🔧 Manual Screenshot Methods

If the script doesn't work, you can take screenshots manually:

### Method 1: Gnome Screenshot
```bash
# Take screenshot after 5 second delay
gnome-screenshot -d 5 -f screenshots/01_dashboard.png
```

### Method 2: Browser Screenshot
- **Chrome:** F12 → Device Toolbar → Capture screenshot
- **Firefox:** F12 → Settings gear → Take a screenshot

### Method 3: System Screenshot
- **Print Screen** key
- **Alt + Print Screen** for active window
- Save to screenshots/ directory

## 📁 File Organization

Screenshots should be saved as:
```
screenshots/
├── 01_dashboard.png       # Main dashboard
├── 02_monitored_hosts.png # Monitored hosts page  
├── 03_analytics.png       # Analytics dashboard
├── 04_health_overview.png # Health overview
└── 05_alerts.png          # Alert management
```

## ✅ Final Checklist

- [ ] All 5 screenshots captured
- [ ] Images are clear and readable
- [ ] File names match the template
- [ ] Screenshots show real data (not loading screens)
- [ ] Navigation and key features are visible
- [ ] Added to git repository
- [ ] README.md displays screenshots correctly

## 🔄 Updating Screenshots

When you update HomeNetMon features:

1. **Delete old screenshots:**
   ```bash
   rm screenshots/*.png
   ```

2. **Take new screenshots** following this guide

3. **Commit updates:**
   ```bash
   git add screenshots/
   git commit -m "Update application screenshots"
   git push
   ```

---

**💡 Pro Tip:** Take screenshots when your HomeNetMon shows interesting data - mix of online/offline devices, some alerts, good uptime stats, etc. This makes the screenshots more compelling for potential users!