#!/bin/bash
# Setup automated backups for HomeNetMon using cron

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_SCRIPT="$SCRIPT_DIR/backup_database.py"
PYTHON_PATH="$SCRIPT_DIR/venv/bin/python"
BACKUP_CONFIG="$SCRIPT_DIR/backup_config.json"

echo -e "${GREEN}🔧 HomeNetMon Backup Cron Setup${NC}"
echo "========================================="

# Check if backup script exists
if [ ! -f "$BACKUP_SCRIPT" ]; then
    echo -e "${RED}Error: Backup script not found at $BACKUP_SCRIPT${NC}"
    exit 1
fi

# Check if Python virtual environment exists
if [ ! -f "$PYTHON_PATH" ]; then
    echo -e "${YELLOW}Warning: Python virtual environment not found at $PYTHON_PATH${NC}"
    echo "Using system Python instead"
    PYTHON_PATH="python3"
fi

# Create backup configuration if it doesn't exist
if [ ! -f "$BACKUP_CONFIG" ]; then
    echo -e "${YELLOW}Creating default backup configuration...${NC}"
    cat > "$BACKUP_CONFIG" << EOF
{
  "backup_dir": "$SCRIPT_DIR/backups",
  "compress": true,
  "encrypt": false,
  "storage_type": "local",
  "retention_days": 30,
  "remove_local_after_upload": false,
  "metadata_max_entries": 1000
}
EOF
    echo -e "${GREEN}✅ Created backup configuration: $BACKUP_CONFIG${NC}"
fi

# Create backup directory
mkdir -p "$SCRIPT_DIR/backups"
mkdir -p "$SCRIPT_DIR/logs"

# Function to add cron job
add_cron_job() {
    local schedule="$1"
    local job_type="$2"
    local job_description="$3"
    
    local cron_command="$PYTHON_PATH $BACKUP_SCRIPT --type $job_type --config $BACKUP_CONFIG --compress"
    local cron_job="$schedule cd $SCRIPT_DIR && $cron_command >> $SCRIPT_DIR/logs/backup_cron.log 2>&1"
    
    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -F "$BACKUP_SCRIPT" | grep -q "$job_type"; then
        echo -e "${YELLOW}⚠️  Cron job for $job_description already exists${NC}"
        return
    fi
    
    # Add cron job
    (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
    echo -e "${GREEN}✅ Added cron job: $job_description${NC}"
    echo "   Schedule: $schedule"
    echo "   Command: $cron_command"
}

# Interactive setup
echo ""
echo "Choose backup schedule options:"
echo ""
echo "1. Conservative (Daily full backups)"
echo "2. Balanced (Daily full + hourly incremental)"
echo "3. Aggressive (Full every 6 hours + hourly incremental)"
echo "4. Custom setup"
echo "5. Remove existing backup cron jobs"

read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        echo -e "${GREEN}Setting up conservative backup schedule...${NC}"
        add_cron_job "0 2 * * *" "full" "Daily full backup at 2 AM"
        ;;
    2)
        echo -e "${GREEN}Setting up balanced backup schedule...${NC}"
        add_cron_job "0 2 * * *" "full" "Daily full backup at 2 AM"
        add_cron_job "0 * * * *" "incremental" "Hourly incremental backup"
        ;;
    3)
        echo -e "${GREEN}Setting up aggressive backup schedule...${NC}"
        add_cron_job "0 */6 * * *" "full" "Full backup every 6 hours"
        add_cron_job "0 * * * *" "incremental" "Hourly incremental backup"
        ;;
    4)
        echo -e "${YELLOW}Custom setup:${NC}"
        echo ""
        echo "Full backup schedule examples:"
        echo "  Daily at 2 AM: 0 2 * * *"
        echo "  Every 12 hours: 0 */12 * * *"
        echo "  Weekly on Sunday at 3 AM: 0 3 * * 0"
        echo ""
        read -p "Enter cron schedule for full backups (or press Enter to skip): " full_schedule
        
        if [ ! -z "$full_schedule" ]; then
            add_cron_job "$full_schedule" "full" "Custom full backup"
        fi
        
        echo ""
        echo "Incremental backup schedule examples:"
        echo "  Every hour: 0 * * * *"
        echo "  Every 2 hours: 0 */2 * * *"
        echo "  Every 30 minutes: */30 * * * *"
        echo ""
        read -p "Enter cron schedule for incremental backups (or press Enter to skip): " inc_schedule
        
        if [ ! -z "$inc_schedule" ]; then
            add_cron_job "$inc_schedule" "incremental" "Custom incremental backup"
        fi
        ;;
    5)
        echo -e "${YELLOW}Removing existing backup cron jobs...${NC}"
        crontab -l 2>/dev/null | grep -v "$BACKUP_SCRIPT" | crontab -
        echo -e "${GREEN}✅ Removed all HomeNetMon backup cron jobs${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice. Exiting.${NC}"
        exit 1
        ;;
esac

# Set up log rotation for backup logs
echo ""
echo -e "${GREEN}Setting up log rotation...${NC}"

# Create logrotate configuration
sudo tee /etc/logrotate.d/homeNetMon-backup > /dev/null << EOF
$SCRIPT_DIR/logs/backup_cron.log {
    daily
    missingok
    rotate 7
    compress
    notifempty
    create 644 $(whoami) $(whoami)
}

$SCRIPT_DIR/logs/backup_*.log {
    daily
    missingok
    rotate 30
    compress
    notifempty
    create 644 $(whoami) $(whoami)
}
EOF

echo -e "${GREEN}✅ Log rotation configured${NC}"

# Test backup script
echo ""
echo -e "${GREEN}Testing backup script...${NC}"
if $PYTHON_PATH "$BACKUP_SCRIPT" --type full --config "$BACKUP_CONFIG" --compress; then
    echo -e "${GREEN}✅ Backup script test successful${NC}"
else
    echo -e "${RED}❌ Backup script test failed${NC}"
    echo "Please check the error messages above and fix any issues before relying on automated backups."
fi

# Show current cron jobs
echo ""
echo -e "${GREEN}Current backup cron jobs:${NC}"
crontab -l 2>/dev/null | grep "$BACKUP_SCRIPT" || echo "No backup cron jobs found"

# Create monitoring script
cat > "$SCRIPT_DIR/check_backup_status.sh" << 'EOF'
#!/bin/bash
# Check backup status and send alerts if needed

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$SCRIPT_DIR/backups"
LOG_FILE="$SCRIPT_DIR/logs/backup_cron.log"

# Check if backup ran in the last 25 hours (allowing for cron timing variations)
LAST_BACKUP=$(find "$BACKUP_DIR" -name "homeNetMon_*" -mtime -1 | head -1)

if [ -z "$LAST_BACKUP" ]; then
    echo "❌ WARNING: No recent backups found in the last 24 hours"
    
    # Check log file for errors
    if [ -f "$LOG_FILE" ]; then
        echo "Recent log entries:"
        tail -20 "$LOG_FILE"
    fi
    
    exit 1
else
    BACKUP_FILE=$(basename "$LAST_BACKUP")
    BACKUP_TIME=$(stat -c %y "$LAST_BACKUP")
    BACKUP_SIZE=$(stat -c %s "$LAST_BACKUP" | numfmt --to=iec)
    
    echo "✅ Recent backup found:"
    echo "   File: $BACKUP_FILE"
    echo "   Time: $BACKUP_TIME"
    echo "   Size: $BACKUP_SIZE"
    
    exit 0
fi
EOF

chmod +x "$SCRIPT_DIR/check_backup_status.sh"

echo ""
echo -e "${GREEN}📊 Setup Summary:${NC}"
echo "================================="
echo "✅ Backup script: $BACKUP_SCRIPT"
echo "✅ Configuration: $BACKUP_CONFIG"
echo "✅ Backup directory: $SCRIPT_DIR/backups"
echo "✅ Log directory: $SCRIPT_DIR/logs"
echo "✅ Status checker: $SCRIPT_DIR/check_backup_status.sh"

echo ""
echo -e "${GREEN}🔍 Monitoring Commands:${NC}"
echo "================================="
echo "Check backup status: $SCRIPT_DIR/check_backup_status.sh"
echo "View cron logs: tail -f $SCRIPT_DIR/logs/backup_cron.log"
echo "List backups: ls -lah $SCRIPT_DIR/backups/"
echo "Edit cron jobs: crontab -e"
echo "View current cron jobs: crontab -l"

echo ""
echo -e "${GREEN}✅ Automated backup setup completed!${NC}"
echo ""
echo "Your database will now be backed up automatically according to the schedule you selected."
echo "Monitor the logs to ensure backups are running successfully."