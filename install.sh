#!/bin/bash
# HomeNetMon installer for Ubuntu/Debian.
#
#   ./install.sh            install (or update) as a system service in /opt/homenetmon
#   ./install.sh --user     install as a per-user systemd service from this checkout (no root)
#   ./install.sh --uninstall
#
# Run as your normal user; the script calls sudo where it needs root.
set -euo pipefail

INSTALL_DIR="/opt/homenetmon"
SERVICE_USER="homenetmon"
UNIT="homenetmon"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-system}"

say()  { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] && die "Run as a normal user (the script uses sudo where needed)."
command -v python3 >/dev/null || die "python3 is required"
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "Python >= 3.11 required (found $PYV)"

install_system_deps() {
    say "Installing system packages (nmap, python3-venv)"
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends nmap python3-venv python3-dev iputils-ping
}

write_env() {
    local target="$1" owner="$2"
    if [[ -f "$target" ]]; then
        say "Keeping existing $target"
        return
    fi
    say "Creating $target from .env.prod.example"
    local range
    range=$(ip -4 route show default 2>/dev/null | awk '{print $3}' | head -1 | sed -E 's/\.[0-9]+$/.0\/24/')
    read -r -p "Network range to monitor [${range:-192.168.1.0/24}]: " answer
    range="${answer:-${range:-192.168.1.0/24}}"
    local secret
    secret=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    sed -e "s#^NETWORK_RANGE=.*#NETWORK_RANGE=${range}#" \
        -e "s#^SECRET_KEY=.*#SECRET_KEY=${secret}#" \
        "$REPO_DIR/.env.prod.example" | sudo -u "$owner" tee "$target" >/dev/null
    sudo chmod 600 "$target"
}

if [[ "$MODE" == "--uninstall" ]]; then
    sudo systemctl disable --now "$UNIT" 2>/dev/null || true
    sudo rm -f "/etc/systemd/system/$UNIT.service"
    sudo systemctl daemon-reload
    warn "Service removed. $INSTALL_DIR (including the database in data/) was left in place."
    exit 0
fi

if [[ "$MODE" == "--user" ]]; then
    say "Installing per-user service from $REPO_DIR"
    install_system_deps
    [[ -d "$REPO_DIR/venv" ]] || python3 -m venv "$REPO_DIR/venv"
    "$REPO_DIR/venv/bin/pip" install --upgrade pip -q
    "$REPO_DIR/venv/bin/pip" install -r "$REPO_DIR/requirements.txt" -q
    [[ -f "$REPO_DIR/.env" ]] || write_env "$REPO_DIR/.env" "$USER"
    mkdir -p "$REPO_DIR/production_data" "$REPO_DIR/logs" ~/.config/systemd/user
    sed -e "s#%h/HomeNetMon#$REPO_DIR#g" "$REPO_DIR/systemd/homenetmon.user.service" > ~/.config/systemd/user/$UNIT.service
    systemctl --user daemon-reload
    systemctl --user enable --now "$UNIT"
    loginctl enable-linger "$USER" 2>/dev/null || warn "Could not enable lingering; the service stops when you log out."
    say "Started. Status: systemctl --user status $UNIT   Logs: journalctl --user -u $UNIT -f"
    exit 0
fi

# ---- system-wide install ----
install_system_deps
id "$SERVICE_USER" &>/dev/null || sudo useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
say "Syncing code to $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"
sudo rsync -a --delete --exclude venv --exclude .env --exclude data --exclude production_data --exclude logs --exclude backups \
     --exclude node_modules --exclude .git "$REPO_DIR/" "$INSTALL_DIR/"
sudo mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/logs" "$INSTALL_DIR/backups"
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
say "Python environment"
[[ -d "$INSTALL_DIR/venv" ]] || sudo -u "$SERVICE_USER" python3 -m venv "$INSTALL_DIR/venv"
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
write_env "$INSTALL_DIR/.env" "$SERVICE_USER"
say "Installing systemd unit"
sudo cp "$INSTALL_DIR/systemd/homenetmon.service" "/etc/systemd/system/$UNIT.service"
sudo systemctl daemon-reload
sudo systemctl enable --now "$UNIT"
sleep 3
if sudo systemctl is-active --quiet "$UNIT"; then
    say "HomeNetMon is running: http://$(hostname -I | awk '{print $1}'):5000"
    say "Status: sudo systemctl status $UNIT   Logs: sudo journalctl -u $UNIT -f"
else
    die "Service failed to start; see: sudo journalctl -u $UNIT -n 50"
fi
