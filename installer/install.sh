#!/bin/bash
set -euo pipefail

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
  INSTALL_USER="${SUDO_USER:-${PODIUM_USER:-event}}"
else
  INSTALL_USER="$(whoami)"
fi

HOME_DIR="$(getent passwd "$INSTALL_USER" | cut -d: -f6 2>/dev/null || true)"
if [ -z "$HOME_DIR" ]; then
  HOME_DIR="/home/$INSTALL_USER"
fi

CONFIG_FILE="${PODIUM_CONFIG_FILE:-/etc/default/podium-kiosk}"
if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

HOST="${HOSTNAME_OVERRIDE:-$(hostname)}"
PODIUM="${PODIUM:-${DISPLAY_ID:-}}"
KIOSK_USER="${KIOSK_USER:-$INSTALL_USER}"
SERVER_HOST="${SERVER_HOST:-podium-1.local}"
SERVER_PORT="${SERVER_PORT:-5001}"
SERVER_URL="${SERVER_URL:-}"
REPO_URL="${REPO_URL:-https://github.com/maxedmini/podium-system.git}"
BRANCH="${BRANCH:-main}"
REPO_DIR="${REPO_DIR:-$HOME_DIR/podium-system}"

if [ -z "${PODIUM}" ]; then
  echo "❌ PODIUM/DISPLAY_ID is not set in $CONFIG_FILE"
  exit 1
fi

case "$PODIUM" in
  1|2|3)
    ;;
  *)
    echo "❌ Invalid PODIUM value: $PODIUM"
    exit 1
    ;;
esac

if [ -z "$SERVER_URL" ]; then
  SERVER_URL="http://${SERVER_HOST}:${SERVER_PORT}/display/${PODIUM}"
fi

echo "=== Podium installer ==="
echo "Host: $HOST"
echo "Install user: $INSTALL_USER"
echo "Kiosk user: $KIOSK_USER"
echo "Podium: $PODIUM"
echo "Repo: $REPO_URL ($BRANCH)"
echo "Server URL: $SERVER_URL"

# Packages
sudo apt update
sudo apt install -y \
  git curl rsync sshpass openssh-client \
  chromium x11-xserver-utils unclutter \
  python3 python3-venv python3-pip

# Clone or update repo
if [ ! -d "$REPO_DIR/.git" ]; then
  git clone --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
else
  cd "$REPO_DIR"
  git fetch origin
  git reset --hard "origin/$BRANCH"
fi

sudo mkdir -p "$(dirname "$CONFIG_FILE")"
sudo tee "$CONFIG_FILE" >/dev/null <<EOF
PODIUM=$PODIUM
DISPLAY_ID=$PODIUM
KIOSK_USER=$KIOSK_USER
SERVER_HOST=$SERVER_HOST
SERVER_PORT=$SERVER_PORT
SERVER_URL=$SERVER_URL
REPO_URL=$REPO_URL
BRANCH=$BRANCH
REPO_DIR=$REPO_DIR
EOF

# Offline fallback
sudo mkdir -p /opt/kiosk-fallback
sudo chown "$INSTALL_USER:$INSTALL_USER" /opt/kiosk-fallback

cat > /opt/kiosk-fallback/offline.html <<'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=1920,height=1080">
<style>
html,body{margin:0;width:100%;height:100%;background:black;overflow:hidden}
img{width:100vw;height:100vh;object-fit:contain}
</style>
</head>
<body>
<img src="offline.png">
</body>
</html>
EOF

sudo install -m 644 "$REPO_DIR/fallback/offline.png" /opt/kiosk-fallback/offline.png

# Install kiosk launcher
sudo install -m 755 "$REPO_DIR/kiosk/kiosk-launch.sh" /usr/local/bin/kiosk-launch.sh

# Generate kiosk.service dynamically (CORRECT WAY)
sudo tee /etc/systemd/system/kiosk.service >/dev/null <<EOF
[Unit]
Description=Podium Display Kiosk
After=graphical.target
Wants=graphical.target

[Service]
User=$KIOSK_USER
Environment=DISPLAY=:0
EnvironmentFile=/etc/default/podium-kiosk
ExecStart=/usr/local/bin/kiosk-launch.sh
Restart=always
RestartSec=5

[Install]
WantedBy=graphical.target
EOF

sudo systemctl unmask kiosk.service || true
sudo systemctl daemon-reload
sudo systemctl enable kiosk
sudo systemctl restart kiosk

# Server only on podium1
if [ "$PODIUM" = "1" ]; then
  cd "$REPO_DIR/server"

  if [ ! -d venv ]; then
    python3 -m venv venv
  fi

  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt

  # Sync static assets for the Flask server (kept outside the repo for durability)
  STATIC_DST="/opt/podium-server/static"
  sudo mkdir -p "$STATIC_DST"
  sudo rsync -a --delete "$REPO_DIR/server/static/" "$STATIC_DST/"
  sudo chown -R "$INSTALL_USER:$INSTALL_USER" "$STATIC_DST"

  sudo tee /etc/systemd/system/podium-server.service >/dev/null <<EOF
[Unit]
Description=Podium Flask Server
After=network-online.target

[Service]
User=$INSTALL_USER
WorkingDirectory=$REPO_DIR/server
Environment=PATH=$REPO_DIR/server/venv/bin
ExecStart=$REPO_DIR/server/venv/bin/python app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable podium-server
  sudo systemctl restart podium-server
else
  sudo systemctl disable --now podium-server >/dev/null 2>&1 || true
fi

echo "=== Installation complete. Reboot recommended. ==="
