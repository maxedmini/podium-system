#!/bin/bash
set -e

USER=$(whoami)
HOST=$(hostname)

case "$HOST" in
  podium1)
    PODIUM=1
    KIOSK_USER=podium1
    ;;
  podium2)
    PODIUM=2
    KIOSK_USER=podium2
    ;;
  podium3)
    PODIUM=3
    KIOSK_USER=podium3
    ;;
  *)
    echo "❌ Unknown hostname: $HOST"
    exit 1
    ;;
esac

REPO_DIR="$HOME/podium-system"
REPO_URL="https://github.com/maxedmini/podium-system.git"
BRANCH="main"

echo "=== Podium installer ==="
echo "Host: $HOST"
echo "User: $USER"
echo "Podium: $PODIUM"

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

# Write podium number (single source of truth)
echo "PODIUM=$PODIUM" | sudo tee /etc/default/podium-kiosk >/dev/null

# Offline fallback
sudo mkdir -p /opt/kiosk-fallback
sudo chown "$USER:$USER" /opt/kiosk-fallback

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
if [ "$HOST" = "podium1" ]; then
  cd "$REPO_DIR/server"

  if [ ! -d venv ]; then
    python3 -m venv venv
  fi

  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt

  sudo tee /etc/systemd/system/podium-server.service >/dev/null <<EOF
[Unit]
Description=Podium Flask Server
After=network-online.target

[Service]
User=$USER
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
fi

echo "=== Installation complete. Reboot recommended. ==="
