#!/bin/bash
set -euo pipefail

BOOT_DIR=""
for candidate in /boot/firmware /boot; do
  if [ -d "$candidate" ]; then
    BOOT_DIR="$candidate"
    break
  fi
done

if [ -z "$BOOT_DIR" ]; then
  echo "No boot partition found"
  exit 1
fi

ENV_FILE="$BOOT_DIR/podium.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE"
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

PI_USERNAME="${PI_USERNAME:-event}"
PODIUM_USER="${PODIUM_USER:-$PI_USERNAME}"
REPO_URL="${REPO_URL:-https://github.com/maxedmini/podium-system.git}"
BRANCH="${BRANCH:-main}"
REPO_DIR="${REPO_DIR:-/home/$PODIUM_USER/podium-system}"
PODIUM="${PODIUM:-${DISPLAY_ID:-}}"
SERVER_HOST="${SERVER_HOST:-podium-1.local}"
SERVER_PORT="${SERVER_PORT:-5001}"
SERVER_URL="${SERVER_URL:-http://${SERVER_HOST}:${SERVER_PORT}/display/${PODIUM}}"
HOSTNAME_OVERRIDE="${HOSTNAME_OVERRIDE:-${PI_HOSTNAME:-}}"
MARKER_FILE="/var/lib/podium-firstboot.done"

mkdir -p /var/lib

if [ -f "$MARKER_FILE" ]; then
  echo "Podium first boot already completed"
  exit 0
fi

if ! id "$PODIUM_USER" >/dev/null 2>&1; then
  echo "User $PODIUM_USER does not exist; create it in Raspberry Pi Imager first"
  exit 1
fi

if [ -n "$HOSTNAME_OVERRIDE" ]; then
  current_hostname="$(hostname)"
  hostnamectl set-hostname "$HOSTNAME_OVERRIDE"
  if [ -f /etc/hosts ]; then
    sed -i "s/127.0.1.1[[:space:]]\+$current_hostname/127.0.1.1\t$HOSTNAME_OVERRIDE/" /etc/hosts || true
  fi
fi

apt-get update
apt-get install -y git

if [ ! -d "$REPO_DIR/.git" ]; then
  install -d -o "$PODIUM_USER" -g "$PODIUM_USER" "$(dirname "$REPO_DIR")"
  sudo -u "$PODIUM_USER" git clone --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
else
  sudo -u "$PODIUM_USER" git -C "$REPO_DIR" fetch origin
  sudo -u "$PODIUM_USER" git -C "$REPO_DIR" reset --hard "origin/$BRANCH"
fi

cat >/etc/default/podium-kiosk <<EOF
PODIUM=$PODIUM
DISPLAY_ID=$PODIUM
PODIUM_USER=$PODIUM_USER
KIOSK_USER=${KIOSK_USER:-$PODIUM_USER}
SERVER_HOST=$SERVER_HOST
SERVER_PORT=$SERVER_PORT
SERVER_URL=$SERVER_URL
REPO_URL=$REPO_URL
BRANCH=$BRANCH
REPO_DIR=$REPO_DIR
HOSTNAME_OVERRIDE=$HOSTNAME_OVERRIDE
EOF

PODIUM_CONFIG_FILE=/etc/default/podium-kiosk \
PODIUM_USER="$PODIUM_USER" \
bash "$REPO_DIR/installer/install.sh"

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$MARKER_FILE"
rm -f "$BOOT_DIR/firstrun.sh" "$BOOT_DIR/podium-firstboot.sh"
reboot
