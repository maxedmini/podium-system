#!/bin/bash
set -e

export DISPLAY=:0
export XAUTHORITY="/home/$(whoami)/.Xauthority"

# Load podium number
if [ -f /etc/default/podium-kiosk ]; then
  source /etc/default/podium-kiosk
else
  PODIUM=1
fi

# Wait for X server
until xset q >/dev/null 2>&1; do
  sleep 1
done

# Disable screen blanking and power saving
xset s off
xset s noblank
xset -dpms

# Hide mouse cursor
unclutter -idle 0 &

SERVER_URL="http://podium1.local:5001/display/${PODIUM}"
FALLBACK_URL="file:///opt/kiosk-fallback/offline.html"

if curl -sf --max-time 2 "$SERVER_URL" >/dev/null; then
  URL="$SERVER_URL"
else
  URL="$FALLBACK_URL"
fi

exec /usr/bin/chromium \
  --kiosk \
  --window-size=1920,1080 \
  --force-device-scale-factor=1 \
  --no-sandbox \
  --incognito \
  --disable-cache \
  --disk-cache-dir=/tmp/chromium-cache \
  --user-data-dir=/tmp/chromium-profile \
  --disable-infobars \
  --disable-session-crashed-bubble \
  --disable-restore-session-state \
  --disable-component-update \
  --disable-background-networking \
  --disable-sync \
  --noerrdialogs \
  --autoplay-policy=no-user-gesture-required \
  "$URL"
