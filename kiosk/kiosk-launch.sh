#!/bin/bash
set -e

HOST=$(hostname)

case "$HOST" in
  podium1) PODIUM=1 ;;
  podium2) PODIUM=2 ;;
  podium3) PODIUM=3 ;;
  *) PODIUM=1 ;;
esac

SERVER_URL="http://podium1.local:5001/display/${PODIUM}"
FALLBACK_URL="file:///opt/kiosk-fallback/offline.html"

if curl -sf --max-time 2 "$SERVER_URL" > /dev/null; then
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

