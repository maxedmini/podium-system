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
API_BASE="${SERVER_URL%/display/*}"
FALLBACK_URL="file:///opt/kiosk-fallback/offline.html"
STATE_FILE="/tmp/podium-kiosk-state-${PODIUM}.json"

# On podium1, wait for local server to come up (max 30s)
if [ "$PODIUM" = "1" ]; then
  for i in {1..30}; do
    if curl -sf "$SERVER_URL" >/dev/null; then
      break
    fi
    sleep 1
  done
fi

CURRENT_MODE=""
STAGED_MODE=""

record_mode_change() {
  local mode="$1"
  if [ -n "$API_BASE" ]; then
    curl -sf --max-time 2 -X POST "$API_BASE/api/kiosk-mode" \
      -d "pos=$PODIUM" -d "mode=$mode" >/dev/null 2>&1 && return 0
  fi
  return 1
}

persist_mode() {
  local mode="$1"
  printf '{"mode":"%s","ts":%s}\n' "$mode" "$(date +%s)" > "$STATE_FILE"
}

load_persisted_mode() {
  if [ -f "$STATE_FILE" ]; then
    STAGED_MODE=$(jq -r '.mode // ""' "$STATE_FILE" 2>/dev/null || true)
    STAGED_TS=$(jq -r '.ts // 0' "$STATE_FILE" 2>/dev/null || echo 0)
  else
    STAGED_MODE=""
    STAGED_TS=0
  fi
}

load_persisted_mode
if [ -n "$STAGED_MODE" ] && [ "$STAGED_MODE" != "$CURRENT_MODE" ]; then
  if record_mode_change "$STAGED_MODE"; then
    CURRENT_MODE="$STAGED_MODE"
    STAGED_MODE=""
    STAGED_TS=0
    rm -f "$STATE_FILE"
  fi
fi

while true; do
  ONLINE=0
  for attempt in {1..5}; do
    if curl -sf --max-time 3 "$SERVER_URL" >/dev/null; then
      ONLINE=1
      break
    fi
    sleep 1
  done

  if [ "$ONLINE" = "1" ]; then
    DESIRED_MODE="LIVE"
    URL="$SERVER_URL"
  else
    DESIRED_MODE="FALLBACK"
    URL="$FALLBACK_URL"
  fi

  # Only relaunch Chromium if mode changed
  if [ "$DESIRED_MODE" != "$CURRENT_MODE" ]; then
    # Tell server about mode change; if offline, persist and retry on next loop.
    if record_mode_change "$DESIRED_MODE"; then
      rm -f "$STATE_FILE"
    else
      persist_mode "$DESIRED_MODE"
    fi

    pkill -f chromium || true
    sleep 1

    /usr/bin/chromium \
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
      "$URL" &

    CURRENT_MODE="$DESIRED_MODE"
  fi

  sleep 5
done
