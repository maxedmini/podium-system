#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="Prepare Podium SD Card.app"
APP_PATH="$SCRIPT_DIR/$APP_NAME"
JXA_SCRIPT="$SCRIPT_DIR/prepare_sd_card.js"
PREP_SCRIPT="$SCRIPT_DIR/prepare_sd_card.sh"
TMP_DIR="$(mktemp -d /tmp/podium-app-build.XXXXXX)"
TMP_APP_PATH="$TMP_DIR/$APP_NAME"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

rm -rf "$APP_PATH"
osacompile -l JavaScript -o "$TMP_APP_PATH" "$JXA_SCRIPT"

mkdir -p "$TMP_APP_PATH/Contents/Resources"
cp "$PREP_SCRIPT" "$TMP_APP_PATH/Contents/Resources/prepare_sd_card.sh"
cp -R "$SCRIPT_DIR/boot" "$TMP_APP_PATH/Contents/Resources/boot"
chmod +x "$TMP_APP_PATH/Contents/Resources/prepare_sd_card.sh"

ditto "$TMP_APP_PATH" "$APP_PATH"

echo "Built:"
echo "  $APP_PATH"
