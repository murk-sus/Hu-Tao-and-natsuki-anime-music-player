#!/bin/bash
PLAYER_PATH="/var/mobile/HuTaoNatsukiPlayer/index.html"

if [ ! -f "$PLAYER_PATH" ]; then
  echo "Player not found: $PLAYER_PATH"
  exit 1
fi

if command -v uiopen >/dev/null 2>&1; then
  uiopen "file://$PLAYER_PATH"
else
  echo "uiopen command is missing. Install uiopen-compatible package or open manually: file://$PLAYER_PATH"
fi
