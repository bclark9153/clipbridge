#!/bin/sh
# Installs or upgrades ClipBridge on macOS from the latest GitHub release:
#   curl -fsSL https://github.com/bclark9153/clipbridge/releases/latest/download/install.sh | sh
# Picks the Apple Silicon or Intel build and puts it in /usr/local/bin
# (asks for your password only if that folder isn't writable).
set -eu

REPO="bclark9153/clipbridge"
DEST="/usr/local/bin"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  ASSET="clipbridge-macos-arm64" ;;
  Darwin-x86_64) ASSET="clipbridge-macos-x86_64" ;;
  *) echo "This installer is for macOS; found $(uname -s) $(uname -m)." >&2; exit 1 ;;
esac

TMP="$(mktemp -t clipbridge)"
trap 'rm -f "$TMP"' EXIT

echo "Downloading $ASSET ..."
curl -fsSL "https://github.com/$REPO/releases/latest/download/$ASSET" -o "$TMP"

SUDO=""
if [ -d "$DEST" ]; then
  [ -w "$DEST" ] || SUDO="sudo"
else
  [ -w "$(dirname "$DEST")" ] || SUDO="sudo"
fi
[ -n "$SUDO" ] && echo "Installing to $DEST needs your Mac password."

$SUDO mkdir -p "$DEST"
$SUDO install -m 755 "$TMP" "$DEST/clipbridge"
$SUDO xattr -c "$DEST/clipbridge" 2>/dev/null || true

echo "Installed $("$DEST/clipbridge" --version) to $DEST/clipbridge"
echo
echo "Next: run   clipbridge listen   and enter the pairing code it shows on your Windows PC."
