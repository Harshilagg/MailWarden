#!/bin/sh
# Rebuild the app icon and dashboard logos from mailwarden/assets/logo-source.png (macOS: sips, iconutil).
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
sips -c 900 900 mailwarden/assets/logo-source.png --out "$tmp/crop.png" >/dev/null
sips -z 824 824 "$tmp/crop.png" --out "$tmp/body.png" >/dev/null
python3 scripts/round_icon.py "$tmp/body.png" mailwarden/assets/icon-1024.png
mkdir -p "$tmp/mailwarden.iconset"
for s in 16 32 128 256 512; do
  sips -z $s $s mailwarden/assets/icon-1024.png --out "$tmp/mailwarden.iconset/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) mailwarden/assets/icon-1024.png --out "$tmp/mailwarden.iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$tmp/mailwarden.iconset" -o mailwarden/assets/mailwarden.icns
sips -z 64 64 mailwarden/assets/icon-1024.png --out mailwarden/delivery/dashboard/static/logo-64.png >/dev/null
sips -z 180 180 mailwarden/assets/icon-1024.png --out mailwarden/delivery/dashboard/static/logo-180.png >/dev/null
rm -rf "$tmp"
echo "icons rebuilt"
