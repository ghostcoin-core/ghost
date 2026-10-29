#!/usr/bin/env bash
# Renders the brand kit's PNGs and favicon.ico from its SVG masters in
# design/brand-kit-v1, with rsvg-convert and ImageMagick's convert only.
#
#   png/       every svg/ghost-logo-*.svg (not the small cut) at 256 and 1024,
#              every svg/ghost-lockup-*.svg at 2400 wide
#   app-icon/  violet at 1024, 512 and 192; white at 1024
#   favicon/   favicon-16/32/48.png and favicon.ico from favicon/favicon.svg
#              (the small cut), apple-touch-icon.png (180) from the white app icon
#   social/    ghost-avatar-800.png, ghost-og-image-1200x630.png and
#              ghost-x-profile.png (400) from the SVGs beside them
#
# The link preview's tagline is set in the kit's own Instrument Sans.
#
# Usage: scripts/build-brand-kit.sh [out]   (out defaults to the kit itself)

set -euo pipefail

RSVG=/usr/bin/rsvg-convert
CONVERT=/usr/bin/convert

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
kit="$(cd "$here/../design/brand-kit-v1" && pwd)"
out="${1:-$kit}"

for tool in "$RSVG" "$CONVERT"; do
  if [ ! -x "$tool" ]; then
    echo "build-brand-kit: $tool is missing" >&2
    exit 1
  fi
done

fontdir="$(mktemp -d)"
trap 'rm -rf "$fontdir"' EXIT
cat >"$fontdir/fonts.conf" <<EOF
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <dir>$kit/fonts</dir>
  <cachedir>$fontdir/cache</cachedir>
</fontconfig>
EOF
export FONTCONFIG_FILE="$fontdir/fonts.conf"

# render SVG WIDTH OUT: SVG (kit-relative) at WIDTH px wide, height to scale.
render() {
  mkdir -p "$(dirname "$out/$3")"
  "$RSVG" --width "$2" --keep-aspect-ratio --output "$out/$3" "$kit/$1"
}

for name in primary on-violet on-ink one-color-ink one-color-white; do
  for size in 256 1024; do
    render "svg/ghost-logo-$name.svg" "$size" "png/ghost-logo-$name-$size.png"
  done
done

for name in primary on-violet on-ink one-color-ink; do
  render "svg/ghost-lockup-$name.svg" 2400 "png/ghost-lockup-$name-2400.png"
done

for size in 1024 512 192; do
  render app-icon/ghost-app-icon-violet.svg "$size" "app-icon/ghost-app-icon-violet-$size.png"
done
render app-icon/ghost-app-icon-white.svg 1024 app-icon/ghost-app-icon-white-1024.png

for size in 16 32 48; do
  render favicon/favicon.svg "$size" "favicon/favicon-$size.png"
done
"$CONVERT" "$out/favicon/favicon-16.png" "$out/favicon/favicon-32.png" "$out/favicon/favicon-48.png" "$out/favicon/favicon.ico"
render app-icon/ghost-app-icon-white.svg 180 favicon/apple-touch-icon.png

render social/ghost-avatar.svg 800 social/ghost-avatar-800.png
render social/ghost-og-image.svg 1200 social/ghost-og-image-1200x630.png
render social/ghost-x-profile.svg 400 social/ghost-x-profile.png
