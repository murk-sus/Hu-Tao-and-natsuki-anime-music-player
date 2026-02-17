#!/usr/bin/env bash
set -euo pipefail

PKG_ID="com.anime.hutao-natsuki-player"
VERSION="1.0.0"
ARCH="iphoneos-arm64"
BUILD_DIR="build"
ROOTFS="$BUILD_DIR/rootfs"
APP_DIR="$ROOTFS/var/mobile/HuTaoNatsukiPlayer"
DEBIAN_DIR="$ROOTFS/DEBIAN"
OUTPUT="$BUILD_DIR/${PKG_ID}_${VERSION}_${ARCH}.deb"

rm -rf "$BUILD_DIR"
mkdir -p "$APP_DIR" "$DEBIAN_DIR" "$ROOTFS/usr/bin"

cp -R src/app/. "$APP_DIR/"
cp resources/launch-player.sh "$ROOTFS/usr/bin/huplayer"
chmod 0755 "$ROOTFS/usr/bin/huplayer"

cat > "$DEBIAN_DIR/control" <<CONTROL
Package: $PKG_ID
Name: Hu Tao Natsuki Anime Player
Version: $VERSION
Architecture: $ARCH
Maintainer: Anime Modder <root@localhost>
Depends: firmware (>= 16.7)
Section: Multimedia
Priority: optional
Description: Offline web-based anime player with Hu Tao and Natsuki theme for jailbroken iOS 16.7.x.
CONTROL

cat > "$DEBIAN_DIR/postinst" <<'POSTINST'
#!/bin/bash
set -e
chmod -R 0755 /var/mobile/HuTaoNatsukiPlayer
chown -R mobile:mobile /var/mobile/HuTaoNatsukiPlayer || true
echo "Run 'huplayer' in terminal to open Hu Tao × Natsuki player."
POSTINST

chmod 0755 "$DEBIAN_DIR/postinst"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required to build the package." >&2
  exit 1
fi

dpkg-deb -b "$ROOTFS" "$OUTPUT"
echo "Created: $OUTPUT"
