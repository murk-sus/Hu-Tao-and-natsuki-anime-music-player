#!/usr/bin/env bash
set -euo pipefail

PKG_ID="com.anime.hutao-natsuki-lockscreen"
VERSION="2.0.0"
ARCH="iphoneos-arm64"
BUILD_DIR="build"
ROOTFS="$BUILD_DIR/rootfs"
WIDGET_DIR="$ROOTFS/var/mobile/Library/LockHTML/HuTaoNatsukiPlayer"
DEBIAN_DIR="$ROOTFS/DEBIAN"
OUTPUT_NAME="${PKG_ID}_${VERSION}_${ARCH}.deb"
OUTPUT="$BUILD_DIR/$OUTPUT_NAME"

rm -rf "$BUILD_DIR"
mkdir -p "$WIDGET_DIR" "$DEBIAN_DIR"

cp -R src/app/. "$WIDGET_DIR/"

cat > "$DEBIAN_DIR/control" <<CONTROL
Package: $PKG_ID
Name: Hu Tao Natsuki Lockscreen Player
Version: $VERSION
Architecture: $ARCH
Maintainer: Anime Modder <root@localhost>
Depends: firmware (>= 16.7), com.matchstic.xenhtml
Section: Multimedia
Priority: optional
Description: Lockscreen-only anime music player widget (Hu Tao x Natsuki) for jailbroken iOS 16.7.x.
CONTROL

cat > "$DEBIAN_DIR/postinst" <<'POSTINST'
#!/bin/bash
set -e
chmod -R 0755 /var/mobile/Library/LockHTML/HuTaoNatsukiPlayer
chown -R mobile:mobile /var/mobile/Library/LockHTML/HuTaoNatsukiPlayer || true

echo "Installed lockscreen widget: /var/mobile/Library/LockHTML/HuTaoNatsukiPlayer"
echo "Open Xen HTML -> Lock Screen -> choose HuTaoNatsukiPlayer"
POSTINST

chmod 0755 "$DEBIAN_DIR/postinst"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required to build the package." >&2
  exit 1
fi

dpkg-deb -b "$ROOTFS" "$OUTPUT"
echo "Created: $OUTPUT"
