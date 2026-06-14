#!/bin/bash
set -e

cd "$(dirname "$0")"

KERNEL_VER=$(uname -r)

if [ ! -d "/lib/modules/$KERNEL_VER/build" ]; then
    echo "Error: kernel headers not found." >&2
    echo "Install: sudo apt install linux-headers-$KERNEL_VER" >&2
    exit 1
fi

echo "==> Building Makefile"
make

echo "==> Building kernel module..."
make -C /lib/modules/$KERNEL_VER/build M=$PWD modules

PKG_DIR="$PWD/debian/kblocker"
DEB_DIR="$PKG_DIR/DEBIAN"

echo "==> Staging package files..."
rm -rf "$PKG_DIR"

install -d "$PKG_DIR/lib/modules/$KERNEL_VER/extra"
install -m 644 kblocker.ko "$PKG_DIR/lib/modules/$KERNEL_VER/extra/"

install -d "$PKG_DIR/usr/local/bin"
install -m 755 kblockerctl "$PKG_DIR/usr/local/bin/kblockerctl"

install -d "$PKG_DIR/etc/kblocker/keys"
install -d "$PKG_DIR/var/lib/kblocker"

BUILD_DIR="$PWD/build"
mkdir -p "$BUILD_DIR"

ARCH=$(dpkg --print-architecture)

install -d "$DEB_DIR"
sed 's/ARCH/'"$ARCH"'/g' debian/control > "$DEB_DIR/control"
install -m 644 debian/changelog "$DEB_DIR/changelog"
gzip -9nf "$DEB_DIR/changelog"
install -m 644 debian/copyright "$DEB_DIR/copyright"
install -m 755 debian/postinst "$DEB_DIR/postinst"
install -m 755 debian/prerm "$DEB_DIR/prerm"
install -m 755 debian/postrm "$DEB_DIR/postrm"

BUILD_DIR="$PWD/build"
mkdir -p "$BUILD_DIR"

DEB_FILE="$BUILD_DIR/kblocker_$KERNEL_VER.deb"
echo "==> Building package..."
fakeroot dpkg-deb --root-owner-group --build "$PKG_DIR" "$DEB_FILE"

echo ""
echo "Done: $DEB_FILE ($(du -h "$DEB_FILE" | cut -f1))"
echo "Install: sudo dpkg -i $(basename "$DEB_FILE")"
