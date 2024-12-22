#!/usr/bin/env bash
set -eu
set -x

cd "$(dirname "$0")"

VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' ../librustls/Cargo.toml)
if [ -z "$VERSION" ]; then
    echo "Failed to extract version from Cargo.toml" >&2
    exit 1
fi

PACKAGE="librustls"
ARCH="amd64"
DIST_DIR="/tmp/dist"
DEB_ROOT="/tmp/deb"

CC=clang CXX=clang cargo cinstall --locked --features cert_compression --release --prefix "${DIST_DIR}"

mkdir -p "${DEB_ROOT}/usr/"{lib,include}
mkdir -p "${DEB_ROOT}/DEBIAN"

cp -r "${DIST_DIR}/lib/"* "${DEB_ROOT}/usr/lib/"
cp -r "${DIST_DIR}/include/"* "${DEB_ROOT}/usr/include/"

sed -i "s|prefix=.*|prefix=/usr|" "${DEB_ROOT}/usr/lib/x86_64-linux-gnu/pkgconfig/rustls.pc"

cat > "${DEB_ROOT}/DEBIAN/control" << EOF
Package: ${PACKAGE}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Daniel McCarney <daniel@binaryparadox.net>
Description: FFI bindings for the Rustls TLS library
Section: libs
Depends: libc6
Priority: optional
EOF

cat > "${DEB_ROOT}/DEBIAN/postinst" << EOF
#!/bin/sh
set -e
ldconfig
EOF
chmod 755 "${DEB_ROOT}/DEBIAN/postinst"

cd ..
dpkg-deb --build ${DEB_ROOT} "${PACKAGE}_${VERSION}_${ARCH}.deb"
