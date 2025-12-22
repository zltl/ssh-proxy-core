#!/bin/bash
# install-libssh.sh - Download and install libssh from source
# Usage: ./scripts/install-libssh.sh [version]

set -e

LIBSSH_VERSION="${1:-0.10.6}"
LIBSSH_URL="https://www.libssh.org/files/0.10/libssh-${LIBSSH_VERSION}.tar.xz"
BUILD_DIR="/tmp/libssh-build"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"

echo "=== libssh Installation Script ==="
echo "Version: ${LIBSSH_VERSION}"
echo "Install prefix: ${INSTALL_PREFIX}"
echo ""

# Check if already installed
if pkg-config --exists libssh 2>/dev/null; then
    INSTALLED_VERSION=$(pkg-config --modversion libssh)
    echo "libssh ${INSTALLED_VERSION} is already installed."
    read -p "Reinstall? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

# Check dependencies
echo "Checking build dependencies..."
DEPS="cmake gcc make libssl-dev zlib1g-dev"
MISSING=""
for dep in $DEPS; do
    if ! dpkg -s "$dep" >/dev/null 2>&1; then
        MISSING="$MISSING $dep"
    fi
done

if [ -n "$MISSING" ]; then
    echo "Installing missing dependencies:$MISSING"
    sudo apt-get update
    sudo apt-get install -y $MISSING
fi

# Create build directory
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Download
echo ""
echo "Downloading libssh ${LIBSSH_VERSION}..."
curl -L -o "libssh-${LIBSSH_VERSION}.tar.xz" "${LIBSSH_URL}"

# Extract
echo "Extracting..."
tar -xf "libssh-${LIBSSH_VERSION}.tar.xz"
cd "libssh-${LIBSSH_VERSION}"

# Build
echo ""
echo "Building libssh..."
mkdir build && cd build
cmake .. \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DWITH_SERVER=ON \
    -DWITH_SFTP=ON \
    -DWITH_GSSAPI=OFF

make -j$(nproc)

# Install
echo ""
echo "Installing libssh..."
sudo make install

# Update library cache
sudo ldconfig

# Cleanup
rm -rf "${BUILD_DIR}"

# Verify
echo ""
echo "=== Installation Complete ==="
if pkg-config --exists libssh; then
    echo "libssh $(pkg-config --modversion libssh) installed successfully!"
    echo "CFLAGS: $(pkg-config --cflags libssh)"
    echo "LIBS:   $(pkg-config --libs libssh)"
else
    echo "Warning: pkg-config cannot find libssh."
    echo "You may need to set PKG_CONFIG_PATH=${INSTALL_PREFIX}/lib/pkgconfig"
fi
