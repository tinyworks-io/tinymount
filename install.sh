#!/bin/sh
set -e

# tinymount installer
# Usage: curl -sSL https://tinymount.com/install.sh | sh

REPO="tinyworks/tinymount"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY="tinymount"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  aarch64|arm64)
    ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

case "$OS" in
  linux|darwin)
    ;;
  *)
    echo "Unsupported OS: $OS"
    echo "tinymount supports Linux and macOS."
    exit 1
    ;;
esac

# Get latest version
echo "Fetching latest release..."
LATEST=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
  echo "Could not determine latest version."
  echo "Check https://github.com/${REPO}/releases"
  exit 1
fi

VERSION="${LATEST#v}"
FILENAME="${BINARY}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${FILENAME}"

# Download and install
echo "Downloading tinymount ${LATEST} for ${OS}/${ARCH}..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -sL "$URL" -o "$TMPDIR/$FILENAME"

echo "Extracting..."
tar -xzf "$TMPDIR/$FILENAME" -C "$TMPDIR"

echo "Installing to ${INSTALL_DIR}..."
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
else
  sudo mv "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
fi

chmod +x "$INSTALL_DIR/$BINARY"

echo ""
echo "tinymount ${LATEST} installed successfully!"
echo ""
echo "Get started:"
echo "  tinymount register    # Create an account"
echo "  tinymount create data # Create a volume"
echo "  tinymount mount data ~/data"
echo ""
echo "Docs: https://tinymount.com/docs"
