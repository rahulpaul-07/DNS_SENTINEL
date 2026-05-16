#!/bin/bash
# Install DNSentinel Native Host for Chrome/Edge on Linux/macOS

set -e

DIR="$( cd "$( dirname "$0" )" && pwd )"
HOST_NAME="com.dnssentinel.host"

if [ "$(uname -s)" == "Darwin" ]; then
  if [ "$(whoami)" == "root" ]; then
    TARGET_DIR="/Library/Google/Chrome/NativeMessagingHosts"
  else
    TARGET_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
  fi
else
  if [ "$(whoami)" == "root" ]; then
    TARGET_DIR="/etc/opt/chrome/native-messaging-hosts"
  else
    TARGET_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
  fi
fi

mkdir -p "$TARGET_DIR"

# Copy the wrapper and make it executable
cp "$DIR/dnssentinel_host.py" "$TARGET_DIR/dnssentinel_host.py"
chmod +x "$TARGET_DIR/dnssentinel_host.py"

# Update path in manifest and copy
sed "s|dnssentinel_host.py|$TARGET_DIR/dnssentinel_host.py|g" "$DIR/$HOST_NAME.json" > "$TARGET_DIR/$HOST_NAME.json"

# Set permissions
chmod 644 "$TARGET_DIR/$HOST_NAME.json"

echo "Native messaging host $HOST_NAME installed successfully to $TARGET_DIR."
