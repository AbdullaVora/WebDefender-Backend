#!/bin/bash
# Ensure the script exits on any error
set -e

echo "Starting Chrome installation..."

# Create a temporary directory for downloads
mkdir -p /tmp/chrome_install
cd /tmp/chrome_install

# Download Chrome
echo "Downloading Chrome..."
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb

# Install Chrome and dependencies
echo "Installing Chrome dependencies..."
apt-get update
apt-get install -y ./google-chrome-stable_current_amd64.deb

# Verify installation
echo "Verifying Chrome installation..."
google-chrome --version

# Clean up
echo "Cleaning up..."
cd -
rm -rf /tmp/chrome_install

echo "Chrome installation completed successfully!"