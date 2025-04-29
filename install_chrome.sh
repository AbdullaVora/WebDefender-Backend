#!/bin/bash
# Install dependencies
apt-get update
apt-get install -y wget gnupg2 apt-transport-https

# Add Google Chrome repository key
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -

# Add Google Chrome repository
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list

# Install Google Chrome
apt-get update
apt-get install -y google-chrome-stable

# Verify the installation
google-chrome --version