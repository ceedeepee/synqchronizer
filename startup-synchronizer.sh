#!/bin/bash
# startup-synchronizer.sh
# Cloud instance user data script for automatic synchronizer deployment
# Usage: Replace [your-api-key] with your actual Enterprise API key

set -e  # Exit on any error

echo "🚀 Starting Synchronizer Cloud Instance Setup..."

# Update package list
echo "📦 Updating package list..."
apt-get update -y

# Install basic dependencies
echo "🔧 Installing dependencies..."
apt-get install -y curl wget

# Define the username (adjust for your cloud provider)
USERNAME="ubuntu"  # EC2 default, change to "root" for DigitalOcean, etc.

echo "👤 Setting up for user: $USERNAME"

# Install NVM and Node.js as the specified user
su - $USERNAME -c "
  echo '🟢 Installing NVM and Node.js...'
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
  export NVM_DIR=\"/home/$USERNAME/.nvm\"
  [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"
  
  echo '📥 Installing latest Node.js LTS...'
  nvm install --lts
  nvm use --lts
  
  echo '⚡ Installing synchronizer-cli globally...'
  npm install -g synchronizer-cli
  
  echo '🏢 Running Enterprise API setup...'
  synchronize --api [your-api-key]
"

echo "✅ Synchronizer cloud instance setup complete!"
echo "🎯 Your synchronizer should now be running automatically."
echo "📊 Check status with: synchronize status"
echo "💰 Check points with: synchronize points" 