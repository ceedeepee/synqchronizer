#!/bin/bash
set -e

echo "🚀 Starting full synchronizer setup..."

# Constants
USERNAME="ubuntu"
API_KEY="REPLACE_WITH_YOUR_API_KEY"
WALLET="REPLACE_WITH_YOUR_WALLET"
DASHBOARD_PASSWORD="REPLACE_WITH_YOUR_PASSWORD"

# Update packages
apt-get update -y
apt-get install -y curl wget gnupg lsb-release ca-certificates apt-transport-https build-essential

# Install Docker
echo "🐳 Installing Docker..."
install_docker() {
  mkdir -m 0755 -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
}
install_docker
usermod -aG docker $USERNAME
systemctl enable docker
systemctl start docker

# Install NVM/Node/npm globally for ubuntu user
su - $USERNAME -c "
  export NVM_DIR=\"/home/$USERNAME/.nvm\"
  mkdir -p \$NVM_DIR
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
  source \$NVM_DIR/nvm.sh
  nvm install --lts
  nvm use --lts
  npm install -g synchronizer-cli
"

# Write synchronizer config manually
CONFIG_DIR="/home/$USERNAME/.synchronizer-cli"
CONFIG_FILE="\$CONFIG_DIR/config.json"
mkdir -p \$CONFIG_DIR
cat > \$CONFIG_FILE <<EOF
{
  "key": "$API_KEY",
  "wallet": "$WALLET",
  "dashboardPassword": "$DASHBOARD_PASSWORD",
  "hostname": "$(hostname)",
  "depin": "wss://api.multisynq.io/depin",
  "launcher": "cli"
}
EOF
chown -R $USERNAME:$USERNAME \$CONFIG_DIR

# Install systemd services
su - $USERNAME -c "synchronize service"
su - $USERNAME -c "synchronize web"

# Copy and enable systemd services
cp /home/$USERNAME/.synchronizer-cli/synchronizer-cli.service /etc/systemd/system/
cp /home/$USERNAME/.synchronizer-cli/synchronizer-cli-web.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable synchronizer-cli
systemctl enable synchronizer-cli-web
systemctl start synchronizer-cli
systemctl start synchronizer-cli-web

echo "✅ Synchronizer setup complete"
