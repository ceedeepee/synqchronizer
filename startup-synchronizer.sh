#!/bin/bash
set -e

echo "🚀 Starting Synchronizer Setup..."

apt-get update -y
apt-get install -y curl wget gnupg lsb-release ca-certificates apt-transport-https

# Install Docker
echo "🐳 Installing Docker..."
install_docker() {
  mkdir -m 0755 -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}
install_docker

# Enable and start Docker
systemctl enable docker
systemctl start docker

USERNAME="ubuntu"
echo "👤 Adding $USERNAME to docker group..."
usermod -aG docker $USERNAME

# Preload Docker socket perms
gpasswd -a $USERNAME docker
newgrp docker << END
echo "🔁 Docker group permissions applied in sub-shell"
END

# Run everything else as non-root user
su - $USERNAME -c "
  set -e
  echo '🟢 Installing NVM and Node.js...'
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
  export NVM_DIR=\"/home/$USERNAME/.nvm\"
  [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"
  [ -s \"\$NVM_DIR/bash_completion\" ] && . \"\$NVM_DIR/bash_completion\"
  nvm install --lts
  nvm use --lts

  echo '⚡ Installing synchronizer-cli globally...'
  npm install -g synchronizer-cli

  echo '🏢 Running synchronizer with API key...'
  synchronize --api [your-api-key]
"

echo "✅ Setup complete. Docker and synchronizer are live."
