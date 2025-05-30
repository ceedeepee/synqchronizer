**Enterprise API endpoints** that allow enterprise users to request and manage synq keys using their enterprise API key:

## 🔑 **Enterprise API Endpoints**

### **Base URL**
```
Production: https://startsynqing.com/api
Development: http://localhost:3000/api  
```

### **Authentication**
All enterprise endpoints require the **Enterprise API Key** in the header:
```http
X-Enterprise-API-Key: your-enterprise-api-key
Content-Type: application/json
```

---

## 📋 **Available Enterprise Endpoints**

### **1. Create New Synchronizer (Generate Synq Key)**
**Creates a named synchronizer with a unique synq key**

```http
POST /synq-keys/enterprise/synchronizer
```

**Headers:**
```http
X-Enterprise-API-Key: your-enterprise-api-key
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "Production Server 1"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Successfully generated synchronizer",
  "synchronizer": {
    "id": "uuid-here",
    "key": "b1df0d63-83b3-478d-a55f-a6c402e74185",
    "name": "Production Server 1"
  }
}
```

**cURL Example:**
```bash
curl -X POST https://startsynqing.com/api/synq-keys/enterprise/synchronizer \
  -H "X-Enterprise-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"name": "Production Server 1"}'
```

---

### **2. Get Enterprise Preferences**
**Retrieve user preferences for automatic CLI configuration**

```http
GET /synq-keys/enterprise/preferences
```

**Headers:**
```http
X-Enterprise-API-Key: your-enterprise-api-key
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Preferences retrieved successfully",
  "preferences": {
    "walletAddress": "0x1234...abcd", 
    "dashboardPassword": "••••••••",
    "defaultAction": "service",
    "web": true,
  },
  "owner": {
    "walletAddress": "0x1234...abcd"
  }
}
```

**cURL Example:**
```bash
curl -X GET https://startsynqing.com/api/synq-keys/enterprise/preferences \
  -H "X-Enterprise-API-Key: your-api-key-here"

**Preference Fields:**
- `walletAddress`: Default wallet address for automatic CLI setup
- `dashboardPassword`: Default dashboard password (masked for security)
- `defaultAction`: Default action to execute (start/service/web)
- `web`: Boolean to automatically start web dashboard if true

```

---

### **3. List All Synchronizers**
**Get all synq keys/synchronizers for your enterprise account**

```http
GET /synq-keys/enterprise/synchronizers
```

**Headers:**
```http
X-Enterprise-API-Key: your-enterprise-api-key
```

**Response (200 OK):**
```json
{
  "success": true,
  "synchronizers": [
    {
      "id": "uuid-1",
      "key": "b1df0d63-83b3-478d-a55f-a6c402e74185",
      "name": "Production Server 1",
      "isEnabled": true,
      "createdAt": "2024-01-15T10:30:00Z"
    },
    {
      "id": "uuid-2", 
      "key": "c2ef1e74-94c4-589e-b66g-b7d513f85296",
      "name": "Staging Server",
      "isEnabled": false,
      "createdAt": "2024-01-16T14:20:00Z"
    }
  ]
}
```

**cURL Example:**
```bash
curl -X GET https://startsynqing.com/api/synq-keys/enterprise/synchronizers \
  -H "X-Enterprise-API-Key: your-api-key-here"
```

---

### **4. Enable/Disable Synchronizer**
**Toggle a synchronizer's enabled status**

```http
PUT /synq-keys/enterprise/synchronizer/:id/toggle
```

**Headers:**
```http
X-Enterprise-API-Key: your-enterprise-api-key
Content-Type: application/json
```

**Request Body:**
```json
{
  "isEnabled": true
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Synchronizer enabled successfully",
  "synchronizer": {
    "id": "uuid-here",
    "key": "b1df0d63-83b3-478d-a55f-a6c402e74185", 
    "name": "Production Server 1",
    "isEnabled": true
  }
}
```

**cURL Example:**
```bash
curl -X PUT https://startsynqing.com/api/synq-keys/enterprise/synchronizer/uuid-here/toggle \
  -H "X-Enterprise-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"isEnabled": false}'
```

---

## 🖥️ **CLI Enterprise Integration**

The **Synchronizer CLI** provides seamless integration with the Enterprise API for automated deployment and management.

### **Installation**
```bash
npm install -g synchronizer-cli
```

### **Enterprise CLI Commands**

#### **1. Interactive Enterprise Setup**
**Guided setup with prompts for enterprise users**

```bash
synchronize api
```

**Features:**
- ✅ Prompts for Enterprise API Key
- ✅ Optional synchronizer name input
- ✅ Wallet address configuration
- ✅ Dashboard password setup
- ✅ Action selection (Start/Service/Web/Quit)
- ✅ Automatic synq key generation
- ✅ Complete CLI configuration

**Example Flow:**
```bash
$ synchronize api
🏢 Enterprise API Setup
Automatically provision a synq key via Enterprise API

? Enterprise API Key: ••••••••••••••••••••
? Synchronizer name (optional): Production-Server-1
✅ Synchronizer created successfully!
   ID: uuid-12345
   Name: Production-Server-1
   Synq Key: b1df0d63-83b3-478d-a55f-a6c402e74185

? Wallet address: 0x1234567890abcdef...
? Set a password for the web dashboard? Yes
? Dashboard password: ••••••••
? What would you like to do next? [S]tart, Se[R]vice, [W]eb, [Q]uit: R

🎉 Enterprise API setup complete!
⚙️ Generating systemd service...
```

---

#### **2. Automatic Enterprise Setup**
**Hands-free setup using API preferences (recommended for automation)**

```bash
synchronize --api <enterprise-api-key>
```

**Features:**
- ✅ **Zero prompts** - completely automatic
- ✅ **Uses API preferences** for wallet, password, and default action
- ✅ **Immediate execution** of configured default action
- ✅ **Perfect for scripts** and automated deployments
- ✅ **Fallback support** if preferences not set

**Example:**
```bash
$ synchronize --api your-enterprise-api-key-here
🏢 Automatic Enterprise API Setup
Using API preferences for hands-free configuration

🔄 Fetching preferences from Enterprise API...
✅ Preferences retrieved successfully!
   Wallet: 0x1234...abcd
   Password: ••••••••
   Default Action: service

🔄 Creating synchronizer via Enterprise API...
✅ Synchronizer created successfully!
   ID: uuid-67890
   Name: auto-generated-name
   Synq Key: c2ef1e74-94c4-589e-b66g-b7d513f85296

🎉 Automatic Enterprise API setup complete!
💰 Wallet: 0x1234567890abcdef...
🔒 Dashboard password protection enabled

🚀 Executing default action: service
⚙️ Generating systemd service...
✅ Service file generated successfully!
```

---

### **Enterprise Deployment Scenarios**

#### **Scenario 1: Manual Server Setup**
```bash
# SSH into server
ssh user@production-server-1

# Install CLI globally
npm install -g synchronizer-cli

# Interactive enterprise setup
synchronize api
# Follow prompts, choose "Service" to generate systemd service

# Install and start service
sudo cp ~/.synchronizer-cli/synchronizer-cli.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable synchronizer-cli
sudo systemctl start synchronizer-cli
```

#### **Scenario 2: Automated Deployment Script**
```bash
#!/bin/bash
# deploy-synchronizer.sh

SERVER=$1
API_KEY=$2

if [ -z "$SERVER" ] || [ -z "$API_KEY" ]; then
  echo "Usage: $0 <server> <enterprise-api-key>"
  exit 1
fi

echo "Deploying synchronizer to $SERVER..."

ssh $SERVER << EOF
  # Install CLI
  npm install -g synchronizer-cli
  
  # Automatic setup with API preferences
  synchronize --api $API_KEY
  
  # Service is automatically generated and configuration is complete
  echo "Synchronizer deployed successfully!"
EOF
```

#### **Scenario 3: Docker Deployment**
```dockerfile
FROM node:20-alpine

# Install CLI globally
RUN npm install -g synchronizer-cli

# Copy enterprise API key (use secrets in production)
ARG ENTERPRISE_API_KEY
ENV ENTERPRISE_API_KEY=$ENTERPRISE_API_KEY

# Setup and run
CMD ["sh", "-c", "synchronize --api $ENTERPRISE_API_KEY"]
```

#### **Scenario 4: Kubernetes Deployment**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: synchronizer-enterprise
spec:
  replicas: 3
  selector:
    matchLabels:
      app: synchronizer
  template:
    metadata:
      labels:
        app: synchronizer
    spec:
      containers:
      - name: synchronizer
        image: node:20-alpine
        command: ["/bin/sh"]
        args: ["-c", "npm install -g synchronizer-cli && synchronize --api $ENTERPRISE_API_KEY"]
        env:
        - name: ENTERPRISE_API_KEY
          valueFrom:
            secretKeyRef:
              name: enterprise-secrets
              key: api-key
```

#### **Scenario 5: Ready-to-Deploy Cloud Script**
**Use the included startup-synchronizer.sh script for instant cloud deployment**

The synchronizer-cli package includes a **production-ready startup script** specifically designed for cloud instances:

📄 **File**: `startup-synchronizer.sh` (included in npm package)

**Features:**
- ✅ **Complete automation** - zero manual steps required
- ✅ **Multi-cloud support** - AWS EC2, DigitalOcean, Google Cloud, Azure
- ✅ **Enterprise API integration** - uses `synchronize --api` for hands-free setup
- ✅ **Error handling** - exits on any failure for reliable deployments
- ✅ **Progress indicators** - visual feedback during installation
- ✅ **User management** - configurable for different cloud providers

**Quick Deployment:**
```bash
# Download and customize the script
curl -o startup-synchronizer.sh https://raw.githubusercontent.com/multisynq/synchronizer-cli/main/startup-synchronizer.sh

# Replace API key placeholder
sed -i 's/\[your-api-key\]/your-actual-enterprise-api-key-here/g' startup-synchronizer.sh

# Deploy to EC2 instance (as User Data)
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t3.micro \
  --user-data file://startup-synchronizer.sh

# Or deploy to DigitalOcean droplet
doctl compute droplet create synchronizer-node \
  --size s-1vcpu-1gb \
  --image ubuntu-20-04-x64 \
  --user-data-file startup-synchronizer.sh
```

**Script Contents Preview:**
```bash
#!/bin/bash
# startup-synchronizer.sh - Ready-to-deploy cloud startup script
set -e  # Exit on any error

echo "🚀 Starting Synchronizer Cloud Instance Setup..."

# Update package list and install dependencies
apt-get update -y
apt-get install -y curl wget

# Configure for your cloud provider
USERNAME="ubuntu"  # Change to "root" for DigitalOcean

# Install Node.js via NVM and synchronizer-cli
su - $USERNAME -c "
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
  export NVM_DIR=\"/home/$USERNAME/.nvm\"
  [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"
  nvm install --lts
  npm install -g synchronizer-cli
  synchronize --api [your-api-key]  # Replace with your Enterprise API key
"

echo "✅ Synchronizer cloud instance setup complete!"
```

**Cloud Provider Customization:**
- **AWS EC2**: Use as-is (username: `ubuntu`)
- **DigitalOcean**: Change `USERNAME="ubuntu"` to `USERNAME="root"`
- **Google Cloud**: Use as-is (username: `ubuntu`)
- **Azure**: Use as-is (username: `azureuser`) or customize as needed

---

### **Enterprise CLI Features**

#### **Configuration Management**
- ✅ **Automatic config generation** from Enterprise API
- ✅ **Secure credential storage** in `~/.synchronizer-cli/config.json`
- ✅ **Enterprise API key persistence** for future operations
- ✅ **Synchronizer ID tracking** for management

#### **Service Integration**
- ✅ **Systemd service generation** for headless operation
- ✅ **Auto-restart capabilities** with proper error handling
- ✅ **Docker container management** with platform detection
- ✅ **Web dashboard setup** with password protection

#### **Monitoring & Management**
- ✅ **Real-time status checking** via `synchronize status`
- ✅ **Points tracking** via `synchronize points`
- ✅ **Container logs access** via `synchronize web`
- ✅ **Update monitoring** via `synchronize check-updates`

---

## 🔒 **Security & Access Control**

### **Enterprise API Key Requirements:**
- ✅ Must be a valid enterprise user (`isEnterprise: true`)
- ✅ API key must exist in the database
- ✅ User must own the synchronizers they're modifying
- ✅ Keys are automatically associated with the enterprise user

### **CLI Security Features:**
- ✅ **Password masking** in terminal input
- ✅ **Secure config storage** with proper file permissions
- ✅ **API key encryption** in local storage
- ✅ **Dashboard authentication** with configurable passwords

### **Error Responses:**
```json
// 401 Unauthorized
{
  "success": false,
  "message": "Unauthorized"
}

// 400 Bad Request  
{
  "success": false,
  "message": "Synchronizer name is required"
}

// 404 Not Found
{
  "success": false,
  "message": "Synchronizer not found"
}

// 403 Forbidden
{
  "success": false,
  "message": "You can only modify your own synchronizers"
}
```

---

## 🛠️ **Integration Examples**

### **Node.js/JavaScript:**
```javascript
const API_BASE = 'https://startsynqing.com/api';
const ENTERPRISE_API_KEY = 'your-enterprise-api-key';

// Create a new synchronizer
async function createSynchronizer(name) {
  const response = await fetch(`${API_BASE}/synq-keys/enterprise/synchronizer`, {
    method: 'POST',
    headers: {
      'X-Enterprise-API-Key': ENTERPRISE_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ name })
  });
  
  return await response.json();
}

// List all synchronizers
async function listSynchronizers() {
  const response = await fetch(`${API_BASE}/synq-keys/enterprise/synchronizers`, {
    headers: {
      'X-Enterprise-API-Key': ENTERPRISE_API_KEY
    }
  });
  
  return await response.json();
}

// Toggle synchronizer
async function toggleSynchronizer(id, isEnabled) {
  const response = await fetch(`${API_BASE}/synq-keys/enterprise/synchronizer/${id}/toggle`, {
    method: 'PUT',
    headers: {
      'X-Enterprise-API-Key': ENTERPRISE_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ isEnabled })
  });
  
  return await response.json();
}
```

### **Python:**
```python
import requests

API_BASE = 'https://startsynqing.com/api'
HEADERS = {
    'X-Enterprise-API-Key': 'your-enterprise-api-key',
    'Content-Type': 'application/json'
}

# Create synchronizer
def create_synchronizer(name):
    response = requests.post(
        f'{API_BASE}/synq-keys/enterprise/synchronizer',
        headers=HEADERS,
        json={'name': name}
    )
    return response.json()

# List synchronizers  
def list_synchronizers():
    response = requests.get(
        f'{API_BASE}/synq-keys/enterprise/synchronizers',
        headers={'X-Enterprise-API-Key': HEADERS['X-Enterprise-API-Key']}
    )
    return response.json()
```

These endpoints allow enterprise users to programmatically manage their synq keys for automated deployment and scaling! 🚀
