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
X-Enterprise-API-Key: your-enterprise-api-key-here
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

### **2. List All Synchronizers**
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

### **3. Enable/Disable Synchronizer**
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

## 🔒 **Security & Access Control**

### **Enterprise API Key Requirements:**
- ✅ Must be a valid enterprise user (`isEnterprise: true`)
- ✅ API key must exist in the database
- ✅ User must own the synchronizers they're modifying
- ✅ Keys are automatically associated with the enterprise user

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
