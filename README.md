# synchronizer-cli

🚀 **Complete CLI toolkit for Multisynq Synchronizer** - Docker container management, auto-installation, systemd service generation, and real-time web dashboard with performance monitoring.

[![npm version](https://badge.fury.io/js/synchronizer-cli.svg)](https://www.npmjs.com/package/synchronizer-cli)
[![Node.js Version](https://img.shields.io/node/v/synchronizer-cli.svg)](https://nodejs.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Downloads](https://img.shields.io/npm/dm/synchronizer-cli.svg)](https://www.npmjs.com/package/synchronizer-cli)

## ✨ Features

### 🎯 Core Functionality
- 🔧 **Interactive Setup** - Guided configuration with prompts for Synq key and wallet
- 🐳 **Smart Docker Management** - Auto-install Docker on Linux with multi-distro support
- 🔐 **Permission Handling** - Automatic Docker permissions fix with user group management
- ⚙️ **Systemd Integration** - Generate service files for headless operation
- 🌐 **Cross-platform** - Full support for Linux, macOS, and Windows
- 🏗️ **Platform Detection** - Automatic Docker architecture detection (ARM64/AMD64)

### 🌐 Web Dashboard & Monitoring
- 📊 **Performance Metrics** - Real-time traffic, sessions, and user monitoring
- 🎯 **Quality of Service (QoS)** - Visual monitoring with reliability, availability, and efficiency scores
- 📈 **Live Charts** - Circular progress indicators with color-coded status (green/yellow/red)
- 📋 **Real-time Logs** - Systemd logs with syntax highlighting and auto-refresh
- 🔗 **API Documentation** - Built-in endpoint documentation with method badges
- 🔄 **Auto-refresh** - Dashboard updates every 5 seconds automatically

### 🔧 Advanced Features
- 🛠️ **Built-in Troubleshooting** - Comprehensive error handling and helpful solutions
- 🔍 **Dynamic NPX Detection** - Smart detection of npm/npx installation paths
- 📦 **Lightweight** - Only ~16KB package size with minimal dependencies
- 🚀 **Enhanced Help** - Comprehensive feature documentation in CLI help
- 🔒 **Security Features** - Masked sensitive data display with click-to-reveal

## Prerequisites

- **Node.js** v10 or higher
- **Docker** (can be auto-installed on Linux)
- **Synq key** from Multisynq platform

## Installation

```bash
npm install -g synchronizer-cli
```

## Quick Start

```bash
# 1. Configure your synchronizer
synchronize init

# 2. Start the synchronizer
synchronize start

# 3. (Optional) Set up as a system service
synchronize service

# 4. Check service status and performance
synchronize status

# 5. Launch web dashboard with performance monitoring
synchronize web
```

## Commands Reference

| Command | Description | Features |
|---------|-------------|----------|
| `synchronize init` | Interactive configuration setup | Synq key, wallet, sync name configuration |
| `synchronize start` | Run synchronizer Docker container | Auto platform detection, Docker checks |
| `synchronize service` | Generate systemd service file | Headless operation, auto-start configuration |
| `synchronize service-web` | Generate web dashboard service | Persistent web monitoring, NPX path detection |
| `synchronize status` | Show service status and logs | Color-coded status, recent logs, helpful commands |
| `synchronize web` | Start web dashboard | Performance metrics, QoS monitoring, API docs |
| `synchronize install-docker` | Auto-install Docker (Linux) | Multi-distro support, service configuration |
| `synchronize fix-docker` | Fix Docker permissions | User group management, permission troubleshooting |
| `synchronize test-platform` | Test Docker compatibility | Platform testing, architecture validation |

## Web Dashboard

The comprehensive web dashboard provides real-time monitoring and system insights:

```bash
synchronize web
```

### 🎨 Dashboard Features

#### 📊 Performance Metrics
- **Total Traffic**: Cumulative data transfer with smart formatting (KB/MB/GB)
- **Active Sessions**: Real-time session count monitoring
- **Traffic Rates**: Live in/out traffic with bytes per second
- **User Count**: Connected users tracking
- **Smart Data**: Metrics reflect actual service status

#### 🎯 Quality of Service (QoS)
- **Overall Score**: Circular progress indicator with color coding
  - 🟢 **Excellent** (80%+): Green indicator for optimal performance
  - 🟡 **Good** (60-79%): Yellow indicator for acceptable performance  
  - 🔴 **Poor** (<60%): Red indicator requiring attention
- **Individual Metrics**:
  - **Reliability**: Service stability percentage
  - **Availability**: Uptime and accessibility percentage
  - **Efficiency**: Performance optimization score

#### 🔗 API Endpoints Documentation
- **Method Badges**: Clear GET/POST indicators
- **Endpoint Paths**: Monospace formatting for clarity
- **Descriptions**: Detailed functionality explanations
- **Live Links**: Direct access to API endpoints

#### ⚙️ System Information
- **Service Status**: Real-time running/stopped/failed indicators
- **Configuration Display**: Masked Synq key with click-to-reveal
- **Platform Details**: Architecture and hostname information
- **Quick Actions**: One-click access to common operations

### 🌐 Server Architecture

The web dashboard runs on dual servers:
- **Dashboard Server** (default port 3000): Main web interface
- **Metrics Server** (default port 3001): JSON API endpoints

*Automatic port detection prevents conflicts*

### 📡 API Endpoints

#### Dashboard API (Port 3000)
- `GET /` - Main dashboard interface
- `GET /api/status` - System and service status JSON
- `GET /api/logs` - Recent systemd logs JSON  
- `GET /api/performance` - Performance metrics and QoS data
- `POST /api/install-web-service` - Generate web dashboard systemd service

#### Metrics API (Port 3001)
- `GET /metrics` - Comprehensive system metrics JSON
- `GET /health` - Health check endpoint for monitoring

## Docker Management

### Automatic Installation

If Docker is not installed, synchronizer-cli offers automatic installation:

```bash
synchronize install-docker
```

**Supported Linux distributions:**
- **Ubuntu/Debian**: APT package management with GPG key verification
- **CentOS/RHEL/Fedora**: YUM/DNF package management
- **Automatic service setup**: Docker daemon start and enable
- **User group management**: Automatic docker group addition

### Permission Management

Fix Docker permission issues automatically:

```bash
synchronize fix-docker
```

This command:
- Adds your user to the docker group
- Provides logout/login instructions
- Offers testing commands for verification

### Platform Compatibility

Test Docker platform compatibility across architectures:

```bash
synchronize test-platform
```

**Testing includes:**
- `linux/amd64` compatibility testing
- `linux/arm64` compatibility testing  
- Platform recommendation based on system architecture
- Comprehensive error reporting and troubleshooting

## Systemd Service Management

### Synchronizer Service

Generate and install the main synchronizer service:

```bash
synchronize service
sudo cp ~/.synchronizer-cli/synchronizer-cli.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable synchronizer-cli
sudo systemctl start synchronizer-cli
```

### Web Dashboard Service

Generate a persistent web dashboard service:

```bash
synchronize service-web
sudo cp ~/.synchronizer-cli/synchronizer-cli-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable synchronizer-cli-web
sudo systemctl start synchronizer-cli-web
```

**Features:**
- **Dynamic NPX Detection**: Automatically finds npm/npx installation path
- **Path Verification**: Tests multiple common installation locations
- **Fallback Support**: Handles various Node.js installation methods (nvm, homebrew, etc.)

## Configuration

Configuration is stored in `~/.synchronizer-cli/config.json`:

```json
{
  "userName": "optional-sync-name",
  "key": "your-synq-key",
  "wallet": "your-wallet-address", 
  "secret": "generated-secret",
  "hostname": "system-hostname",
  "syncHash": "generated-sync-hash",
  "depin": "wss://api.multisynq.io/depin",
  "launcher": "cli"
}
```

## Version Information

The synchronizer-cli ecosystem uses several versioned components:

| Component | Version | Description |
|-----------|---------|-------------|
| **synchronizer-cli** | 2.0.4 | The npm package version of this CLI tool |
| **Croquet** | 2.0.1 | The version of Croquet used in the Docker image |
| **Docker Image** | latest | The cdrakep/synqchronizer Docker image tag |
| **Launcher ID** | cli-2.0.1 | The launcher identifier used for the Croquet session |

When using the CLI, the launcher ID is automatically set to match the Croquet version (e.g., `cli-2.0.1`) to ensure session compatibility. The Docker image is configured to use the correct Croquet version internally.

### Version History

- **2.0.4**: Added intelligent Docker image update checking to avoid unnecessary downloads
- **2.0.3**: Fixed Docker image to use Croquet 2.0.1 and added version identification in launcher ID
- **2.0.2**: Added multi-architecture Docker image support (ARM64/AMD64)
- **2.0.1**: Initial stable release with web dashboard

## Enhanced CLI Experience

### Comprehensive Help Output

Run `synchronize --help` for detailed feature information:
- 🎯 **Feature highlights** with emoji indicators
- 🌐 **Web dashboard capabilities** overview
- 🔧 **Troubleshooting features** summary
- 📦 **Package information** with links
- 🔗 **Homepage and issues** direct links

### Smart Error Handling

- **Docker not found**: Automatic installation prompts
- **Permission denied**: Clear fix instructions with commands
- **Platform mismatch**: Architecture-specific troubleshooting
- **Service failures**: Detailed error analysis and solutions

## Troubleshooting Guide

### Common Issues & Solutions

#### Docker Installation Issues
```bash
# Auto-install Docker (Linux only)
synchronize install-docker

# Manual installation check
docker --version
```

#### Permission Problems
```bash
# Fix Docker permissions
synchronize fix-docker

# Verify after logout/login
docker run hello-world
```

#### Platform Architecture Issues
```bash
# Test platform compatibility
synchronize test-platform

# Check system architecture
uname -m
```

#### Service Status Problems
```bash
# Check detailed service status
synchronize status

# View live logs
journalctl -u synchronizer-cli -f
```

#### NPX/Node.js Issues
```bash
# Check NPX detection
synchronize service-web

# Verify Node.js installation
node --version
npm --version
```

## Platform Support Matrix

| Platform | Docker Install | Permission Fix | Service Generation | Web Dashboard | Architecture |
|----------|----------------|----------------|-------------------|---------------|--------------|
| **Ubuntu/Debian** | ✅ Auto | ✅ Auto | ✅ Full | ✅ Full | AMD64/ARM64 |
| **CentOS/RHEL** | ✅ Auto | ✅ Auto | ✅ Full | ✅ Full | AMD64/ARM64 |
| **Fedora** | ✅ Auto | ✅ Auto | ✅ Full | ✅ Full | AMD64/ARM64 |
| **macOS** | 📖 Manual | N/A | N/A | ✅ Full | AMD64/ARM64 |
| **Windows** | 📖 Manual | N/A | N/A | ✅ Full | AMD64 |

## Performance & Monitoring

### Real-time Metrics
- **Traffic Monitoring**: Bytes transferred with smart formatting
- **Session Tracking**: Active connection monitoring  
- **User Analytics**: Connected user statistics
- **QoS Scoring**: Automated quality assessment

### Health Monitoring
- **Service Status**: Running/stopped/failed detection
- **Docker Health**: Container and daemon status
- **System Resources**: Memory, CPU, and load monitoring
- **Uptime Tracking**: Service availability metrics

## Security Features

- **Masked Credentials**: Synq keys hidden by default with click-to-reveal
- **Secure Storage**: Configuration stored in user home directory
- **Permission Validation**: Docker access verification
- **Service Isolation**: Systemd service runs with user permissions

## Development & Contributing

### Package Information
- **Size**: ~16KB package, ~65KB unpacked
- **Dependencies**: Minimal (chalk, commander, inquirer, express)
- **Node.js**: Compatible with v10+
- **License**: Apache-2.0

### Contributing
- **Issues**: Report bugs and feature requests on [GitHub](https://github.com/ceedeepee/synchronizer-cli/issues)
- **Pull Requests**: Contributions welcome
- **Documentation**: Help improve this README

## License

Apache-2.0 © [ceedeepee](https://github.com/ceedeepee)

---

**Latest Version**: Check [npm](https://www.npmjs.com/package/synchronizer-cli) for the most recent release with new features and improvements.