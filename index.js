#!/usr/bin/env node

const { Command } = require('commander');
const inquirer = require('inquirer');
const chalk = require('chalk');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawn, execSync } = require('child_process');
const express = require('express');
const packageJson = require('./package.json');
const fetch = require('node-fetch'); // Add node-fetch for API validation
const WebSocket = require('ws'); // Add WebSocket for real-time container communication
const program = new Command();

const CONFIG_DIR = path.join(os.homedir(), '.synchronizer-cli');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const POINTS_FILE = path.join(CONFIG_DIR, 'points.json');

// Cache file for wallet points API responses
const CACHE_FILE = path.join(CONFIG_DIR, 'wallet-points-cache.json');
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds for successful responses
const ERROR_CACHE_DURATION = 30 * 1000; // 30 seconds for error responses

// Global variable to store WebSocket connection and latest data
let containerWebSocket = null;
let latestContainerData = null;
let wsConnectionAttempts = 0;
const MAX_WS_RECONNECT_ATTEMPTS = 5;
let wsInitialized = false; // Flag to ensure we only try to connect once

// Global rate limiting and caching for ALL stats requests
let lastStatsRequestTime = 0;
let lastStatsResult = null;
let statsRequestInProgress = null; // Promise to prevent race conditions
const STATS_REQUEST_COOLDOWN = 60 * 1000; // 60 seconds between ANY stats requests (once a minute as requested)
const STATS_CACHE_DURATION = 60 * 1000; // Cache results for 60 seconds (once a minute as requested)

// Global WebSocket connection management
let wsConnectionInProgress = false;
let lastWebSocketRequestTime = 0;
const WS_REQUEST_COOLDOWN = 10 * 1000; // Only allow WebSocket requests every 10 seconds

// Global caching for all dashboard data to prevent redundant requests
let globalCache = {
  performance: { data: null, timestamp: 0 },
  points: { data: null, timestamp: 0 },
  status: { data: null, timestamp: 0 }
};
const DASHBOARD_CACHE_DURATION = 30 * 1000; // Cache dashboard data for 30 seconds

function loadConfig() {
  if (fs.existsSync(CONFIG_FILE)) {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  }
  return {};
}

function saveConfig(config) {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

function loadPointsData() {
  if (fs.existsSync(POINTS_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(POINTS_FILE, 'utf8'));
    } catch (error) {
      console.log('Error loading points data, starting fresh:', error.message);
      return createEmptyPointsData();
    }
  }
  return createEmptyPointsData();
}

function savePointsData(pointsData) {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
  fs.writeFileSync(POINTS_FILE, JSON.stringify(pointsData, null, 2));
}

function createEmptyPointsData() {
  return {
    totalLifetimePoints: 0,
    sessions: [],
    lastUpdated: new Date().toISOString(),
    version: '1.0'
  };
}

function authenticateRequest(req, res, next) {
  const config = loadConfig();
  
  // If no password is set, allow access
  if (!config.dashboardPassword) {
    return next();
  }
  
  const auth = req.headers.authorization;
  
  if (!auth || !auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Synchronizer Dashboard"');
    res.status(401).send('Authentication required');
    return;
  }
  
  const credentials = Buffer.from(auth.slice(6), 'base64').toString();
  const [username, password] = credentials.split(':');
  
  // Simple authentication - username can be anything, password must match
  if (password === config.dashboardPassword) {
    req.authenticated = true;
    return next();
  }
  
  res.setHeader('WWW-Authenticate', 'Basic realm="Synchronizer Dashboard"');
  res.status(401).send('Invalid credentials');
}

function generateSyncHash(userName, secret, hostname) {
  const input = `${userName || ''}:${hostname}:${secret}`;
  const hash = crypto.createHash('sha256').update(input).digest('hex');
  return `synq-${hash.slice(0, 12)}`;
}

function detectNpxPath() {
  try {
    // Try to find npx using 'which' command
    const npxPath = execSync('which npx', { encoding: 'utf8', stdio: 'pipe' }).trim();
    if (npxPath && fs.existsSync(npxPath)) {
      return npxPath;
    }
  } catch (error) {
    // 'which' failed, try other methods
  }
  
  try {
    // Try to find npm and assume npx is in the same directory
    const npmPath = execSync('which npm', { encoding: 'utf8', stdio: 'pipe' }).trim();
    if (npmPath) {
      const npxPath = npmPath.replace(/npm$/, 'npx');
      if (fs.existsSync(npxPath)) {
        return npxPath;
      }
    }
  } catch (error) {
    // npm not found either
  }
  
  // Common fallback locations
  const fallbackPaths = [
    '/usr/bin/npx',
    '/usr/local/bin/npx',
    '/opt/homebrew/bin/npx',
    path.join(os.homedir(), '.npm-global/bin/npx'),
    path.join(os.homedir(), '.nvm/current/bin/npx')
  ];
  
  for (const fallbackPath of fallbackPaths) {
    if (fs.existsSync(fallbackPath)) {
      return fallbackPath;
    }
  }
  
  // Last resort - assume it's in PATH
  return 'npx';
}

/**
 * Check if a new Docker image is available by comparing local and remote digests
 * @param {string} imageName Docker image name with tag
 * @returns {Promise<boolean>} True if new image is available or no local image exists
 */
async function isNewDockerImageAvailable(imageName) {
  try {
    // Check if we have the image locally
    try {
      const localImageCmd = `docker images ${imageName} --format "{{.ID}}"`;
      const localImageId = execSync(localImageCmd, { encoding: 'utf8', stdio: 'pipe' }).trim();
      
      // If there's no local image, we need to pull
      if (!localImageId) {
        return true;
      }
    } catch (error) {
      // No local image found
      return true;
    }
    
    // For now, we'll use a simpler approach:
    // Always pull with --pull always flag when starting containers
    // This lets Docker handle the logic of whether to actually download
    // Return false to avoid duplicate pulling attempts
    return false;
    
  } catch (error) {
    // On any error, assume we should try to pull
    return true;
  }
}

/**
 * Validate synq key format using regex pattern
 * Checks if the key is a valid UUID v4 format
 * @param {string} key The synq key to validate
 * @returns {boolean} True if the key format is valid
 */
function validateSynqKeyFormat(key) {
  return /^[0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i.test(key);
}

/**
 * Check if a synq key is valid by calling the remote API
 * @param {string} key The synq key to check
 * @param {string} nickname Optional nickname for the synchronizer
 * @returns {Promise<{isValid: boolean, message: string}>} Result object with validation status and message
 */
async function validateSynqKeyWithAPI(key, nickname = '') {
  const DOMAIN = 'multisynq.io';
  const SYNQ_KEY_URL = `https://api.${DOMAIN}/depin/synchronizers/key`;
  
  // If no nickname is provided, use a default one to prevent the "missing synchronizer name" error
  const syncNickname = nickname || 'cli-validator';
  
  const url = `${SYNQ_KEY_URL}/${key}/precheck?nickname=${encodeURIComponent(syncNickname)}`;
  
  console.log(chalk.gray(`Validating synq key with remote API...`));
  
  try {
    const response = await fetch(url);
    const keyStatus = await response.text();
    
    if (keyStatus === 'ok') {
      return { isValid: true, message: 'Key is valid and available' };
    } else {
      return { isValid: false, message: keyStatus };
    }
  } catch (error) {
    return { 
      isValid: false, 
      message: `Could not validate key with API: ${error.message}. Will proceed with local validation only.` 
    };
  }
}

async function init() {
  const questions = [];

  questions.push({
    type: 'input',
    name: 'userName',
    message: 'Optional sync name (for your reference only):',
    default: ''
  });

  // Get the userName first
  const userNameAnswer = await inquirer.prompt([questions[0]]);
  const userName = userNameAnswer.userName;

  // Then use it when validating the key
  const keyQuestion = {
    type: 'input',
    name: 'key',
    message: 'Synq key:',
    validate: async (input) => {
      if (!input) return 'Synq key is required';
      
      // First validate the format locally
      if (!validateSynqKeyFormat(input)) {
        return 'Invalid synq key format. Must be a valid UUID v4 format (XXXXXXXX-XXXX-4XXX-YXXX-XXXXXXXXXXXX where Y is 8, 9, A, or B)';
      }
      
      // If local validation passes, try remote validation with the userName
      try {
        // Use the userName or a default nickname
        const nickname = userName || 'cli-setup';
        const validationResult = await validateSynqKeyWithAPI(input, nickname);
        
        if (!validationResult.isValid) {
          // If API returns an error specific to the key, show it
          if (validationResult.message.includes('Key')) {
            return validationResult.message;
          }
          // For network errors, we'll accept the key if it passed format validation
          console.log(chalk.yellow(`⚠️  ${validationResult.message}`));
          console.log(chalk.yellow('Continuing with local validation only.'));
        } else {
          console.log(chalk.green('✅ Key validated successfully with API'));
        }
        
        return true;
      } catch (error) {
        // If API validation fails for any reason, accept the key if it passed format validation
        console.log(chalk.yellow(`⚠️  API validation error: ${error.message}`));
        console.log(chalk.yellow('Continuing with local validation only.'));
        return true;
      }
    }
  };
  
  // Add the key question and wallet question
  const remainingQuestions = [
    keyQuestion,
    {
      type: 'input',
      name: 'wallet',
      message: 'Wallet address:',
      validate: input => input ? true : 'Wallet is required',
    },
    {
      type: 'confirm',
      name: 'setDashboardPassword',
      message: 'Set a password for the web dashboard? (Recommended for security):',
      default: true
    }
  ];

  // Get answers for the remaining questions
  const remainingAnswers = await inquirer.prompt(remainingQuestions);
  
  // Combine all answers
  const answers = {
    ...userNameAnswer,
    ...remainingAnswers
  };

  // Ask for password if user wants to set one
  if (answers.setDashboardPassword) {
    const passwordQuestions = [{
      type: 'password',
      name: 'dashboardPassword',
      message: 'Dashboard password:',
      validate: input => input && input.length >= 4 ? true : 'Password must be at least 4 characters',
      mask: '*'
    }];
    
    const passwordAnswers = await inquirer.prompt(passwordQuestions);
    answers.dashboardPassword = passwordAnswers.dashboardPassword;
  }

  const secret = crypto.randomBytes(8).toString('hex');
  const hostname = os.hostname();
  const syncHash = generateSyncHash(answers.userName, secret, hostname);

  const config = {
    ...answers,
    secret,
    hostname,
    syncHash,
    depin: 'wss://api.multisynq.io/depin',
    launcher: 'cli'
  };

  // Remove the setDashboardPassword flag from config
  delete config.setDashboardPassword;

  saveConfig(config);
  console.log(chalk.green('Configuration saved to'), CONFIG_FILE);
  
  if (config.dashboardPassword) {
    console.log(chalk.yellow('🔒 Dashboard password protection enabled'));
    console.log(chalk.gray('Use any username with your password to access the web dashboard'));
  } else {
    console.log(chalk.yellow('⚠️  Dashboard is unprotected - synq key will be visible to anyone'));
  }
}

function checkDocker() {
  try {
    execSync('docker --version', { stdio: 'ignore' });
    return true;
  } catch (error) {
    return false;
  }
}

async function installDocker() {
  const platform = os.platform();
  
  console.log(chalk.blue('🐳 Docker Installation Helper'));
  console.log(chalk.yellow('This will help you install Docker on your system.\n'));

  if (platform === 'linux') {
    const distro = await detectLinuxDistro();
    console.log(chalk.cyan(`Detected Linux distribution: ${distro}`));
    
    const confirm = await inquirer.prompt([{
      type: 'confirm',
      name: 'install',
      message: 'Would you like to install Docker automatically?',
      default: true
    }]);

    if (confirm.install) {
      await installDockerLinux(distro);
    } else {
      showManualInstructions(platform);
    }
  } else {
    console.log(chalk.yellow(`Automatic installation not supported on ${platform}.`));
    showManualInstructions(platform);
  }
}

async function detectLinuxDistro() {
  try {
    const release = fs.readFileSync('/etc/os-release', 'utf8');
    if (release.includes('ubuntu') || release.includes('Ubuntu')) return 'ubuntu';
    if (release.includes('debian') || release.includes('Debian')) return 'debian';
    if (release.includes('centos') || release.includes('CentOS')) return 'centos';
    if (release.includes('rhel') || release.includes('Red Hat')) return 'rhel';
    if (release.includes('fedora') || release.includes('Fedora')) return 'fedora';
    return 'unknown';
  } catch (error) {
    return 'unknown';
  }
}

async function installDockerLinux(distro) {
  console.log(chalk.blue('Installing Docker...'));
  
  try {
    if (distro === 'ubuntu' || distro === 'debian') {
      console.log(chalk.cyan('Updating package index...'));
      execSync('sudo apt-get update', { stdio: 'inherit' });
      
      console.log(chalk.cyan('Installing prerequisites...'));
      execSync('sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release', { stdio: 'inherit' });
      
      console.log(chalk.cyan('Adding Docker GPG key...'));
      execSync('curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg', { stdio: 'inherit' });
      
      console.log(chalk.cyan('Adding Docker repository...'));
      const arch = execSync('dpkg --print-architecture', { encoding: 'utf8' }).trim();
      const codename = execSync('lsb_release -cs', { encoding: 'utf8' }).trim();
      execSync(`echo "deb [arch=${arch} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null`, { stdio: 'inherit' });
      
      console.log(chalk.cyan('Installing Docker...'));
      execSync('sudo apt-get update', { stdio: 'inherit' });
      execSync('sudo apt-get install -y docker-ce docker-ce-cli containerd.io', { stdio: 'inherit' });
      
    } else if (distro === 'centos' || distro === 'rhel' || distro === 'fedora') {
      console.log(chalk.cyan('Installing Docker via yum/dnf...'));
      const installer = distro === 'fedora' ? 'dnf' : 'yum';
      execSync(`sudo ${installer} install -y yum-utils`, { stdio: 'inherit' });
      execSync(`sudo ${installer}-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo`, { stdio: 'inherit' });
      execSync(`sudo ${installer} install -y docker-ce docker-ce-cli containerd.io`, { stdio: 'inherit' });
    }
    
    console.log(chalk.cyan('Starting Docker service...'));
    execSync('sudo systemctl start docker', { stdio: 'inherit' });
    execSync('sudo systemctl enable docker', { stdio: 'inherit' });
    
    console.log(chalk.cyan('Adding user to docker group...'));
    const username = os.userInfo().username;
    execSync(`sudo usermod -aG docker ${username}`, { stdio: 'inherit' });
    
    console.log(chalk.green('✅ Docker installed successfully!'));
    console.log(chalk.yellow('⚠️  You may need to log out and log back in for group changes to take effect.'));
    console.log(chalk.blue('You can test Docker with: docker run hello-world'));
    
  } catch (error) {
    console.error(chalk.red('❌ Failed to install Docker automatically.'));
    console.error(chalk.red('Error:', error.message));
    showManualInstructions('linux');
  }
}

function showManualInstructions(platform) {
  console.log(chalk.blue('\n📖 Manual Installation Instructions:'));
  
  if (platform === 'linux') {
    console.log(chalk.white('For Ubuntu/Debian:'));
    console.log(chalk.gray('  curl -fsSL https://get.docker.com -o get-docker.sh'));
    console.log(chalk.gray('  sudo sh get-docker.sh'));
    console.log(chalk.white('\nFor CentOS/RHEL/Fedora:'));
    console.log(chalk.gray('  sudo yum install -y docker-ce'));
    console.log(chalk.gray('  sudo systemctl start docker'));
  } else if (platform === 'darwin') {
    console.log(chalk.white('For macOS:'));
    console.log(chalk.gray('  Download Docker Desktop from: https://docs.docker.com/desktop/mac/install/'));
    console.log(chalk.gray('  Or install via Homebrew: brew install --cask docker'));
  } else if (platform === 'win32') {
    console.log(chalk.white('For Windows:'));
    console.log(chalk.gray('  Download Docker Desktop from: https://docs.docker.com/desktop/windows/install/'));
  }
  
  console.log(chalk.blue('\nFor more details: https://docs.docker.com/get-docker/'));
}

async function start() {
  const config = loadConfig();
  if (!config.key) {
    console.error(chalk.red('Missing synq key. Run `synchronize init` first.'));
    process.exit(1);
  }

  if (config.hostname !== os.hostname()) {
    console.error(chalk.red(`This config was created for ${config.hostname}, not ${os.hostname()}.`));
    process.exit(1);
  }

  // Check if Docker is installed
  if (!checkDocker()) {
    console.error(chalk.red('Docker is not installed or not accessible.'));
    
    const shouldInstall = await inquirer.prompt([{
      type: 'confirm',
      name: 'install',
      message: 'Would you like to install Docker now?',
      default: true
    }]);

    if (shouldInstall.install) {
      await installDocker();
      
      // Check again after installation
      if (!checkDocker()) {
        console.error(chalk.red('Docker installation may have failed or requires a restart.'));
        console.error(chalk.yellow('Please try running the command again after restarting your terminal.'));
        process.exit(1);
      }
    } else {
      console.error(chalk.yellow('Please install Docker first: https://docs.docker.com/get-docker/'));
      process.exit(1);
    }
  }
  
  const syncName = config.syncHash;
  const containerName = 'synchronizer-cli';

  // Check if container is already running
  try {
    const runningContainers = execSync(`docker ps --filter name=${containerName} --format "{{.Names}}"`, {
      encoding: 'utf8',
      stdio: 'pipe'
    });
    
    if (runningContainers.includes(containerName)) {
      console.log(chalk.green(`✅ Found existing synchronizer container running`));
      console.log(chalk.cyan(`🔗 Connecting to logs... (Ctrl+C will stop the container)`));
      
      // Connect to the existing container's logs
      const logProc = spawn('docker', ['logs', '-f', containerName], { stdio: 'inherit' });
      
      // Handle Ctrl+C to stop the container
      const cleanup = () => {
        console.log(chalk.yellow('\n🛑 Stopping synchronizer container...'));
        try {
          execSync(`docker stop ${containerName}`, { stdio: 'pipe' });
          console.log(chalk.green('✅ Container stopped'));
        } catch (error) {
          console.log(chalk.red('❌ Error stopping container:', error.message));
        }
        process.exit(0);
      };
      
      process.on('SIGINT', cleanup);
      process.on('SIGTERM', cleanup);
      
      logProc.on('exit', (code) => {
        process.exit(code);
      });
      
      return;
    }
  } catch (error) {
    // No existing container, continue with normal startup
  }

  // Detect platform architecture
  const arch = os.arch();
  const platform = os.platform();
  let dockerPlatform = 'linux/amd64'; // Default to amd64
  
  if (platform === 'linux') {
    if (arch === 'arm64' || arch === 'aarch64') {
      dockerPlatform = 'linux/arm64';
    } else if (arch === 'x64' || arch === 'x86_64') {
      dockerPlatform = 'linux/amd64';
    }
  } else if (platform === 'darwin') {
    dockerPlatform = arch === 'arm64' ? 'linux/arm64' : 'linux/amd64';
  }

  console.log(chalk.blue(`Detected platform: ${platform}/${arch} -> Using Docker platform: ${dockerPlatform}`));

  // Use the main synchronizer image  
  const imageName = 'cdrakep/synqchronizer:latest';
  
  // Get dynamic version info for launcher
  let dockerImageVersion = 'latest';
  try {
    // Try to get the version from the image we're about to use
    const imageInspectOutput = execSync(`docker inspect ${imageName} --format "{{json .Config.Labels}}"`, {
      encoding: 'utf8',
      stdio: 'pipe'
    });
    
    const labels = JSON.parse(imageInspectOutput);
    if (labels && labels.version) {
      dockerImageVersion = labels.version;
    } else {
      // Get image creation date as fallback
      const createdOutput = execSync(`docker inspect ${imageName} --format "{{.Created}}"`, {
        encoding: 'utf8',
        stdio: 'pipe'
      });
      const created = new Date(createdOutput.trim());
      dockerImageVersion = `${created.toISOString().split('T')[0]}`;
    }
  } catch (error) {
    // Use latest as fallback
    dockerImageVersion = 'latest';
  }

  // Set launcher with dynamic version
  const launcherWithVersion = `cli-${packageJson.version}/docker-${dockerImageVersion}`;
  console.log(chalk.cyan(`Using launcher identifier: ${launcherWithVersion}`));

  // Check if we need to pull the latest Docker image
  const shouldPull = await isNewDockerImageAvailable(imageName);
  
  // Pull the latest image only if necessary
  if (shouldPull) {
    console.log(chalk.cyan('Pulling latest Docker image...'));
    try {
      execSync(`docker pull ${imageName}`, { 
        stdio: ['ignore', 'pipe', 'pipe']
      });
      console.log(chalk.green('✅ Docker image pulled successfully'));
    } catch (error) {
      console.log(chalk.yellow('⚠️  Could not pull latest image - will use local cache if available'));
      console.log(chalk.gray(error.message));
    }
  }

  // Create Docker command
  const dockerCmd = 'docker';
  const args = [
    'run', '--rm', '--name', containerName,
    '--pull', 'always', // Always try to pull the latest image
    '--platform', dockerPlatform,
    '-p', '3333:3333', // Expose WebSocket CLI port
    '-p', '9090:9090', // Expose HTTP metrics port
    imageName
  ];
  
  // Add container arguments correctly - each flag and value as separate items
  if (config.depin) {
    args.push('--depin');
    args.push(config.depin);
  } else {
    args.push('--depin');
    args.push('wss://api.multisynq.io/depin');
  }
  
  args.push('--sync-name');
  args.push(syncName);
  
  args.push('--launcher');
  args.push(launcherWithVersion);
  
  args.push('--key');
  args.push(config.key);
  
  if (config.wallet) {
    args.push('--wallet');
    args.push(config.wallet);
  }
  
  if (config.account) {
    args.push('--account');
    args.push(config.account);
  }

  console.log(chalk.cyan(`Running synchronizer "${syncName}" with wallet ${config.wallet || '[none]'}`));
  
  // For debugging
  console.log(chalk.gray(`Running command: ${dockerCmd} ${args.join(' ')}`));
  
  const proc = spawn(dockerCmd, args, { stdio: 'inherit' });
  
  // Handle Ctrl+C to stop the container
  const cleanup = () => {
    console.log(chalk.yellow('\n🛑 Stopping synchronizer container...'));
    try {
      execSync(`docker stop ${containerName}`, { stdio: 'pipe' });
      console.log(chalk.green('✅ Container stopped'));
    } catch (error) {
      console.log(chalk.red('❌ Error stopping container:', error.message));
    }
    process.exit(0);
  };
  
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  
  proc.on('error', (err) => {
    if (err.code === 'ENOENT') {
      console.error(chalk.red('Docker command not found. Please ensure Docker is installed and in your PATH.'));
    } else {
      console.error(chalk.red('Error running Docker:'), err.message);
    }
    process.exit(1);
  });
  
  proc.on('exit', code => {
    if (code === 126) {
      console.error(chalk.red('❌ Docker permission denied.'));
      console.error(chalk.yellow('This usually means your user is not in the docker group.'));
      console.error(chalk.blue('\n🔧 To fix this:'));
      console.error(chalk.white('1. Add your user to the docker group:'));
      console.error(chalk.gray(`   sudo usermod -aG docker ${os.userInfo().username}`));
      console.error(chalk.white('2. Log out and log back in (or restart your terminal)'));
      console.error(chalk.white('3. Test with: docker run hello-world'));
      console.error(chalk.blue('\n💡 Alternative: Run with sudo (not recommended):'));
      console.error(chalk.gray('   sudo synchronize start'));
      console.error(chalk.blue('\n🔧 Or use the fix command:'));
      console.error(chalk.gray('   synchronize fix-docker'));
    } else if (code === 125) {
      console.error(chalk.red('❌ Docker container failed to start.'));
      console.error(chalk.yellow('This might be due to platform architecture issues.'));
      console.error(chalk.blue('\n🔧 Troubleshooting steps:'));
      console.error(chalk.gray('1. Test platform compatibility:'));
      console.error(chalk.gray('   synchronize test-platform'));
      console.error(chalk.gray('2. Check Docker logs:'));
      console.error(chalk.gray('   docker logs synchronizer-cli'));
      console.error(chalk.gray('3. Try running with different platform:'));
      console.error(chalk.gray('   docker run --platform linux/amd64 cdrakep/synqchronizer:latest --help'));
    } else if (code !== 0) {
      console.error(chalk.red(`Docker process exited with code ${code}`));
    }
    process.exit(code);
  });
}


/**
 * Generate systemd service file and environment file for headless operation.
 */
async function installService() {
  const config = loadConfig();
  if (!config.key) {
    console.error(chalk.red('Missing synq key. Run `synchronize init` first.'));
    process.exit(1);
  }
  if (!config.wallet && !config.account) {
    console.error(chalk.red('Missing wallet or account. Run `synchronize init` first.'));
    process.exit(1);
  }

  const serviceFile = path.join(CONFIG_DIR, 'synchronizer-cli.service');
  const user = os.userInfo().username;

  // Detect platform architecture (same logic as start function)
  const arch = os.arch();
  const platform = os.platform();
  let dockerPlatform = 'linux/amd64'; // Default to amd64
  
  if (platform === 'linux') {
    if (arch === 'arm64' || arch === 'aarch64') {
      dockerPlatform = 'linux/arm64';
    } else if (arch === 'x64' || arch === 'x86_64') {
      dockerPlatform = 'linux/amd64';
    }
  } else if (platform === 'darwin') {
    dockerPlatform = arch === 'arm64' ? 'linux/arm64' : 'linux/amd64';
  }

  // Detect Docker path for PATH environment
  let dockerPath = '/usr/bin/docker';
  try {
    const dockerWhich = execSync('which docker', { encoding: 'utf8', stdio: 'pipe' }).trim();
    if (dockerWhich && fs.existsSync(dockerWhich)) {
      dockerPath = dockerWhich;
    }
  } catch (error) {
    // Use default path
  }
  
  const dockerDir = path.dirname(dockerPath);
  
  // Build PATH environment variable including docker directory
  const systemPaths = [
    '/usr/local/sbin',
    '/usr/local/bin', 
    '/usr/sbin',
    '/usr/bin',
    '/sbin',
    '/bin'
  ];
  
  // Add docker directory to the beginning of PATH if it's not already a system path
  const pathDirs = systemPaths.includes(dockerDir) ? systemPaths : [dockerDir, ...systemPaths];
  const pathEnv = pathDirs.join(':');

  // Get dynamic version info for service launcher
  let dockerImageVersion = 'latest';
  try {
    // Try to get the version from the main image
    const imageName = 'cdrakep/synqchronizer:latest';
    const imageInspectOutput = execSync(`docker inspect ${imageName} --format "{{json .Config.Labels}}"`, {
      encoding: 'utf8',
      stdio: 'pipe'
    });
    
    const labels = JSON.parse(imageInspectOutput);
    if (labels && labels.version) {
      dockerImageVersion = labels.version;
    } else {
      // Get image creation date as fallback
      const createdOutput = execSync(`docker inspect ${imageName} --format "{{.Created}}"`, {
        encoding: 'utf8',
        stdio: 'pipe'
      });
      const created = new Date(createdOutput.trim());
      dockerImageVersion = `${created.toISOString().split('T')[0]}`;
    }
  } catch (error) {
    // Use latest as fallback
    dockerImageVersion = 'latest';
  }

  // Set launcher with dynamic version
  const launcherWithVersion = `cli-${packageJson.version}/docker-${dockerImageVersion}`;
  console.log(chalk.cyan(`Using launcher identifier: ${launcherWithVersion}`));

  // No need to check for image updates here - the service will use --pull always
  
  // Build the exact same command as the start function
  const dockerArgs = [
    'run', '--rm', '--name', 'synchronizer-cli',
    '--pull', 'always', // Always try to pull the latest image
    '--platform', dockerPlatform,
    'cdrakep/synqchronizer:latest',
    '--depin', config.depin || 'wss://api.multisynq.io/depin',
    '--sync-name', config.syncHash,
    '--launcher', launcherWithVersion,
    '--key', config.key,
    ...(config.wallet ? ['--wallet', config.wallet] : []),
    ...(config.account ? ['--account', config.account] : [])
  ].join(' ');

  const unit = `[Unit]
Description=Multisynq Synchronizer headless service
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=${user}
Restart=always
RestartSec=10
ExecStart=${dockerPath} ${dockerArgs}
Environment=PATH=${pathEnv}

[Install]
WantedBy=multi-user.target
`;

  fs.writeFileSync(serviceFile, unit);
  console.log(chalk.green('Systemd service file written to'), serviceFile);
  console.log(chalk.blue(`To install the service, run:
  sudo cp ${serviceFile} /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable synchronizer-cli
  sudo systemctl start synchronizer-cli`));
  
  console.log(chalk.cyan('\n📋 Service will run with the following configuration:'));
  console.log(chalk.gray(`Platform: ${dockerPlatform}`));
  console.log(chalk.gray(`Docker Path: ${dockerPath}`));
  console.log(chalk.gray(`PATH: ${pathEnv}`));
  console.log(chalk.gray(`DePIN: ${config.depin || 'wss://api.multisynq.io/depin'}`));
  console.log(chalk.gray(`Sync Name: ${config.syncHash}`));
  console.log(chalk.gray(`Wallet: ${config.wallet || '[none]'}`));
  console.log(chalk.gray(`Account: ${config.account || '[none]'}`));
}

async function fixDockerPermissions() {
  console.log(chalk.blue('🔧 Docker Permissions Fix'));
  console.log(chalk.yellow('This will add your user to the docker group.\n'));

  const username = os.userInfo().username;
  
  try {
    console.log(chalk.cyan(`Adding user "${username}" to docker group...`));
    execSync(`sudo usermod -aG docker ${username}`, { stdio: 'inherit' });
    
    console.log(chalk.green('✅ User added to docker group successfully!'));
    console.log(chalk.yellow('⚠️  You need to log out and log back in for changes to take effect.'));
    console.log(chalk.blue('\n🧪 To test after logging back in:'));
    console.log(chalk.gray('   docker run hello-world'));
    console.log(chalk.gray('   synchronize start'));
    
  } catch (error) {
    console.error(chalk.red('❌ Failed to add user to docker group.'));
    console.error(chalk.red('Error:', error.message));
    console.error(chalk.blue('\n📖 Manual steps:'));
    console.error(chalk.gray(`   sudo usermod -aG docker ${username}`));
    console.error(chalk.gray('   # Then log out and log back in'));
  }
}

async function testPlatform() {
  console.log(chalk.blue('🔍 Platform Compatibility Test'));
  console.log(chalk.yellow('Testing Docker platform compatibility...\n'));

  const arch = os.arch();
  const platform = os.platform();
  
  console.log(chalk.cyan(`Host System: ${platform}/${arch}`));
  
  // Test Docker availability
  if (!checkDocker()) {
    console.error(chalk.red('❌ Docker is not available'));
    return;
  }
  
  console.log(chalk.green('✅ Docker is available'));
  
  // Test both platforms and fallback
  const tests = [
    { name: 'linux/amd64', args: ['--platform', 'linux/amd64'] },
    { name: 'linux/arm64', args: ['--platform', 'linux/arm64'] },
    { name: 'no platform flag', args: [] }
  ];
  
  let workingPlatforms = [];
  
  for (const test of tests) {
    console.log(chalk.blue(`\nTesting ${test.name}...`));
    
    try {
      const args = [
        'run', '--rm',
        ...test.args,
        'cdrakep/synqchronizer:latest',
        '--help'
      ];
      
      const result = execSync(`docker ${args.join(' ')}`, { 
        encoding: 'utf8', 
        timeout: 30000,
        stdio: 'pipe'
      });
      
      if (result.includes('Usage:') || result.includes('--help')) {
        console.log(chalk.green(`✅ ${test.name} works`));
        workingPlatforms.push(test.name);
      } else {
        console.log(chalk.yellow(`⚠️  ${test.name} responded but output unexpected`));
      }
    } catch (error) {
      const errorMsg = error.message.split('\n')[0];
      console.log(chalk.red(`❌ ${test.name} failed: ${errorMsg}`));
    }
  }
  
  // Recommend best platform
  let recommendedPlatform = 'linux/amd64';
  if (arch === 'arm64' || arch === 'aarch64') {
    recommendedPlatform = 'linux/arm64';
  }
  
  console.log(chalk.blue(`\n💡 Recommended platform for your system: ${recommendedPlatform}`));
  
  if (workingPlatforms.length === 0) {
    console.log(chalk.red('\n❌ No platforms are working!'));
    console.log(chalk.yellow('This suggests the Docker image may not support your architecture.'));
    console.log(chalk.blue('\n🔧 Troubleshooting steps:'));
    console.log(chalk.gray('1. Check what platforms the image supports:'));
    console.log(chalk.gray('   docker manifest inspect cdrakep/synqchronizer:latest'));
    console.log(chalk.gray('2. Try pulling the image manually:'));
    console.log(chalk.gray('   docker pull cdrakep/synqchronizer:latest'));
    console.log(chalk.gray('3. Check if there are architecture-specific tags:'));
    console.log(chalk.gray('   docker search cdrakep/synqchronizer'));
    console.log(chalk.gray('4. Contact the image maintainer for multi-arch support'));
  } else {
    console.log(chalk.green(`\n✅ Working platforms: ${workingPlatforms.join(', ')}`));
    console.log(chalk.gray('synchronize start will try these platforms automatically'));
  }
}

async function showStatus() {
  console.log(chalk.blue('🔍 synchronizer Service Status'));
  console.log(chalk.yellow('Checking systemd service status...\n'));

  try {
    // Check if service file exists
    const serviceExists = fs.existsSync('/etc/systemd/system/synchronizer-cli.service');
    
    if (!serviceExists) {
      console.log(chalk.yellow('⚠️  Systemd service not installed'));
      console.log(chalk.gray('Run `synchronize service` to generate the service file'));
      return;
    }

    console.log(chalk.green('✅ Service file exists: /etc/systemd/system/synchronizer-cli.service'));

    // Get service status
    try {
      const statusOutput = execSync('systemctl status synchronizer-cli --no-pager', { 
        encoding: 'utf8',
        stdio: 'pipe'
      });
      
      // Parse status for key information
      const lines = statusOutput.split('\n');
      const statusLine = lines.find(line => line.includes('Active:'));
      const loadedLine = lines.find(line => line.includes('Loaded:'));
      
      if (statusLine) {
        if (statusLine.includes('active (running)')) {
          console.log(chalk.green('🟢 Status: Running'));
        } else if (statusLine.includes('inactive (dead)')) {
          console.log(chalk.red('🔴 Status: Stopped'));
        } else if (statusLine.includes('failed')) {
          console.log(chalk.red('❌ Status: Failed'));
        } else {
          console.log(chalk.yellow('🟡 Status: Unknown'));
        }
      }

      if (loadedLine && loadedLine.includes('enabled')) {
        console.log(chalk.green('✅ Auto-start: Enabled'));
      } else {
        console.log(chalk.yellow('⚠️  Auto-start: Disabled'));
      }

    } catch (error) {
      console.log(chalk.red('❌ Service status: Not found or error'));
      console.log(chalk.gray('The service may not be installed or you may need sudo access'));
    }

    // Show recent logs
    console.log(chalk.blue('\n📋 Recent Logs (last 10 lines):'));
    console.log(chalk.gray('─'.repeat(60)));
    
    try {
      const logsOutput = execSync('journalctl -u synchronizer-cli --no-pager -n 10', { 
        encoding: 'utf8',
        stdio: 'pipe'
      });
      
      if (logsOutput.trim()) {
        // Color-code log levels
        const coloredLogs = logsOutput
          .split('\n')
          .map(line => {
            if (line.includes('"level":"error"') || line.includes('ERROR')) {
              return chalk.red(line);
            } else if (line.includes('"level":"warn"') || line.includes('WARNING')) {
              return chalk.yellow(line);
            } else if (line.includes('"level":"info"') || line.includes('INFO')) {
              return chalk.cyan(line);
            } else if (line.includes('"level":"debug"') || line.includes('DEBUG')) {
              return chalk.gray(line);
            } else if (line.includes('proxy-connected') || line.includes('registered')) {
              return chalk.green(line);
            } else {
              return line;
            }
          })
          .join('\n');
        
        console.log(coloredLogs);
      } else {
        console.log(chalk.gray('No recent logs found'));
      }
    } catch (error) {
      console.log(chalk.red('❌ Could not retrieve logs'));
      console.log(chalk.gray('You may need sudo access to view systemd logs'));
    }

    // Show helpful commands
    console.log(chalk.blue('\n🛠️  Useful Commands:'));
    console.log(chalk.gray('  Start service:    sudo systemctl start synchronizer-cli'));
    console.log(chalk.gray('  Stop service:     sudo systemctl stop synchronizer-cli'));
    console.log(chalk.gray('  Restart service:  sudo systemctl restart synchronizer-cli'));
    console.log(chalk.gray('  Enable auto-start: sudo systemctl enable synchronizer-cli'));
    console.log(chalk.gray('  View live logs:   journalctl -u synchronizer-cli -f'));
    console.log(chalk.gray('  View all logs:    journalctl -u synchronizer-cli'));

    // Check if running as manual process
    try {
      const dockerPs = execSync('docker ps --filter name=synchronizer-cli --format "table {{.Names}}\\t{{.Status}}"', {
        encoding: 'utf8',
        stdio: 'pipe'
      });
      
      if (dockerPs.includes('synchronizer-cli')) {
        console.log(chalk.yellow('\n⚠️  Manual synchronizer process also detected!'));
        console.log(chalk.gray('You may have both service and manual process running'));
        console.log(chalk.gray('Consider stopping one to avoid conflicts'));
      }
    } catch (error) {
      // Docker not available or no containers running
    }

  } catch (error) {
    console.error(chalk.red('❌ Error checking service status:'), error.message);
  }
}

/**
 * Get the primary local IP address, filtering out virtual adapters and loopback interfaces
 * Works across Windows, Mac, and Linux
 * @returns {string} The primary local IP address or 'localhost' as fallback
 */
function getPrimaryLocalIP() {
  const interfaces = os.networkInterfaces();
  
  // Priority order for interface types (prefer physical over virtual)
  const interfacePriority = {
    // Physical interfaces (highest priority)
    'eth': 100,     // Ethernet (Linux)
    'en': 90,       // Ethernet (macOS)
    'Ethernet': 80, // Ethernet (Windows)
    'Wi-Fi': 70,    // WiFi (Windows)
    'wlan': 60,     // WiFi (Linux)
    'wlp': 55,      // WiFi (Linux - newer naming)
    
    // Virtual interfaces (lower priority)
    'docker': 10,   // Docker interfaces
    'veth': 10,     // Virtual Ethernet
    'br-': 10,      // Bridge interfaces
    'virbr': 10,    // Virtual bridge
    'vmnet': 10,    // VMware
    'vbox': 10,     // VirtualBox
    'tun': 10,      // Tunnel interfaces
    'tap': 10,      // TAP interfaces
    'utun': 10,     // User tunnel (macOS)
    'awdl': 10,     // Apple Wireless Direct Link
    'llw': 10,      // Low Latency WLAN (macOS)
    'bridge': 10,   // Bridge interfaces
    'vnic': 10,     // Virtual NIC
    'Hyper-V': 10,  // Hyper-V (Windows)
    'VirtualBox': 10, // VirtualBox (Windows)
    'VMware': 10,   // VMware (Windows)
    'Loopback': 5,  // Loopback (Windows)
    'lo': 5         // Loopback (Linux/macOS)
  };
  
  const candidates = [];
  
  for (const [interfaceName, addresses] of Object.entries(interfaces)) {
    // Skip loopback interfaces
    if (interfaceName === 'lo' || interfaceName.includes('Loopback')) {
      continue;
    }
    
    for (const addr of addresses) {
      // Only consider IPv4 addresses that are not internal (loopback)
      if (addr.family === 'IPv4' && !addr.internal) {
        // Calculate priority based on interface name
        let priority = 1; // Default low priority
        
        for (const [pattern, score] of Object.entries(interfacePriority)) {
          if (interfaceName.toLowerCase().startsWith(pattern.toLowerCase()) ||
              interfaceName.toLowerCase().includes(pattern.toLowerCase())) {
            priority = score;
            break;
          }
        }
        
        // Boost priority for common private network ranges
        const ip = addr.address;
        if (ip.startsWith('192.168.') || 
            ip.startsWith('10.') || 
            (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31)) {
          priority += 20; // Prefer private network IPs
        }
        
        // Penalise virtual/container networks
        if (interfaceName.toLowerCase().includes('docker') ||
            interfaceName.toLowerCase().includes('veth') ||
            interfaceName.toLowerCase().includes('br-') ||
            interfaceName.toLowerCase().includes('virbr') ||
            ip.startsWith('172.17.') ||  // Default Docker network
            ip.startsWith('172.18.') ||  // Docker networks
            ip.startsWith('172.19.') ||
            ip.startsWith('172.20.') ||
            ip.startsWith('169.254.')) { // Link-local
          priority -= 50;
        }
        
        candidates.push({
          ip: ip,
          interface: interfaceName,
          priority: priority,
          mac: addr.mac
        });
      }
    }
  }
  
  // Sort by priority (highest first) and return the best candidate
  candidates.sort((a, b) => b.priority - a.priority);
  
  if (candidates.length > 0) {
    const best = candidates[0];
    console.log(chalk.gray(`🌐 Detected primary IP: ${best.ip} (${best.interface})`));
    
    // Log other candidates for debugging if needed
    if (candidates.length > 1) {
      console.log(chalk.gray(`   Other interfaces: ${candidates.slice(1, 3).map(c => `${c.ip} (${c.interface})`).join(', ')}`));
    }
    
    return best.ip;
  }
  
  console.log(chalk.yellow('⚠️  Could not detect primary IP, using localhost'));
  return 'localhost';
}

async function startWebGUI(options = {}) {
  console.log(chalk.blue('🌐 Starting synchronizer Web GUI'));
  console.log(chalk.yellow('Setting up web dashboard and metrics endpoints...\n'));

  const config = loadConfig();
  
  if (config.dashboardPassword) {
    console.log(chalk.green('🔒 Dashboard password protection enabled'));
  } else {
    console.log(chalk.yellow('⚠️  Dashboard is unprotected - consider setting a password'));
  }
  
  // Get the primary local IP address
  const primaryIP = getPrimaryLocalIP();
  
  // Use custom ports if provided, otherwise find available ports
  let guiPort, metricsPort;
  
  if (options.port && options.metricsPort) {
    // Both ports provided - validate they don't conflict
    guiPort = options.port;
    metricsPort = options.metricsPort;
    console.log(chalk.cyan(`📌 Using custom dashboard port: ${guiPort}`));
    console.log(chalk.cyan(`📌 Using custom metrics port: ${metricsPort}`));
    
    if (guiPort === metricsPort) {
      console.error(chalk.red('❌ Error: Dashboard and metrics ports cannot be the same'));
      console.log(chalk.gray('   Use different values for --port and --metrics-port'));
      process.exit(1);
    }
  } else if (options.port) {
    // Only dashboard port provided
    guiPort = options.port;
    console.log(chalk.cyan(`📌 Using custom dashboard port: ${guiPort}`));
    console.log(chalk.gray('🔍 Finding available port for metrics...'));
    metricsPort = await findAvailablePort(guiPort + 1);
    console.log(chalk.green(`✅ Found metrics port: ${metricsPort}`));
  } else if (options.metricsPort) {
    // Only metrics port provided
    metricsPort = options.metricsPort;
    console.log(chalk.cyan(`📌 Using custom metrics port: ${metricsPort}`));
    console.log(chalk.gray('🔍 Finding available port for dashboard...'));
    guiPort = await findAvailablePort(3000);
    if (guiPort === metricsPort) {
      // If we found the same port, find a different one
      guiPort = await findAvailablePort(metricsPort === 3000 ? 3001 : 3000);
    }
    if (guiPort !== 3000) {
      console.log(chalk.yellow(`⚠️  Port 3000 was busy, using port ${guiPort} for dashboard`));
    }
  } else {
    // No custom ports - find both automatically
    console.log(chalk.gray('🔍 Finding available ports for dashboard and metrics...'));
    
    // Find dashboard port first
    guiPort = await findAvailablePort(3000);
    if (guiPort !== 3000) {
      console.log(chalk.yellow(`⚠️  Port 3000 was busy, using port ${guiPort} for dashboard`));
    }
    
    // Find metrics port, starting from guiPort + 1
    metricsPort = await findAvailablePort(guiPort + 1);
    const expectedMetricsPort = guiPort === 3000 ? 3001 : guiPort + 1;
    if (metricsPort !== expectedMetricsPort) {
      console.log(chalk.yellow(`⚠️  Port ${expectedMetricsPort} was busy, using port ${metricsPort} for metrics`));
    }
  }
  
  // Final validation
  if (guiPort === metricsPort) {
    console.error(chalk.red('❌ Error: Dashboard and metrics ports cannot be the same'));
    console.log(chalk.gray('   This should not happen - please report this as a bug'));
    process.exit(1);
  }
  
  console.log(chalk.blue(`🎯 Dashboard will use port ${guiPort}, metrics will use port ${metricsPort}`));
  
  // Initialize the global WebSocket connection ONCE when web server starts
  console.log(chalk.blue('🔌 Starting global WebSocket initialization...'));
  await initializeGlobalWebSocket();
  
  // Create Express apps
  const guiApp = express();
  const metricsApp = express();
  
  // Add authentication middleware to GUI app
  guiApp.use(authenticateRequest);
  
  // GUI Dashboard
  guiApp.get('/', async (req, res) => {
    const versionInfo = await getVersionInfo();
    const html = generateDashboardHTML(config, metricsPort, req.authenticated, primaryIP, versionInfo);
    res.send(html);
  });
  
  guiApp.get('/api/status', async (req, res) => {
    const status = await getSystemStatus(config);
    res.json(status);
  });
  
  guiApp.get('/api/versions', async (req, res) => {
    const versions = await getVersionInfo();
    res.json({
      timestamp: new Date().toISOString(),
      versions
    });
  });
  
  guiApp.get('/api/logs', async (req, res) => {
    const logs = await getRecentLogs();
    res.json({ logs });
  });
  
  guiApp.get('/api/performance', async (req, res) => {
    const performance = await getPerformanceData(config);
    res.json(performance);
  });
  
  guiApp.get('/api/points', async (req, res) => {
    const points = await getPointsData(config);
    res.json(points);
  });
  
  guiApp.post('/api/install-web-service', async (req, res) => {
    try {
      const result = await installWebServiceFile();
      res.json(result);
    } catch (error) {
      res.json({ success: false, error: error.message });
    }
  });
  
  guiApp.get('/api/check-updates', async (req, res) => {
    try {
      const images = [
        'cdrakep/synqchronizer:latest',
        'cdrakep/synqchronizer-test-fixed:latest'
      ];
      
      const updateStatus = [];
      let totalUpdates = 0;
      
      for (const imageName of images) {
        try {
          const hasUpdate = await isNewDockerImageAvailable(imageName);
          updateStatus.push({
            name: imageName,
            updateAvailable: hasUpdate,
            checked: true
          });
          if (hasUpdate) totalUpdates++;
        } catch (error) {
          updateStatus.push({
            name: imageName,
            updateAvailable: false,
            checked: false,
            error: error.message
          });
        }
      }
      
      res.json({
        success: true,
        totalUpdates,
        images: updateStatus,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.json({ success: false, error: error.message });
    }
  });
  
  guiApp.post('/api/pull-image', async (req, res) => {
    try {
      const { imageName } = req.body;
      
      if (!imageName) {
        return res.json({ success: false, error: 'Image name is required' });
      }
      
      // Security check - only allow known synchronizer images
      const allowedImages = [
        'cdrakep/synqchronizer:latest',
        'cdrakep/synqchronizer-test-fixed:latest'
      ];
      
      if (!allowedImages.includes(imageName)) {
        return res.json({ success: false, error: 'Image not allowed' });
      }
      
      execSync(`docker pull ${imageName}`, { stdio: 'pipe' });
      res.json({ 
        success: true, 
        message: `Successfully pulled ${imageName}`,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.json({ success: false, error: error.message });
    }
  });
  
  guiApp.post('/api/test-websocket', async (req, res) => {
    try {
      const { timeout = 10, quiet = true } = req.body;
      
      console.log(chalk.blue('🧪 Running WebSocket test from web dashboard...'));
      
      const result = await runWebSocketTest(timeout * 1000, quiet);
      
      res.json({
        success: true,
        timestamp: new Date().toISOString(),
        test: {
          ...result,
          timeout: timeout,
          connectionUrl: 'ws://localhost:3333'
        }
      });
    } catch (error) {
      res.json({ 
        success: false, 
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  });
  
  guiApp.get('/api/websocket-status', async (req, res) => {
    try {
      // Quick check of WebSocket connectivity without full test
      const wsStatus = {
        timestamp: new Date().toISOString(),
        containerRunning: false,
        portExposed: false,
        canConnect: false,
        lastTestResult: null
      };
      
      // Check if container is running
      try {
        const psOutput = execSync('docker ps --filter name=synchronizer --format "{{.Names}}"', {
          encoding: 'utf8',
          stdio: 'pipe'
        });
        
        if (psOutput.trim()) {
          wsStatus.containerRunning = true;
          wsStatus.containerName = psOutput.trim();
          
          // Check if port 3333 is exposed
          try {
            const portOutput = execSync(`docker port ${psOutput.trim()} 3333`, {
              encoding: 'utf8',
              stdio: 'pipe'
            });
            
            if (portOutput.includes('3333')) {
              wsStatus.portExposed = true;
              wsStatus.exposedPort = portOutput.trim();
            }
          } catch (portError) {
            // Port not exposed
          }
        }
      } catch (containerError) {
        // Container not running
      }
      
      res.json(wsStatus);
    } catch (error) {
      res.json({ 
        success: false, 
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  });
  
  // Metrics endpoint (no auth required for monitoring)
  metricsApp.get('/metrics', async (req, res) => {
    const metrics = await generateMetrics(config);
    res.json(metrics);
  });
  
  metricsApp.get('/health', async (req, res) => {
    const health = await getHealthStatus();
    res.json(health);
  });
  
  // Start servers sequentially to avoid race conditions
  return new Promise((resolve, reject) => {
    // Start dashboard server first
    const guiServer = guiApp.listen(guiPort, '0.0.0.0', () => {
      console.log(chalk.green(`🎨 Web Dashboard: http://${primaryIP}:${guiPort}`));
      if (config.dashboardPassword) {
        console.log(chalk.gray('   Use any username with your configured password to access'));
      }
      
      // Only start metrics server after dashboard is successfully listening
      const metricsServer = metricsApp.listen(metricsPort, '0.0.0.0', () => {
        console.log(chalk.green(`📊 Metrics API: http://${primaryIP}:${metricsPort}/metrics`));
        console.log(chalk.green(`❤️  Health Check: http://${primaryIP}:${metricsPort}/health`));
        
        // Show local URLs in a separate section if not localhost
        if (primaryIP !== 'localhost') {
          console.log(chalk.blue('\n📍 Local Access:'));
          console.log(chalk.gray(`   Dashboard: http://localhost:${guiPort}`));
          console.log(chalk.gray(`   Metrics: http://localhost:${metricsPort}/metrics`));
          console.log(chalk.gray(`   Health: http://localhost:${metricsPort}/health`));
        }
        
        console.log(chalk.blue('\n🔄 Auto-refresh dashboard every 5 seconds'));
        console.log(chalk.gray('Press Ctrl+C to stop the web servers\n'));
        
        // Set up graceful shutdown for both servers
        const shutdown = () => {
          console.log(chalk.yellow('\n🛑 Shutting down web servers...'));
          clearUsedPorts(); // Clear used ports so they can be reused
          guiServer.close();
          metricsServer.close();
          process.exit(0);
        };
        
        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
        
        // Keep the process alive
        setInterval(() => {
          // Just keep alive, servers handle requests
        }, 5000);
        
        resolve({ guiServer, metricsServer });
      });
      
      metricsServer.on('error', (err) => {
        console.error(chalk.red('❌ Failed to start metrics server:'), err.message);
        if (err.code === 'EADDRINUSE') {
          console.error(chalk.yellow(`   Port ${metricsPort} is already in use. Try stopping other services or use custom ports:`));
          console.error(chalk.gray(`   synchronize web --port ${guiPort} --metrics-port ${metricsPort + 1}`));
        }
        guiServer.close();
        reject(err);
      });
    });
    
    guiServer.on('error', (err) => {
      console.error(chalk.red('❌ Failed to start dashboard server:'), err.message);
      if (err.code === 'EADDRINUSE') {
        console.error(chalk.yellow(`   Port ${guiPort} is already in use. Try stopping other services or use custom ports:`));
        console.error(chalk.gray(`   synchronize web --port ${guiPort + 1} --metrics-port ${metricsPort + 1}`));
      }
      reject(err);
    });
  });
}

// Track ports being used to prevent race conditions
const usedPorts = new Set();

// Clear used ports when servers shut down
function clearUsedPorts() {
  usedPorts.clear();
}

async function findAvailablePort(startPort) {
  const net = require('net');
  
  return new Promise((resolve, reject) => {
    // Limit the search to prevent infinite loops
    const maxAttempts = 100;
    let attempts = 0;
    
    function tryPort(port) {
      if (attempts >= maxAttempts) {
        reject(new Error(`Could not find available port after ${maxAttempts} attempts starting from ${startPort}`));
        return;
      }
      
      attempts++;
      
      // Create a new server for testing
      const testServer = net.createServer();
      
      testServer.on('error', (err) => {
        if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
          // Port is busy, try the next one
          tryPort(port + 1);
        } else {
          // Other error, try next port anyway
          tryPort(port + 1);
        }
      });
      
      testServer.on('listening', () => {
        const actualPort = testServer.address().port;
        testServer.close(() => {
          resolve(actualPort);
        });
      });
      
      // Test the port
      testServer.listen(port, '0.0.0.0');
    }
    
    tryPort(startPort);
  });
}

function generateDashboardHTML(config, metricsPort, authenticated, primaryIP, versions = null) {
  // Determine if we should show sensitive data
  const showSensitiveData = !config.dashboardPassword || authenticated;
  const maskedKey = showSensitiveData ? config.key : '••••••••-••••-••••-••••-••••••••••••';
  const maskedWallet = showSensitiveData ? config.wallet : '0x••••••••••••••••••••••••••••••••••••••••';
  
  // Use primaryIP for display, fallback to localhost if not provided
  const displayIP = primaryIP || 'localhost';
  
  // Use dynamic versions if provided, otherwise fall back to defaults
  const versionInfo = versions || {
    cli: packageJson.version,
    dockerImage: 'Unknown',
    containerImage: 'Unknown',
    reflectorVersion: 'Unknown',
    launcher: 'Unknown'
  };
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Synchronizer Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.8; font-size: 1.1em; }
        .top-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }
        .performance-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-bottom: 20px; }
        .points-section { width: 100%; margin-bottom: 20px; }
        .card { 
            background: rgba(255,255,255,0.1); 
            backdrop-filter: blur(10px);
            border-radius: 15px; 
            padding: 25px; 
            border: 1px solid rgba(255,255,255,0.2);
        }
        .card h3 { margin-bottom: 15px; font-size: 1.3em; }
        .status-indicator { 
            display: inline-block; 
            width: 12px; 
            height: 12px; 
            border-radius: 50%; 
            margin-right: 8px; 
        }
        .status-running { background: #4ade80; }
        .status-stopped { background: #ef4444; }
        .status-unknown { background: #fbbf24; }
        .metric { margin: 10px 0; }
        .metric-label { opacity: 0.8; }
        .metric-value { font-weight: bold; font-size: 1.1em; }
        .logs { 
            background: rgba(0,0,0,0.3); 
            padding: 15px; 
            border-radius: 8px; 
            font-family: 'Courier New', monospace; 
            font-size: 0.9em;
            max-height: 400px;
            overflow-y: auto;
        }
        .log-line { margin: 2px 0; }
        .log-error { color: #fca5a5; }
        .log-warn { color: #fde047; }
        .log-info { color: #93c5fd; }
        .log-success { color: #86efac; }
        .refresh-info { text-align: center; margin-top: 20px; opacity: 0.7; }
        .config-item { margin: 8px 0; }
        .config-label { opacity: 0.8; display: inline-block; width: 120px; }
        .config-value { font-weight: bold; }
        .action-button {
            background: rgba(255,255,255,0.2); 
            border: none; 
            color: white; 
            padding: 10px 15px; 
            border-radius: 8px; 
            margin: 5px; 
            cursor: pointer;
            transition: background 0.2s;
        }
        .action-button:hover {
            background: rgba(255,255,255,0.3);
        }
        .performance-metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 12px 0;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .performance-metric:last-child {
            border-bottom: none;
        }
        .performance-label {
            opacity: 0.8;
            font-size: 0.9em;
        }
        .performance-value {
            font-weight: bold;
            font-size: 1.1em;
        }
        .qos-score {
            text-align: center;
            margin: 20px 0;
        }
        .qos-circle {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            margin: 0 auto 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5em;
            font-weight: bold;
            position: relative;
        }
        .qos-excellent { background: conic-gradient(#4ade80 0deg 360deg, rgba(255,255,255,0.2) 360deg); }
        .qos-good { background: conic-gradient(#fbbf24 0deg 270deg, rgba(255,255,255,0.2) 270deg); }
        .qos-poor { background: conic-gradient(#ef4444 0deg 108deg, rgba(255,255,255,0.2) 108deg); }
        .qos-status {
            display: flex;
            justify-content: space-between;
            margin: 8px 0;
            font-size: 0.9em;
        }
        .qos-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 6px;
        }
        .status-excellent { background: #4ade80; }
        .status-good { background: #fbbf24; }
        .status-poor { background: #ef4444; }
        .api-section { width: 100%; margin-bottom: 20px; }
        .api-endpoints { display: flex; flex-direction: column; gap: 12px; }
        .api-endpoint {
            display: flex;
            align-items: center;
            padding: 12px;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            border-left: 3px solid rgba(255,255,255,0.3);
        }
        .api-method {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            min-width: 50px;
            text-align: center;
            margin-right: 12px;
        }
        .api-path {
            font-family: 'Courier New', monospace;
            color: #93c5fd;
            font-weight: bold;
            margin-right: 12px;
            min-width: 200px;
        }
        .api-desc {
            opacity: 0.8;
            font-size: 0.9em;
        }
        .points-section { width: 100%; margin-bottom: 20px; }
        .logs-section { width: 100%; }
        .points-display {
            display: flex;
            justify-content: space-around;
            align-items: center;
            margin: 20px 0;
        }
        .points-total {
            text-align: center;
        }
        .points-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #fbbf24;
            text-shadow: 0 0 10px rgba(251, 191, 36, 0.3);
        }
        .points-label {
            opacity: 0.8;
            margin-top: 5px;
            font-size: 0.9em;
        }
        .points-breakdown {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .points-item {
            background: rgba(255,255,255,0.05);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border-left: 3px solid #fbbf24;
        }
        .points-item-value {
            font-size: 1.4em;
            font-weight: bold;
            color: #fbbf24;
        }
        .points-item-label {
            opacity: 0.8;
            font-size: 0.8em;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Synchronizer Dashboard</h1>
            <p>Real-time monitoring and status</p>
        </div>
        
        <div class="top-grid">
            <div class="card">
                <h3>📊 System Status</h3>
                <div id="status-content">Loading...</div>
            </div>
            
            <div class="card">
                <h3>⚙️ Configuration</h3>
                <div class="config-item">
                    <span class="config-label">Sync Name:</span>
                    <span class="config-value">${config.syncHash || 'Not configured'}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Synq Key:</span>
                    <span class="config-value">
                        <span id="synq-key-masked" style="cursor: pointer; user-select: none;" onclick="toggleSynqKey()" title="Click to reveal">
                            ${config.key ? '••••••••-••••-••••-••••-••••••••••••' : 'Not set'}
                        </span>
                        <span id="synq-key-full" style="display: none; cursor: pointer; user-select: none;" onclick="toggleSynqKey()" title="Click to hide">
                            ${config.key || 'Not set'}
                        </span>
                    </span>
                </div>
                <div class="config-item">
                    <span class="config-label">Wallet:</span>
                    <span class="config-value">${config.wallet || 'Not set'}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Hostname:</span>
                    <span class="config-value">${config.hostname || 'Unknown'}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Platform:</span>
                    <span class="config-value">${os.platform()}/${os.arch()}</span>
                </div>
                
                <h4 style="margin-top: 20px; margin-bottom: 10px; opacity: 0.9;">📦 Versions</h4>
                <div class="config-item">
                    <span class="config-label">CLI:</span>
                    <span class="config-value">v${versionInfo.cli}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Docker Image:</span>
                    <span class="config-value">${versionInfo.dockerImage}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Container:</span>
                    <span class="config-value">${versionInfo.containerImage}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Reflector:</span>
                    <span class="config-value">${versionInfo.reflectorVersion}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Launcher:</span>
                    <span class="config-value">${versionInfo.launcher}</span>
                </div>
            </div>
            
            <div class="card">
                <h3>🛠️ Quick Actions</h3>
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <button onclick="window.open('/api/status', '_blank')" class="action-button">View Status JSON</button>
                    <button onclick="openMetrics()" class="action-button">View Metrics</button>
                    <button onclick="refreshData()" class="action-button">🔄 Refresh Now</button>
                    <button onclick="installWebService()" class="action-button">📦 Install Web Service</button>
                </div>
            </div>
        </div>
        
        <div class="performance-grid">
            <div class="card">
                <h3>📈 Performance</h3>
                <div id="performance-content">Loading...</div>
            </div>
            
            <div class="card">
                <h3>🎯 Quality of Service</h3>
                <div id="qos-content">Loading...</div>
            </div>
        </div>
        
        <div class="points-section">
            <div class="card">
                <h3>🏆 Rewards & Points</h3>
                <div id="points-content">Loading...</div>
            </div>
        </div>
        
        <div class="api-section">
            <div class="card">
                <h3>🔗 API Endpoints</h3>
                <div class="api-endpoints">
                    <div class="api-endpoint">
                        <span class="api-method">GET</span>
                        <span class="api-path">/api/status</span>
                        <span class="api-desc">System and service status information</span>
                    </div>
                    <div class="api-endpoint">
                        <span class="api-method">GET</span>
                        <span class="api-path">/api/versions</span>
                        <span class="api-desc">Dynamic version information for all components</span>
                    </div>
                    <div class="api-endpoint">
                        <span class="api-method">GET</span>
                        <span class="api-path">/api/logs</span>
                        <span class="api-desc">Recent systemd service logs</span>
                    </div>
                    <div class="api-endpoint">
                        <span class="api-method">GET</span>
                        <span class="api-path">/api/performance</span>
                        <span class="api-desc">Performance metrics and QoS data</span>
                    </div>
                    <div class="api-endpoint">
                        <span class="api-method">GET</span>
                        <span class="api-path">/api/points</span>
                        <span class="api-desc">Rewards and points data</span>
                    </div>
                    <div class="api-endpoint">
                        <span class="api-method">POST</span>
                        <span class="api-path">/api/install-web-service</span>
                        <span class="api-desc">Generate systemd service for web dashboard</span>
                    </div>
                    <div class="api-endpoint">
                        <span class="api-method">GET</span>
                        <span class="api-path">/api/check-updates</span>
                        <span class="api-desc">Check for Docker image updates</span>
                    </div>
                    <div class="api-endpoint">
                        <span class="api-method">POST</span>
                        <span class="api-path">/api/pull-image</span>
                        <span class="api-desc">Pull latest Docker image (requires imageName in body)</span>
                    </div>
                    <div class="api-endpoint">
                        <span class="api-method">GET</span>
                        <span class="api-path">http://${displayIP}:${metricsPort}/metrics</span>
                        <span class="api-desc">Comprehensive system metrics (JSON)</span>
                    </div>
                    <div class="api-endpoint">
                        <span class="api-method">GET</span>
                        <span class="api-path">http://${displayIP}:${metricsPort}/health</span>
                        <span class="api-desc">Health check endpoint</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="api-section">
            <div class="card">
                <h3>🧪 WebSocket Testing</h3>
                <div id="websocket-status">Loading WebSocket status...</div>
                
                <div style="margin: 20px 0;">
                    <button onclick="runWebSocketTest()" class="action-button" id="test-websocket-btn">🔍 Test WebSocket Connection</button>
                    <button onclick="checkWebSocketStatus()" class="action-button">📊 Check WebSocket Status</button>
                </div>
                
                <div id="websocket-results" style="display: none;">
                    <h4 style="margin: 15px 0 10px 0;">Test Results:</h4>
                    <div id="websocket-test-output" class="logs"></div>
                </div>
            </div>
        </div>
        
        <div class="logs-section">
            <div class="card">
                <h3>📋 Recent Logs</h3>
                <div class="logs" id="logs-content">Loading logs...</div>
            </div>
        </div>
        
        <div class="refresh-info">
            <p>Auto-refreshing every 5 seconds • Last updated: <span id="last-updated">Never</span></p>
        </div>
    </div>

    <script>
        async function fetchStatus() {
            try {
                const response = await fetch('/api/status');
                const status = await response.json();
                updateStatusDisplay(status);
            } catch (error) {
                document.getElementById('status-content').innerHTML = '<span style="color: #fca5a5;">Error loading status</span>';
            }
        }
        
        async function fetchLogs() {
            try {
                const response = await fetch('/api/logs');
                const data = await response.json();
                updateLogsDisplay(data.logs);
            } catch (error) {
                document.getElementById('logs-content').innerHTML = '<span style="color: #fca5a5;">Error loading logs</span>';
            }
        }
        
        async function fetchPerformance() {
            try {
                const response = await fetch('/api/performance');
                const data = await response.json();
                updatePerformanceDisplay(data);
            } catch (error) {
                document.getElementById('performance-content').innerHTML = '<span style="color: #fca5a5;">Error loading performance data</span>';
                document.getElementById('qos-content').innerHTML = '<span style="color: #fca5a5;">Error loading QoS data</span>';
            }
        }
        
        async function fetchPoints() {
            try {
                const response = await fetch('/api/points');
                const data = await response.json();
                updatePointsDisplay(data);
            } catch (error) {
                document.getElementById('points-content').innerHTML = '<span style="color: #fca5a5;">Error loading points data</span>';
            }
        }
        
        function updateStatusDisplay(status) {
            const statusHtml = \`
                <div class="metric">
                    <div class="metric-label">Service Status:</div>
                    <div class="metric-value">
                        <span class="status-indicator status-\${status.serviceStatus === 'running' ? 'running' : status.serviceStatus === 'stopped' ? 'stopped' : 'unknown'}"></span>
                        \${status.serviceStatus || 'Unknown'}
                    </div>
                </div>
                <div class="metric">
                    <div class="metric-label">Docker Status:</div>
                    <div class="metric-value">\${status.dockerAvailable ? '✅ Available' : '❌ Not Available'}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Auto-start:</div>
                    <div class="metric-value">\${status.autoStart ? '✅ Enabled' : '⚠️ Disabled'}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Uptime:</div>
                    <div class="metric-value">\${status.uptime || 'Unknown'}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Image Updates:</div>
                    <div class="metric-value">
                        \${status.imageUpdates ? 
                            (status.imageUpdates.available > 0 ? 
                                \`🔄 \${status.imageUpdates.available} update(s) available\` : 
                                '✅ All images up to date'
                            ) : '❔ Check pending'
                        }
                    </div>
                </div>
                \${status.imageUpdates && status.imageUpdates.lastChecked ? \`
                <div class="metric">
                    <div class="metric-label">Last Checked:</div>
                    <div class="metric-value" style="font-size: 0.9em;">\${new Date(status.imageUpdates.lastChecked).toLocaleTimeString()}</div>
                </div>
                \` : ''}
            \`;
            document.getElementById('status-content').innerHTML = statusHtml;
        }
        
        function updateLogsDisplay(logs) {
            if (!logs || logs.length === 0) {
                document.getElementById('logs-content').innerHTML = '<span style="opacity: 0.6;">No recent logs</span>';
                return;
            }
            
            const logsHtml = logs.map(log => {
                let className = 'log-line';
                if (log.includes('error') || log.includes('ERROR')) className += ' log-error';
                else if (log.includes('warn') || log.includes('WARNING')) className += ' log-warn';
                else if (log.includes('info') || log.includes('INFO')) className += ' log-info';
                else if (log.includes('proxy-connected') || log.includes('registered')) className += ' log-success';
                
                return \`<div class="\${className}">\${log}</div>\`;
            }).join('');
            
            document.getElementById('logs-content').innerHTML = logsHtml;
        }
        
        function updatePerformanceDisplay(data) {
            // Performance metrics
            const performanceHtml = \`
                <div class="performance-metric">
                    <span class="performance-label">Cumulative Traffic:</span>
                    <span class="performance-value">\${formatBytes(data.performance.totalTraffic || 0)}</span>
                </div>
                <div class="performance-metric">
                    <span class="performance-label">Total Sessions:</span>
                    <span class="performance-value">\${data.performance.sessions || '0'}</span>
                </div>
                <div class="performance-metric">
                    <span class="performance-label">Current Users:</span>
                    <span class="performance-value">\${data.performance.users || '0'}</span>
                </div>
                <div class="performance-metric">
                    <span class="performance-label">Demo Sessions:</span>
                    <span class="performance-value">\${data.performance.demoSessions || '0'}</span>
                </div>
                <div class="performance-metric">
                    <span class="performance-label">Bytes In:</span>
                    <span class="performance-value">\${formatBytes(data.performance.bytesIn || 0)}</span>
                </div>
                <div class="performance-metric">
                    <span class="performance-label">Bytes Out:</span>
                    <span class="performance-value">\${formatBytes(data.performance.bytesOut || 0)}</span>
                </div>
                \${data.performance.proxyConnectionState ? \`
                <div class="performance-metric">
                    <span class="performance-label">Connection State:</span>
                    <span class="performance-value" style="color: \${data.performance.proxyConnectionState === 'CONNECTED' ? '#4ade80' : '#fbbf24'}">\${data.performance.proxyConnectionState}</span>
                </div>
                \` : ''}
            \`;
            
            // QoS display with new rating system conversion
            const qos = data.qos || {};
            
            // Convert 0/1/2 rating values to percentage values for display
            // 0 = 100%, 1 = 67%, 2 = 33%
            const convertRatingToPercentage = (rating) => {
                if (rating === 0) return 100;
                if (rating === 1) return 67;
                if (rating === 2) return 33;
                return 0; // fallback for undefined/null
            };
            
            // Get the raw rating values (0, 1, or 2)
            const availabilityRating = qos.availability !== undefined ? qos.availability : 2;
            const reliabilityRating = qos.reliability !== undefined ? qos.reliability : 2;
            const efficiencyRating = qos.efficiency !== undefined ? qos.efficiency : 2;
            
            // Convert to percentages for display
            const availability = convertRatingToPercentage(availabilityRating);
            const reliability = convertRatingToPercentage(reliabilityRating);
            const efficiency = convertRatingToPercentage(efficiencyRating);
            
            // Calculate overall health score using new formula:
            // 40% base + 10% for every amount under 2
            const score = 40 + 10 * ((2 - availabilityRating) + (2 - reliabilityRating) + (2 - efficiencyRating));
            
            let qosClass = 'qos-poor';
            if (score >= 80) {
                qosClass = 'qos-excellent';
            } else if (score >= 60) {
                qosClass = 'qos-good';
            }
            
            // Parse ratingsBlurbs if available
            let ratingsBlurbs = null;
            if (qos.ratingsBlurbs) {
                try {
                    if (typeof qos.ratingsBlurbs === 'string') {
                        ratingsBlurbs = JSON.parse(qos.ratingsBlurbs);
                    } else if (typeof qos.ratingsBlurbs === 'object') {
                        ratingsBlurbs = qos.ratingsBlurbs;
                    }
                } catch (e) {
                    console.log('Error parsing ratingsBlurbs:', e);
                    // If JSON parsing fails, treat as plain text
                    ratingsBlurbs = { general: String(qos.ratingsBlurbs) };
                }
            }
            
            console.log('ratingsBlurbs processed:', ratingsBlurbs); // Debug log
            
            const qosHtml = \`
                <div class="qos-score">
                    <div class="qos-circle \${qosClass}">
                        \${score}%
                    </div>
                    <div style="opacity: 0.8;">Overall Health Score</div>
                </div>
                <div class="qos-status">
                    <span><span class="qos-indicator \${reliability >= 80 ? 'status-excellent' : reliability >= 60 ? 'status-good' : 'status-poor'}"></span>Reliability</span>
                    <span style="font-weight: bold;">\${reliability}%</span>
                </div>
                \${ratingsBlurbs && ratingsBlurbs.reliability ? \`
                <div style="margin: 5px 0 10px 20px; padding: 8px; background: rgba(255,255,255,0.05); border-radius: 4px; font-size: 0.8em; opacity: 0.8; line-height: 1.3;">
                    \${ratingsBlurbs.reliability.replace(/\\n/g, '<br>')}
                </div>
                \` : ''}
                
                <div class="qos-status">
                    <span><span class="qos-indicator \${availability >= 80 ? 'status-excellent' : availability >= 60 ? 'status-good' : 'status-poor'}"></span>Availability</span>
                    <span style="font-weight: bold;">\${availability}%</span>
                </div>
                \${ratingsBlurbs && ratingsBlurbs.availability ? \`
                <div style="margin: 5px 0 10px 20px; padding: 8px; background: rgba(255,255,255,0.05); border-radius: 4px; font-size: 0.8em; opacity: 0.8; line-height: 1.3;">
                    \${ratingsBlurbs.availability.replace(/\\n/g, '<br>')}
                </div>
                \` : ''}
                
                <div class="qos-status">
                    <span><span class="qos-indicator \${efficiency >= 80 ? 'status-excellent' : efficiency >= 60 ? 'status-good' : 'status-poor'}"></span>Efficiency</span>
                    <span style="font-weight: bold;">\${efficiency}%</span>
                </div>
                \${ratingsBlurbs && ratingsBlurbs.efficiency ? \`
                <div style="margin: 5px 0 10px 20px; padding: 8px; background: rgba(255,255,255,0.05); border-radius: 4px; font-size: 0.8em; opacity: 0.8; line-height: 1.3;">
                    \${ratingsBlurbs.efficiency.replace(/\\n/g, '<br>')}
                </div>
                \` : ''}
                
                \${ratingsBlurbs && (ratingsBlurbs.general || ratingsBlurbs.overall) ? \`
                <div style="margin-top: 15px; padding: 10px; background: rgba(255,255,255,0.08); border-radius: 6px; border-left: 3px solid #fbbf24;">
                    <div style="font-size: 0.9em; font-weight: bold; margin-bottom: 8px; opacity: 0.9;">📝 Overall Assessment:</div>
                    <div style="font-size: 0.8em; opacity: 0.8; line-height: 1.4;">\${(ratingsBlurbs.general || ratingsBlurbs.overall).replace(/\\n/g, '<br>')}</div>
                </div>
                \` : ''}
                
                \${ratingsBlurbs ? \`
                <div style="margin-top: 10px; padding: 8px; background: rgba(255,255,255,0.03); border-radius: 4px; border-left: 2px solid #60a5fa;">
                    <div style="font-size: 0.8em; font-weight: bold; margin-bottom: 6px; opacity: 0.8; color: #60a5fa;">📊 Quality Insights:</div>
                    <div style="font-size: 0.7em; opacity: 0.7; line-height: 1.3;">
                        Real-time quality assessments from the synchronizer network.
                    </div>
                </div>
                \` : \`
                <div style="margin-top: 10px; padding: 8px; background: rgba(255,255,255,0.03); border-radius: 4px; border-left: 2px solid #6b7280;">
                    <div style="font-size: 0.7em; opacity: 0.6; line-height: 1.3;">
                        Quality insights will appear here when synchronizer data is available.
                    </div>
                </div>
                \`}
            \`;
            
            document.getElementById('performance-content').innerHTML = performanceHtml;
            document.getElementById('qos-content').innerHTML = qosHtml;
        }
        
        function updatePointsDisplay(data) {
            const points = data.points || {};
            const totalPoints = points.total || 0;
            
            // Check for errors or fallback mode
            if (data.error) {
                const errorHtml = '<div style="text-align: center; padding: 20px;">' +
                    '<div style="color: #fca5a5; margin-bottom: 10px;">⚠️ Unable to fetch real points data</div>' +
                    '<div style="opacity: 0.8; font-size: 0.9em;">' + data.error + '</div>' +
                    (data.fallback ? '<div style="opacity: 0.6; font-size: 0.8em; margin-top: 10px;">Configure your Synq key and wallet to see real points</div>' : '') +
                    '</div>';
                document.getElementById('points-content').innerHTML = errorHtml;
                return;
            }
            
            // Show different types of points separately if available
            const syncLifePoints = data.syncLifePoints !== undefined ? data.syncLifePoints : null;
            const walletLifePoints = data.walletLifePoints !== undefined ? data.walletLifePoints : null;
            const walletBalance = data.walletBalance !== undefined ? data.walletBalance : null;
            
            let pointsMainDisplay = '';
            
            if (syncLifePoints !== null || walletLifePoints !== null) {
                // Show separate sync and wallet points
                pointsMainDisplay = \`
                    <div class="points-display" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                        \${syncLifePoints !== null ? \`
                        <div class="points-total">
                            <div class="points-number" style="color: #60a5fa;">\${syncLifePoints.toLocaleString()}</div>
                            <div class="points-label">Sync Life Points</div>
                            <div style="opacity: 0.6; font-size: 0.7em; color: #60a5fa;">🔄 Service Credits</div>
                        </div>
                        \` : ''}
                        \${walletLifePoints !== null ? \`
                        <div class="points-total">
                            <div class="points-number" style="color: #34d399;">\${walletLifePoints.toLocaleString()}</div>
                            <div class="points-label">Wallet Life Points</div>
                            <div style="opacity: 0.6; font-size: 0.7em; color: #34d399;">💰 Earnings</div>
                        </div>
                        \` : ''}
                        \${walletBalance !== null ? \`
                        <div class="points-total">
                            <div class="points-number" style="color: #fbbf24;">\${walletBalance.toLocaleString()}</div>
                            <div class="points-label">Wallet Balance</div>
                            <div style="opacity: 0.6; font-size: 0.7em; color: #fbbf24;">🏦 Current Balance</div>
                        </div>
                        \` : ''}
                    </div>
                \`;
            } else {
                // Fallback to total points display
                pointsMainDisplay = \`
                    <div class="points-display">
                        <div class="points-total">
                            <div class="points-number">\${totalPoints.toLocaleString()}</div>
                            <div class="points-label">Total Points</div>
                            \${data.source === 'websocket_priority' ? '<div style="opacity: 0.6; font-size: 0.7em; color: #4ade80;">🔌 Live WebSocket Data</div>' : ''}
                            \${data.source === 'container_stats' ? '<div style="opacity: 0.6; font-size: 0.7em; color: #4ade80;">🐳 Live from Container</div>' : ''}
                            \${data.source === 'api' ? '<div style="opacity: 0.6; font-size: 0.7em; color: #4ade80;">🔗 Live from API</div>' : ''}
                        </div>
                    </div>
                \`;
            }
            
            const pointsHtml = pointsMainDisplay + \`
                <div class="points-breakdown">
                    
                </div>
                \${data.isEarning !== undefined ? \`
                <div style="margin-top: 15px; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 6px; text-align: center;">
                    <span style="color: \${data.isEarning ? '#4ade80' : '#fbbf24'}; font-weight: bold;">
                        \${data.isEarning ? '✅ Currently Earning' : '⚠️ Not Currently Earning'}
                    </span>
                    \${data.connectionState ? \`<span style="opacity: 0.8; margin-left: 10px;">• \${data.connectionState}</span>\` : ''}
                </div>
                \` : ''}
            \`;
            
            document.getElementById('points-content').innerHTML = pointsHtml;
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }
        
        function openMetrics() {
            // Try the detected IP first, then fallback to localhost
            const metricsUrls = [
                \`http://${displayIP}:${metricsPort}/metrics\`,
                \`http://localhost:${metricsPort}/metrics\`
            ];
            
            // Open the first URL (primary IP)
            window.open(metricsUrls[0], '_blank');
        }
        
        function toggleSynqKey() {
            const masked = document.getElementById('synq-key-masked');
            const full = document.getElementById('synq-key-full');
            
            if (masked.style.display === 'none') {
                masked.style.display = 'inline';
                full.style.display = 'none';
            } else {
                masked.style.display = 'none';
                full.style.display = 'inline';
            }
        }
        
        function installWebService() {
            if (confirm('This will generate a systemd service file for the web dashboard. Continue?')) {
                fetch('/api/install-web-service', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert('Web service file generated successfully!\\n\\nTo install:\\n' + data.instructions);
                        } else {
                            alert('Error: ' + data.error);
                        }
                    })
                    .catch(error => {
                        alert('Error installing web service: ' + error.message);
                    });
            }
        }
        
        function refreshData() {
            fetchStatus();
            fetchLogs();
            fetchPerformance();
            fetchPoints();
            checkWebSocketStatus();
            document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
        }
        
        async function runWebSocketTest() {
            const testBtn = document.getElementById('test-websocket-btn');
            const resultsDiv = document.getElementById('websocket-results');
            const outputDiv = document.getElementById('websocket-test-output');
            
            testBtn.disabled = true;
            testBtn.textContent = '🔄 Testing...';
            resultsDiv.style.display = 'block';
            outputDiv.innerHTML = '<div style="color: #93c5fd;">Running WebSocket test...</div>';
            
            try {
                const response = await fetch('/api/test-websocket', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ timeout: 10, quiet: true })
                });
                
                const result = await response.json();
                
                if (result.success && result.test) {
                    const test = result.test;
                    let output = '';
                    
                    // Connection status
                    output += '<div style="color: ' + (test.success ? '#86efac' : '#fca5a5') + ';">';
                    output += (test.success ? '✅' : '❌') + ' Connection: ' + (test.success ? 'Successful' : 'Failed');
                    output += '</div>';
                    
                    if (test.error) {
                        output += '<div style="color: #fca5a5;">Error: ' + test.error + '</div>';
                    }
                    
                    // Message count
                    output += '<div style="color: #93c5fd;">📊 Messages received: ' + test.messageCount + '</div>';
                    
                    // Data quality
                    if (test.hasRealData) {
                        output += '<div style="color: #86efac;">🎉 Real data detected!</div>';
                    } else if (test.hasAnyData) {
                        output += '<div style="color: #fde047;">⚠️ Connected but only zero/empty data</div>';
                    } else if (test.success) {
                        output += '<div style="color: #fca5a5;">❌ No meaningful data received</div>';
                    }
                    
                    // Show sample messages
                    if (test.messages && test.messages.length > 0) {
                        output += '<div style="margin-top: 10px; color: #d1d5db;">Sample Messages:</div>';
                        test.messages.slice(0, 3).forEach((msg, index) => {
                            output += '<div style="margin: 5px 0; padding: 5px; background: rgba(0,0,0,0.3); border-radius: 4px; font-size: 0.8em;">';
                            output += '<div style="color: #fbbf24;">' + msg.timestamp + '</div>';
                            const msgData = JSON.stringify(msg.data);
                            const truncatedData = msgData.length > 200 ? msgData.substring(0, 200) + '...' : msgData;
                            output += '<div style="color: #d1d5db;">' + truncatedData + '</div>';
                            output += '</div>';
                        });
                    }
                    
                    output += '<div style="margin-top: 10px; color: #6b7280; font-size: 0.8em;">Test completed at ' + new Date(result.timestamp).toLocaleTimeString() + '</div>';
                    
                    outputDiv.innerHTML = output;
                } else {
                    outputDiv.innerHTML = '<div style="color: #fca5a5;">❌ Test failed: ' + (result.error || 'Unknown error') + '</div>';
                }
            } catch (error) {
                outputDiv.innerHTML = '<div style="color: #fca5a5;">❌ Error running test: ' + error.message + '</div>';
            } finally {
                testBtn.disabled = false;
                testBtn.textContent = '🔍 Test WebSocket Connection';
            }
        }
        
        async function checkWebSocketStatus() {
            try {
                const response = await fetch('/api/websocket-status');
                const status = await response.json();
                
                let statusHtml = '';
                
                // Container status
                statusHtml += '<div style="margin: 8px 0;">';
                statusHtml += '<span style="color: #d1d5db;">Container:</span> ';
                if (status.containerRunning) {
                    statusHtml += '<span style="color: #86efac;">✅ Running (' + status.containerName + ')</span>';
                } else {
                    statusHtml += '<span style="color: #fca5a5;">❌ Not running</span>';
                }
                statusHtml += '</div>';
                
                // Port exposure
                statusHtml += '<div style="margin: 8px 0;">';
                statusHtml += '<span style="color: #d1d5db;">Port 3333:</span> ';
                if (status.portExposed) {
                    statusHtml += '<span style="color: #86efac;">✅ Exposed (' + status.exposedPort + ')</span>';
                } else if (status.containerRunning) {
                    statusHtml += '<span style="color: #fca5a5;">❌ Not exposed</span>';
                } else {
                    statusHtml += '<span style="color: #6b7280;">⚪ N/A (container not running)</span>';
                }
                statusHtml += '</div>';
                
                // WebSocket URL
                statusHtml += '<div style="margin: 8px 0;">';
                statusHtml += '<span style="color: #d1d5db;">WebSocket URL:</span> ';
                statusHtml += '<span style="color: #93c5fd; font-family: monospace;">ws://localhost:3333</span>';
                statusHtml += '</div>';
                
                // Status summary
                const isReady = status.containerRunning && status.portExposed;
                statusHtml += '<div style="margin: 12px 0; padding: 8px; border-radius: 4px; background: rgba(' + (isReady ? '134, 239, 172' : '252, 165, 165') + ', 0.1);">';
                statusHtml += '<span style="color: ' + (isReady ? '#86efac' : '#fca5a5') + ';">';
                statusHtml += (isReady ? '✅ Ready for WebSocket testing' : '❌ WebSocket testing not available');
                statusHtml += '</span>';
                statusHtml += '</div>';
                
                document.getElementById('websocket-status').innerHTML = statusHtml;
                
            } catch (error) {
                document.getElementById('websocket-status').innerHTML = 
                    '<div style="color: #fca5a5;">❌ Error checking WebSocket status: ' + error.message + '</div>';
            }
        }
        
        // Initial load
        refreshData();
        
        // Auto-refresh every 5 seconds
        setInterval(refreshData, 5000);
    </script>
</body>
</html>`;
}

async function getSystemStatus(config) {
  const status = {
    timestamp: new Date().toISOString(),
    serviceStatus: 'unknown',
    dockerAvailable: false,
    autoStart: false,
    uptime: null,
    containerRunning: false,
    imageUpdates: {
      available: 0,
      lastChecked: null,
      images: []
    }
  };
  
  // Check Docker
  try {
    execSync('docker --version', { stdio: 'ignore' });
    status.dockerAvailable = true;
  } catch (error) {
    status.dockerAvailable = false;
  }
  
  // Check systemd service
  try {
    const serviceExists = fs.existsSync('/etc/systemd/system/synchronizer-cli.service');
    if (serviceExists) {
      const statusOutput = execSync('systemctl status synchronizer-cli --no-pager', { 
        encoding: 'utf8',
        stdio: 'pipe'
      });
      
      if (statusOutput.includes('active (running)')) {
        status.serviceStatus = 'running';
      } else if (statusOutput.includes('inactive (dead)')) {
        status.serviceStatus = 'stopped';
      } else if (statusOutput.includes('failed')) {
        status.serviceStatus = 'failed';
      }
      
      if (statusOutput.includes('enabled')) {
        status.autoStart = true;
      }
      
      // Extract uptime if running
      const uptimeLine = statusOutput.split('\n').find(line => line.includes('Active:'));
      if (uptimeLine && uptimeLine.includes('since')) {
        const match = uptimeLine.match(/since (.+?);/);
        if (match) {
          status.uptime = match[1];
        }
      }
    }
  } catch (error) {
    // Service not found or no permissions
  }
  
  // Check if container is running manually
  try {
    const dockerPs = execSync('docker ps --filter name=synchronizer-cli --format "{{.Names}}"', {
      encoding: 'utf8',
      stdio: 'pipe'
    });
    status.containerRunning = dockerPs.includes('synchronizer-cli');
  } catch (error) {
    // Docker not available
  }
  
  // Check Docker image updates (quick check, no pulling)
  if (status.dockerAvailable) {
    try {
      const images = [
        'cdrakep/synqchronizer:latest',
        'cdrakep/synqchronizer-test-fixed:latest'
      ];
      
      let updatesAvailable = 0;
      const imageStatuses = [];
      
      for (const imageName of images) {
        try {
          // Quick check without pulling
          const hasUpdate = await isNewDockerImageAvailable(imageName);
          imageStatuses.push({
            name: imageName,
            updateAvailable: hasUpdate
          });
          if (hasUpdate) updatesAvailable++;
        } catch (error) {
          imageStatuses.push({
            name: imageName,
            updateAvailable: false,
            error: error.message
          });
        }
      }
      
      status.imageUpdates = {
        available: updatesAvailable,
        lastChecked: new Date().toISOString(),
        images: imageStatuses
      };
    } catch (error) {
      // Image update check failed
      status.imageUpdates.error = error.message;
    }
  }
  
  return status;
}

async function getRecentLogs() {
  try {
    const logsOutput = execSync('journalctl -u synchronizer-cli --no-pager -n 20 --output=short-iso', { 
      encoding: 'utf8',
      stdio: 'pipe'
    });
    
    return logsOutput.split('\n').filter(line => line.trim()).slice(-15);
  } catch (error) {
    return ['No logs available or insufficient permissions'];
  }
}

async function generateMetrics(config) {
  const status = await getSystemStatus(config);
  
  return {
    timestamp: new Date().toISOString(),
    version: packageJson.version,
    system: {
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
      uptime: os.uptime(),
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem()
      },
      loadavg: os.loadavg()
    },
    synchronizer: {
      configured: !!config.key,
      syncHash: config.syncHash,
      wallet: config.wallet ? config.wallet.substring(0, 10) + '...' : null,
      serviceStatus: status.serviceStatus,
      dockerAvailable: status.dockerAvailable,
      autoStart: status.autoStart,
      containerRunning: status.containerRunning
    },
    health: {
      overall: status.serviceStatus === 'running' && status.dockerAvailable ? 'healthy' : 'unhealthy',
      checks: {
        docker: status.dockerAvailable,
        service: status.serviceStatus === 'running',
        configuration: !!config.key
      }
    }
  };
}

async function getHealthStatus() {
  const config = loadConfig();
  const status = await getSystemStatus(config);
  
  const isHealthy = status.serviceStatus === 'running' && status.dockerAvailable && !!config.key;
  
  return {
    status: isHealthy ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    checks: {
      docker: { status: status.dockerAvailable ? 'pass' : 'fail' },
      service: { status: status.serviceStatus === 'running' ? 'pass' : 'fail' },
      configuration: { status: !!config.key ? 'pass' : 'fail' }
    }
  };
}

async function getPerformanceData(config) {
  const now = Date.now();
  
  // PRIORITY 1: Check if we have fresh WebSocket data that overrides cache
  const containerStats = await getContainerStats();
  if (containerStats && containerStats.hasWebSocketData) {
    console.log(chalk.cyan(`🔍 Container stats ratingsBlurbs check:`));
    console.log(chalk.cyan(`   Type: ${typeof containerStats.ratingsBlurbs}`));
    console.log(chalk.cyan(`   Value: ${containerStats.ratingsBlurbs ? 'PRESENT' : 'NULL'}`));
    if (containerStats.ratingsBlurbs) {
      console.log(chalk.cyan(`   Content sample: ${JSON.stringify(containerStats.ratingsBlurbs).substring(0, 100)}...`));
    }
    
    // We have fresh WebSocket data - use it immediately, ignore cache
    let performance = {
      totalTraffic: containerStats.syncLifeTraffic || (containerStats.bytesIn + containerStats.bytesOut) || 0,
      sessions: containerStats.sessions || 0,
      users: containerStats.users || 0,
      demoSessions: containerStats.demoSessions || 0,
      bytesIn: containerStats.bytesIn || 0,
      bytesOut: containerStats.bytesOut || 0,
      proxyConnectionState: containerStats.proxyConnectionState || 'UNKNOWN'
    };
    
    // Use actual QoS values from WebSocket data
    const availability = containerStats.availability !== undefined ? containerStats.availability : 0;
    const reliability = containerStats.reliability !== undefined ? containerStats.reliability : 0;
    const efficiency = containerStats.efficiency !== undefined ? containerStats.efficiency : 0;
    
    // Calculate overall score from the three QoS metrics
    const score = Math.floor((availability + reliability + efficiency) / 3);
    
    let qos = {
      score: score,
      reliability: reliability,
      availability: availability,
      efficiency: efficiency,
      ratingsBlurbs: containerStats.ratingsBlurbs || null
    };

    console.log(chalk.blue(`🔍 Sending QoS data to frontend:`));
    console.log(chalk.blue(`   QoS score: ${score}%, Ratings: ${availability}/${reliability}/${efficiency}`));
    if (qos.ratingsBlurbs) {
      console.log(chalk.blue(`   Ratings Blurbs: PRESENT for frontend`));
      console.log(chalk.cyan(`   Blurbs type: ${typeof qos.ratingsBlurbs}, keys: ${Object.keys(qos.ratingsBlurbs || {}).join(', ')}`));
    } else {
      console.log(chalk.yellow(`   Ratings Blurbs: NULL for frontend`));
      console.log(chalk.gray(`   Container ratingsBlurbs: ${containerStats.ratingsBlurbs ? 'PRESENT in container' : 'NULL in container'}`));
    }

    const result = {
      timestamp: new Date().toISOString(),
      performance,
      qos
    };

    // Cache the fresh WebSocket result
    globalCache.performance = {
      data: result,
      timestamp: now
    };

    return result;
  }

  // PRIORITY 2: Use cached success data if recent
  if (globalCache.performance.data && !globalCache.performance.data.error && (now - globalCache.performance.timestamp) < DASHBOARD_CACHE_DURATION) {
    return globalCache.performance.data;
  }

  // PRIORITY 3: Use cached error data only if very recent (5 seconds)
  if (globalCache.performance.data && globalCache.performance.data.error && (now - globalCache.performance.timestamp) < 5000) {
    return globalCache.performance.data;
  }

  // PRIORITY 4: Fallback to system status check
  const status = await getSystemStatus(config);
  
  // Get real performance data from the running synchronizer container
  const isRunning = status.serviceStatus === 'running' || status.containerRunning;
  let performance = {
    totalTraffic: 0,
    sessions: 0,
    users: 0,
    demoSessions: 0,
    bytesIn: 0,
    bytesOut: 0,
    proxyConnectionState: 'UNKNOWN'
  };
  
  let qos = {
    score: 0,
    reliability: 0,
    availability: 0, 
    efficiency: 0,
    ratingsBlurbs: null
  };
  
  if (isRunning && containerStats) {
    // Container is running but no WebSocket data
    if (containerStats.hasRealStats) {
      // Use container stats data
      performance = {
        totalTraffic: containerStats.syncLifeTraffic || (containerStats.bytesIn + containerStats.bytesOut) || 0,
        sessions: containerStats.sessions || 0,
        users: containerStats.users || 0,
        demoSessions: containerStats.demoSessions || 0,
        bytesIn: containerStats.bytesIn || 0,
        bytesOut: containerStats.bytesOut || 0,
        proxyConnectionState: containerStats.proxyConnectionState || 'UNKNOWN'
      };
      
      // Use actual QoS values if available, otherwise calculate based on status
      const availability = containerStats.availability !== undefined ? 
        containerStats.availability : (containerStats.proxyConnectionState === 'CONNECTED' ? 95 : 20);
      const reliability = containerStats.reliability !== undefined ? 
        containerStats.reliability : (containerStats.isEarningPoints ? 
          (containerStats.syncLifePoints > 0 ? 95 : 85) : 40);
      const efficiency = containerStats.efficiency !== undefined ? 
        containerStats.efficiency : (containerStats.isEarningPoints ? 90 : 
          (containerStats.proxyConnectionState === 'CONNECTED' ? 60 : 20));
      
      const score = Math.floor((availability + reliability + efficiency) / 3);
      
      qos = {
        score: score,
        reliability: reliability,
        availability: availability,
        efficiency: efficiency,
        ratingsBlurbs: containerStats.ratingsBlurbs || null
      };
    } else {
      // Container running but no real stats available
      const uptimeHours = containerStats.uptimeHours || 0;
      const baseTrafficPerHour = 10 * 1024 * 1024; // 10MB/hour baseline
      const estimatedTraffic = Math.floor(uptimeHours * baseTrafficPerHour);
      
      performance = {
        totalTraffic: estimatedTraffic,
        sessions: 0,
        users: 0,
        demoSessions: 0,
        bytesIn: 0,
        bytesOut: 0,
        proxyConnectionState: 'UNKNOWN'
      };
      
      qos = {
        score: 50, // Neutral score for running but unconnected
        reliability: 60,
        availability: 50,
        efficiency: 50,
        ratingsBlurbs: null
      };
    }
  } else if (isRunning) {
    // Container reported as running but no stats
    qos = {
      score: 25,
      reliability: 1,
      availability: 2,
      efficiency: 1,
      ratingsBlurbs: null
    };
  } else {
    // Not running - show poor but not zero stats
    qos = {
      score: 5,
      reliability: 10,
      availability: 0,
      efficiency: 5,
      ratingsBlurbs: null
    };
  }

  const result = {
    timestamp: new Date().toISOString(),
    performance,
    qos
  };

  // Cache the result
  globalCache.performance = {
    data: result,
    timestamp: now
  };

  return result;
}

async function getPointsData(config) {
  const now = Date.now();
  
  if (!config.wallet) {
    const result = {
      timestamp: new Date().toISOString(),
      points: {
        total: 0,
        daily: 0,
        weekly: 0,
        monthly: 0,
        streak: 0,
        rank: 'N/A',
        multiplier: '1.0'
      },
      error: 'Missing wallet address'
    };
    
    // Cache error result for shorter time
    globalCache.points = {
      data: result,
      timestamp: now
    };
    
    return result;
  }

  // PRIORITY 1: Check if we have fresh WebSocket data that overrides cache
  const containerStats = await getContainerStats();
  if (containerStats && containerStats.hasWebSocketData) {
    // We have fresh WebSocket data - use it immediately, ignore cache
    const walletLifePoints = containerStats.walletLifePoints || 0;
    const syncLifePoints = containerStats.syncLifePoints || 0;
    const walletBalance = containerStats.walletBalance || 0;
    const currentPoints = containerStats.isEarningPoints ? Math.floor(containerStats.uptimeHours || 0) : 0;
    
    const result = {
      timestamp: new Date().toISOString(),
      points: {
        total: walletLifePoints + syncLifePoints, // Combined for compatibility
        daily: 0, // Not tracked by CLI
        weekly: 0, // Not tracked by CLI
        monthly: 0, // Not tracked by CLI
        streak: 0, // Not tracked by CLI
        rank: 'N/A', // Not tracked by CLI
        multiplier: 'N/A' // Not tracked by CLI
      },
      // Add separate fields for different point types
      syncLifePoints: syncLifePoints,
      walletLifePoints: walletLifePoints,
      walletBalance: walletBalance,
      source: 'websocket_priority', // Data comes from WebSocket (priority)
      containerUptime: `${(containerStats.uptimeHours || 0).toFixed(1)} hours`,
      isEarning: containerStats.isEarningPoints,
      connectionState: containerStats.proxyConnectionState
    };
    
    // Cache the fresh WebSocket result
    globalCache.points = {
      data: result,
      timestamp: now
    };
    
    return result;
  }

  // PRIORITY 2: Use cached success data if recent
  if (globalCache.points.data && !globalCache.points.data.error && (now - globalCache.points.timestamp) < DASHBOARD_CACHE_DURATION) {
    return globalCache.points.data;
  }

  // PRIORITY 3: Use cached error data only if very recent (5 seconds)
  if (globalCache.points.data && globalCache.points.data.error && (now - globalCache.points.timestamp) < 5000) {
    return globalCache.points.data;
  }

  // PRIORITY 4: Try API if rate limit allows
  const timeSinceLastRequest = now - lastStatsRequestTime;
  
  if (timeSinceLastRequest > STATS_REQUEST_COOLDOWN || lastStatsRequestTime === 0) {
    try {
      const apiData = await fetchWalletLifetimePoints(null, config.wallet, config);
      
      if (apiData.success) {
        const data = apiData.data;
        const walletLifePoints = data.lifetimePoints || 0;
        
        const result = {
          timestamp: new Date().toISOString(),
          points: {
            total: walletLifePoints,
            daily: data.dailyPoints || 0, // Use API data if available
            weekly: data.weeklyPoints || 0, // Use API data if available  
            monthly: data.monthlyPoints || 0, // Use API data if available
            streak: data.streak || 0, // Use API data if available
            rank: data.rank || 'N/A', // Use API data if available
            multiplier: data.multiplier || 'N/A' // Use API data if available
          },
          // Add separate fields (may not be available from API)
          syncLifePoints: null,
          walletLifePoints: walletLifePoints,
          walletBalance: null,
          source: 'api',
          apiExtras: {
            lastWithdrawn: data.lastWithdrawn,
            lastUpdated: data.lastUpdated,
            activeSynchronizers: data.activeSynchronizers,
            totalSessions: data.totalSessions,
            totalTraffic: data.totalTraffic
          }
        };
        
        // Cache the API result
        globalCache.points = {
          data: result,
          timestamp: now
        };
        
        return result;
      }
    } catch (error) {
      // API failed, continue to container stats
    }
  }

  // PRIORITY 5: Use container stats (if not already used in priority 1)
  if (containerStats) {
    const walletLifePoints = containerStats.walletLifePoints || 0;
    const syncLifePoints = containerStats.syncLifePoints || 0;
    const walletBalance = containerStats.walletBalance || 0;
    const currentPoints = containerStats.isEarningPoints ? Math.floor(containerStats.uptimeHours || 0) : 0;
    
    const result = {
      timestamp: new Date().toISOString(),
      points: {
        total: walletLifePoints + syncLifePoints,
        daily: 0, // Not tracked by CLI
        weekly: 0, // Not tracked by CLI
        monthly: 0, // Not tracked by CLI
        streak: 0, // Not tracked by CLI
        rank: 'N/A', // Not tracked by CLI
        multiplier: 'N/A' // Not tracked by CLI
      },
      // Add separate fields for different point types
      syncLifePoints: syncLifePoints,
      walletLifePoints: walletLifePoints,
      walletBalance: walletBalance,
      source: 'container_stats',
      containerUptime: `${(containerStats.uptimeHours || 0).toFixed(1)} hours`,
      isEarning: containerStats.isEarningPoints,
      connectionState: containerStats.proxyConnectionState
    };
    
    // Cache the container stats result
    globalCache.points = {
      data: result,
      timestamp: now
    };
    
    return result;
  }

  // PRIORITY 6: Error fallback
  const result = {
    timestamp: new Date().toISOString(),
    points: {
      total: 0,
      daily: 0,
      weekly: 0,
      monthly: 0,
      streak: 0,
      rank: 'N/A',
      multiplier: '1.0'
    },
    // Add null separate fields
    syncLifePoints: null,
    walletLifePoints: null,
    walletBalance: null,
    error: 'Synchronizer container not running - start it first',
    fallback: true
  };
  
  // Cache error result for very short time only
  globalCache.points = {
    data: result,
    timestamp: now
  };
  
  return result;
}

/**
 * Parse container logs for stats (fallback when WebSocket is not available)
 * @param {string} containerName Name of the container
 * @returns {object|null} Parsed stats or null if not found
 */
async function parseContainerLogs(containerName) {
  try {
    // Get comprehensive logs to extract stats data
    const logsOutput = execSync(`docker logs ${containerName} --tail 100`, {
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 10000
    });
    
    // Look for signs that the synchronizer is actually working
    const isEarning = logsOutput.includes('proxy-connected') || 
                     logsOutput.includes('registered') ||
                     logsOutput.includes('session') ||
                     logsOutput.includes('traffic') ||
                     logsOutput.includes('stats');
    
    let realStats = null;
    
    // Try to extract real stats from logs if available
    // Look for JSON stats messages in the logs
    const logLines = logsOutput.split('\n');
    for (const line of logLines.reverse()) { // Start from most recent
      try {
        // Look for JSON objects that might contain stats
        const jsonMatch = line.match(/\{.*"syncLifePoints".*\}/);
        if (jsonMatch) {
          const statsData = JSON.parse(jsonMatch[0]);
          if (statsData.syncLifePoints !== undefined || statsData.walletLifePoints !== undefined) {
            realStats = { ...statsData, isEarning };
            break;
          }
        }
        
        // Look for UPDATE_TALLIES messages from the registry
        const updateTalliesMatch = line.match(/\{.*"what":\s*"UPDATE_TALLIES".*\}/);
        if (updateTalliesMatch) {
          const talliesData = JSON.parse(updateTalliesMatch[0]);
          if (talliesData.walletPoints !== undefined) {
            realStats = realStats || { isEarning };
            realStats.walletLifePoints = talliesData.walletPoints;
            realStats.syncLifePoints = talliesData.lifePoints || realStats.syncLifePoints;
            realStats.syncLifeTraffic = talliesData.lifeTraffic || realStats.syncLifeTraffic;
          }
        }
        
        // Look for stats patterns with "walletPoints" (no "Life")
        const walletPointsMatch = line.match(/walletPoints[:\s]+(\d+)/i);
        if (walletPointsMatch) {
          realStats = realStats || { isEarning };
          realStats.walletLifePoints = parseInt(walletPointsMatch[1]);
        }
        
        // Also look for other stat patterns
        const pointsMatch = line.match(/points[:\s]+(\d+)/i);
        const trafficMatch = line.match(/traffic[:\s]+(\d+)/i);
        const sessionsMatch = line.match(/sessions[:\s]+(\d+)/i);
        
        if (pointsMatch || trafficMatch || sessionsMatch) {
          realStats = realStats || { isEarning };
          if (pointsMatch) realStats.syncLifePoints = parseInt(pointsMatch[1]);
          if (trafficMatch) realStats.syncLifeTraffic = parseInt(trafficMatch[1]);
          if (sessionsMatch) realStats.sessions = parseInt(sessionsMatch[1]);
        }
      } catch (parseError) {
        // Continue looking through logs
      }
    }
    
    return realStats;
    
  } catch (logError) {
    console.log(chalk.yellow(`⚠️ Could not parse container logs: ${logError.message}`));
    return null;
  }
}

/**
 * Start the nightly test version of the synchronizer with latest Docker image
 */
async function startNightly() {
  const config = loadConfig();
  if (!config.key) {
    console.error(chalk.red('Missing synq key. Run `synchronize init` first.'));
    process.exit(1);
  }

  if (config.hostname !== os.hostname()) {
    console.error(chalk.red(`This config was created for ${config.hostname}, not ${os.hostname()}.`));
    process.exit(1);
  }

  // Check if Docker is installed
  if (!checkDocker()) {
    console.error(chalk.red('Docker is not installed or not accessible.'));
    
    const shouldInstall = await inquirer.prompt([{
      type: 'confirm',
      name: 'install',
      message: 'Would you like to install Docker now?',
      default: true
    }]);

    if (shouldInstall.install) {
      await installDocker();
      
      // Check again after installation
      if (!checkDocker()) {
        console.error(chalk.red('Docker installation may have failed or requires a restart.'));
        console.error(chalk.yellow('Please try running the command again after restarting your terminal.'));
        process.exit(1);
      }
    } else {
      console.error(chalk.yellow('Please install Docker first: https://docs.docker.com/get-docker/'));
      process.exit(1);
    }
  }
  
  const syncName = config.syncHash;
  const containerName = 'synchronizer-nightly';

  // Check if container is already running
  try {
    const runningContainers = execSync(`docker ps --filter name=${containerName} --format "{{.Names}}"`, {
      encoding: 'utf8',
      stdio: 'pipe'
    });
    
    if (runningContainers.includes(containerName)) {
      console.log(chalk.green(`✅ Found existing nightly container running`));
      console.log(chalk.cyan(`🔗 Connecting to logs... (Ctrl+C will stop the container)`));
      
      // Connect to the existing container's logs
      const logProc = spawn('docker', ['logs', '-f', containerName], { stdio: 'inherit' });
      
      // Handle Ctrl+C to stop the container
      const cleanup = () => {
        console.log(chalk.yellow('\n🛑 Stopping nightly container...'));
        try {
          execSync(`docker stop ${containerName}`, { stdio: 'pipe' });
          console.log(chalk.green('✅ Container stopped'));
        } catch (error) {
          console.log(chalk.red('❌ Error stopping container:', error.message));
        }
        process.exit(0);
      };
      
      process.on('SIGINT', cleanup);
      process.on('SIGTERM', cleanup);
      
      logProc.on('exit', (code) => {
        process.exit(code);
      });
      
      return;
    }
  } catch (error) {
    // No existing container, continue with normal startup
  }

  // Detect platform architecture
  const arch = os.arch();
  const platform = os.platform();
  let dockerPlatform = 'linux/amd64'; // Default to amd64
  
  if (platform === 'linux') {
    if (arch === 'arm64' || arch === 'aarch64') {
      dockerPlatform = 'linux/arm64';
    } else if (arch === 'x64' || arch === 'x86_64') {
      dockerPlatform = 'linux/amd64';
    }
  } else if (platform === 'darwin') {
    dockerPlatform = arch === 'arm64' ? 'linux/arm64' : 'linux/amd64';
  }

  console.log(chalk.blue(`Detected platform: ${platform}/${arch} -> Using Docker platform: ${dockerPlatform}`));

  // Use the FIXED nightly test image
  const imageName = 'cdrakep/synqchronizer-test-fixed:latest';
  
  // Get dynamic version info for nightly launcher
  let dockerImageVersion = 'nightly';
  try {
    // Try to get the version from the nightly image
    const imageInspectOutput = execSync(`docker inspect ${imageName} --format "{{json .Config.Labels}}"`, {
      encoding: 'utf8',
      stdio: 'pipe'
    });
    
    const labels = JSON.parse(imageInspectOutput);
    if (labels && labels.version) {
      dockerImageVersion = `${labels.version}-nightly`;
    } else {
      // Get image creation date as fallback
      const createdOutput = execSync(`docker inspect ${imageName} --format "{{.Created}}"`, {
        encoding: 'utf8',
        stdio: 'pipe'
      });
      const created = new Date(createdOutput.trim());
      dockerImageVersion = `${created.toISOString().split('T')[0]}-nightly`;
    }
  } catch (error) {
    // Use nightly as fallback
    dockerImageVersion = 'nightly';
  }

  // Set nightly-specific launcher with dynamic version
  const launcherWithVersion = `cli-${packageJson.version}/docker-${dockerImageVersion}`;
  console.log(chalk.cyan(`Using launcher identifier: ${launcherWithVersion}`));

  // Check if we need to pull the latest Docker image
  const shouldPull = await isNewDockerImageAvailable(imageName);
  
  // Pull the latest image only if necessary
  if (shouldPull) {
    console.log(chalk.cyan('Pulling latest nightly test image...'));
    try {
      execSync(`docker pull ${imageName}`, { 
        stdio: ['ignore', 'pipe', 'pipe']
      });
      console.log(chalk.green('✅ Nightly test image pulled successfully'));
    } catch (error) {
      console.log(chalk.yellow('⚠️  Could not pull latest image - will use local cache if available'));
      console.log(chalk.gray(error.message));
    }
  }

  console.log(chalk.magenta(`🌙 Running NIGHTLY TEST synchronizer "${syncName}" with wallet ${config.wallet || '[none]'}`));
  console.log(chalk.yellow(`⚠️  This is a TEST version for development/testing purposes`));
  console.log(chalk.green(`✅ Using container image: ${imageName}`));

  // Create Docker command using the same approach as start() function
  const dockerCmd = 'docker';
  const args = [
    'run', '--rm', '--name', containerName,
    '--pull', 'always', // Always try to pull the latest image
    '--platform', dockerPlatform,
    '-p', '3333:3333', // Expose WebSocket CLI port
    '-p', '9090:9090', // Expose HTTP metrics port
    imageName
  ];
  
  // Add container arguments correctly - each flag and value as separate items
  if (config.depin) {
    args.push('--depin');
    args.push(config.depin);
  } else {
    args.push('--depin');
    args.push('wss://api.multisynq.io/depin');
  }
  
  args.push('--sync-name');
  args.push(syncName);
  
  args.push('--launcher');
  args.push(launcherWithVersion);
  
  args.push('--key');
  args.push(config.key);
  
  if (config.wallet) {
    args.push('--wallet');
    args.push(config.wallet);
  }
  
  if (config.account) {
    args.push('--account');
    args.push(config.account);
  }

  // For debugging
  console.log(chalk.gray(`Running command: ${dockerCmd} ${args.join(' ')}`));
  
  const proc = spawn(dockerCmd, args, { stdio: 'inherit' });
  
  // Handle Ctrl+C to stop the container
  const cleanup = () => {
    console.log(chalk.yellow('\n🛑 Stopping nightly container...'));
    try {
      execSync(`docker stop ${containerName}`, { stdio: 'pipe' });
      console.log(chalk.green('✅ Container stopped'));
    } catch (error) {
      console.log(chalk.red('❌ Error stopping container:', error.message));
    }
    process.exit(0);
  };
  
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  
  proc.on('error', (err) => {
    if (err.code === 'ENOENT') {
      console.error(chalk.red('Docker command not found. Please ensure Docker is installed and in your PATH.'));
    } else {
      console.error(chalk.red('Error running Docker:'), err.message);
    }
    process.exit(1);
  });
  
  proc.on('exit', code => {
    if (code === 126) {
      console.error(chalk.red('❌ Docker permission denied.'));
      console.error(chalk.yellow('This usually means your user is not in the docker group.'));
      console.error(chalk.blue('\n🔧 To fix this:'));
      console.error(chalk.white('1. Add your user to the docker group:'));
      console.error(chalk.gray(`   sudo usermod -aG docker ${os.userInfo().username}`));
      console.error(chalk.white('2. Log out and log back in (or restart your terminal)'));
      console.error(chalk.blue('\n🔧 Or use the fix command:'));
      console.error(chalk.gray('   synchronize fix-docker'));
    } else if (code === 125) {
      console.error(chalk.red('❌ Docker container failed to start.'));
      console.error(chalk.yellow('This might be due to platform architecture issues.'));
      console.error(chalk.blue('\n🔧 Troubleshooting steps:'));
      console.error(chalk.gray('1. Test platform compatibility:'));
      console.error(chalk.gray('   synchronize test-platform'));
    } else if (code !== 0) {
      console.error(chalk.red(`Docker process exited with code ${code}`));
    }
    process.exit(code);
  });
}

// Add this new function
async function testNightly() {
  const config = loadConfig();
  if (!config.key) {
    console.error(chalk.red('Missing synq key. Run `synchronize init` first.'));
    process.exit(1);
  }
  
  const syncName = config.syncHash;
  console.log(chalk.magenta(`🧪 TEST NIGHTLY - Running NIGHTLY TEST synchronizer "${syncName}" with wallet ${config.wallet || '[none]'}`));
  console.log(chalk.yellow(`⚠️  This is a direct Docker command execution test`));
  
  // Use simple shell execution for testing
  const shellCommand = `docker run --rm --name synchronizer-nightly --platform linux/$(uname -m | sed 's/x86_64/amd64/' | sed 's/arm64/arm64/') cdrakep/synqchronizer-test:latest --depin wss://api.multisynq.io/depin --sync-name "${syncName}" --launcher nightly-test-2.0.1 --key "${config.key}" ${config.wallet ? `--wallet "${config.wallet}"` : ''}`;
  
  console.log(chalk.gray(`Executing: ${shellCommand}`));
  
  // Run as direct shell command
  const child = require('child_process').spawn('/bin/sh', ['-c', shellCommand], {
    stdio: 'inherit'
  });
  
  child.on('exit', (code) => {
    process.exit(code || 0);
  });
}

/**
 * Check for Docker image updates manually
 */
async function checkImageUpdates() {
  console.log(chalk.blue('🔍 Checking for Docker Image Updates'));
  console.log(chalk.yellow('Checking all synchronizer Docker images...\n'));

  const images = [
    { name: 'cdrakep/synqchronizer:latest', description: 'Main synchronizer image' },
    { name: 'cdrakep/synqchronizer-test-fixed:latest', description: 'Fixed nightly test image' }
  ];

  let updatesAvailable = 0;

  for (const image of images) {
    console.log(chalk.cyan(`Checking ${image.description}...`));
    console.log(chalk.gray(`Image: ${image.name}`));
    
    try {
      const hasUpdate = await isNewDockerImageAvailable(image.name);
      
      if (hasUpdate) {
        console.log(chalk.yellow(`🔄 Update available for ${image.name}`));
        updatesAvailable++;
        
        const shouldPull = await inquirer.prompt([{
          type: 'confirm',
          name: 'pull',
          message: `Pull latest version of ${image.name}?`,
          default: true
        }]);
        
        if (shouldPull.pull) {
          try {
            console.log(chalk.cyan(`Pulling ${image.name}...`));
            execSync(`docker pull ${image.name}`, { stdio: 'inherit' });
            console.log(chalk.green(`✅ Successfully updated ${image.name}`));
          } catch (error) {
            console.log(chalk.red(`❌ Failed to pull ${image.name}: ${error.message}`));
          }
        }
      } else {
        console.log(chalk.green(`✅ ${image.name} is up to date`));
      }
      
      console.log(''); // Add spacing between images
    } catch (error) {
      console.log(chalk.red(`❌ Error checking ${image.name}: ${error.message}`));
      console.log('');
    }
  }

  console.log(chalk.blue('📊 Update Check Summary:'));
  if (updatesAvailable === 0) {
    console.log(chalk.green('✅ All images are up to date'));
  } else {
    console.log(chalk.yellow(`🔄 ${updatesAvailable} image(s) had updates available`));
  }
  
  console.log(chalk.gray('\n💡 Tip: Use `synchronize monitor` to automatically check for updates'));
}

/**
 * Start background monitoring for Docker image updates
 */
async function startImageMonitoring() {
  console.log(chalk.blue('🕐 Starting Docker Image Monitoring'));
  console.log(chalk.yellow('Background service to check for image updates every 30 minutes\n'));

  const config = loadConfig();
  
  // Configuration for monitoring
  const monitoringConfig = {
    checkInterval: 30 * 60 * 1000, // 30 minutes in milliseconds
    autoUpdate: false, // Set to true to automatically pull updates
    notifyOnly: true   // Just notify, don't auto-update
  };

  const images = [
    'cdrakep/synqchronizer:latest',
    'cdrakep/synqchronizer-test-fixed:latest'
  ];

  console.log(chalk.cyan(`📋 Monitoring Configuration:`));
  console.log(chalk.gray(`   Check interval: ${monitoringConfig.checkInterval / 60000} minutes`));
  console.log(chalk.gray(`   Auto-update: ${monitoringConfig.autoUpdate ? 'Enabled' : 'Disabled'}`));
  console.log(chalk.gray(`   Images: ${images.length} configured`));
  console.log('');

  let checkCount = 0;

  const performCheck = async () => {
    checkCount++;
    const timestamp = new Date().toLocaleString();
    
    console.log(chalk.blue(`🔍 Check #${checkCount} at ${timestamp}`));
    
    let updatesFound = 0;
    
    for (const imageName of images) {
      try {
        const hasUpdate = await isNewDockerImageAvailable(imageName);
        
        if (hasUpdate) {
          updatesFound++;
          console.log(chalk.yellow(`🔄 Update available: ${imageName}`));
          
          if (monitoringConfig.autoUpdate) {
            try {
              console.log(chalk.cyan(`⬇️ Auto-updating ${imageName}...`));
              execSync(`docker pull ${imageName}`, { stdio: 'pipe' });
              console.log(chalk.green(`✅ Auto-updated ${imageName}`));
            } catch (error) {
              console.log(chalk.red(`❌ Auto-update failed for ${imageName}: ${error.message}`));
            }
          }
        } else {
          console.log(chalk.gray(`✅ ${imageName} is up to date`));
        }
      } catch (error) {
        console.log(chalk.red(`❌ Error checking ${imageName}: ${error.message}`));
      }
    }
    
    if (updatesFound === 0) {
      console.log(chalk.green(`✅ All ${images.length} images are up to date`));
    } else {
      console.log(chalk.yellow(`🔄 Found ${updatesFound} image(s) with updates`));
      if (!monitoringConfig.autoUpdate) {
        console.log(chalk.gray('   Run `synchronize check-updates` to update manually'));
      }
    }
    
    console.log(chalk.gray(`⏰ Next check in ${monitoringConfig.checkInterval / 60000} minutes\n`));
  };

  // Perform initial check
  await performCheck();

  // Set up interval for periodic checks
  const monitoringInterval = setInterval(performCheck, monitoringConfig.checkInterval);

  console.log(chalk.green('🚀 Monitoring started - Press Ctrl+C to stop'));
  console.log(chalk.gray('Tip: You can safely run this in the background or as a systemd service\n'));

  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log(chalk.yellow('\n🛑 Stopping image monitoring...'));
    clearInterval(monitoringInterval);
    console.log(chalk.green('✅ Monitoring stopped'));
    process.exit(0);
  });

  // Keep the process alive
  setInterval(() => {
    // Just keep the monitoring alive
  }, 1000);
}

/**
 * Generate systemd service file for image monitoring
 */
async function installImageMonitoringService() {
  const config = loadConfig();
  const serviceFile = path.join(CONFIG_DIR, 'synchronizer-cli-monitor.service');
  const user = os.userInfo().username;
  const npxPath = detectNpxPath();
  
  // Get the directory containing npx for PATH
  const npxDir = path.dirname(npxPath);
  
  // Build PATH environment variable including npx directory
  const systemPaths = [
    '/usr/local/sbin',
    '/usr/local/bin', 
    '/usr/sbin',
    '/usr/bin',
    '/sbin',
    '/bin'
  ];
  
  // Add npx directory to the beginning of PATH if it's not already a system path
  const pathDirs = systemPaths.includes(npxDir) ? systemPaths : [npxDir, ...systemPaths];
  const pathEnv = pathDirs.join(':');

  const unit = `[Unit]
Description=Synchronizer CLI Docker Image Monitor
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=${user}
Restart=always
RestartSec=30
WorkingDirectory=${os.homedir()}
ExecStart=${npxPath} synchronize monitor
Environment=NODE_ENV=production
Environment=PATH=${pathEnv}

[Install]
WantedBy=multi-user.target
`;

  fs.writeFileSync(serviceFile, unit);
  
  const instructions = `sudo cp ${serviceFile} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable synchronizer-cli-monitor
sudo systemctl start synchronizer-cli-monitor`;

  return {
    success: true,
    serviceFile,
    instructions,
    message: 'Docker image monitoring service file generated successfully'
  };
}

/**
 * Enterprise API integration - Create synchronizer via Enterprise API
 * This uses the Enterprise API to automatically provision a synq key
 */
async function setupViaEnterpriseAPI() {
  console.log(chalk.blue('🏢 Enterprise API Setup'));
  console.log(chalk.yellow('Automatically provision a synq key via Enterprise API\n'));

  // Get Enterprise API key
  const apiKeyQuestion = await inquirer.prompt([{
    type: 'password',
    name: 'enterpriseApiKey',
    message: 'Enterprise API Key:',
    validate: input => input ? true : 'Enterprise API Key is required',
    mask: '*'
  }]);

  const enterpriseApiKey = apiKeyQuestion.enterpriseApiKey;

  // Get optional synchronizer name
  const nameQuestion = await inquirer.prompt([{
    type: 'input',
    name: 'synchronizerName',
    message: 'Synchronizer name (optional):',
    default: ''
  }]);

  const synchronizerName = nameQuestion.synchronizerName;

  console.log(chalk.cyan('\n🔄 Creating synchronizer via Enterprise API...'));

  try {
    // Call Enterprise API to create synchronizer
    const apiUrl = 'https://startsynqing.com/api/synq-keys/enterprise/synchronizer';
    
    const requestBody = synchronizerName ? { name: synchronizerName } : {};
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'X-Enterprise-API-Key': enterpriseApiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorMessage = `API request failed (${response.status})`;
      
      try {
        const errorJson = JSON.parse(errorText);
        errorMessage = errorJson.message || errorMessage;
      } catch (parseError) {
        errorMessage = errorText || errorMessage;
      }
      
      throw new Error(errorMessage);
    }

    const result = await response.json();
    
    if (!result.success || !result.synchronizer) {
      throw new Error(result.message || 'Failed to create synchronizer');
    }

    const synchronizer = result.synchronizer;
    const finalName = synchronizer.name || synchronizer.id;
    
    console.log(chalk.green('✅ Synchronizer created successfully!'));
    console.log(chalk.gray(`   ID: ${synchronizer.id}`));
    console.log(chalk.gray(`   Name: ${finalName}`));
    console.log(chalk.gray(`   Synq Key: ${synchronizer.key}`));

    // Now set up the CLI configuration automatically
    console.log(chalk.cyan('\n⚙️ Setting up CLI configuration...'));

    // Get wallet address
    const walletQuestion = await inquirer.prompt([{
      type: 'input',
      name: 'wallet',
      message: 'Wallet address:',
      validate: input => input ? true : 'Wallet is required'
    }]);

    // Ask about dashboard password
    const passwordQuestion = await inquirer.prompt([{
      type: 'confirm',
      name: 'setDashboardPassword',
      message: 'Set a password for the web dashboard? (Recommended for security):',
      default: true
    }]);

    let dashboardPassword = undefined;
    if (passwordQuestion.setDashboardPassword) {
      const passwordAnswers = await inquirer.prompt([{
        type: 'password',
        name: 'dashboardPassword',
        message: 'Dashboard password:',
        validate: input => input && input.length >= 4 ? true : 'Password must be at least 4 characters',
        mask: '*'
      }]);
      dashboardPassword = passwordAnswers.dashboardPassword;
    }

    // Generate configuration using the API-provided synq key
    const secret = crypto.randomBytes(8).toString('hex');
    const hostname = os.hostname();
    const syncHash = generateSyncHash(finalName, secret, hostname);

    const config = {
      userName: finalName,
      key: synchronizer.key,
      wallet: walletQuestion.wallet,
      secret,
      hostname,
      syncHash,
      depin: 'wss://api.multisynq.io/depin',
      launcher: 'cli',
      enterpriseApiKey: enterpriseApiKey, // Store for future use
      synchronizerId: synchronizer.id
    };

    if (dashboardPassword) {
      config.dashboardPassword = dashboardPassword;
    }

    // Save configuration
    saveConfig(config);
    
    console.log(chalk.green('\n🎉 Enterprise API setup complete!'));
    console.log(chalk.blue('📁 Configuration saved to'), CONFIG_FILE);
    console.log(chalk.cyan(`🔗 Sync Name: ${syncHash}`));
    console.log(chalk.cyan(`🆔 Synchronizer ID: ${synchronizer.id}`));
    
    if (dashboardPassword) {
      console.log(chalk.yellow('🔒 Dashboard password protection enabled'));
    }
    
    // Ask what to do next
    const nextActionQuestion = await inquirer.prompt([{
      type: 'input',
      name: 'action',
      message: 'What would you like to do next? [S]tart, Se[R]vice, [W]eb, [Q]uit:',
      default: 'start',
      validate: (input) => {
        const normalized = input.toLowerCase().trim();
        if (['start', 's', 'service', 'r', 'web', 'w', 'quit', 'q'].includes(normalized)) {
          return true;
        }
        return 'Please enter: Start/S, Service/R, Web/W, or Quit/Q';
      }
    }]);

    const action = nextActionQuestion.action.toLowerCase().trim();
    
    if (action === 'start' || action === 's') {
      console.log(chalk.cyan('\n🚀 Starting synchronizer...'));
      await start();
    } else if (action === 'service' || action === 'r') {
      console.log(chalk.cyan('\n⚙️ Generating systemd service...'));
      await installService();
    } else if (action === 'web' || action === 'w') {
      console.log(chalk.cyan('\n🌐 Starting web dashboard...'));
      await startWebGUI();
    } else {
      console.log(chalk.gray('\n💡 You can now run:'));
      console.log(chalk.gray('   synchronize start     # Start synchronizer'));
      console.log(chalk.gray('   synchronize service   # Generate systemd service'));
      console.log(chalk.gray('   synchronize points    # View points'));
      console.log(chalk.gray('   synchronize web       # Launch dashboard'));
    }

  } catch (error) {
    console.error(chalk.red('❌ Enterprise API setup failed:'));
    console.error(chalk.red(error.message));
    
    if (error.message.includes('401') || error.message.includes('Unauthorized')) {
      console.error(chalk.yellow('\n💡 Troubleshooting:'));
      console.error(chalk.gray('• Check that your Enterprise API Key is correct'));
      console.error(chalk.gray('• Ensure your account has enterprise privileges'));
      console.error(chalk.gray('• Contact support if the issue persists'));
    } else if (error.message.includes('400') || error.message.includes('Bad Request')) {
      console.error(chalk.yellow('\n💡 The request was invalid. Check your inputs and try again.'));
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('network')) {
      console.error(chalk.yellow('\n💡 Network error. Check your internet connection and try again.'));
    }
    
    process.exit(1);
  }
}

/**
 * Automatic Enterprise API setup using API preferences
 * This fetches preferences from the Enterprise API and configures automatically
 */
async function setupViaEnterpriseAPIAutomatic(apiKey) {
  console.log(chalk.blue('🏢 Automatic Enterprise API Setup'));
  console.log(chalk.yellow('Using API preferences for hands-free configuration\n'));

  try {
    // First, call the Enterprise API to get preferences
    console.log(chalk.cyan('🔄 Fetching preferences from Enterprise API...'));
    
    const preferencesUrl = 'https://startsynqing.com/api/synq-keys/enterprise/preferences';
    
    const preferencesResponse = await fetch(preferencesUrl, {
      method: 'GET',
      headers: {
        'X-Enterprise-API-Key': apiKey,
        'Content-Type': 'application/json'
      }
    });

    if (!preferencesResponse.ok) {
      const errorText = await preferencesResponse.text();
      let errorMessage = `Failed to fetch preferences (${preferencesResponse.status})`;
      
      try {
        const errorJson = JSON.parse(errorText);
        errorMessage = errorJson.message || errorMessage;
      } catch (parseError) {
        errorMessage = errorText || errorMessage;
      }
      
      throw new Error(errorMessage);
    }

    const preferencesResult = await preferencesResponse.json();
    
    if (!preferencesResult.success) {
      throw new Error(preferencesResult.message || 'Failed to fetch preferences');
    }

    const preferences = preferencesResult.preferences;
    const owner = preferencesResult.owner;

    console.log(chalk.green('✅ Preferences retrieved successfully!'));
    console.log(chalk.gray(`   Wallet: ${preferences.walletAddress || 'Not set'}`));
    console.log(chalk.gray(`   Password: ${preferences.dashboardPassword ? '••••••••' : 'None'}`));
    console.log(chalk.gray(`   Default Action: ${preferences.defaultAction || 'start'}`));
    console.log(chalk.gray(`   Web Interface: ${preferences.web ? 'Yes' : 'No'}`));

    // Create synchronizer using Enterprise API
    console.log(chalk.cyan('\n🔄 Creating synchronizer via Enterprise API...'));
    
    const apiUrl = 'https://startsynqing.com/api/synq-keys/enterprise/synchronizer';
    
    // Use a default name if none provided in preferences
    const requestBody = {};
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'X-Enterprise-API-Key': apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorMessage = `API request failed (${response.status})`;
      
      try {
        const errorJson = JSON.parse(errorText);
        errorMessage = errorJson.message || errorMessage;
      } catch (parseError) {
        errorMessage = errorText || errorMessage;
      }
      
      throw new Error(errorMessage);
    }

    const result = await response.json();
    
    if (!result.success || !result.synchronizer) {
      throw new Error(result.message || 'Failed to create synchronizer');
    }

    const synchronizer = result.synchronizer;
    const finalName = synchronizer.name || synchronizer.id;
    
    console.log(chalk.green('✅ Synchronizer created successfully!'));
    console.log(chalk.gray(`   ID: ${synchronizer.id}`));
    console.log(chalk.gray(`   Name: ${finalName}`));
    console.log(chalk.gray(`   Synq Key: ${synchronizer.key}`));

    // Use wallet from preferences or fallback to owner wallet
    const walletAddress = preferences.walletAddress || owner.walletAddress;
    
    if (!walletAddress) {
      throw new Error('No wallet address found in preferences or owner information');
    }

    // Generate configuration using the API-provided synq key and preferences
    const secret = crypto.randomBytes(8).toString('hex');
    const hostname = os.hostname();
    const syncHash = generateSyncHash(finalName, secret, hostname);

    const config = {
      userName: finalName,
      key: synchronizer.key,
      wallet: walletAddress,
      secret,
      hostname,
      syncHash,
      depin: 'wss://api.multisynq.io/depin',
      launcher: 'cli',
      enterpriseApiKey: apiKey,
      synchronizerId: synchronizer.id
    };

    // Set dashboard password if provided in preferences
    if (preferences.dashboardPassword && preferences.dashboardPassword !== '••••••••') {
      config.dashboardPassword = preferences.dashboardPassword;
    }

    // Save configuration
    saveConfig(config);
    
    console.log(chalk.green('\n🎉 Automatic Enterprise API setup complete!'));
    console.log(chalk.blue('📁 Configuration saved to'), CONFIG_FILE);
    console.log(chalk.cyan(`🔗 Sync Name: ${syncHash}`));
    console.log(chalk.cyan(`🆔 Synchronizer ID: ${synchronizer.id}`));
    console.log(chalk.cyan(`💰 Wallet: ${walletAddress}`));
    
    if (config.dashboardPassword) {
      console.log(chalk.yellow('🔒 Dashboard password protection enabled'));
    } else {
      console.log(chalk.gray('🔓 No dashboard password set'));
    }
    // Start web interface if web preference is true
    if (preferences.web === true) {
      console.log(chalk.cyan('\n🌐 Starting web dashboard (from preferences)...'));
      // Start web interface in background
      setTimeout(() => {
        startWebGUI().catch(console.error);
      }, 1000);
    }


    // Execute default action from preferences
    const defaultAction = preferences.defaultAction || 'start';
    
    console.log(chalk.cyan(`\n🚀 Executing default action: ${defaultAction}`));
    
    if (defaultAction === 'start' || defaultAction === 's') {
      console.log(chalk.cyan('Starting synchronizer...'));
      await start();
    } else if (defaultAction === 'service' || defaultAction === 'r') {
      console.log(chalk.cyan('Generating systemd service...'));
      await installService();
    } else if (defaultAction === 'web' || defaultAction === 'w') {
      console.log(chalk.cyan('Starting web dashboard...'));
      await startWebGUI();
    } else {
      console.log(chalk.yellow(`Unknown default action: ${defaultAction}, skipping automatic execution`));
      console.log(chalk.gray('\n💡 You can now run:'));
      console.log(chalk.gray('   synchronize start     # Start synchronizer'));
      console.log(chalk.gray('   synchronize service   # Generate systemd service'));
      console.log(chalk.gray('   synchronize web       # Launch dashboard'));
    }

  } catch (error) {
    console.error(chalk.red('❌ Automatic Enterprise API setup failed:'));
    console.error(chalk.red(error.message));
    
    if (error.message.includes('401') || error.message.includes('Unauthorized')) {
      console.error(chalk.yellow('\n💡 Troubleshooting:'));
      console.error(chalk.gray('• Check that your Enterprise API Key is correct'));
      console.error(chalk.gray('• Ensure your account has enterprise privileges'));
      console.error(chalk.gray('• Contact support if the issue persists'));
    } else if (error.message.includes('400') || error.message.includes('Bad Request')) {
      console.error(chalk.yellow('\n💡 The request was invalid. Check your inputs and try again.'));
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('network')) {
      console.error(chalk.yellow('\n💡 Network error. Check your internet connection and try again.'));
    }
    
    process.exit(1);
  }
}

program
  .name('synchronize')
  .description(`🚀 Synchronizer v${packageJson.version} - Complete CLI Toolkit for Multisynq Synchronizer

🎯 FEATURES:
  • Docker container management with auto-installation
  • Enterprise API integration for automated synq key provisioning
  • Automated Docker image update monitoring (every 30-60 minutes)
  • Multi-platform support (Linux/macOS/Windows) 
  • Systemd service generation for headless operation
  • Real-time web dashboard with performance metrics
  • Persistent wallet lifetime points tracking (survives restarts)
  • Password-protected dashboard for security
  • Quality of Service (QoS) monitoring
  • Built-in troubleshooting and permission fixes
  • Platform architecture detection (ARM64/AMD64)
  
🌐 WEB DASHBOARD:
  • Real-time monitoring with performance metrics
  • Custom port configuration (--port and --metrics-port options)
  • Automatic port detection to prevent conflicts
  • Password protection and authentication
  • Quality of Service (QoS) indicators
  • Wallet address and points tracking
  • Docker image update monitoring
  • Systemd service management
  • Automatic update checking
  • Background monitoring service
  • Version tracking

🏢 ENTERPRISE API:
  • Automatic synq key provisioning via Enterprise API
  • Streamlined setup for enterprise deployments
  • Automated configuration with API-generated keys
  • Hands-free setup using API preferences (--api option)

🔄 DOCKER IMAGE MONITORING:
  • Automatic update checking every 30-60 minutes
  • Manual update checking with interactive pulls
  • Background monitoring service with systemd integration
  • Version tracking with CLI version / Docker version format

🐳 FIXED CONTAINER VERSIONING:
  • Displays "CLI {version} / Docker {version}" format
  • Proper environment variable injection for versions
  • Enhanced logging with versioned container information

💡 QUICK START:
    synchronize init          # Interactive configuration (manual)
    synchronize api           # Enterprise API setup (interactive)
    synchronize --api <key>   # Enterprise API setup (automatic)
    synchronize start         # Start synchronizer container
    synchronize nightly       # Run fixed nightly test version
    synchronize dashboard     # Launch web dashboard
    synchronize check-updates # Check for Docker image updates
    synchronize update        # Update CLI to latest version
    synchronize web                # Launch web dashboard (auto ports)
    synchronize web --port 8080    # Launch with custom dashboard port
    synchronize web -p 8080 -m 8081 # Custom dashboard and metrics ports
    
    # One-command deployment:
    synchronize deploy -k <synq-key> -w <wallet-address>
    synchronize deploy -k <synq-key> -w <wallet-address> -p 8080 -m 8081
    synchronize deploy -k <synq-key> -w <wallet-address> --password <pwd> -n <name>`)
  .version(packageJson.version)
  .option('--api <key>', 'Automatic Enterprise API setup using API key and preferences');

program.command('init')
  .description('Interactive configuration')
  .option('-k, --key [synq_key]', 'synq key to use (will prompt if not provided)')
  .option('-w, --wallet [wallet_address]', 'wallet address for points tracking')
  .option('-d, --depin [depin_endpoint]', 'depin endpoint URL')
  .option('-a, --account [account_id]', 'account ID for synchronizer')
  .action(init);
program.command('start').description('Build and run synchronizer Docker container').action(start);
program.command('service').description('Generate systemd service file for headless service').action(installService);
program.command('service-web').description('Generate systemd service file for web dashboard').action(async () => {
  try {
    const result = await installWebServiceFile();
    console.log(chalk.green('✅ Web service file generated successfully!'));
    console.log(chalk.blue(`📁 Service file: ${result.serviceFile}`));
    console.log(chalk.cyan(`🔧 Detected npx path: ${result.npxPath}`));
    console.log(chalk.cyan(`📂 NPX directory: ${result.npxDir}`));
    console.log(chalk.cyan(`🛤️  PATH environment: ${result.pathEnv}`));
    console.log(chalk.blue('\n📋 To install the service, run:'));
    console.log(chalk.gray(result.instructions));
    console.log(chalk.yellow('\n💡 Note: The service includes PATH environment variable to ensure npx is accessible'));
  } catch (error) {
    console.error(chalk.red('❌ Error generating web service:'), error.message);
    process.exit(1);
  }
});
program.command('status').description('Show systemd service status and recent logs').action(showStatus);
program.command('web')
  .description('Start web dashboard and metrics server with optional Enterprise API setup')
  .option('-p, --port <port>', 'Dashboard port (default: 3000)', parseInt)
  .option('-m, --metrics-port <port>', 'Metrics port (default: 3001)', parseInt)
  .option('-a, --api <key>', 'Enterprise API key for automatic setup')
  .option('-d, --dashboard-password <password>', 'Set dashboard password')
  .option('-w, --wallet <address>', 'Wallet address')
  .option('-s, --synchronizer-id <id>', 'Synchronizer ID (for existing configs)')
  .option('-n, --synchronizer-name <n>', 'Synchronizer name (for display/reference)')
  .action(async (options) => {
    try {
      await startWebGUI(options);
    } catch (error) {
      console.error(chalk.red('❌ Failed to start web dashboard:'), error.message);
      process.exit(1);
    }
  });
program.command('install-docker').description('Install Docker automatically (Linux only)').action(installDocker);
program.command('fix-docker').description('Fix Docker permissions (add user to docker group)').action(fixDockerPermissions);
program.command('test-platform').description('Test Docker platform compatibility').action(testPlatform);
program.command('points').description('Show wallet lifetime points and stats').action(showPoints);
program.command('set-password').description('Set or change the dashboard password').action(setDashboardPassword);
program.command('validate-key [key]')
  .description('Validate a synq key format and check availability with API')
  .action(validateSynqKey);
program.command('nightly').description('Start synchronizer with latest nightly test Docker image').action(startNightly);
program.command('test-nightly').description('Test nightly launch with direct Docker command').action(testNightly);
program.command('check-updates').description('Check for Docker image updates manually').action(checkImageUpdates);
program.command('monitor').description('Start background monitoring for Docker image updates').action(startImageMonitoring);
program.command('monitor-service').description('Generate systemd service file for image monitoring').action(async () => {
  try {
    const result = await installImageMonitoringService();
    console.log(chalk.green('✅ Image monitoring service file generated successfully!'));
    console.log(chalk.blue(`📁 Service file: ${result.serviceFile}`));
    console.log(chalk.blue('\n📋 To install the monitoring service, run:'));
    console.log(chalk.gray(result.instructions));
    console.log(chalk.yellow('\n💡 The monitoring service will check for Docker image updates every 30 minutes'));
    console.log(chalk.cyan('🔍 View monitoring logs with: journalctl -u synchronizer-cli-monitor -f'));
  } catch (error) {
    console.error(chalk.red('❌ Error generating monitoring service:'), error.message);
    process.exit(1);
  }
});
program.command('api').description('Set up synchronizer via Enterprise API').action(setupViaEnterpriseAPI);
program.command('api-auto').description('Automatic Enterprise API setup using API preferences').action(async () => {
  try {
    const apiKey = await inquirer.prompt([{
      type: 'password',
      name: 'apiKey',
      message: 'Enter Enterprise API Key:',
      validate: input => input ? true : 'Enterprise API Key is required'
    }]);
    await setupViaEnterpriseAPIAutomatic(apiKey.apiKey);
  } catch (error) {
    console.error(chalk.red('❌ Error setting up Enterprise API:'), error.message);
    process.exit(1);
  }
});
program.command('clear-cache').description('Clear wallet points cache to force fresh API data').action(clearWalletPointsCache);

// Temporarily disabled due to linter errors - to be fixed in next version
// program.command('test-websocket')
//   .description('Test direct WebSocket connection to synchronizer container')
//   .option('-t, --timeout <seconds>', 'Test timeout in seconds (default: 30)', parseInt, 30)
//   .option('-q, --quiet', 'Reduce output verbosity')
//   .action(testWebSocketConnection);

program.command('deploy')
  .description('One-command deployment: configure, start synchronizer, and launch web dashboard')
  .requiredOption('-k, --key <synq-key>', 'Synq key (required)')
  .requiredOption('-w, --wallet <address>', 'Wallet address (required)')
  .option('-n, --name <name>', 'Optional sync name for reference')
  .option('-p, --port <port>', 'Dashboard port (default: 3000)', parseInt)
  .option('-m, --metrics-port <port>', 'Metrics port (default: 3001)', parseInt)
  .option('--password <password>', 'Dashboard password for security')
  .action(deployAll);

program.command('update')
  .description('Update synchronizer-cli to the latest version from npm')
  .option('--check-only', 'Only check for updates without installing')
  .option('--force', 'Force reinstall even if already latest version')
  .action(updateCLI);

// Handle global --api option before parsing commands
const options = program.opts();

// Check if --api option is provided
if (process.argv.includes('--api')) {
  const apiIndex = process.argv.indexOf('--api');
  if (apiIndex !== -1 && apiIndex + 1 < process.argv.length) {
    const apiKey = process.argv[apiIndex + 1];
    if (apiKey && !apiKey.startsWith('-')) {
      // Run automatic Enterprise API setup
      (async () => {
        try {
          await setupViaEnterpriseAPIAutomatic(apiKey);
        } catch (error) {
          console.error(chalk.red('❌ Error with automatic Enterprise API setup:'), error.message);
          process.exit(1);
        }
      })();
      return; // Exit early to prevent normal command parsing
    } else {
      console.error(chalk.red('❌ --api option requires an API key'));
      console.error(chalk.yellow('Usage: synchronize --api <enterprise-api-key>'));
      process.exit(1);
    }
  }
}

program.parse(process.argv);

/**
 * Clear the wallet points cache (useful for testing or forcing fresh data)
 */
function clearWalletPointsCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      fs.unlinkSync(CACHE_FILE);
    }
    console.log(chalk.green('✅ Wallet points cache cleared'));
    console.log(chalk.gray('Next points request will fetch fresh data from API'));
  } catch (error) {
    console.log(chalk.yellow(`⚠️ Warning: Could not clear cache file: ${error.message}`));
  }
}

async function deployAll(options) {
  console.log(chalk.blue('🚀 Starting one-command deployment...'));
  console.log(chalk.gray('Configuring synchronizer, starting container, and launching web dashboard\n'));

  try {
    // 1. Create configuration from command line options
    const config = {
      userName: options.name || `sync-${Date.now()}`,
      key: options.key,
      wallet: options.wallet,
      secret: crypto.randomBytes(8).toString('hex'),
      hostname: os.hostname(),
      depin: 'wss://api.multisynq.io/depin',
      launcher: 'cli'
    };
    
    // Generate sync hash
    config.syncHash = generateSyncHash(config.userName, config.secret, config.hostname);
    
    // Set dashboard password if provided
    if (options.password) {
      config.dashboardPassword = options.password;
    }

    // 2. Save the configuration
    console.log(chalk.cyan('📝 Saving configuration...'));
    saveConfig(config);
    console.log(chalk.green('✅ Configuration saved successfully'));

    // 3. Start the synchronizer container
    console.log(chalk.cyan('🐳 Starting synchronizer container...'));
    await start(); // Use existing start function
    
    // Wait a moment for container to initialize
    console.log(chalk.gray('⏳ Waiting for container initialization...'));
    await new Promise(resolve => setTimeout(resolve, 3000));

    // 4. Start the web dashboard
    console.log(chalk.cyan('🌐 Launching web dashboard...'));
    const webOptions = {
      port: options.port,
      metricsPort: options.metricsPort
    };
    await startWebGUI(webOptions);

  } catch (error) {
    console.error(chalk.red('❌ Deployment failed:'), error.message);
    process.exit(1);
  }
}

async function getContainerStats() {
  try {
    const now = Date.now();
    
    // Check if we have recent cached data
    if (lastStatsResult && (now - lastStatsRequestTime) < STATS_CACHE_DURATION) {
      // Return cached data silently - no new request needed
      return lastStatsResult;
    }

    // Check rate limiting - only allow actual requests once per minute
    if (lastStatsRequestTime > 0 && (now - lastStatsRequestTime) < STATS_REQUEST_COOLDOWN) {
      // Return cached data or null if no cache available
      return lastStatsResult || null;
    }

    // If a request is already in progress, wait for it instead of starting a new one
    if (statsRequestInProgress) {
      console.log(chalk.gray('⏳ Waiting for in-progress stats request...'));
      return await statsRequestInProgress;
    }

    // THIS is where we actually make a new request - create a promise to prevent race conditions
    console.log(chalk.blue('🔄 Making fresh stats request (not cached)'));
    
    statsRequestInProgress = (async () => {
      try {
        // Check for either synchronizer container
        const containerNames = ['synchronizer-cli', 'synchronizer-nightly'];
        let containerName = null;
        
        // Find which container is running
        for (const name of containerNames) {
          try {
            const psOutput = execSync(`docker ps --filter name=${name} --format "{{.Names}}"`, {
              encoding: 'utf8',
              stdio: 'pipe'
            });
            
            if (psOutput.includes(name)) {
              containerName = name;
              break;
            }
          } catch (error) {
            // Continue checking next container name
          }
        }
        
        if (!containerName) {
          // No synchronizer container running
          lastStatsResult = null;
          console.log(chalk.yellow('⚠️ No synchronizer container running'));
          return null;
        }

        // Use existing WebSocket connection if available (NEVER create new ones here)
        const realtimeData = getLatestContainerData();
        
        // Container is running, proceed with stats gathering
        
        // Check how long the container has been running
        const inspectOutput = execSync(`docker inspect ${containerName} --format "{{.State.StartedAt}}"`, {
          encoding: 'utf8',
          stdio: 'pipe'
        });
        
        const startTime = new Date(inspectOutput.trim());
        const nowTime = new Date();
        const uptimeMs = nowTime.getTime() - startTime.getTime();
        const uptimeHours = uptimeMs / (1000 * 60 * 60);
        
        let isEarningPoints = false;
        let realStats = null;
        
        if (realtimeData) {
          // Use real-time WebSocket data (most accurate)
          console.log(chalk.green('✅ Using fresh WebSocket data'));
          realStats = parseReflectorStats(realtimeData, latestContainerData);
          isEarningPoints = realStats ? realStats.isEarning : false;
          
        } else {
          // No WebSocket data available, try HTTP metrics endpoint
          console.log(chalk.yellow('⚠️ No WebSocket data, trying HTTP metrics'));
          // const httpStats = await getStatsFromReflectorHTTP(containerName);
          
          if (httpStats) {
            // Use HTTP metrics data
            realStats = {
              syncLifePoints: 0, // Not available from Prometheus metrics
              walletLifePoints: 0, // Not available from Prometheus metrics  
              syncLifeTraffic: (httpStats.bytesIn || 0) + (httpStats.bytesOut || 0),
              bytesIn: httpStats.bytesIn || 0,
              bytesOut: httpStats.bytesOut || 0,
              sessions: httpStats.sessions || 0,
              users: httpStats.users || 0,
              proxyConnectionState: httpStats.proxyConnectionState || 'UNKNOWN',
              availability: 1, // Assume OK if we can get metrics
              reliability: 1,
              efficiency: 1,
              isEarning: httpStats.isEarning
            };
            isEarningPoints = realStats.isEarning;
            console.log(chalk.green('✅ Using HTTP metrics data'));
          } else {
            // HTTP metrics also failed, fall back to log parsing
            console.log(chalk.yellow('⚠️ HTTP metrics failed, parsing logs'));
            realStats = await parseContainerLogs(containerName);
            isEarningPoints = realStats ? realStats.isEarning : false;
          }
        }
        
        // Build result
        let result = null;
        
        // Use real stats if found, otherwise return null to show "Unavailable"
        if (realStats) {
          // Return real stats from container
          result = {
            bytesIn: realStats.bytesIn || 0,
            bytesOut: realStats.bytesOut || 0,
            bytesInDelta: realStats.bytesInDelta || 0,
            bytesOutDelta: realStats.bytesOutDelta || 0,
            sessions: realStats.sessions || 0,
            users: realStats.users || 0,
            syncLifePoints: realStats.syncLifePoints || 0,
            syncLifePointsDelta: realStats.syncLifePointsDelta || 0,
            syncLifeTraffic: realStats.syncLifeTraffic || (realStats.bytesIn + realStats.bytesOut) || 0,
            walletLifePoints: realStats.walletLifePoints || 0,
            walletBalance: realStats.walletBalance || 0,
            availability: realStats.availability !== undefined ? realStats.availability : 2,
            reliability: realStats.reliability !== undefined ? realStats.reliability : 2,
            efficiency: realStats.efficiency !== undefined ? realStats.efficiency : 2,
            ratingsBlurbs: realStats.ratingsBlurbs || null,
            proxyConnectionState: realStats.proxyConnectionState || 'UNKNOWN',
            now: Date.now(),
            uptimeHours: uptimeHours,
            isEarningPoints: isEarningPoints,
            hasRealStats: true,
            hasWebSocketData: !!realtimeData,
            hasHTTPStats: realStats && !realtimeData && realStats.sessions !== undefined,
            containerStartTime: startTime.toISOString(),
            dataSource: realtimeData ? 'websocket' : (realStats && realStats.sessions !== undefined ? 'http_metrics' : 'log_parsing')
          };
          
          console.log(chalk.green(`✅ Fresh stats retrieved: ${result.dataSource}, Points: ${result.walletLifePoints}, Traffic: ${result.syncLifeTraffic}`));
          console.log(chalk.cyan(`🔍 Result ratingsBlurbs: ${result.ratingsBlurbs ? 'PRESENT' : 'NULL'}`));
          if (result.ratingsBlurbs) {
            console.log(chalk.cyan(`   Blurbs keys: ${Object.keys(result.ratingsBlurbs).join(', ')}`));
          }
        } else {
          console.log(chalk.red('❌ No stats data available from any source'));
        }
        
        return result;
        
      } finally {
        // Always clear the in-progress flag
        statsRequestInProgress = null;
      }
    })();

    const result = await statsRequestInProgress;
    
    // ONLY set the timestamp and cache AFTER we actually completed the request
    lastStatsRequestTime = now;
    lastStatsResult = result;
    console.log(chalk.cyan(`📝 Stats cached for ${STATS_CACHE_DURATION/1000} seconds`));
    
    return result;
    
  } catch (error) {
    console.log(chalk.red(`❌ Error in getContainerStats: ${error.message}`));
    statsRequestInProgress = null; // Clear the flag on error
    return lastStatsResult || null; // Return cached data if available
  }
}

async function showPoints() {
  console.log(chalk.blue('💰 Wallet Lifetime Points'));
  console.log(chalk.yellow('Fetching points data...\n'));

  const config = loadConfig();
  if (!config.wallet) {
    console.error(chalk.red('❌ Missing wallet address. Run `synchronize init` first.'));
    process.exit(1);
  }

  try {
    const pointsData = await getPointsDataForCommand(config);
    const containerStats = await getContainerStats();
    
    console.log(chalk.cyan(`🔗 Wallet: ${config.wallet}`));
    if (config.syncHash) {
      console.log(chalk.cyan(`🔑 Sync Hash: ${config.syncHash}`));
    }
    console.log('');
    
    if (pointsData.error) {
      console.log(chalk.red(`❌ Error: ${pointsData.error}`));
      if (pointsData.fallback) {
        console.log(chalk.yellow('📊 Using fallback data'));
      }
    } else {
      console.log(chalk.green('✅ Points data retrieved successfully'));
      
      // Show the data source
      if (pointsData.source === 'external_api') {
        console.log(chalk.green('🌐 Using real data from external API (most accurate)'));
      } else if (pointsData.source === 'container_stats') {
        console.log(chalk.cyan('🐳 Using data from container stats'));
      } else {
        console.log(chalk.yellow('📊 Using calculated stats based on container uptime'));
      }
    }
    
    console.log('');
    console.log(chalk.bold('📈 LIFETIME POINTS BREAKDOWN:'));
    console.log('');
    
    const points = pointsData.points;
    console.log(chalk.yellow(`💎 Total Points:    ${chalk.bold(points.total.toLocaleString())}`));
    console.log(chalk.blue(`📅 Today:           ${chalk.bold(points.daily.toLocaleString())}`));
    console.log(chalk.blue(`📊 This Week:       ${chalk.bold(points.weekly.toLocaleString())}`));
    console.log(chalk.blue(`📈 This Month:      ${chalk.bold(points.monthly.toLocaleString())}`));
    console.log(chalk.green(`🔥 Streak:          ${chalk.bold(points.streak)} days`));
    console.log(chalk.magenta(`🏆 Rank:            ${chalk.bold(points.rank)}`));
    console.log(chalk.cyan(`⚡ Multiplier:      ${chalk.bold(points.multiplier)}x`));
    
    // Display external API specific details if available
    if (pointsData.source === 'external_api') {
      console.log('');
      console.log(chalk.bold('🌐 EXTERNAL API DETAILS:'));
      console.log('');
      
      if (pointsData.serviceCredits !== undefined) {
        console.log(chalk.blue(`💰 Service Credits: ${chalk.bold(pointsData.serviceCredits.toLocaleString())}`));
      }
      
      if (pointsData.lastWithdrawn !== undefined) {
        console.log(chalk.blue(`💸 Last Withdrawn:  ${chalk.bold(pointsData.lastWithdrawn.toLocaleString())} credits`));
      }
      
      if (pointsData.lastUpdated) {
        const lastUpdated = pointsData.lastUpdated === 0 ? 'Never' : new Date(pointsData.lastUpdated).toLocaleString();
        console.log(chalk.blue(`⏰ Last Updated:    ${chalk.bold(lastUpdated)}`));
      }
    }
    
    if (containerStats) {
      console.log('');
      console.log(chalk.bold('🐳 CONTAINER STATUS:'));
      console.log('');
      console.log(chalk.blue(`⏱️  Uptime:          ${chalk.bold(containerStats.uptimeHours.toFixed(1))} hours`));
      console.log(chalk.blue(`🚀 Started:         ${chalk.bold(new Date(containerStats.containerStartTime).toLocaleString())}`));
      console.log(chalk.blue(`💰 Earning:         ${chalk.bold(containerStats.isEarningPoints ? '✅ Yes' : '❌ No')}`));
      console.log(chalk.blue(`🔗 Connection:      ${chalk.bold(containerStats.proxyConnectionState)}`));
      
      // Show WebSocket connectivity status
      if (containerStats.hasWebSocketData) {
        console.log(chalk.blue(`🔌 WebSocket:       ${chalk.bold('✅ Connected (Real-time data)')}`));
      } else {
        console.log(chalk.blue(`🔌 WebSocket:       ${chalk.bold('❌ Disconnected (Fallback data)')}`));
      }
      
      console.log(chalk.blue(`👥 Sessions:        ${chalk.bold(containerStats.sessions)}`));
      console.log(chalk.blue(`👤 Users:           ${chalk.bold(containerStats.users)}`));
      
      const totalTraffic = containerStats.bytesIn + containerStats.bytesOut;
      const trafficMB = (totalTraffic / (1024 * 1024)).toFixed(2);
      console.log(chalk.blue(`📊 Traffic:         ${chalk.bold(trafficMB)} MB`));
    }
    
    console.log('');
    console.log(chalk.gray(`🕐 Last updated: ${new Date(pointsData.timestamp).toLocaleString()}`));
    
    if (pointsData.source) {
      console.log(chalk.gray(`📡 Data source: ${pointsData.source}`));
    }
    
  } catch (error) {
    console.error(chalk.red('❌ Error fetching points data:'), error.message);
    process.exit(1);
  }
}

async function setDashboardPassword() {
  console.log(chalk.blue('🔒 Dashboard Password Setup'));
  console.log(chalk.yellow('Configure password protection for the web dashboard\n'));

  const config = loadConfig();
  
  if (config.dashboardPassword) {
    console.log(chalk.yellow('Dashboard password is currently set.'));
    
    const changePassword = await inquirer.prompt([{
      type: 'confirm',
      name: 'change',
      message: 'Do you want to change the existing password?',
      default: false
    }]);
    
    if (!changePassword.change) {
      console.log(chalk.gray('Password unchanged.'));
      return;
    }
  }

  const questions = [{
    type: 'list',
    name: 'action',
    message: 'What would you like to do?',
    choices: [
      { name: 'Set a new password', value: 'set' },
      { name: 'Remove password protection', value: 'remove' }
    ]
  }];

  const { action } = await inquirer.prompt(questions);

  if (action === 'remove') {
    delete config.dashboardPassword;
    saveConfig(config);
    console.log(chalk.green('✅ Password protection removed'));
    console.log(chalk.yellow('⚠️  Dashboard is now unprotected - synq key will be visible to anyone'));
    return;
  }

  const passwordQuestions = [{
    type: 'password',
    name: 'password',
    message: 'Enter new dashboard password:',
    validate: input => input && input.length >= 4 ? true : 'Password must be at least 4 characters',
    mask: '*'
  }, {
    type: 'password',
    name: 'confirmPassword',
    message: 'Confirm password:',
    validate: (input, answers) => input === answers.password ? true : 'Passwords do not match',
    mask: '*'
  }];

  const { password } = await inquirer.prompt(passwordQuestions);
  
  config.dashboardPassword = password;
  saveConfig(config);
  
  console.log(chalk.green('✅ Dashboard password set successfully'));
  console.log(chalk.blue('🔒 Dashboard is now password protected'));
  console.log(chalk.gray('Use any username with your password to access the web dashboard'));
  console.log(chalk.gray('Restart the web dashboard for changes to take effect'));
}

async function validateSynqKey(keyToValidate) {
  let nicknameToUse = 'cli-validator'; // Default nickname
  
  // If no key is provided, prompt for one
  if (!keyToValidate) {
    const answers = await inquirer.prompt([
      {
        type: 'input',
        name: 'key',
        message: 'Enter synq key to validate:',
        validate: input => input ? true : 'Synq key is required'
      },
      {
        type: 'input',
        name: 'nickname',
        message: 'Enter a nickname for validation (optional):',
        default: nicknameToUse
      }
    ]);
    
    keyToValidate = answers.key;
    nicknameToUse = answers.nickname;
  } else {
    // If key was provided as argument, prompt only for nickname
    const answer = await inquirer.prompt([{
      type: 'input',
      name: 'nickname',
      message: 'Enter a nickname for validation (optional):',
      default: nicknameToUse
    }]);
    
    nicknameToUse = answer.nickname;
  }
  
  console.log(chalk.blue('🔑 Synq Key Validation'));
  console.log(chalk.gray('Validating synq key format and availability\n'));
  console.log(chalk.gray(`Using nickname: ${nicknameToUse}`));
  
  // First validate the format locally
  console.log(chalk.cyan('Checking key format...'));
  const isValidFormat = validateSynqKeyFormat(keyToValidate);
  
  if (!isValidFormat) {
    console.log(chalk.red('❌ Invalid key format'));
    console.log(chalk.yellow('Key must be in UUID v4 format:'));
    console.log(chalk.gray('XXXXXXXX-XXXX-4XXX-YXXX-XXXXXXXXXXXX where Y is 8, 9, A, or B'));
    return;
  }
  
  console.log(chalk.green('✅ Key format is valid'));
  
  // If format is valid, check with API
  console.log(chalk.cyan('\nChecking key with remote API...'));
  const apiResult = await validateSynqKeyWithAPI(keyToValidate, nicknameToUse);
  
  if (apiResult.isValid) {
    console.log(chalk.green('✅ Key is valid and available for use'));
    console.log(chalk.gray(`API Response: ${apiResult.message}`));
  } else {
    console.log(chalk.red(`❌ API validation failed: ${apiResult.message}`));
    
    // Provide helpful context based on error message
    if (apiResult.message.includes('does not exist')) {
      console.log(chalk.yellow('This key does not exist in the system.'));
    } else if (apiResult.message.includes('in use')) {
      console.log(chalk.yellow('This key is already being used by another synchronizer.'));
    } else if (apiResult.message.includes('disabled')) {
      console.log(chalk.yellow('This key has been disabled by an administrator.'));
    } else if (apiResult.message.includes('deleted')) {
      console.log(chalk.yellow('This key has been deleted from the system.'));
    } else {
      console.log(chalk.yellow('There was an issue validating this key.'));
    }
  }
}

async function checkImageUpdates() {
  console.log(chalk.blue('🔍 Checking for Docker Image Updates'));
  console.log(chalk.yellow('Checking all synchronizer Docker images...\n'));

  const images = [
    { name: 'cdrakep/synqchronizer:latest', description: 'Main synchronizer image' },
    { name: 'cdrakep/synqchronizer-test-fixed:latest', description: 'Fixed nightly test image' }
  ];

  let updatesAvailable = 0;

  for (const image of images) {
    console.log(chalk.cyan(`Checking ${image.description}...`));
    console.log(chalk.gray(`Image: ${image.name}`));
    
    try {
      const hasUpdate = await isNewDockerImageAvailable(image.name);
      
      if (hasUpdate) {
        console.log(chalk.yellow(`🔄 Update available for ${image.name}`));
        updatesAvailable++;
        
        const shouldPull = await inquirer.prompt([{
          type: 'confirm',
          name: 'pull',
          message: `Pull latest version of ${image.name}?`,
          default: true
        }]);
        
        if (shouldPull.pull) {
          try {
            console.log(chalk.cyan(`Pulling ${image.name}...`));
            execSync(`docker pull ${image.name}`, { stdio: 'inherit' });
            console.log(chalk.green(`✅ Successfully updated ${image.name}`));
          } catch (error) {
            console.log(chalk.red(`❌ Failed to pull ${image.name}: ${error.message}`));
          }
        }
      } else {
        console.log(chalk.green(`✅ ${image.name} is up to date`));
      }
      
      console.log(''); // Add spacing between images
    } catch (error) {
      console.log(chalk.red(`❌ Error checking ${image.name}: ${error.message}`));
      console.log('');
    }
  }

  console.log(chalk.blue('📊 Update Check Summary:'));
  if (updatesAvailable === 0) {
    console.log(chalk.green('✅ All images are up to date'));
  } else {
    console.log(chalk.yellow(`🔄 ${updatesAvailable} image(s) had updates available`));
  }
  
  console.log(chalk.gray('\n💡 Tip: Use `synchronize monitor` to automatically check for updates'));
}

async function startImageMonitoring() {
  console.log(chalk.blue('🕐 Starting Docker Image Monitoring'));
  console.log(chalk.yellow('Background service to check for image updates every 30 minutes\n'));

  const config = loadConfig();
  
  // Configuration for monitoring
  const monitoringConfig = {
    checkInterval: 30 * 60 * 1000, // 30 minutes in milliseconds
    autoUpdate: false, // Set to true to automatically pull updates
    notifyOnly: true   // Just notify, don't auto-update
  };

  const images = [
    'cdrakep/synqchronizer:latest',
    'cdrakep/synqchronizer-test-fixed:latest'
  ];

  console.log(chalk.cyan(`📋 Monitoring Configuration:`));
  console.log(chalk.gray(`   Check interval: ${monitoringConfig.checkInterval / 60000} minutes`));
  console.log(chalk.gray(`   Auto-update: ${monitoringConfig.autoUpdate ? 'Enabled' : 'Disabled'}`));
  console.log(chalk.gray(`   Images: ${images.length} configured`));
  console.log('');

  let checkCount = 0;

  const performCheck = async () => {
    checkCount++;
    const timestamp = new Date().toLocaleString();
    
    console.log(chalk.blue(`🔍 Check #${checkCount} at ${timestamp}`));
    
    let updatesFound = 0;
    
    for (const imageName of images) {
      try {
        const hasUpdate = await isNewDockerImageAvailable(imageName);
        
        if (hasUpdate) {
          updatesFound++;
          console.log(chalk.yellow(`🔄 Update available: ${imageName}`));
          
          if (monitoringConfig.autoUpdate) {
            try {
              console.log(chalk.cyan(`⬇️ Auto-updating ${imageName}...`));
              execSync(`docker pull ${imageName}`, { stdio: 'pipe' });
              console.log(chalk.green(`✅ Auto-updated ${imageName}`));
            } catch (error) {
              console.log(chalk.red(`❌ Auto-update failed for ${imageName}: ${error.message}`));
            }
          }
        } else {
          console.log(chalk.gray(`✅ ${imageName} is up to date`));
        }
      } catch (error) {
        console.log(chalk.red(`❌ Error checking ${imageName}: ${error.message}`));
      }
    }
    
    if (updatesFound === 0) {
      console.log(chalk.green(`✅ All ${images.length} images are up to date`));
    } else {
      console.log(chalk.yellow(`🔄 Found ${updatesFound} image(s) with updates`));
      if (!monitoringConfig.autoUpdate) {
        console.log(chalk.gray('   Run `synchronize check-updates` to update manually'));
      }
    }
    
    console.log(chalk.gray(`⏰ Next check in ${monitoringConfig.checkInterval / 60000} minutes\n`));
  };

  // Perform initial check
  await performCheck();

  // Set up interval for periodic checks
  const monitoringInterval = setInterval(performCheck, monitoringConfig.checkInterval);

  console.log(chalk.green('🚀 Monitoring started - Press Ctrl+C to stop'));
  console.log(chalk.gray('Tip: You can safely run this in the background or as a systemd service\n'));

  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log(chalk.yellow('\n🛑 Stopping image monitoring...'));
    clearInterval(monitoringInterval);
    console.log(chalk.green('✅ Monitoring stopped'));
    process.exit(0);
  });

  // Keep the process alive
  setInterval(() => {
    // Just keep the monitoring alive
  }, 1000);
}

/**
 * Connect to the Docker container's internal WebSocket for real-time metrics
 * The container exposes a WebSocket on port 3333 for CLI communication via wrapper.js
 * @param {string} containerName Name of the Docker container
 * @returns {Promise<boolean>} True if connection successful
 */
async function connectToContainerWebSocket(containerName) {
  // If already connected and working, don't reconnect
  if (containerWebSocket && containerWebSocket.readyState === WebSocket.OPEN) {
    return true;
  }

  // If connection in progress, don't start another
  if (wsConnectionInProgress) {
    return false;
  }

  // Don't attempt connection if we've already failed multiple times recently
  // FIXED: This function NO LONGER creates connections to prevent duplicates
  // All connection creation is handled by initializeGlobalWebSocket()
  console.log(chalk.yellow('⚠️ connectToContainerWebSocket called - now handled by initializeGlobalWebSocket()'));
  return false;
}

/**
 * Disconnect from the container WebSocket
 */
function disconnectContainerWebSocket() {
  if (containerWebSocket) {
    containerWebSocket.close();
    containerWebSocket = null;
    latestContainerData = null;
    console.log(chalk.gray('🔌 Disconnected from container CLI WebSocket'));
  }
}

/**
 * Get the latest real-time data from the container WebSocket
 * @returns {object|null} Latest container data or null if not available
 */
function getLatestContainerData() {
  // Check if data is recent (within last 90 seconds to outlast the 60-second cache)
  if (latestContainerData && (Date.now() - latestContainerData.receivedAt) < 90000) {
    return latestContainerData;
  }
  return null;
}

/**
 * Parse stats data received from the reflector via WebSocket
 * @param {object} data Raw data from reflector WebSocket
 * @param {object} existingData Previous data to preserve certain fields from
 * @returns {object|null} Parsed stats or null if data is invalid
 */
function parseReflectorStats(data, existingData = null) {
  if (!data || typeof data !== 'object') {
    return null;
  }
  
  try {
    // The reflector sends responses in different formats depending on the request type
    let statsData = data;
    
    // Handle wrapped responses (e.g., {what: "stats", value: {...}})
    if (data.what === 'stats' && data.value) {
      statsData = data.value;
      console.log(chalk.cyan(`🔍 Parsing wrapped stats response with ${Object.keys(statsData).length} fields`));
    } else if (data.what === 'QUERY_WALLET_STATS' || data.what === 'UPDATE_TALLIES') {
      // Handle wallet-specific stats messages
      statsData = data;
      console.log(chalk.cyan(`🔍 Parsing wallet stats message: ${data.what}`));
    } else if (data.what === 'debug') {
      // Handle debug responses that may contain stats
      statsData = { ...data, ...(data.value || {}) };
      console.log(chalk.cyan(`🔍 Parsing debug response with ${Object.keys(statsData).length} fields`));
    } else {
      // Handle direct stats objects (not wrapped)
      console.log(chalk.cyan(`🔍 Parsing direct stats object with ${Object.keys(statsData).length} fields`));
    }
    console.dir(statsData, { depth: null });
    // Log all available fields for debugging
    console.log(chalk.gray(`Available fields: ${Object.keys(statsData).join(', ')}`));
    
    // Parse the data format that comes from the reflector L() function in refl.js
    const stats = {
      // Core wallet and sync data (highest priority)
      syncLifePoints: statsData.syncLifePoints || 0,
      walletLifePoints: statsData.walletLifePoints || 0,
      syncLifeTraffic: statsData.syncLifeTraffic || 0,
      walletBalance: statsData.walletBalance || 0,
      
      // Network traffic data
      bytesIn: statsData.bytesIn || 0,
      bytesOut: statsData.bytesOut || 0,
      
      // Session and user data (real activity indicators)
      sessions: statsData.sessions || 0,
      demoSessions: statsData.demoSessions || 0,
      users: statsData.users || 0,
      
      // Connection and proxy state
      proxyConnectionState: statsData.proxyConnectionState || 'UNKNOWN',
      
      // Performance ratings
      availability: statsData.availability !== undefined ? statsData.availability : 2,
      reliability: statsData.reliability !== undefined ? statsData.reliability : 2,
      efficiency: statsData.efficiency !== undefined ? statsData.efficiency : 2,
      
      // Timing and metadata
      now: statsData.now || Date.now(),
      ratingsTimepoint: statsData.ratingsTimepoint,
      
      // Handle ratingsBlurbs with persistence
      ratingsBlurbs: statsData.ratingsBlurbs || (existingData ? existingData.ratingsBlurbs : null),
      
      // Additional fields that might be available
      numApps: statsData.numApps || 0, // Running apps/utilities
      tallyPeriodStart: statsData.tallyPeriodStart,
      
      // Handle legacy field names that might be in the data
      lifePoints: statsData.lifePoints, // Alternative name for syncLifePoints
      lifeTraffic: statsData.lifeTraffic, // Alternative name for syncLifeTraffic
      walletPoints: statsData.walletPoints // Alternative name for walletLifePoints
    };
    
    // Use legacy fields if main fields are zero/empty
    if (stats.syncLifePoints === 0 && statsData.lifePoints) {
      stats.syncLifePoints = statsData.lifePoints;
    }
    if (stats.syncLifeTraffic === 0 && statsData.lifeTraffic) {
      stats.syncLifeTraffic = statsData.lifeTraffic;
    }
    if (stats.walletLifePoints === 0 && statsData.walletPoints) {
      stats.walletLifePoints = statsData.walletPoints;
    }
    
    // Determine if the synchronizer is earning points based on multiple indicators
    stats.isEarning = stats.proxyConnectionState === 'CONNECTED' || 
                     stats.sessions > 0 || 
                     stats.users > 0 ||
                     stats.syncLifePoints > 0 ||
                     stats.numApps > 0 ||
                     (statsData.isEarning !== undefined ? statsData.isEarning : false);
    
    // Log the key parsed stats for verification
    console.log(chalk.green(`✅ Parsed reflector stats:`));
    console.log(chalk.green(`   Sessions: ${stats.sessions}, Users: ${stats.users}`));
    console.log(chalk.green(`   Sync Life Points: ${stats.syncLifePoints}, Traffic: ${stats.syncLifeTraffic}`));
    console.log(chalk.green(`   Wallet Points: ${stats.walletLifePoints}, Balance: ${stats.walletBalance}`));
    console.log(chalk.green(`   Connection: ${stats.proxyConnectionState}, Earning: ${stats.isEarning}`));
    console.log(chalk.green(`   QoS Ratings: Avail=${stats.availability}, Rel=${stats.reliability}, Eff=${stats.efficiency}`));
    if (stats.ratingsBlurbs) {
      console.log(chalk.green(`   Ratings Blurbs: PRESENT`));
    }
    
    return stats;
  } catch (error) {
    console.log(chalk.yellow(`⚠️ Error parsing reflector stats: ${error.message}`));
    console.log(chalk.gray(`Raw data: ${JSON.stringify(data).substring(0, 300)}...`));
    return null;
  }
}

/**
 * Parse container logs for stats (fallback when WebSocket is not available)
 * @param {string} containerName Name of the container
 * @returns {object|null} Parsed stats or null if not found
 */
async function parseContainerLogs(containerName) {
  try {
    // Get comprehensive logs to extract stats data
    const logsOutput = execSync(`docker logs ${containerName} --tail 100`, {
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 10000
    });
    
    // Look for signs that the synchronizer is actually working
    const isEarning = logsOutput.includes('proxy-connected') || 
                     logsOutput.includes('registered') ||
                     logsOutput.includes('session') ||
                     logsOutput.includes('traffic') ||
                     logsOutput.includes('stats');
    
    let realStats = null;
    
    // Try to extract real stats from logs if available
    // Look for JSON stats messages in the logs
    const logLines = logsOutput.split('\n');
    for (const line of logLines.reverse()) { // Start from most recent
      try {
        // Look for JSON objects that might contain stats
        const jsonMatch = line.match(/\{.*"syncLifePoints".*\}/);
        if (jsonMatch) {
          const statsData = JSON.parse(jsonMatch[0]);
          if (statsData.syncLifePoints !== undefined || statsData.walletLifePoints !== undefined) {
            realStats = { ...statsData, isEarning };
            break;
          }
        }
        
        // Look for UPDATE_TALLIES messages from the registry
        const updateTalliesMatch = line.match(/\{.*"what":\s*"UPDATE_TALLIES".*\}/);
        if (updateTalliesMatch) {
          const talliesData = JSON.parse(updateTalliesMatch[0]);
          if (talliesData.walletPoints !== undefined) {
            realStats = realStats || { isEarning };
            realStats.walletLifePoints = talliesData.walletPoints;
            realStats.syncLifePoints = talliesData.lifePoints || realStats.syncLifePoints;
            realStats.syncLifeTraffic = talliesData.lifeTraffic || realStats.syncLifeTraffic;
          }
        }
        
        // Look for stats patterns with "walletPoints" (no "Life")
        const walletPointsMatch = line.match(/walletPoints[:\s]+(\d+)/i);
        if (walletPointsMatch) {
          realStats = realStats || { isEarning };
          realStats.walletLifePoints = parseInt(walletPointsMatch[1]);
        }
        
        // Also look for other stat patterns
        const pointsMatch = line.match(/points[:\s]+(\d+)/i);
        const trafficMatch = line.match(/traffic[:\s]+(\d+)/i);
        const sessionsMatch = line.match(/sessions[:\s]+(\d+)/i);
        
        if (pointsMatch || trafficMatch || sessionsMatch) {
          realStats = realStats || { isEarning };
          if (pointsMatch) realStats.syncLifePoints = parseInt(pointsMatch[1]);
          if (trafficMatch) realStats.syncLifeTraffic = parseInt(trafficMatch[1]);
          if (sessionsMatch) realStats.sessions = parseInt(sessionsMatch[1]);
        }
      } catch (parseError) {
        // Continue looking through logs
      }
    }
    
    return realStats;
    
  } catch (logError) {
    console.log(chalk.yellow(`⚠️ Could not parse container logs: ${logError.message}`));
    return null;
  }
}

/**
 * Fetch wallet lifetime points from the API
 * @param {string|null} apiKey Optional API key for authenticated requests (deprecated - not used with external API)
 * @param {string} walletAddress Wallet address to fetch points for
 * @param {object} config Configuration object
 * @returns {Promise<object>} API response with points data
 */
async function fetchWalletLifetimePoints(apiKey, walletAddress, config) {
  if (!walletAddress) {
    return {
      success: false,
      error: 'Missing wallet address'
    };
  }

  try {
    // Use the external API endpoint with wallet address in URL
    const apiUrl = `https://startsynqing.com/api/external/multisynq/synqers/${walletAddress}`;
    
    console.log(chalk.gray(`🔗 Fetching points from: ${apiUrl}`));

    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': `synchronizer-cli/${packageJson.version}`
    };

    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: headers,
      timeout: 10000
    });

    if (!response.ok) {
      return {
        success: false,
        error: `API responded with ${response.status}: ${response.statusText}`
      };
    }

    const data = await response.json();
    
    console.log(chalk.green(`✅ Points API response: ${JSON.stringify(data)}`));
    
    // Transform the external API response to match expected format
    const transformedData = {
      lifetimePoints: data.serviceCredits || 0,
      lastWithdrawn: data.lastWithdrawnCredits || 0,
      lastUpdated: data.lastUpdated || 0,
      // Add calculated fields for compatibility
      dailyPoints: 0, // Not available from external API
      weeklyPoints: 0, // Not available from external API
      monthlyPoints: 0, // Not available from external API
      streak: 0, // Not available from external API
      rank: 'N/A', // Not available from external API
      multiplier: '1.0' // Not available from external API
    };
    
    return {
      success: true,
      data: transformedData
    };

  } catch (error) {
    console.log(chalk.red(`❌ Points API error: ${error.message}`));
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Generate systemd service file for image monitoring
 */
async function installImageMonitoringService() {
  const config = loadConfig();
  const serviceFile = path.join(CONFIG_DIR, 'synchronizer-cli-monitor.service');
  const user = os.userInfo().username;
  const npxPath = detectNpxPath();
  
  // Get the directory containing npx for PATH
  const npxDir = path.dirname(npxPath);
  
  // Build PATH environment variable including npx directory
  const systemPaths = [
    '/usr/local/sbin',
    '/usr/local/bin', 
    '/usr/sbin',
    '/usr/bin',
    '/sbin',
    '/bin'
  ];
  
  // Add npx directory to the beginning of PATH if it's not already a system path
  const pathDirs = systemPaths.includes(npxDir) ? systemPaths : [npxDir, ...systemPaths];
  const pathEnv = pathDirs.join(':');

  const unit = `[Unit]
Description=Synchronizer CLI Docker Image Monitor
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=${user}
Restart=always
RestartSec=30
WorkingDirectory=${os.homedir()}
ExecStart=${npxPath} synchronize monitor
Environment=NODE_ENV=production
Environment=PATH=${pathEnv}

[Install]
WantedBy=multi-user.target
`;

  fs.writeFileSync(serviceFile, unit);
  
  const instructions = `sudo cp ${serviceFile} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable synchronizer-cli-monitor
sudo systemctl start synchronizer-cli-monitor`;

  return {
    success: true,
    serviceFile,
    instructions,
    message: 'Docker image monitoring service file generated successfully'
  };
}

/**
 * Get version information for all components
 * @returns {Promise<object>} Object containing version information
 */
async function getVersionInfo() {
  const versions = {
    cli: packageJson.version,
    dockerImage: 'Unknown',
    containerImage: 'Unknown', 
    reflectorVersion: 'Unknown',
    launcher: 'Unknown'
  };

  try {
    // Try to get Docker image version from main image
    const imageName = 'cdrakep/synqchronizer:latest';
    try {
      const imageInspectOutput = execSync(`docker inspect ${imageName} --format "{{json .Config.Labels}}"`, {
        encoding: 'utf8',
        stdio: 'pipe'
      });
      
      const labels = JSON.parse(imageInspectOutput);
      if (labels && labels.version) {
        versions.dockerImage = labels.version;
      } else {
        // Get image creation date as fallback
        const createdOutput = execSync(`docker inspect ${imageName} --format "{{.Created}}"`, {
          encoding: 'utf8',
          stdio: 'pipe'
        });
        const created = new Date(createdOutput.trim());
        versions.dockerImage = `${created.toISOString().split('T')[0]}`;
      }
    } catch (error) {
      versions.dockerImage = 'latest';
    }

    // Try to get version from running container
    const containerNames = ['synchronizer-cli', 'synchronizer-nightly'];
    for (const containerName of containerNames) {
      try {
        const psOutput = execSync(`docker ps --filter name=${containerName} --format "{{.Names}}"`, {
          encoding: 'utf8',
          stdio: 'pipe'
        });
        
        if (psOutput.includes(containerName)) {
          // Get container image version
          const containerImageOutput = execSync(`docker inspect ${containerName} --format "{{.Config.Image}}"`, {
            encoding: 'utf8',
            stdio: 'pipe'
          });
          versions.containerImage = containerImageOutput.trim();
          
          // Try to get reflector version from container logs
          try {
            const logsOutput = execSync(`docker logs ${containerName} --tail 50`, {
              encoding: 'utf8',
              stdio: 'pipe'
            });
            
            // Look for version information in logs
            const versionMatch = logsOutput.match(/version[:\s]+([0-9.]+)/i);
            if (versionMatch) {
              versions.reflectorVersion = versionMatch[1];
            }
          } catch (logError) {
            // Logs not accessible
          }
          
          break;
        }
      } catch (error) {
        // Container not running or not accessible
      }
    }

    // Generate launcher string
    versions.launcher = `cli-${versions.cli}/docker-${versions.dockerImage}`;

  } catch (error) {
    // Keep default values on error
  }

  return versions;
}

/**
 * Generate systemd service file for web dashboard
 * @returns {Promise<object>} Service generation result
 */
async function installWebServiceFile() {
  const config = loadConfig();
  const serviceFile = path.join(CONFIG_DIR, 'synchronizer-cli-web.service');
  const user = os.userInfo().username;
  const npxPath = detectNpxPath();
  
  // Get the directory containing npx for PATH
  const npxDir = path.dirname(npxPath);
  
  // Build PATH environment variable including npx directory
  const systemPaths = [
    '/usr/local/sbin',
    '/usr/local/bin', 
    '/usr/sbin',
    '/usr/bin',
    '/sbin',
    '/bin'
  ];
  
  // Add npx directory to the beginning of PATH if it's not already a system path
  const pathDirs = systemPaths.includes(npxDir) ? systemPaths : [npxDir, ...systemPaths];
  const pathEnv = pathDirs.join(':');

  const unit = `[Unit]
Description=Synchronizer CLI Web Dashboard
After=network.target
Wants=network.target

[Service]
Type=simple
User=${user}
Restart=always
RestartSec=10
WorkingDirectory=${os.homedir()}
ExecStart=${npxPath} synchronize web
Environment=NODE_ENV=production
Environment=PATH=${pathEnv}

[Install]
WantedBy=multi-user.target
`;

  fs.writeFileSync(serviceFile, unit);
  
  const instructions = `sudo cp ${serviceFile} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable synchronizer-cli-web
sudo systemctl start synchronizer-cli-web`;

  return {
    success: true,
    serviceFile,
    npxPath,
    npxDir,
    pathEnv,
    instructions,
    message: 'Web dashboard service file generated successfully'
  };
}

/**
 * Test WebSocket connection to synchronizer container
 * @param {object} options Command options
 */
async function testWebSocketConnection(options = {}) {
  console.log(chalk.blue('🧪 WebSocket Connection Test'));
  console.log(chalk.yellow('Testing direct connection to synchronizer container WebSocket\n'));

  const timeout = (options.timeout || 30) * 1000;
  const quiet = options.quiet || false;

  // Check if container is running first
  try {
    const psOutput = execSync('docker ps --filter name=synchronizer --format "{{.Names}}"', {
      encoding: 'utf8',
      stdio: 'pipe'
    });
    
    if (!psOutput.trim()) {
      console.log(chalk.red('❌ No synchronizer container found running'));
      console.log(chalk.yellow('Start a container first with: synchronize start'));
      return { success: false, error: 'No container running' };
    }
    
    console.log(chalk.green(`✅ Found running container: ${psOutput.trim()}`));
  } catch (error) {
    console.log(chalk.red('❌ Error checking containers:', error.message));
    return { success: false, error: error.message };
  }

  // Run the WebSocket test
  const result = await runWebSocketTest(timeout, quiet);
  
  if (result.success) {
    console.log(chalk.green('\n✅ WebSocket test completed successfully'));
    console.log(chalk.blue(`📊 Total messages received: ${result.messageCount}`));
    
    if (result.hasRealData) {
      console.log(chalk.green('🎉 Real data detected in WebSocket responses!'));
    } else if (result.hasAnyData) {
      console.log(chalk.yellow('⚠️  Connected but only zero/empty data detected'));
    } else {
      console.log(chalk.red('❌ No meaningful data received'));
    }
  } else {
    console.log(chalk.red('\n❌ WebSocket test failed'));
    console.log(chalk.red(`Error: ${result.error}`));
  }

  return result;
}

/**
 * Run WebSocket test and return results
 * @param {number} timeout Test timeout in milliseconds
 * @param {boolean} quiet Reduce logging verbosity
 * @returns {Promise<object>} Test results
 */
function runWebSocketTest(timeout = 30000, quiet = false) {
  // Temporarily disabled function to fix syntax errors
  return Promise.resolve({
    success: false,
    error: 'WebSocket test temporarily disabled - function has syntax errors',
    messageCount: 0,
    messages: [],
    rawMessages: [],
    test: { 
      success: false, 
      error: 'Temporarily disabled', 
      messageCount: 0, 
      hasRealData: false, 
      dataQuality: 'unknown', 
      totalFields: 0, 
      uniqueMessageTypes: new Set(), 
      statsFound: null 
    }
  });
}

/**
 * Analyze WebSocket data quality
 * @param {object} data WebSocket message data
 * @returns {string} Quality assessment
 */
function analyzeWebSocketDataQuality(data) {
  const stats = data.value || data.data || data;
  
  if (!stats || typeof stats !== 'object') {
    return 'No stats data found';
  }
  
  // Check for signs of real data
  const hasNonZeroSessions = (stats.sessions && stats.sessions > 0);
  const hasNonZeroUsers = (stats.users && stats.users > 0);
  const hasLifePoints = (stats.syncLifePoints && stats.syncLifePoints > 0) || (stats.walletLifePoints && stats.walletLifePoints > 0);
  const hasTraffic = (stats.bytesIn && stats.bytesIn > 0) || (stats.bytesOut && stats.bytesOut > 0);
  const hasConnectionState = stats.proxyConnectionState && stats.proxyConnectionState !== 'UNKNOWN';
  
  // Check for signs of fake data
  const allZeros = !hasNonZeroSessions && !hasNonZeroUsers && !hasLifePoints && !hasTraffic;
  const onlyConnectedState = hasConnectionState && !hasNonZeroSessions && !hasNonZeroUsers;
  
  if (allZeros) {
    return '❌ ALL ZEROS - No real activity detected';
  } else if (onlyConnectedState) {
    return '⚠️  CONNECTED BUT NO ACTIVITY - May be waiting for traffic';
  } else if (hasNonZeroSessions || hasNonZeroUsers) {
    return '✅ REAL ACTIVITY DETECTED - Has active sessions/users';
  } else if (hasLifePoints) {
    return '✅ LIFETIME POINTS DETECTED - Has earning history';
  } else {
    return '❔ UNCLEAR - Data present but quality uncertain';
  }
}

/**
 * Update synchronizer-cli to the latest version from npm
 * @param {object} options Command options
 */
async function updateCLI(options = {}) {
  console.log(chalk.blue('📦 Synchronizer CLI Update'));
  console.log(chalk.yellow('Checking for updates from npm...\n'));

  const currentVersion = packageJson.version;
  console.log(chalk.cyan(`📌 Current version: ${currentVersion}`));

  try {
    // Check the latest version on npm
    console.log(chalk.gray('🔍 Checking npm for latest version...'));
    
    const npmInfoOutput = execSync('npm info synchronizer-cli version', {
      encoding: 'utf8',
      stdio: 'pipe'
    });
    
    const latestVersion = npmInfoOutput.trim();
    console.log(chalk.cyan(`🌟 Latest version: ${latestVersion}`));

    // Compare versions
    const isUpToDate = currentVersion === latestVersion;
    const needsUpdate = !isUpToDate || options.force;

    if (isUpToDate && !options.force) {
      console.log(chalk.green('\n✅ You are already running the latest version!'));
      console.log(chalk.gray('Use --force to reinstall the current version'));
      return;
    }

    if (options.checkOnly) {
      if (needsUpdate) {
        console.log(chalk.yellow(`\n🔄 Update available: ${currentVersion} → ${latestVersion}`));
        console.log(chalk.gray('Run `synchronize update` to install the latest version'));
      } else {
        console.log(chalk.green('\n✅ No updates available'));
      }
      return;
    }

    // Show what will be updated
    if (options.force) {
      console.log(chalk.yellow(`\n🔄 Force reinstalling version ${latestVersion}`));
    } else {
      console.log(chalk.yellow(`\n🔄 Update available: ${currentVersion} → ${latestVersion}`));
    }

    // Ask for confirmation
    const shouldUpdate = await inquirer.prompt([{
      type: 'confirm',
      name: 'proceed',
      message: `Proceed with ${options.force ? 'reinstalling' : 'updating'} synchronizer-cli?`,
      default: true
    }]);

    if (!shouldUpdate.proceed) {
      console.log(chalk.gray('Update cancelled.'));
      return;
    }

    // Perform the update
    console.log(chalk.cyan('\n⬇️ Installing latest version...'));
    console.log(chalk.gray('This may take a moment...'));

    try {
      // Install the latest version globally
      execSync('npm install -g synchronizer-cli@latest', {
        stdio: 'inherit'
      });

      console.log(chalk.green('\n✅ Update completed successfully!'));
      
      // Show the version we updated to (we already know this from latestVersion)
      console.log(chalk.cyan(`🎉 Successfully updated to version ${latestVersion}`));
      
      // Important note about restarting
      console.log(chalk.yellow('\n⚠️  IMPORTANT: You need to restart your terminal or start a new CLI session'));
      console.log(chalk.yellow('   to use the updated version. This CLI instance is still running v' + currentVersion));

      // Show what's new if it's a real update (not force reinstall)
      if (!options.force) {
        console.log(chalk.blue('\n📋 To verify the update:'));
        console.log(chalk.gray('• Open a new terminal and run `synchronize --version`'));
        console.log(chalk.gray('• Run `synchronize --help` to see all commands'));
        console.log(chalk.gray('• Visit https://www.npmjs.com/package/synchronizer-cli for changelog'));
      } else {
        console.log(chalk.blue('\n📋 To verify the reinstall:'));
        console.log(chalk.gray('• Open a new terminal and run `synchronize --version`'));
      }

    } catch (updateError) {
      console.error(chalk.red('\n❌ Update failed:'), updateError.message);
      
      // Provide troubleshooting tips
      console.log(chalk.yellow('\n💡 Troubleshooting:'));
      console.log(chalk.gray('• Make sure you have npm installed and up to date'));
      console.log(chalk.gray('• Try running with sudo (Linux/macOS): sudo npm install -g synchronizer-cli@latest'));
      console.log(chalk.gray('• Check your internet connection'));
      console.log(chalk.gray('• Clear npm cache: npm cache clean --force'));
      
      process.exit(1);
    }

  } catch (error) {
    console.error(chalk.red('❌ Error checking for updates:'), error.message);
    
    if (error.message.includes('ENOENT') || error.message.includes('npm not found')) {
      console.log(chalk.yellow('\n💡 npm is not installed or not in PATH'));
      console.log(chalk.gray('Install Node.js and npm from: https://nodejs.org/'));
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('network')) {
      console.log(chalk.yellow('\n💡 Network error - check your internet connection'));
    } else {
      console.log(chalk.yellow('\n💡 You can also update manually with:'));
      console.log(chalk.gray('npm install -g synchronizer-cli@latest'));
    }
    
    process.exit(1);
  }
}

/**
 * Initialize WebSocket connection once and never create multiple connections
 * This is called when the web server starts to establish persistent connection
 */
async function initializeGlobalWebSocket() {
  if (wsInitialized) {
    console.log(chalk.gray('🔌 WebSocket already initialized'));
    return;
  }

  wsInitialized = true;
  console.log(chalk.blue('🔌 Initializing global WebSocket connection...'));

  // Try to find which container is running
  const containerNames = ['synchronizer-cli', 'synchronizer-nightly'];
  let containerName = null;
  
  for (const name of containerNames) {
    try {
      const psOutput = execSync(`docker ps --filter name=${name} --format "{{.Names}}"`, {
        encoding: 'utf8',
        stdio: 'pipe'
      }).trim();
      
      if (psOutput.includes(name)) {
        containerName = name;
        console.log(chalk.blue(`🔍 Found running container: ${containerName}`));
        break;
      }
    } catch (error) {
      // Container not found, try next one
      continue;
    }
  }

  if (!containerName) {
    console.log(chalk.yellow('⚠️ No synchronizer container found running'));
    return;
  }

  // Start the WebSocket connection to the correct port
  await startWebSocketConnection(containerName);
}

/**
 * Start persistent WebSocket connection that never creates duplicates
 */
async function startPersistentWebSocket() {
  // STRICT: Never create multiple connections
  if (containerWebSocket && containerWebSocket.readyState === WebSocket.OPEN) {
    console.log(chalk.gray('🔌 WebSocket already connected and working'));
    return true;
  }

  if (wsConnectionInProgress) {
    console.log(chalk.gray('🔌 WebSocket connection already in progress'));
    return false;
  }

  wsConnectionInProgress = true;

  try {
    const wsUrl = `ws://localhost:3333`;
    console.log(chalk.cyan(`🔌 Creating persistent WebSocket connection to ${wsUrl}`));
    
    return new Promise((resolve) => {
      const ws = new WebSocket(wsUrl, {
        handshakeTimeout: 5000,
        timeout: 5000
      });
      
      const timeout = setTimeout(() => {
        ws.terminate();
        wsConnectionInProgress = false;
        console.log(chalk.yellow(`⚠️ WebSocket connection timeout to ${wsUrl}`));
        resolve(false);
      }, 10000);
      
      ws.on('open', () => {
        clearTimeout(timeout);
        wsConnectionInProgress = false;
        containerWebSocket = ws;
        
        console.log(chalk.green(`🔌 PERSISTENT WebSocket connected successfully`));
        
        // Set up message handler for reflector responses
        ws.on('message', (data) => {
          try {
            const message = JSON.parse(data.toString());
            
            // Store the latest data with timestamp and merge with previous data
            // Preserve ratingsBlurbs from previous messages if not present in current message
            const previousBlurbs = latestContainerData ? latestContainerData.ratingsBlurbs : null;
            
            latestContainerData = {
              ...(latestContainerData || {}), // Keep previous data
              ...message, // Merge in new data
              receivedAt: Date.now()
            };
            
            // Handle specific message types
            if (message.what) {
              if (message.what === 'stats' && message.value) {
                latestContainerData = {
                  ...latestContainerData,
                  ...message.value,
                  receivedAt: Date.now()
                };
                
                // Preserve ratingsBlurbs if not in current message but was in previous
                if (!latestContainerData.ratingsBlurbs && previousBlurbs) {
                  latestContainerData.ratingsBlurbs = previousBlurbs;
                  console.log(chalk.gray('📋 Preserved previous ratingsBlurbs'));
                }
              } else if (message.what === 'UPDATE_TALLIES') {
                if (message.lifePoints !== undefined) {
                  latestContainerData.syncLifePoints = message.lifePoints;
                }
                if (message.lifeTraffic !== undefined) {
                  latestContainerData.syncLifeTraffic = message.lifeTraffic;
                }
                if (message.walletPoints !== undefined) {
                  latestContainerData.walletLifePoints = message.walletPoints;
                }
                if (message.walletBalance !== undefined) {
                  latestContainerData.walletBalance = message.walletBalance;
                }
                
                // Preserve ratingsBlurbs for UPDATE_TALLIES messages too
                if (!latestContainerData.ratingsBlurbs && previousBlurbs) {
                  latestContainerData.ratingsBlurbs = previousBlurbs;
                }
              }
            } else {
              // For direct messages, preserve ratingsBlurbs if not present
              if (!latestContainerData.ratingsBlurbs && previousBlurbs) {
                latestContainerData.ratingsBlurbs = previousBlurbs;
                console.log(chalk.gray('📋 Preserved ratingsBlurbs from previous message'));
              }
            }
            
          } catch (error) {
            // Ignore parsing errors
          }
        });
        
        // Handle disconnection - but DO NOT reconnect automatically
        ws.on('close', () => {
          console.log(chalk.yellow('🔌 PERSISTENT WebSocket disconnected - will use cached data'));
          containerWebSocket = null;
          wsConnectionInProgress = false;
          // DO NOT reset wsInitialized - keep using cached data
        });
        
        ws.on('error', (error) => {
          console.log(chalk.yellow(`⚠️ PERSISTENT WebSocket error: ${error.message}`));
          containerWebSocket = null;
          wsConnectionInProgress = false;
          // DO NOT reset wsInitialized - keep using cached data
        });
        
        // Send periodic stats requests every 30 seconds to keep data fresh
        const statsInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ what: 'stats' }));
            console.log(chalk.gray(`📡 Sent periodic stats request`));
          } else {
            clearInterval(statsInterval);
          }
        }, 30000);
        
        // Send initial stats request
        setTimeout(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ what: 'stats' }));
            console.log(chalk.gray(`📡 Sent initial stats request`));
          }
        }, 500);
        
        resolve(true);
      });
      
      ws.on('error', (error) => {
        clearTimeout(timeout);
        wsConnectionInProgress = false;
        console.log(chalk.yellow(`⚠️ PERSISTENT WebSocket connection failed: ${error.message}`));
        resolve(false);
      });
    });
    
  } catch (error) {
    wsConnectionInProgress = false;
    console.log(chalk.yellow(`⚠️ PERSISTENT WebSocket connection error: ${error.message}`));
    return false;
  }
}

/**
 * Check if WebSocket connection exists and is working
 * This function NO LONGER creates connections - just checks status
 * @param {string} containerName Name of the Docker container (for logging only)
 * @returns {boolean} True if connection exists and is open
 */
function connectToContainerWebSocket(containerName) {
  // Just check if we have an active connection
  if (containerWebSocket && containerWebSocket.readyState === WebSocket.OPEN) {
    console.log(chalk.gray('🔌 Using existing WebSocket connection'));
    return true;
  }
  
  if (containerWebSocket) {
    console.log(chalk.yellow(`⚠️ WebSocket exists but state is: ${containerWebSocket.readyState}`));
  } else {
    console.log(chalk.yellow('⚠️ No WebSocket connection available'));
  }
  
  return false;
}

/**
 * Start a persistent WebSocket connection to the container's internal reflector
 * @param {string} containerName Name of the Docker container
 */
async function startPersistentWebSocket(containerName) {
  if (containerWebSocket && containerWebSocket.readyState === WebSocket.OPEN) {
    console.log(chalk.gray('🔌 WebSocket already connected'));
    return;
  }

  try {
    // Actually, let's use HTTP requests to the reflector's metrics endpoint
    // The reflector.js shows it supports /metrics, /sessions, /users endpoints
    console.log(chalk.blue(`🔌 Setting up HTTP connection to reflector on port 9090...`));
    
    // Test connection to the reflector's metrics endpoint
    const response = await fetch('http://localhost:9090/metrics');
    if (response.ok) {
      const metricsText = await response.text();
      latestContainerData = {
        // Parse Prometheus metrics from the reflector
        syncLifeTraffic: extractMetricValue(metricsText, 'reflector_messages_total') || 0,
        sessions: extractMetricValue(metricsText, 'reflector_sessions') || 0,
        users: extractMetricValue(metricsText, 'reflector_connections') || 0,
        syncLifePoints: 0, // Not available from reflector metrics
        walletLifePoints: 0, // Not available from reflector metrics  
        proxyConnectionState: 'CONNECTED',
        hasWebSocketData: true,
        receivedAt: Date.now()
      };
      console.log(chalk.green('🔌 Connected to reflector HTTP endpoint'));
      console.log(chalk.gray('📊 Retrieved initial reflector stats'));
    } else {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
  } catch (error) {
    console.log(chalk.red(`❌ Failed to connect to reflector: ${error.message}`));
    wsConnectionAttempts++;
  }
}

// Helper function to extract metrics values from Prometheus format
function extractMetricValue(metricsText, metricName) {
  if (typeof metricsText !== 'string') return null;
  
  const lines = metricsText.split('\n');
  for (const line of lines) {
    if (line.startsWith(metricName) && !line.startsWith('#')) {
      const parts = line.split(' ');
      if (parts.length >= 2) {
        return parseFloat(parts[1]) || 0;
      }
    }
  }
  return null;
}

/**
 * Start periodic HTTP polling to the container's internal reflector
 * @param {string} containerName Name of the Docker container
 */
async function startReflectorPolling(containerName) {
  if (containerWebSocket && containerWebSocket._pollInterval) {
    console.log(chalk.gray('🔌 Reflector polling already active'));
    return;
  }

  try {
    console.log(chalk.blue(`🔌 Setting up HTTP polling to reflector on port 9090...`));
    
    // Function to fetch latest stats from reflector
    const fetchReflectorStats = async () => {
      try {
        const response = await fetch('http://localhost:3000/metrics');
        if (response.ok) {
          const metricsText = await response.text();
          
          // Also get session info
          const sessionsResponse = await fetch('http://localhost:9090/sessions');
          const sessionsText = sessionsResponse.ok ? await sessionsResponse.text() : '';
          
          latestContainerData = {
            // Parse Prometheus metrics from the reflector
            syncLifeTraffic: extractMetricValue(metricsText, 'reflector_messages_total') || 0,
            sessions: extractMetricValue(metricsText, 'reflector_sessions') || 0,
            users: extractMetricValue(metricsText, 'reflector_connections') || 0,
            syncLifePoints: 0, // Not available from reflector metrics
            walletLifePoints: 0, // Not available from reflector metrics  
            proxyConnectionState: 'CONNECTED',
            hasWebSocketData: true,
            receivedAt: Date.now(),
            // Additional metrics from reflector
            totalMessages: extractMetricValue(metricsText, 'reflector_messages_total') || 0,
            totalTicks: extractMetricValue(metricsText, 'reflector_ticks_total') || 0,
            sessionsDetails: sessionsText
          };
          console.log(chalk.gray('📊 Updated reflector stats via HTTP'));
        }
      } catch (error) {
        console.log(chalk.yellow(`⚠️ Error fetching reflector stats: ${error.message}`));
      }
    };
    
    // Initial fetch
    await fetchReflectorStats();
    console.log(chalk.green('🔌 Connected to reflector HTTP endpoint'));
    
    // Set up periodic polling (every 30 seconds to avoid spam)
    const pollInterval = setInterval(fetchReflectorStats, 30000);
    
    // Store the interval ID so we can clean it up later
    containerWebSocket = { _pollInterval: pollInterval };
    
  } catch (error) {
    console.log(chalk.red(`❌ Failed to connect to reflector: ${error.message}`));
    wsConnectionAttempts++;
  }
}

/**
 * Start WebSocket connection to the container's reflector WebSocket server
 * The reflector runs a WebSocket server on port 9090 (as shown in reflector.js)
 * @param {string} containerName Name of the Docker container
 */
async function startWebSocketConnection(containerName) {
  if (containerWebSocket && containerWebSocket.readyState === WebSocket.OPEN) {
    console.log(chalk.gray('🔌 WebSocket already connected'));
    return;
  }

  try {
    // Connect to the reflector's WebSocket server on port 9090 (from reflector.js line 215)
    const wsUrl = `ws://localhost:3333`;
    console.log(chalk.cyan(`🔌 Connecting to reflector WebSocket at ${wsUrl}...`));
    
    containerWebSocket = new WebSocket(wsUrl);
    
    containerWebSocket.on('open', () => {
      console.log(chalk.green('🔌 Connected to reflector WebSocket'));
      
      // Send initial stats request
      const statsRequest = { what: 'stats' };
      containerWebSocket.send(JSON.stringify(statsRequest));
      console.log(chalk.gray('📡 Sent initial stats request'));
      
      // Set up periodic stats requests every 30 seconds
      const statsInterval = setInterval(() => {
        if (containerWebSocket && containerWebSocket.readyState === WebSocket.OPEN) {
          containerWebSocket.send(JSON.stringify({ what: 'stats' }));
          console.log(chalk.gray('📡 Sent periodic stats request'));
        } else {
          clearInterval(statsInterval);
        }
      }, 30000);
    });
    
    containerWebSocket.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        
        // Store the latest data with timestamp
        latestContainerData = {
          ...message,
          receivedAt: Date.now()
        };
        
        // Log the data received for debugging
        console.log(chalk.cyan(`📨 WebSocket data: ${Object.keys(message).join(', ')}`));
        
        // Handle different message types from reflector
        if (message.what === 'stats' && message.value) {
          console.dir(message.value, { depth: null });
          // Merge stats data
          latestContainerData = {
            ...latestContainerData,
            ...message.value,
            receivedAt: Date.now()
          };
          console.dir(latestContainerData, { depth: null });
          console.log(chalk.green(`✅ Received stats: sessions=${message.value.sessions}, users=${message.value.users}`));
        }
        
      } catch (error) {
        console.log(chalk.yellow(`⚠️ Error parsing WebSocket message: ${error.message}`));
      }
    });
    
    containerWebSocket.on('close', (code, reason) => {
      console.log(chalk.yellow(`🔌 WebSocket disconnected: ${code} ${reason}`));
      containerWebSocket = null;
      // Don't automatically reconnect to avoid spam
    });
    
    containerWebSocket.on('error', (error) => {
      console.log(chalk.red(`❌ WebSocket error: ${error.message}`));
      containerWebSocket = null;
    });
    
  } catch (error) {
    console.log(chalk.red(`❌ Failed to connect to WebSocket: ${error.message}`));
    wsConnectionAttempts++;
  }
}

/**
 * Get points data specifically for the synchronize points command
 * This function is isolated and doesn't affect the web dashboard
 * @param {object} config Configuration object
 * @returns {Promise<object>} Points data from external API or container stats
 */
async function getPointsDataForCommand(config) {
  if (!config.wallet) {
    return {
      timestamp: new Date().toISOString(),
      points: {
        total: 0,
        daily: 0,
        weekly: 0,
        monthly: 0,
        streak: 0,
        rank: 'N/A',
        multiplier: '1.0'
      },
      error: 'Missing wallet address'
    };
  }

  // PRIORITY 1: Try external API first (dedicated for points command)
  console.log(chalk.cyan('🌐 Fetching points from external API...'));
  try {
    const apiData = await fetchWalletLifetimePoints(null, config.wallet, config);
    
    if (apiData.success) {
      const data = apiData.data;
      console.log(chalk.green(`✅ External API returned ${data.lifetimePoints} service credits`));
      
      return {
        timestamp: new Date().toISOString(),
        points: {
          total: data.lifetimePoints,
          daily: data.dailyPoints,
          weekly: data.weeklyPoints,
          monthly: data.monthlyPoints,
          streak: data.streak,
          rank: data.rank,
          multiplier: data.multiplier
        },
        // External API specific fields
        serviceCredits: data.lifetimePoints,
        lastWithdrawn: data.lastWithdrawn,
        lastUpdated: data.lastUpdated,
        source: 'external_api'
      };
    } else {
      console.log(chalk.yellow(`⚠️ External API failed: ${apiData.error}`));
    }
  } catch (error) {
    console.log(chalk.red(`❌ External API error: ${error.message}`));
  }

  // PRIORITY 2: Fallback to container stats if available
  const containerStats = await getContainerStats();
  if (containerStats && (containerStats.walletLifePoints > 0 || containerStats.syncLifePoints > 0)) {
    console.log(chalk.blue('🐳 Using container stats as fallback'));
    
    return {
      timestamp: new Date().toISOString(),
      points: {
        total: containerStats.walletLifePoints + containerStats.syncLifePoints,
        daily: 0, // Not tracked by container
        weekly: 0, // Not tracked by container
        monthly: 0, // Not tracked by container
        streak: 0, // Not tracked by container
        rank: 'N/A', // Not tracked by container
        multiplier: 'N/A' // Not tracked by container
      },
      syncLifePoints: containerStats.syncLifePoints,
      walletLifePoints: containerStats.walletLifePoints,
      walletBalance: containerStats.walletBalance,
      source: 'container_stats',
      containerUptime: `${(containerStats.uptimeHours || 0).toFixed(1)} hours`,
      isEarning: containerStats.isEarningPoints,
      connectionState: containerStats.proxyConnectionState
    };
  }

  // PRIORITY 3: Error fallback
  return {
    timestamp: new Date().toISOString(),
    points: {
      total: 0,
      daily: 0,
      weekly: 0,
      monthly: 0,
      streak: 0,
      rank: 'N/A',
      multiplier: '1.0'
    },
    error: 'Unable to fetch points data - external API failed and synchronizer container not running',
    fallback: true
  };
}