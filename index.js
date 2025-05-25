#!/usr/bin/env node

const { Command } = require('commander');
const inquirer = require('inquirer').default;
const chalk = require('chalk').default;
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawn } = require('child_process');
const packageJson = require('./package.json');
const program = new Command();

const CONFIG_DIR = path.join(os.homedir(), '.synqchronizer');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

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

function generateSyncHash(userName, secret, hostname) {
  const input = `${userName || ''}:${hostname}:${secret}`;
  const hash = crypto.createHash('sha256').update(input).digest('hex');
  return `synq-${hash.slice(0, 12)}`;
}

async function init() {
  const questions = [];

  questions.push({
    type: 'input',
    name: 'userName',
    message: 'Optional sync name (for your reference only):',
    default: ''
  });

  questions.push({
    type: 'input',
    name: 'key',
    message: 'Synq key:',
    validate: input => input ? true : 'Synq key is required',
  });

  questions.push({
    type: 'input',
    name: 'wallet',
    message: 'Wallet address:',
    validate: input => input ? true : 'Wallet is required',
  });

  const answers = await inquirer.prompt(questions);

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

  saveConfig(config);
  console.log(chalk.green('Configuration saved to'), CONFIG_FILE);
}


function start() {
  const config = loadConfig();
  if (!config.key) {
    console.error(chalk.red('Missing synq key. Run `synqchronize init` first.'));
    process.exit(1);
  }

  if (config.hostname !== os.hostname()) {
    console.error(chalk.red(`This config was created for ${config.hostname}, not ${os.hostname()}.`));
    process.exit(1);
  }
  
  const syncName = config.syncHash;

  const args = [
    'run', '--rm', '--name', 'synqchronizer',
    'cdrakep/synqchronizer:latest',
    '--depin', config.depin || 'wss://api.multisynq.io/depin',
    '--sync-name', syncName,
    '--launcher', config.launcher || 'cli',
    '--key', config.key,
    ...(config.wallet ? ['--wallet', config.wallet] : []),
    ...(config.account ? ['--account', config.account] : [])
  ];

  console.log(chalk.cyan(`Running synchronizer "${syncName}" with wallet ${config.wallet || '[none]'}`));
  const proc = spawn('docker', args, { stdio: 'inherit' });
  proc.on('exit', code => process.exit(code));
}


/**
 * Generate systemd service file and environment file for headless operation.
 */
async function installService() {
  const config = loadConfig();
  if (!config.key) {
    console.error(chalk.red('Missing synq key. Run `synqchronize init` first.'));
    process.exit(1);
  }
  if (!config.wallet && !config.account) {
    console.error(chalk.red('Missing wallet or account. Run `synqchronize init` first.'));
    process.exit(1);
  }

  const serviceFile = path.join(CONFIG_DIR, 'synqchronizer.service');
  const user = os.userInfo().username;

  const unit = `[Unit]
Description=Multisynq Synchronizer headless service
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=${user}
Restart=always
RestartSec=10
ExecStart=/usr/bin/docker run --rm --name synqchronizer \\
  -e DEPIN=${config.depin} \\
  -e LAUNCHER=${config.launcher} \\
  -e ID=${config.syncHash} \\
  cdrakep/synqchronizer:latest \\
  --key ${config.key} \\
  --wallet ${config.wallet || ''} \\
  --account ${config.account || ''}

[Install]
WantedBy=multi-user.target
`;

  fs.writeFileSync(serviceFile, unit);
  console.log(chalk.green('Systemd service file written to'), serviceFile);
  console.log(chalk.blue(`To install the service, run:
  sudo cp ${serviceFile} /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable synqchronizer
  sudo systemctl start synqchronizer`));
}


program.name('synqchronize')
  .description('CLI wrapper for Multisynq Synchronizer headless service')
  .version(packageJson.version);

program.command('init').description('Interactive configuration').action(init);
program.command('start').description('Build and run synchronizer Docker container').action(start);
program.command('service').description('Generate systemd service file for headless service').action(installService);

program.parse(process.argv);