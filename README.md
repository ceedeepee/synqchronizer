# synqchronizer

CLI wrapper for the Multisynq Synchronizer headless service.

## Installation

```bash
npm install -g synqchronizer
```

## Usage

```bash
synqchronize init      # Interactive configuration (Synq key, wallet/account, registry, etc.)
synqchronize start     # Build and run the synchronizer Docker container
synqchronize service   # Generate a systemd service unit and environment file for headless setup
```

After running `synqchronize service`, copy the generated service file to `/etc/systemd/system/` and enable it:

```bash
sudo cp ~/.synqchronizer/synqchronizer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable synqchronizer
sudo systemctl start synqchronizer
```