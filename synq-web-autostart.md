# Setup Synchronizer CLI Web Dashboard AutoStart

1. **Find the Full Path of `synchronize`**

```bash
which synchronize
```

Example output:

```bash
/root/.nvm/versions/node/v20.19.2/bin/synchronize
```

2. **Create a Systemd Service File**

```bash
sudo nano /etc/systemd/system/synchronizer-web.service
```

Paste the following configuration:

```ini
[Unit]
Description=Synchronizer CLI Web Dashboard
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/root/.nvm/versions/node/v20.19.2/bin/synchronize web
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

3. **Reload Systemd**

```bash
sudo systemctl daemon-reload
```

4. **Enable the Service to Start on Boot**

```bash
sudo systemctl enable synchronizer-web
```

5. **Start the Service Now**

```bash
sudo systemctl start synchronizer-web
```

6. **Check the Service Status**

```bash
sudo systemctl status synchronizer-web
```

Expected output:

```bash
● synchronizer-web.service - Synchronizer CLI Web Dashboard
     Loaded: loaded (/etc/systemd/system/synchronizer-web.service; enabled)
     Active: active (running)
```
