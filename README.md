# Instructions
This is how you **SHOULD** be using **ValiantProxy** for your server.
___
1. Make a `directory` for Valiant on your server's filesystem.
2. Drag `ValiantProxy` and the `.env` into the directory.
3. Open the `.env` file and validate all the data is correct.
```dotenv
# ValiantProxy address
LOCAL_ADDR=127.0.0.1:19132
# real server address
REMOTE_ADDR=10.0.0.1:19300

# max connections per IP address (recommended: 1)
MAX_CONNECTIONS_ALLOWED=1

# this is used for ValiantProxy to log to your discord channel. (optional)
WEBHOOK_URL=https://discord.com/api/webhooks/CHANNEL_ID/TOKEN
```
4. Run the following command to ensure ValiantProxy has executable permissions:
```bash
chmod +x ValiantProxy
```
___
### Optional
These steps only matter if ValiantProxy is running on the **SAME** server as the real server. If ValiantProxy is running on a different server, these steps do not apply.

5. We should limit the access to the real server to only connections from the proxy, we can do this by adding a firewall rule.

Run the following command to allow only incoming connections from the ValiantProxy:
```bash
sudo ufw deny REAL_PORT/tcp
sudo ufw deny REAL_PORT/udp
sudo ufw enable
```
Inverse Rules
```bash
sudo ufw allow REAL_PORT/tcp
sudo ufw allow REAL_PORT/udp
sudo ufw reload
```
To disable the firewall:
```bash
sudo ufw disable
```
___
6. Make a systemd service file for ValiantProxy.
```bash
sudo nano /etc/systemd/system/valiant.service
```
```ini
[Unit]
Description=ValiantProxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/ValiantProxy
ExecStart=sudo ValiantProxy
Restart=always
[Install]
WantedBy=multi-user.target
```
7. Enable and start the service:
```bash
sudo systemctl enable valiant
sudo systemctl start valiant
```
8. Check the status of the service:
```bash
sudo systemctl status valiant
```
___
### Game Settings

9. Make sure to enable doimmediaterespawn in your server by running the following command in-game:
```
/gamerule doimmediaterespawn true
```
