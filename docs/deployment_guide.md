# LinuxOps Production Deployment & Architecture Guide

This document specifies the target production deployment architecture, security hardening guidelines, OpenID Connect (OIDC) authentication setup, and remote host agent telemetry flow for **LinuxOps**.

---

## 1. Production Architecture Overview

```
                                  [ Remote Operator / Evaluator ]
                                                │
                                                ▼ HTTPS (Port 443)
                                ┌───────────────────────────────┐
                                │   Nginx / Caddy Reverse Proxy │
                                │   - TLS 1.3 / Let's Encrypt   │
                                │   - WebSocket Upgrade Proxy   │
                                │   - Strict Security Headers   │
                                └───────────────┬───────────────┘
                                                │ Localhost TCP (127.0.0.1:8501)
                                                ▼
                                ┌───────────────────────────────┐
                                │   LinuxOps Streamlit Service  │
                                │   - Bound to 127.0.0.1:8501   │
                                │   - Native OIDC Auth (OAuth2) │
                                │   - RBAC (Admin vs Viewer)    │
                                │   - Session State Isolation   │
                                └───────────▲───────▲───────────┘
                                            │       │
                     Outbound Push via TLS  │       │ Outbound Push via TLS
                   (HMAC-SHA256 Authenticated)│     │ (HMAC-SHA256 Authenticated)
                                            │       │
                        ┌───────────────────┘       └───────────────────┐
                        │                                               │
          ┌─────────────┴─────────────┐                   ┌─────────────┴─────────────┐
          │   Monitored Node: East    │                   │   Monitored Node: West    │
          │  - scripts/linuxops_agent │                   │  - scripts/linuxops_agent │
          │  - Rootless Podman 5.x    │                   │  - Rootless Podman 5.x    │
          │  - /proc Resource Telemetry│                  │  - /proc Resource Telemetry│
          │  - Outbound Push Only     │                   │  - Outbound Push Only     │
          └───────────────────────────┘                   └───────────────────────────┘
```

### Critical Security Invariants
1. **Zero Public Socket Exposure**: Neither the Podman API unix socket (`/run/user/1000/podman/podman.sock`) nor any Docker-compatible TCP socket is ever exposed across the public internet.
2. **Outbound Push Telemetry**: Monitored hosts initiate outbound HTTPS connections to push scrubbed, signed telemetry. No inbound ports need to be opened on the monitored hosts.
3. **Fail-Closed Gate**: If OpenID Connect is unconfigured or unavailable in `production` mode, the application immediately blocks all access and refuses to display container inventories, metrics, or diagnostic incidents.
4. **Localhost Daemon Binding**: Streamlit binds strictly to `127.0.0.1:8501`, preventing direct unauthenticated internet access.

---

## 2. Recommended Hosting Platforms

| Hosting Tier | Recommended Provider | Specs | Estimated Cost | Use Case |
|---|---|---|---|---|
| **Dedicated Cloud VM** (Recommended) | AWS EC2 (`t4g.small` or `t3.small`) / Hetzner Cloud (`CX22`) / DigitalOcean Droplet | 2 vCPU, 2GB–4GB RAM, Ubuntu 24.04 LTS | ~$5–$15 / month | Dedicated academic/interview demo, production fleet observability |
| **PaaS / Container Host** | Fly.io / Render / AWS ECS Fargate | 1 CPU, 1GB–2GB RAM | ~$7–$12 / month | Ephemeral demo deployment with persistent volume for audit logs |
| **Development Machine** (Current) | Local Windows 11 + Ubuntu-24.04 WSL2 | Local hardware, localhost bridge | Free | Local development, unit testing, and simulation evaluation |

---

## 3. Reverse Proxy Configuration (Nginx)

Place this configuration at `/etc/nginx/sites-available/linuxops.conf` and symlink to `/etc/nginx/sites-enabled/`:

```nginx
# Map WebSocket upgrade headers
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name linuxops.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name linuxops.yourdomain.com;

    # SSL Certificates (managed via Certbot / Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/linuxops.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/linuxops.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Defensive Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Proxy to Streamlit local daemon
    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;

        # WebSocket support (required by Streamlit)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_buffering off;
    }

    # Dedicated Health Endpoint for Load Balancers
    location /_stcore/health {
        proxy_pass http://127.0.0.1:8501/_stcore/health;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        access_log off;
    }
}
```

---

## 4. OpenID Connect (OIDC) Authentication Setup

### Step 1: Register OAuth Application in Provider
1. Navigate to Google Cloud Console (APIs & Credentials) or Microsoft Entra ID (App Registrations).
2. Create **OAuth 2.0 Web Application**.
3. Configure:
   - **Authorized JavaScript Origins**: `https://linuxops.yourdomain.com`
   - **Authorized Redirect URIs**: `https://linuxops.yourdomain.com/oauth2callback`

### Step 2: Configure Streamlit Secrets
On the production server, create `/home/linuxops/linuxops/.streamlit/secrets.toml` (owned by user `linuxops`, mode `0600`):

```toml
[auth]
redirect_uri = "https://linuxops.yourdomain.com/oauth2callback"
cookie_secret = "GENERATE_RANDOM_64_CHAR_HEX_STRING_HERE"
client_id = "YOUR_OAUTH_CLIENT_ID.apps.googleusercontent.com"
client_secret = "YOUR_OAUTH_CLIENT_SECRET"
server_metadata_url = "https://accounts.google.com/.well-known/openid-configuration"
admin_users = "admin@yourcompany.com,neha@yourcompany.com"
```

---

## 5. Systemd Production Service

Create `/etc/systemd/system/linuxops-dashboard.service`:

```ini
[Unit]
Description=LinuxOps Operations Console
After=network.target

[Service]
Type=exec
User=linuxops
Group=linuxops
WorkingDirectory=/home/linuxops/linuxops
Environment="PATH=/home/linuxops/linuxops/.venv/bin:/usr/bin:/bin"
Environment="LINUXOPS_AUTH_MODE=production"
Environment="LINUXOPS_RECOVERY_DISABLED=1"
Environment="LINUXOPS_AGENT_SECRET=YOUR_PRESHARED_HMAC_SECRET"
ExecStart=/home/linuxops/linuxops/.venv/bin/streamlit run app/dashboard.py \
    --server.address 127.0.0.1 \
    --server.port 8501 \
    --server.headless true \
    --browser.gatherUsageStats false
Restart=always
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

---

## 6. Remote Host Monitoring Agent Setup

On each remote Linux/Podman host:

1. Copy [`scripts/linuxops_agent.py`](file:///wsl.localhost/Ubuntu-24.04/home/neha_borse/linuxops/scripts/linuxops_agent.py) to `/usr/local/bin/linuxops_agent.py`.
2. Ensure Python 3.10+ and standard libraries are installed (`urllib.request`, `hmac`, `json`, `hashlib`).
3. Create systemd timer or service `/etc/systemd/system/linuxops-agent.service`:

```ini
[Unit]
Description=LinuxOps Host Monitoring Telemetry Agent
After=network.target

[Service]
Type=exec
User=rootless-user
ExecStart=/usr/bin/python3 /usr/local/bin/linuxops_agent.py \
    --host-id node-east-1 \
    --endpoint https://linuxops.yourdomain.com/api/v1/telemetry \
    --secret YOUR_PRESHARED_HMAC_SECRET \
    --interval 30
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=default.target
```

4. Enable and start the agent:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now linuxops-agent.service
   ```

---

## 7. Ordered Production Deployment Checklist

Follow this exact order when commissioning a new production environment:

### Phase A: Target Preparation & Network Hardening
1. **Provision Ubuntu 24.04 LTS VPS**: Minimum 2 vCPU, 2GB–4GB RAM, 25GB NVMe.
2. **Configure Firewall (UFW)**:
   ```bash
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw allow 22/tcp comment 'SSH Management'
   sudo ufw allow 80/tcp comment 'HTTP (Let\'s Encrypt Challenge)'
   sudo ufw allow 443/tcp comment 'HTTPS Production Traffic'
   sudo ufw enable
   ```
3. **Provision Dedicated System User**:
   ```bash
   sudo useradd -m -s /bin/bash linuxops
   sudo -u linuxops mkdir -p /home/linuxops/linuxops /home/linuxops/linuxops/logs
   ```

### Phase B: Code & Dependency Setup
4. **Deploy Application Codebase**: Clone or rsync repository to `/home/linuxops/linuxops`.
5. **Initialize Python Environment**:
   ```bash
   cd /home/linuxops/linuxops
   python3 -m venv .venv
   .venv/bin/pip install --upgrade pip
   .venv/bin/pip install -r requirements.txt
   ```

### Phase C: Secret & Identity Configuration
6. **Deploy Production Environment Variables**:
   Copy `.env.production.example` to `/home/linuxops/linuxops/.env.production` and populate placeholders:
   ```bash
   chmod 0600 /home/linuxops/linuxops/.env.production
   ```
7. **Configure OpenID Connect Secrets**:
   Create `/home/linuxops/linuxops/.streamlit/secrets.toml`:
   ```bash
   chmod 0600 /home/linuxops/linuxops/.streamlit/secrets.toml
   ```
   Verify `cookie_secret` is a cryptographically strong 64-character hex key.
8. **Verify Admin Whitelist**: Ensure only trusted operations staff emails are listed in `LINUXOPS_ADMIN_USERS`.

### Phase D: Service & Proxy Activation
9. **Install & Start Systemd Unit**:
   ```bash
   sudo cp deploy/linuxops-dashboard.service /etc/systemd/system/ # or use section 5 template
   sudo systemctl daemon-reload
   sudo systemctl enable --now linuxops-dashboard.service
   ```
10. **Verify Local Daemon Response**:
    ```bash
    curl -i http://127.0.0.1:8501/_stcore/health
    # Expected response: HTTP/1.1 200 OK
    ```
11. **Configure Nginx & TLS**:
    - Install Nginx and Certbot: `sudo apt install -y nginx certbot python3-certbot-nginx`
    - Configure virtual host using template from Section 3.
    - Obtain TLS Certificate: `sudo certbot --nginx -d linuxops.yourdomain.com`
    - Reload Nginx: `sudo nginx -t && sudo systemctl reload nginx`

### Phase E: Verification
12. **Verify Public Endpoints**:
    - Open `https://linuxops.yourdomain.com` in an incognito window.
    - Confirm the **LinuxOps Security Gate** renders immediately and blocks all dashboard views.
    - Confirm unauthenticated users CANNOT see container names, metrics, logs, or diagnostic reports.
    - Test OIDC sign-in with a viewer account; confirm Viewer role badge and disabled approval buttons.
    - Test OIDC sign-in with an admin account; confirm Admin role badge and enabled simulated approvals.

---

## 8. Health Checks, Logging & Audit Persistence

### Health Check Endpoints
- **Streamlit Health Check**: `GET /_stcore/health`
  - Returns `200 OK` when the Python event loop and WebSocket server are responsive.
  - Recommended load balancer / uptime monitor probe: interval 15s, timeout 3s, healthy threshold 2, unhealthy threshold 3.

### Audit Log Persistence & Log Rotation
LinuxOps writes critical operational logs to `logs/`:
- `logs/policy_history.jsonl`: Audit log of policy evaluation, plan generation, and gate checks.
- `logs/recovery_history.jsonl`: Immutable log of approval tokens, simulated executions, and outcomes.

Configure log rotation at `/etc/logrotate.d/linuxops`:
```
/home/linuxops/linuxops/logs/*.jsonl {
    daily
    missingok
    rotate 90
    compress
    delaycompress
    notifempty
    create 0640 linuxops linuxops
}
```

### Backup Strategy
Perform daily automated backups of the `logs/` directory to encrypted offsite object storage (e.g. AWS S3 with KMS or BorgBackup):
```bash
#!/usr/bin/env bash
tar -czf /tmp/linuxops-audit-$(date +%F).tar.gz -C /home/linuxops/linuxops logs/
aws s3 cp /tmp/linuxops-audit-$(date +%F).tar.gz s3://your-audit-bucket/linuxops/ --sse aws:kms
rm -f /tmp/linuxops-audit-$(date +%F).tar.gz
```

---

## 9. Zero-Downtime Upgrades & Rollback Runbook

### Standard Upgrade Procedure
1. Run local automated tests prior to deployment:
   ```bash
   PYTHONPATH=. .venv/bin/pytest tests/
   ```
2. Pull updated release onto production server into a timestamped release directory:
   ```bash
   RELEASE_DIR="/home/linuxops/releases/$(date +%Y%m%d%H%M%S)"
   git clone --depth 1 /path/to/repo "$RELEASE_DIR"
   cd "$RELEASE_DIR"
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ln -s /home/linuxops/shared/logs "$RELEASE_DIR/logs"
   ln -s /home/linuxops/shared/secrets.toml "$RELEASE_DIR/.streamlit/secrets.toml"
   ln -s /home/linuxops/shared/.env.production "$RELEASE_DIR/.env"
   ```
3. Atomic Cutover:
   ```bash
   ln -sfn "$RELEASE_DIR" /home/linuxops/linuxops-current
   sudo systemctl restart linuxops-dashboard.service
   ```
4. Verify health immediately:
   ```bash
   curl -f http://127.0.0.1:8501/_stcore/health || exit 1
   ```

### Emergency Rollback Runbook
If an upgrade causes errors, regressions, or authentication failures:
1. Identify previous stable release directory:
   ```bash
   ls -ld /home/linuxops/releases/*
   ```
2. Atomically point symlink back to previous release:
   ```bash
   ln -sfn /home/linuxops/releases/PREVIOUS_STABLE /home/linuxops/linuxops-current
   sudo systemctl restart linuxops-dashboard.service
   ```
3. Confirm health check:
   ```bash
   curl -i http://127.0.0.1:8501/_stcore/health
   ```
4. Notify incident response team and review `/var/log/nginx/error.log` and `journalctl -u linuxops-dashboard.service -n 100`.

---

## 10. Security Gaps to Resolve Before Connecting Real Production Hosts

Before transitioning from **Simulation Lab** to connecting **real production hosts**:

1. **Dedicated Ingestion Microservice**:
   - Streamlit is optimized for interactive WebSocket UI rendering, not high-volume HTTP ingestion.
   - Deploy a lightweight, asynchronous FastAPI/Go sidecar dedicated to receiving `/api/v1/telemetry`, validating HMAC signatures, and writing to an encrypted database or Redis cache.
2. **Mutual TLS (mTLS)**:
   - In addition to HMAC-SHA256 application signatures, configure mutual TLS between the host agents and the reverse proxy so untrusted network clients cannot even establish a TCP handshake with the ingestion endpoint.
3. **Per-Host Preshared Keys (PSK) & Key Rotation**:
   - Replace the single global `LINUXOPS_AGENT_SECRET` with per-host cryptographic keys and automated key rotation mechanisms (e.g. HashiCorp Vault or AWS KMS).
4. **Rate Limiting & DoS Shield**:
   - In Nginx, apply strict rate limiting on the telemetry push endpoint:
     ```nginx
     limit_req_zone $binary_remote_addr zone=telemetry_limit:10m rate=5r/s;
     location /api/v1/telemetry {
         limit_req zone=telemetry_limit burst=10 nodelay;
         client_max_body_size 2M;
         ...
     }
     ```
5. **Strict Network Segmentation**:
   - Ensure the central LinuxOps server resides in a dedicated management VPC or uses WireGuard/Tailscale overlay networks to communicate with monitored host agents rather than exposing the ingestion endpoint to the public internet.

