# opnSentral

Self-hosted central management for multiple OPNsense firewalls.

opnSentral is the actively maintained successor to **opnCentral**. New development, issues and releases belong in this repository.

## Features in 0.6.20.23

### Central OPNsense management

- Central dashboard for multiple OPNsense firewalls
- Firewall reachability, system and firmware status
- Detailed firewall views and direct access to the managed OPNsense Web UI
- Central configuration access with session-based read-only / unlocked mode
- Optional IPv4-only connections to managed OPNsense systems
- Presentation Mode for anonymising firewall names, IP addresses, domains and email addresses in screenshots and demonstrations

### Configuration, aliases and categories

- Central alias inventory and management
- Managed OPNsense category support
- Alias distribution and takeover of existing aliases
- GeoIP alias support
- Category management
- Configuration comparison and troubleshooting tools

### Backup and restore

- One-click OPNsense configuration backups
- Backup history per firewall
- Automatic pre-change backups before managed changes
- Configurable pre-change backup retention
- opnSentral self-backup and restore
- Optional inclusion of stored OPNsense configuration backups in an opnSentral backup

### VPN management

- WireGuard management
- WireGuard site-to-site configuration
- OpenVPN management
- OpenVPN Roadwarrior/server configuration
- VPN-related monitoring and notifications

### IDS / IPS

- IDS/IPS administration
- Ruleset management
- Policy management and deployment
- Bulk actions and filtering for IDS rules and policies

### Firmware and plug-ins

- Central firmware status
- Update checks and firmware actions
- Installed OPNsense plug-in overview and management
- Security, Health, Connectivity and Cleanup firmware audits
- Upgrade-log access
- Live audit-status polling with retained recent output

### Notifications and application management

- Email notifications with configurable SMTP settings
- Configurable alert checks and failure thresholds
- English, German, French and Dutch interface
- Light and dark themes
- Built-in update check against published GitHub releases
- Anonymous installation telemetry with an explicit Settings control and manual **Send now** action
- Immediate telemetry attempt on container start when telemetry is enabled
- Developer telemetry dashboard kept separate from the normal opnSentral UI

### Docker / platform support

- Published Docker images for AMD64 and ARM64
- Raspberry Pi 4/5 support with a 64-bit OS
- Synology and Portainer friendly deployment
- Persistent application data and OPNsense backup storage

## Container images

```text
ghcr.io/frazon11/opnsentral
docker.io/frazon11/opnsentral
```

The normal opnSentral image is published to both GHCR and Docker Hub.

## Quick start with Docker Compose

Clone the repository or download `docker-compose.yml` and `.env.example`.

Create your environment file:

```bash
cp .env.example .env
```

Generate a 64-character hexadecimal application key:

```bash
openssl rand -hex 32
```

Put that value into `APP_KEY` in `.env`, set a strong `ADMIN_PASSWORD`, then start opnSentral:

```bash
docker compose pull
docker compose up -d
```

Default web address:

```text
http://DOCKER-HOST:8788
```

The default compose file uses the published `latest` image unless `IMAGE_VERSION` is changed.

Telemetry client defaults are defined directly in `docker-compose.yml`; they do not belong in `.env` or the Portainer Stack environment.

## Portainer: deploy as a Stack from the Git repository

This is the recommended approach when opnSentral runs on a Synology NAS or another Docker host managed by Portainer.

### 1. Create the persistent folder

For the default Synology layout create:

```text
/volume1/docker/opnsentral
```

opnSentral will use subdirectories below this path for persistent application data and stored backups.

### 2. Create the Stack in Portainer

In Portainer:

1. Open **Stacks**.
2. Click **Add stack**.
3. Enter a name, for example `opnSentral`.
4. Select **Git repository** as the build/deployment method.
5. Use the repository URL:

   ```text
   https://github.com/frazon11/opnSentral.git
   ```

6. Use the repository reference/branch:

   ```text
   refs/heads/main
   ```

7. Set **Compose path** to:

   ```text
   docker-compose.yml
   ```

8. Leave authentication disabled because the repository is public.

### 3. Add the Stack environment variables

At the bottom of the Portainer Stack page, add only the environment variables that are intentionally user-specific.

A practical starting configuration is:

```env
BASE_PATH=/volume1/docker/opnsentral
WEB_PORT=8788
IMAGE_VERSION=latest
TZ=Europe/Brussels
APP_NAME=opnSentral

ADMIN_USER=admin
ADMIN_PASSWORD=CHANGE_ME_TO_A_STRONG_PASSWORD
APP_KEY=REPLACE_WITH_64_HEX_CHARACTERS

SESSION_SECURE=false
DEFAULT_LANGUAGE=en

ALERTS_ENABLED=false
ALERT_VPN=true
ALERT_CHECK_INTERVAL=300
ALERT_FAILURE_THRESHOLD=2

SMTP_HOST=
SMTP_PORT=587
SMTP_SECURITY=tls
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_FROM_NAME=opnSentral
NOTIFY_TO=

PRECHANGE_BACKUP_RETENTION=20
```

Do **not** add `TELEMETRY_ENABLED`, `TELEMETRY_URL` or `TELEMETRY_WRITE_TOKEN` to the Portainer environment. Those client telemetry values are defined directly in `docker-compose.yml`.

Generate `APP_KEY` once with:

```bash
openssl rand -hex 32
```

and paste the result into the Portainer `APP_KEY` variable.

**Keep the same `APP_KEY` permanently.** It is used to encrypt stored OPNsense API credentials. Changing it later makes existing encrypted credentials unreadable.

### 4. Deploy

Click **Deploy the stack**.

After the container becomes healthy, open:

```text
http://DOCKER-HOST:8788
```

and log in with the configured `ADMIN_USER` and `ADMIN_PASSWORD`.

### 5. Update an existing Portainer Git Stack

When a new opnSentral version is available:

1. Open **Stacks → opnSentral**.
2. Use **Pull and redeploy** / **Update the stack** depending on your Portainer version.
3. Make sure Portainer pulls the latest repository content and the latest container image.

Your persistent data remains below `BASE_PATH` and is not stored inside the disposable application container.

## Persistent data

Inside the container opnSentral uses:

```text
/var/www/data
/var/www/backups
```

With the default Synology `BASE_PATH` these map to:

```text
/volume1/docker/opnsentral/data
/volume1/docker/opnsentral/backups
```

Keep the existing `APP_KEY` when migrating from opnCentral or moving the deployment to another host. Changing it makes stored OPNsense API credentials unreadable.

## First login / basic setup

After logging in:

1. Open **Settings** and review language, theme and Interface & access settings.
2. Add the first OPNsense firewall.
3. Enter its base URL and OPNsense API credentials.
4. Keep opnSentral in **read-only mode** until you intentionally need configuration changes.
5. Use **Presentation Mode** when preparing screenshots or demonstrations containing customer/firewall information.
6. Configure notifications if email alerts are required.

## Telemetry

The normal opnSentral client telemetry configuration is defined directly in `docker-compose.yml`, not in `.env` or Portainer Stack variables.

Anonymous installation statistics can still be enabled or disabled from **Settings**. The normal client reports only the anonymous installation hash, opnSentral version, CPU architecture and Docker platform information.

The developer telemetry receiver/dashboard is separate from the normal opnSentral interface. Project statistics such as Docker Hub pulls and GitHub traffic are shown only on that developer telemetry dashboard.

## Documentation

- [Changelog](CHANGELOG.md) — release history and notable changes
- [Telemetry receiver](telemetry-server/README.md) — developer-only telemetry server deployment

## Project history

The previous project is retained at [frazon11/opnCentral](https://github.com/frazon11/opnCentral) for compatibility and historical releases.

## License

MIT
