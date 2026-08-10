# opnSentral Telemetry

A small optional receiving service for anonymous opnSentral active-installation statistics.

## Data stored

- SHA-256 anonymous installation hash
- first and last seen timestamps
- opnSentral version
- CPU architecture
- platform (`docker`)
- number of accepted checks

The application does not store firewall names, addresses, credentials, networks, VPN data, usernames, email addresses, or APP_KEY.

Apache access logging is disabled in the supplied image to avoid retaining client IP addresses. Reverse proxies placed in front of this container may still log IP addresses; disable or anonymise those logs separately.

## Container image

```text
ghcr.io/frazon11/opnsentral-telemetry:latest
docker.io/frazon11/opnsentral-telemetry:latest
```

The telemetry image is built by the repository CI for AMD64 and ARM64. Portainer and Synology do not need to build the image locally.

## Environment

Use the supplied `.env.example`:

```env
BASE_PATH=/volume1/docker/opnsentral-telemetry
WEB_PORT=4455
IMAGE_VERSION=latest
TZ=Europe/Brussels

TELEMETRY_WRITE_TOKEN=OMwcXVnI9rTcXiNjGnXz41X6
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=replace-with-a-strong-password
RETENTION_DAYS=730
```

`BASE_PATH` is the persistent host path. On Synology create this directory before deployment:

```text
/volume1/docker/opnsentral-telemetry/data
```

## Portainer / Synology Git repository deployment

Create a new stack using **Git repository** and use:

```text
Repository: https://github.com/frazon11/opnSentral.git
Compose path: telemetry-server/docker-compose.yml
```

Add the environment variables shown above in the stack environment-variable section. The compose file pulls the published telemetry image and therefore does not contain a local `build:` step.

For Synology the important variables are:

```text
BASE_PATH=/volume1/docker/opnsentral-telemetry
WEB_PORT=4455
IMAGE_VERSION=latest
```

Then deploy the stack.

## Docker Compose deployment

From the `telemetry-server` directory:

```bash
cp .env.example .env
docker compose pull
docker compose up -d
```

Do not use `--build`; the normal deployment uses the published image.

## Connect opnSentral

The receiver endpoint is `/api.php` and accepts telemetry via HTTP POST with the configured write token.

If the telemetry service itself is publicly exposed as HTTPS on port 4455, configure opnSentral with:

```text
TELEMETRY_URL=https://opnsentral.kryszon.info:4455/api.php
TELEMETRY_WRITE_TOKEN=OMwcXVnI9rTcXiNjGnXz41X6
```

If a reverse proxy listens on normal HTTPS port 443 and forwards internally to the telemetry container on port 4455, omit the port from the public URL:

```text
TELEMETRY_URL=https://opnsentral.kryszon.info/api.php
```

Recreate opnSentral, then enable **Settings → Anonymous installation statistics**.

When telemetry is enabled, opnSentral sends once on every container start (including the first start after creation) and continues with the normal 24-hour schedule while the container is running.

The telemetry dashboard is served from the same public base URL without `/api.php`.

The browser prompts for `DASHBOARD_USER` and `DASHBOARD_PASSWORD`.
