# opnSentral Telemetry Receiver

This directory contains the developer-operated receiver for anonymous opnSentral installation telemetry.

It is infrastructure for the project maintainer, not an end-user opnSentral feature.

## Public vs private endpoints

Only the ingest endpoint needs to be reachable by opnSentral installations:

```text
https://opnsentral.kryszon.info:4455/api.php
```

The telemetry dashboard at `/` is developer-only and is disabled by default. When disabled it returns HTTP 404.

To enable the dashboard on a private or otherwise restricted deployment:

```env
TELEMETRY_DASHBOARD_ENABLED=true
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=replace-with-a-strong-password
```

Basic authentication is still required when the dashboard is enabled. Restrict dashboard access further at the reverse proxy or firewall where possible.

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

The telemetry image is built for AMD64 and ARM64.

## Synology / Portainer environment

```env
BASE_PATH=/volume1/docker/opnsentral-telemetry
WEB_PORT=4455
IMAGE_VERSION=latest
TZ=Europe/Brussels

# Optional API Bearer token. Standard public opnSentral clients do not embed a secret.
TELEMETRY_WRITE_TOKEN=

# Keep the dashboard disabled unless access is deliberately restricted.
TELEMETRY_DASHBOARD_ENABLED=false
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=

RETENTION_DAYS=730
```

Persistent data directory:

```text
/volume1/docker/opnsentral-telemetry/data
```

## Portainer Git repository deployment

```text
Repository: https://github.com/frazon11/opnSentral.git
Compose path: telemetry-server/docker-compose.yml
```

The compose file pulls the published telemetry image and does not build locally.

## Client configuration

The public opnSentral client only requires:

```text
TELEMETRY_ENABLED=true
TELEMETRY_URL=https://opnsentral.kryszon.info:4455/api.php
```

`TELEMETRY_WRITE_TOKEN` is optional. If a private receiver deployment enables a token, only clients configured with the same token can submit telemetry.
