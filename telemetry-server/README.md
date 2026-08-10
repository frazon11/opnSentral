# opnSentral Telemetry Receiver

This directory contains the developer-operated receiver for anonymous opnSentral installation telemetry.

It is infrastructure for the project maintainer, not an end-user opnSentral feature.

## Public vs private endpoints

The ingest endpoint must be reachable by opnSentral installations:

```text
https://opnsentral.kryszon.info:4455/api.php
```

The telemetry dashboard at `/` is developer-only. It is enabled by default for the telemetry-server deployment and protected by HTTP Basic Auth:

```env
TELEMETRY_DASHBOARD_ENABLED=true
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=replace-with-a-strong-password
```

Restrict dashboard access further at the reverse proxy or firewall where possible.

## Dashboard contents

The developer dashboard shows:

- known telemetry installations
- active installations for 24 hours, 7 days and 30 days
- active opnSentral versions and architectures
- recent anonymous installation activity
- Project statistics: Docker Hub pulls plus GitHub views, unique visitors, clones and unique cloners
- telemetry server version

Project statistics are intentionally available only on the telemetry-server dashboard and are not exposed in the normal opnSentral UI.

GitHub traffic statistics require a GitHub token with permission to read repository traffic:

```env
DOCKER_HUB_REPOSITORY=frazon11/opnsentral
GITHUB_TRAFFIC_REPOSITORY=frazon11/opnSentral
GITHUB_TRAFFIC_TOKEN=
```

Docker Hub lifetime pull count does not require authentication.

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
```

The telemetry image is built for AMD64 and ARM64. It is not published to Docker Hub.

## Synology / Portainer environment

```env
BASE_PATH=/volume1/docker/opnsentral-telemetry
WEB_PORT=4455
IMAGE_VERSION=latest
TZ=Europe/Brussels

TELEMETRY_WRITE_TOKEN=

TELEMETRY_DASHBOARD_ENABLED=true
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=replace-with-a-strong-password

DOCKER_HUB_REPOSITORY=frazon11/opnsentral
GITHUB_TRAFFIC_REPOSITORY=frazon11/opnSentral
GITHUB_TRAFFIC_TOKEN=

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

The normal opnSentral compose enables anonymous telemetry by default and supplies the receiver URL and write-token default directly from `docker-compose.yml`. These values do not need to be added to the normal opnSentral `.env` file.
