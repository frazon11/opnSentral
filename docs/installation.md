# Installation

## Synology / Docker Compose

Create the application directories:

```bash
mkdir -p /volume1/docker/opncentral/data
mkdir -p /volume1/docker/opncentral/backups
```

Copy `docker-compose.yml` and `.env.example` to `/volume1/docker/opncentral/`, then rename the environment file:

```bash
cp .env.example .env
```

Edit `.env` and set at least:

```dotenv
ADMIN_PASSWORD=YOUR_STRONG_PASSWORD
APP_KEY=YOUR_64_CHARACTER_HEX_KEY
```

Generate `APP_KEY` once:

```bash
openssl rand -hex 32
```

Start or update:

```bash
docker compose pull
docker compose up -d
```

Open:

```text
http://SYNOLOGY-IP:8788
```

Never change `APP_KEY` after firewall credentials have been saved.
