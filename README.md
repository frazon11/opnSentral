# opnSentral

Self-hosted central management for multiple OPNsense firewalls.

opnSentral is the actively maintained successor to **opnCentral**. New development, issues and releases belong in this repository.

## Main features

- Central firewall status and firmware information
- Encrypted OPNsense API credential storage
- Configuration backup history and one-click backups
- Automatic backups before managed changes
- Central alias and category management
- WireGuard and OpenVPN management
- IDS/IPS administration, rulesets and policy deployment
- Plug-in and firmware management
- Email notifications
- Light and dark themes
- English, German, French and Dutch interface
- Self-backup and restore
- AMD64 and ARM64 Docker images

## Container images

```text
ghcr.io/frazon11/opnsentral
docker.io/frazon11/opnsentral
```

## Quick start

```bash
cp .env.example .env
openssl rand -hex 32
```

Add the generated value as `APP_KEY` in `.env`, set the administrator password, then start the application:

```bash
docker compose pull
docker compose up -d
```

Default web address:

```text
http://DOCKER-HOST:8788
```

## Persistent data

```text
/var/www/data
/var/www/backups
```

Keep the existing `APP_KEY` when migrating from opnCentral. Changing it makes stored OPNsense API credentials unreadable.

## Project history

The previous project is retained at [frazon11/opnCentral](https://github.com/frazon11/opnCentral) for compatibility and historical releases.

## License

MIT
