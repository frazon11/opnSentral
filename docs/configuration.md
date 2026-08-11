# Configuration

The canonical environment template is `.env.example`.

Important variables:

| Variable | Purpose |
|---|---|
| `APP_KEY` | Encrypts stored OPNsense API credentials |
| `ADMIN_USER` | opnCentral administrator account |
| `ADMIN_PASSWORD` | opnCentral administrator password |
| `SESSION_SECURE` | Set to `true` when opnCentral is served only through HTTPS |
| `PRECHANGE_BACKUP_RETENTION` | Number of automatic pre-change backups retained per firewall |
| `TELEMETRY_URL` | Optional anonymous telemetry receiver |
| `TELEMETRY_WRITE_TOKEN` | Optional shared write token for telemetry |

Persistent paths:

```text
/var/www/data
/var/www/backups
```
