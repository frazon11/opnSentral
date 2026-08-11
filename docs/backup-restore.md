# Backup and restore

Open **Settings → Backup & Restore**.

A self-backup can include:

- the consistent SQLite database snapshot
- application state from `/var/www/data`
- optionally, stored OPNsense configuration backups

`APP_KEY` is deliberately not included. Preserve the exact key separately.

Restore validation includes:

- manifest format checking
- APP_KEY fingerprint matching
- safe archive-path validation
- SHA-256 verification
- SQLite integrity checking
- automatic safety backup before replacement

Restart or recreate the container after a successful restore.
