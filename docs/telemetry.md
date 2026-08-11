# Anonymous installation statistics

Telemetry is disabled by default.

When enabled, opnCentral sends once every 24 hours:

- anonymous SHA-256 installation hash
- opnCentral version
- CPU architecture
- platform `docker`

It does not send firewall data, credentials, usernames, networks, VPN configuration, email addresses or `APP_KEY`.

The optional receiver is included under `telemetry-server/`. See its README for deployment and reverse-proxy guidance.
