# Minimal opnCentral agent

The first agent is read-only and reports hostname, OPNsense version and running
services using outbound HTTPS. Requests use a unique agent ID, a 256-bit secret,
HMAC-SHA256, timestamps and one-time nonces.

## Prototype test

1. Open **Agents** and create credentials.
2. Copy `agent-plugin/os-opncentral-agent` to a test firewall.
3. Run `sh install-prototype.sh`.
4. Edit `/usr/local/etc/opncentral-agent.conf`.
5. Run `configctl opncentralagent report`.

The prototype installer is for a controlled test firewall. A repository-signed
`.pkg` is still required before production or mass distribution.
