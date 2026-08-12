# Changelog

All notable changes to opnSentral are documented here.

Historical releases remain summarized here and in published GitHub releases. The active Git history intentionally starts from the cleaned repository baseline.

## Unreleased

- Clarified Docker platform support in the README, including Raspberry Pi 4/5 with a 64-bit OS.
- Removed low-level implementation details from the README feature list.
- Consolidated and cleaned the changelog so future changes are tracked here instead of as repeated README or release notes.

## 0.6.21.11

- Added controlled editing for existing `System → Access → Users` entries.
- Added editable Disabled, Login shell, Group membership and direct Privileges fields while preserving passwords, OTP seeds, authorized keys and API keys.
- Added per-firewall target selection so one user's selected settings can be deployed to one or multiple firewalls where that user already exists.
- Added pre-change configuration backups and per-firewall queued/running/success/failure deployment results for user changes.
- Added agent 0.1.3 with the strictly allow-listed `set_access_user` job using OPNsense local-user and group synchronization functions.
- Prevented opnSentral from disabling UID 0.
- Reconciled user group membership from the authoritative group member UID lists so Access inventory does not depend only on legacy user-side group fields.

## 0.6.21.10

- Added `System → Access → Users` as a fleet-wide local-user inventory and comparison view.
- Added `System → Access → Groups` as a fleet-wide local-group, membership and privilege comparison view.
- Added presence/missing status per managed firewall so account and group drift is immediately visible.
- Displays non-secret account metadata such as description, UID/GID, disabled state, group membership, assigned privileges and whether password/OTP authentication is configured.
- Password hashes and OTP seeds are never displayed.
- Kept Users/Groups read-only in this first Access release so the parsed configuration model can be verified before enabling authentication-critical central writes.

## 0.6.21.9

- Added one-time SSH bootstrap deployment for managed firewalls with no opnSentral agent.
- Added password and private-key SSH authentication for bootstrap without storing the supplied credential.
- Added persistent SSH host-key tracking in opnSentral data so later host-key changes are detected.
- Added agent deployment status for every managed firewall, including Missing, Current, Update available, Online and Stale states.
- Added agent 0.1.2 with a strictly allow-listed, SHA-256-verified self-update job for future outbound agent upgrades.
- Preserved the existing agent identity and secret during SSH recovery/update so an upgrade does not create duplicate agent registrations.
- Added an installer recovery/update mode that rebuilds the service while keeping `/usr/local/etc/opnsentral-agent.json` intact.
- Added `openssh-client` and `sshpass` to the opnSentral image for one-time SSH bootstrap operations.
- Kept the existing manual one-line registration command as a fallback when SSH from opnSentral cannot reach the remote firewall.

## 0.6.21.8

- Added a side-by-side `System → Settings → Administration` fleet matrix with settings as rows and managed firewalls as columns.
- Added per-firewall checkboxes plus an `All` checkbox on each row for supported Web GUI boolean settings.
- Added write support for Disable HTTP redirect rule, HSTS, WebGUI access logging, DNS rebind-check disablement, HTTP_REFERER enforcement disablement and Quiet login.
- Added opnSentral agent 0.1.1 with a strictly allow-listed Administration-settings job; arbitrary configuration paths and shell commands are not exposed.
- Added an automatic pre-change OPNsense configuration backup for every firewall before its Administration job is queued.
- Added queued, running, successful and failed deployment feedback per target firewall.
- Kept direct-API-only firewalls readable in the matrix while requiring an associated agent 0.1.1 or newer for Administration writes.
- Kept the detailed single-firewall Administration page accessible from each firewall column.

## 0.6.21.7

- Added a read-only `System → Settings → General` view for managed OPNsense firewalls.
- Added hostname, domain, time zone, language, theme, IPv4 preference, DNS servers, DNS search domains, WAN DNS override, local DNS nameserver usage and default gateway switching visibility.
- Restructured navigation to expose `System → Settings → General` and `System → Settings → Administration` alongside `Firewall → Settings → Advanced`.
- Updated the Administration page-local settings tree to include General and the correct System → Settings hierarchy.

## 0.6.21.6

- Added explicit visual deployment results for alias and category distribution.
- Successful targets now show a green `Successfully deployed` badge and failed targets show `Deployment failed`.
- Added an overall deployment summary showing successful, failed, or partially successful target counts.
- Kept the original per-firewall deployment message visible for detailed feedback.

## 0.6.21.5

- Added explicit Rename actions for existing aliases and categories in their inventory overview pages.
- Added a choice to rename only the selected firewall copy or all matching copies across managed firewalls.
- Added duplicate-name validation and pre-change configuration backups before remote renames.
- Kept central alias/category definitions synchronized when all matching copies are renamed successfully.
- When the configured managed category is renamed across all matching firewalls, its opnSentral managed-category setting is updated as well.

## 0.6.21.4

- Reorganized Settings into clear Interface, OPNsense, Application, and Data & privacy sections.
- Grouped related cards together instead of presenting one long mixed settings grid.
- Moved Presentation Mode into a normal top-level card instead of a nested panel.
- Moved OPNsense network settings into the OPNsense section beside the managed-category settings.
- Kept telemetry endpoint details hidden from the Settings UI.

## 0.6.21.3

- Changed the telemetry server default host port from 4455 to standard HTTPS port 443.
- Updated the normal opnSentral telemetry client endpoint to `https://opnsentral.kryszon.info/api.php` without an explicit non-standard port.
- Updated the telemetry-server environment example to use port 443.

## 0.6.21.2

- Compacted Settings cards for Interface & access, OPNsense managed category and OPNsense network connections so they no longer consume a full-width row unnecessarily.
- Simplified the Presentation Mode section to a single-column panel.
- Removed the telemetry receiver endpoint URL from the Settings UI and reduced telemetry status to Last sent and Status.
- Removed stale Configuration Lock/Unlock markup from Settings now that 0.6.21 no longer uses a separate read-only mode.

## 0.6.21.1

- Added short-lived, single-use registration tokens for outbound OPNsense agents.
- Added a one-command remote OPNsense installer generated from the Agents page.
- Added per-agent HMAC-SHA256 authentication with timestamp and nonce replay protection, including compatibility with the earlier agent header names.
- Added authenticated heartbeat/reporting plus an outbound job queue and result channel.
- Added initial allow-listed remote jobs for inventory and system status; arbitrary remote command execution is not exposed.
- Added five-minute job leases so abandoned running jobs can be re-queued automatically.
- Added OPNsense rc(8) service installation using `/etc/rc.conf.d/opnsentral_agent`.

## 0.6.20.19

- Added the running telemetry server version to the private telemetry dashboard.
- Passed the application version into the telemetry image at build time so the dashboard shows the actual image version.
- Changed the Docker image workflow to read `OPNSENTRAL_VERSION` once and reuse it for image tags instead of maintaining separate hard-coded image versions.
- Stopped publishing `opnsentral-telemetry` to Docker Hub; future telemetry images are published to GHCR only.

## 0.6.20.18

- Made the telemetry dashboard developer-only and disabled by default.
- Added `TELEMETRY_DASHBOARD_ENABLED`; when disabled the dashboard root returns HTTP 404 while `/api.php` remains available for anonymous telemetry ingestion.
- Kept Basic Auth mandatory when the developer dashboard is explicitly enabled.
- Removed the hard-coded public telemetry write token from the main opnSentral compose and environment template.
- Made `TELEMETRY_WRITE_TOKEN` optional on both the client and receiver instead of treating a repository-embedded value as a secret.
- Updated telemetry receiver documentation to distinguish the public ingest endpoint from the private developer dashboard.

## 0.6.20.17

- Removed the duplicate `telemetry-server/env.example`; `.env.example` is now the single telemetry environment template.
- Added an immediate telemetry send on every opnSentral container start, including the first start after container creation, while preserving the existing telemetry opt-in.
- Moved startup telemetry out of the browser path so no login or page load is required for the startup send.
- Made the sidebar version read directly from `OPNSENTRAL_VERSION` and removed the independent footer JavaScript version override.
- Cleaned remaining active `opnCentral` branding from the root Dockerfile, image labels, PHP upload config and entrypoint naming.

## 0.6.20.16

- Fixed telemetry authentication handling behind Apache/reverse-proxy setups by accepting the standard Authorization header through multiple PHP/Apache server-header paths.
- Updated telemetry client version reporting and User-Agent naming from the old `opnCentral` identifiers to `opnSentral` / `OPNSENTRAL_VERSION`.
- Fixed the GitHub release workflow after the version constant was renamed from `OPNCENTRAL_VERSION` to `OPNSENTRAL_VERSION`.

## 0.6.20.15

- Fixed telemetry startup on Synology/Portainer bind mounts where SQLite failed with `unable to open database file`.
- Added a telemetry entrypoint that creates `/var/www/data` and restores `www-data` ownership and write permissions at container startup.
- Kept Apache running through the official PHP image entrypoint after the permission initialization.

## 0.6.20.14

- Changed the telemetry server default web port to `4455`.
- Added the shared telemetry write-token default to both the telemetry receiver stack and the main opnSentral stack.
- Added the default telemetry client endpoint `https://opnsentral.kryszon.info:4455/api.php` to the main compose and environment template.
- Updated telemetry environment templates to match the new port and token defaults.
- Documented the difference between direct public HTTPS on port 4455 and reverse-proxy HTTPS on the standard port 443.

## 0.6.20.13

- Reworked the telemetry Docker deployment for Synology and Portainer Git-repository stacks.
- Removed the telemetry compose `build:` step and switched deployment to the published `opnsentral-telemetry` image.
- Added AMD64 and ARM64 telemetry image publishing to the existing Docker CI workflow.
- Replaced the relative telemetry `./data` bind mount with the standard `BASE_PATH` host path used by opnSentral.
- Aligned telemetry stack variables with the main stack: `BASE_PATH`, `WEB_PORT`, `IMAGE_VERSION` and `TZ`.
- Updated both telemetry environment templates for Synology/File Station and Portainer use.
- Replaced active telemetry branding and authentication text from `opnCentral` to `opnSentral`.
- Renamed active update-check constants from `OPNCENTRAL_*` to `OPNSENTRAL_VERSION`.
- Rewrote telemetry deployment documentation with a Portainer Git-repository example.

## 0.6.20.12

- Removed remaining hard-coded `opnCentral` wording from the alias distribution page.
- Alias distribution now displays the configured managed-category name from Settings.
- Updated missing-category errors, takeover guidance and confirmation text to use the configured managed-category name.
- Added `GeoIP` directly to the server-rendered alias type list as well as the existing GeoIP guidance.

## 0.6.20.11

- Added the missing `GeoIP` alias type to the central alias editor.
- GeoIP aliases use the OPNsense alias type value `geoip`.
- Added country-code guidance for GeoIP alias content, using ISO country codes such as `BE`, `DE` and `NL`.

## 0.6.20.10

- Structurally moved Configuration Lock/Unlock out of the top bar and into Settings → Interface & access.
- Structurally moved Presentation Mode out of the top bar and into Settings → Interface & access.
- Removed the temporary DOM-relocation helper used in 0.6.20.9.
- Kept the support link independent in the top bar instead of coupling it to Lock/Unlock.
- Moved configuration-access behavior into a dedicated JavaScript module.
- Moved Presentation Mode runtime behavior into a dedicated JavaScript module while keeping its state browser-persistent.
- Locked write controls now point users to the Settings access section.

## 0.6.20.9

- Added the first Settings-oriented Interface & access layout for Configuration Lock/Unlock and Presentation Mode.
- Made firmware audit output collapsible per firewall for a cleaner overview.

## 0.6.20.8

- Added a persistent Settings option to disable IPv6 for OPNsense connections and force IPv4.
- Applied the IPv4-only setting consistently to normal API calls, parallel requests and backup connections.
- Added the OPNsense network connection settings panel.

## 0.6.20.7

- Added selectable firmware audits instead of a single generic Run Audit action.
- Added Security, Health, Connectivity and Cleanup audits plus Upgrade Log access.
- Added live audit-status polling and visible audit output per firewall.
- Stored the most recent audit output in the browser so it remains available after reopening the Firmware Status page.
- Updated firmware management and audit handling for the current OPNsense API endpoints.

## 0.6.20.6

- Added System firmware status management with update checks and firmware actions.
- Added central plug-in and firmware navigation.
- Added GeoIP settings integration.
- Improved sidebar and menu organization around System, Firmware and Configuration functions.

## 0.6.11.1 and earlier

This period contains the original opnCentral/opnSentral feature build-out and many iterative fixes. Major capabilities introduced during that work include:

- Multi-firewall OPNsense management.
- Dashboard and firewall status views.
- Alias and category inventory and management.
- Configuration backup history and automatic pre-change backups.
- WireGuard management and site-to-site VPN creation.
- OpenVPN management and site-to-site VPN creation.
- OpenVPN management and Roadwarrior server creation.
- Services and agent management.
- IDS/IPS ruleset and policy management.
- Plug-in and firmware operations.
- Troubleshooting and configuration comparison views.
- Configuration read-only lock and protected write operations.
- Presentation Mode for anonymized screenshots and demonstrations.
- Managed OPNsense category support.
- Self-backup and restore.
- Telemetry and update-check infrastructure.
- Multi-architecture Docker publishing.

For exact historical behavior, use the release summaries above and published GitHub releases.
