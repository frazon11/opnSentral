# Changelog

All notable changes to opnSentral are documented here.

The detailed development history remains available through the Git commit history and GitHub releases. This file is intentionally kept concise and release-oriented.

## Unreleased

- Clarified Docker platform support in the README, including Raspberry Pi 4/5 with a 64-bit OS.
- Removed low-level implementation details from the README feature list.
- Consolidated and cleaned the changelog so future changes are tracked here instead of as repeated README or release notes.

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
- Renamed active update-check constants from `OPNCENTRAL_*` to `OPNSENTRAL_*`.
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

For exact historical changes from this period, use the Git commit history and published GitHub releases.
