# os-opnsentral-agent prototype

This directory contains the first OPNsense-native packaging prototype for the existing opnSentral outbound agent.

Expected package name: `os-opnsentral-agent`

Expected GUI location: `Services -> opnSentral Agent`

The plugin wraps the existing outbound agent with native OPNsense service/package integration. It does not introduce an inbound remote shell.

## Current state

Implemented in source:

- plugin Makefile and OPNsense menu entry
- ACL for the plugin UI/API namespace
- rc.d service wrapper for the long-running worker
- canonical agent manifest endpoint on opnSentral
- plugin bootstrap helper with HTTPS-only registration
- SHA-256, file-size and declared-version verification before activating the downloaded worker
- persistent local agent identity/configuration with mode 0600
- initial `once` connectivity/job-poll test before daemon startup
- `repair` mode that preserves the registered agent identity and re-downloads the canonical worker
- OPNsense index controller and informational plugin page

Still required before production use:

- fixed backend bridge for the GUI Register/Repair/Test buttons (the ChatGPT GitHub connector currently blocks committing executable configd/API action definitions)
- package build and install test in an OPNsense plugin build tree
- live registration and daemon test against one managed OPNsense firewall
- package signing/repository work if this is distributed outside a local test

## First live test

The first test firewall should prove the worker before GUI polish:

1. Verify `https://OPNSENTRAL/agent/manifest.php` returns the canonical worker manifest.
2. Install the plugin prototype files/package on one test OPNsense firewall.
3. Generate a one-time registration token in opnSentral.
4. Run the plugin bootstrap registration helper locally on OPNsense.
5. Confirm the helper downloads and verifies the canonical worker.
6. Confirm the initial `once` cycle succeeds and the firewall appears Online in opnSentral.
7. Confirm `service opnsentral_agent status` remains running.
8. Queue an inventory job and confirm the result is returned.
9. Queue one low-risk Administration setting change on the test firewall and verify backup, execution and result reporting.

Only after these steps pass should GUI registration become the primary deployment path.
