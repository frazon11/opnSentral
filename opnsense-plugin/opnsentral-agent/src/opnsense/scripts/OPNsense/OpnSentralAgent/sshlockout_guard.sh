#!/bin/sh
# Keep persistent trusted sshlockout hosts represented in the live PF table.
# OPNsense periodically expires sshlockout table entries, so boot-only sync is
# insufficient for an "always trusted" host.

HELPER=/usr/local/opnsense/scripts/OPNsense/OpnSentralAgent/sshlockout.php
INTERVAL=300

while :; do
    if [ -x "$HELPER" ]; then
        "$HELPER" sync >/dev/null 2>&1 || true
    fi
    sleep "$INTERVAL"
done
