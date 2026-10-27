#!/bin/sh
set -eu

SERVER_URL="${1:-}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root on OPNsense." >&2
    exit 1
fi

case "$SERVER_URL" in
    https://*) ;;
    *)
        echo "Usage: fetch -o - https://OPNSENTRAL/system-access-bridge-install.sh | sh -s -- https://OPNSENTRAL" >&2
        echo "The opnSentral URL must use HTTPS." >&2
        exit 1
        ;;
esac

SERVER_URL="${SERVER_URL%/}"
command -v fetch >/dev/null 2>&1 || { echo "FreeBSD fetch is required." >&2; exit 1; }
[ -x /usr/local/bin/php ] || { echo "/usr/local/bin/php is required." >&2; exit 1; }

TMPDIR="/tmp/opnsentral-system-access.$$"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM
mkdir -p "$TMPDIR"

fetch_bridge_file()
{
    key="$1"
    target="$2"
    temp="$TMPDIR/$key"
    fetch -q -o "$temp" "$SERVER_URL/agent/plugin_file.php?file=$key"
    [ -s "$temp" ] || { echo "Downloaded bridge file $key is empty." >&2; exit 1; }
    mkdir -p "$(dirname "$target")"
    install -m 0644 "$temp" "$target"
}

fetch_bridge_file access_controller /usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/AccessController.php
fetch_bridge_file acl /usr/local/opnsense/mvc/app/models/OPNsense/OpnSentralAgent/ACL/ACL.xml

/usr/local/bin/php -l /usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/AccessController.php >/dev/null
service configd restart >/dev/null 2>&1 || true

test -r /usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/AccessController.php
test -r /usr/local/opnsense/mvc/app/models/OPNsense/OpnSentralAgent/ACL/ACL.xml

echo "opnSentral System Access API bridge installed."
echo "API: /api/opnsentralagent/access/snapshot"
