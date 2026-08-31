#!/bin/sh
set -eu

SERVER_URL="${1:-}"
TOKEN="${2:-}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root on OPNsense." >&2
    exit 1
fi

case "$SERVER_URL" in
    https://*) ;;
    *)
        echo "Usage: fetch -o - https://OPNSENTRAL/agent/install-plugin.sh | sh -s -- https://OPNSENTRAL REGISTRATION_TOKEN" >&2
        echo "The opnSentral URL must use HTTPS." >&2
        exit 1
        ;;
esac

SERVER_URL="${SERVER_URL%/}"

command -v fetch >/dev/null 2>&1 || {
    echo "FreeBSD fetch is required." >&2
    exit 1
}
command -v curl >/dev/null 2>&1 || {
    echo "curl is required on OPNsense." >&2
    exit 1
}
[ -x /usr/local/bin/php ] || {
    echo "/usr/local/bin/php is required." >&2
    exit 1
}

TMPDIR="/tmp/opnsentral-plugin.$$"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM
mkdir -p "$TMPDIR"

fetch_plugin_file()
{
    key="$1"
    target="$2"
    mode="$3"
    temp="$TMPDIR/$key"

    echo "Downloading $key ..."
    fetch -q -o "$temp" "$SERVER_URL/agent/plugin_file.php?file=$key"
    [ -s "$temp" ] || {
        echo "Downloaded plugin file $key is empty." >&2
        exit 1
    }

    mkdir -p "$(dirname "$target")"
    install -m "$mode" "$temp" "$target"
}

fetch_plugin_file rc \
    /usr/local/etc/rc.d/opnsentral_agent 0755
fetch_plugin_file syshook \
    /usr/local/etc/rc.syshook.d/start/50-opnsentral-agent 0755
fetch_plugin_file bootstrap \
    /usr/local/opnsense/scripts/OPNsense/OpnSentralAgent/bootstrap.php 0755
fetch_plugin_file controller \
    /usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/IndexController.php 0644
fetch_plugin_file hardware_controller \
    /usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/HardwareController.php 0644
fetch_plugin_file acl \
    /usr/local/opnsense/mvc/app/models/OPNsense/OpnSentralAgent/ACL/ACL.xml 0644
fetch_plugin_file menu \
    /usr/local/opnsense/mvc/app/models/OPNsense/OpnSentralAgent/Menu/Menu.xml 0644
fetch_plugin_file view \
    /usr/local/opnsense/mvc/app/views/OPNsense/OpnSentralAgent/index.volt 0644

/usr/local/bin/php -l /usr/local/opnsense/scripts/OPNsense/OpnSentralAgent/bootstrap.php >/dev/null
/usr/local/bin/php -l /usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/IndexController.php >/dev/null
/usr/local/bin/php -l /usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/HardwareController.php >/dev/null

BOOTSTRAP=/usr/local/opnsense/scripts/OPNsense/OpnSentralAgent/bootstrap.php
CONFIG=/usr/local/etc/opnsentral-agent.json

if [ -s "$CONFIG" ]; then
    echo "Existing opnSentral registration found; repairing/verifying the worker."
    "$BOOTSTRAP" repair
else
    if [ -z "$TOKEN" ]; then
        echo "A registration token is required for first installation." >&2
        exit 1
    fi
    "$BOOTSTRAP" register "$SERVER_URL" "$TOKEN"
fi

service opnsentral_agent onestatus >/dev/null

[ -x /usr/local/etc/rc.syshook.d/start/50-opnsentral-agent ] || {
    echo "Agent startup recovery hook was not installed correctly." >&2
    exit 1
}
[ -r /usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/HardwareController.php ] || {
    echo "Hardware inventory API was not installed correctly." >&2
    exit 1
}

echo ""
echo "os-opnsentral-agent installed and online."
echo "Service: service opnsentral_agent status"
echo "Boot recovery: /usr/local/etc/rc.syshook.d/start/50-opnsentral-agent"
echo "Hardware API: /api/opnsentralagent/hardware/get"
echo "GUI:     Services -> opnSentral Agent"
