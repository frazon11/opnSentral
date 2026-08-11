#!/bin/sh
set -eu

SERVER_URL="${1:-}"
TOKEN="${2:-}"

if [ -z "$SERVER_URL" ] || [ -z "$TOKEN" ]; then
    echo "Usage: install.sh https://OPNSENTRAL REGISTRATION_TOKEN" >&2
    exit 1
fi

case "$SERVER_URL" in
    https://*) ;;
    *)
        echo "The opnSentral URL must use https://" >&2
        exit 1
        ;;
esac

SERVER_URL="${SERVER_URL%/}"
AGENT_BIN="/usr/local/sbin/opnsentral-agent"
RC_SCRIPT="/usr/local/etc/rc.d/opnsentral_agent"
RC_CONF_DIR="/etc/rc.conf.d"
RC_CONF_FILE="$RC_CONF_DIR/opnsentral_agent"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root on OPNsense." >&2
    exit 1
fi

command -v fetch >/dev/null 2>&1 || {
    echo "FreeBSD fetch is required." >&2
    exit 1
}

[ -x /usr/local/bin/php ] || {
    echo "/usr/local/bin/php is required." >&2
    exit 1
}

fetch -q -o "$AGENT_BIN" "$SERVER_URL/agent/opnsentral-agent"
chmod 0755 "$AGENT_BIN"

"$AGENT_BIN" register "$SERVER_URL" "$TOKEN"

cat > "$RC_SCRIPT" <<'EOF'
#!/bin/sh
# PROVIDE: opnsentral_agent
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="opnsentral_agent"
rcvar="opnsentral_agent_enable"
pidfile="/var/run/opnsentral-agent.pid"
command="/usr/sbin/daemon"
command_args="-p ${pidfile} -f /usr/local/sbin/opnsentral-agent run"

load_rc_config "$name"
: ${opnsentral_agent_enable:="NO"}
run_rc_command "$1"
EOF

chmod 0755 "$RC_SCRIPT"
mkdir -p "$RC_CONF_DIR"
cat > "$RC_CONF_FILE" <<'EOF'
opnsentral_agent_enable="YES"
EOF
chmod 0644 "$RC_CONF_FILE"

service opnsentral_agent stop >/dev/null 2>&1 || true
service opnsentral_agent start

echo ""
echo "opnSentral agent installed and started."
echo "Configuration: /usr/local/etc/opnsentral-agent.json"
echo "Service:       service opnsentral_agent status"
