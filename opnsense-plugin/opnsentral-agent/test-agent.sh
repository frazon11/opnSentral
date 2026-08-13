#!/bin/sh

set -u

BOOTSTRAP="/usr/local/opnsense/scripts/OPNsense/OpnSentralAgent/bootstrap.php"
WORKER="/usr/local/sbin/opnsentral-agent"
CONFIG="/usr/local/etc/opnsentral-agent.json"
SERVICE="opnsentral_agent"

ok()
{
    printf '[OK] %s\n' "$1"
}

fail()
{
    printf '[FAIL] %s\n' "$1" >&2
    exit 1
}

[ -f "$BOOTSTRAP" ] || fail "Plugin bootstrap helper is missing: $BOOTSTRAP"
ok "Plugin bootstrap helper exists"

[ -f "$CONFIG" ] || fail "Agent is not registered: $CONFIG is missing"
ok "Agent registration file exists"

[ -f "$WORKER" ] || fail "Agent worker is missing: $WORKER"
ok "Agent worker exists"

/usr/local/bin/php -r '$c=json_decode(file_get_contents("/usr/local/etc/opnsentral-agent.json"),true); if(!is_array($c)||empty($c["server_url"])||empty($c["agent_id"])||empty($c["agent_secret"])) exit(1);' \
    || fail "Agent registration file is invalid"
ok "Agent registration file is valid"

SERVER_URL=$(/usr/local/bin/php -r '$c=json_decode(file_get_contents("/usr/local/etc/opnsentral-agent.json"),true); echo rtrim((string)$c["server_url"],"/");')
[ -n "$SERVER_URL" ] || fail "Registered opnSentral server URL is empty"
ok "Registered server: $SERVER_URL"

/usr/local/bin/php "$BOOTSTRAP" repair >/tmp/opnsentral-agent-repair-test.log 2>&1 \
    || { cat /tmp/opnsentral-agent-repair-test.log >&2; fail "Canonical worker manifest/download verification failed"; }
ok "Canonical worker manifest and SHA-256 verification passed"

/usr/local/bin/php "$BOOTSTRAP" once >/tmp/opnsentral-agent-once-test.log 2>&1 \
    || { cat /tmp/opnsentral-agent-once-test.log >&2; fail "Agent one-shot report/job poll failed"; }
ok "Agent one-shot report/job poll passed"

/usr/sbin/service "$SERVICE" onestatus >/tmp/opnsentral-agent-service-test.log 2>&1 \
    || { cat /tmp/opnsentral-agent-service-test.log >&2; fail "Agent service is not running"; }
ok "Agent service is running"

printf '\nopnSentral agent transport test passed.\n'
