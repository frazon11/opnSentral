#!/bin/sh
set -eu
SRC="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/src"
mkdir -p /usr/local/opncentral-agent
cp "$SRC/usr/local/opncentral-agent/report.py" /usr/local/opncentral-agent/
cp "$SRC/opnsense/service/conf/actions.d/actions_opncentralagent.conf" /usr/local/opnsense/service/conf/actions.d/
if [ ! -f /usr/local/etc/opncentral-agent.conf ]; then cp "$SRC/usr/local/etc/opncentral-agent.conf.sample" /usr/local/etc/opncentral-agent.conf;chmod 600 /usr/local/etc/opncentral-agent.conf;fi
service configd restart
echo '*/1 * * * * root /usr/local/sbin/configctl opncentralagent report >/dev/null 2>&1' > /etc/cron.d/opncentral-agent
service cron restart
echo "Installed. Edit /usr/local/etc/opncentral-agent.conf"
