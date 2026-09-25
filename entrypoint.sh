#!/bin/sh
set -eu

mkdir -p /var/www/data /var/www/backups
chown -R www-data:www-data /var/www/data /var/www/backups

su -s /bin/sh www-data -c 'node /opt/opnsentral-webssh/server.js' &
su -s /bin/sh www-data -c 'php /var/www/html/alert_worker.php' &
su -s /bin/sh www-data -c 'php /var/www/html/agent_recovery_worker.php' &

(
    sleep 2
    su -s /bin/sh www-data -c 'php /var/www/html/telemetry_startup.php'
) &

exec "$@"
