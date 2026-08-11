#!/bin/sh
set -eu

DATA_DIR=/var/www/data

mkdir -p "$DATA_DIR"

# Synology/Portainer bind mounts replace the image-time ownership of /var/www/data.
# Restore the permissions required by Apache/PHP before the service starts.
chown -R www-data:www-data "$DATA_DIR"
chmod 0770 "$DATA_DIR"

exec docker-php-entrypoint "$@"
