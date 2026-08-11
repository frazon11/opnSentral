#!/bin/sh
set -eu
BASE="${BASE_PATH:-/volume1/docker/opnsense-central}"
SRC="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mkdir -p "$BASE/data" "$BASE/backups"
cp "$SRC/docker-compose.yml" "$SRC/Dockerfile" "$SRC/apache.conf" "$SRC/entrypoint.sh" "$BASE/"
rm -rf "$BASE/app"; cp -R "$SRC/app" "$BASE/app"; chmod +x "$BASE/entrypoint.sh"
if [ ! -f "$BASE/.env" ]; then
 P="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"; K="$(openssl rand -hex 32)"
 cat > "$BASE/.env" <<EOF
BASE_PATH=$BASE
WEB_PORT=8788
TZ=Europe/Brussels
APP_NAME=OPNsense Central Lite
ADMIN_USER=admin
ADMIN_PASSWORD=$P
APP_KEY=$K
SESSION_SECURE=false
EOF
 chmod 600 "$BASE/.env"; echo "Username: admin"; echo "Password: $P"; echo "Stored in $BASE/.env"
fi
cd "$BASE"; docker compose config >/dev/null; docker compose up -d --build; docker compose ps; echo "Open http://SYNOLOGY-IP:8788"
