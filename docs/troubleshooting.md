# Troubleshooting

## GitHub update check cannot resolve `api.github.com`

Test from the container:

```bash
docker exec -it OpnCentral getent hosts api.github.com
docker exec -it OpnCentral curl -I https://api.github.com
```

When Docker DNS is unreliable, configure DNS servers in Compose:

```yaml
services:
  opncentral:
    dns:
      - 1.1.1.1
      - 8.8.8.8
```

Recreate the container after changing Compose.

## Restored credentials cannot be decrypted

The restored data was created with a different `APP_KEY`. Restore the original key and recreate the container.
