FROM php:8.5-apache-trixie

LABEL org.opencontainers.image.title="opnSentral"
LABEL org.opencontainers.image.description="Central manager for multiple OPNsense firewalls"
LABEL org.opencontainers.image.source="https://github.com/frazon11/opnSentral"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update; \
    apt-get upgrade -y; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libcurl4t64 \
        libsqlite3-0 \
        libcurl4-openssl-dev \
        libsqlite3-dev \
        libzip-dev \
        libzip5; \
    docker-php-ext-configure zip; \
    docker-php-ext-install -j"$(nproc)" curl pdo_sqlite zip; \
    docker-php-ext-enable zip; \
    php -r 'if (!class_exists("ZipArchive")) { fwrite(STDERR, "ZipArchive unavailable\\n"); exit(1); }'; \
    php -m | grep -Fx zip; \
    printf '%s\n' \
        'upload_max_filesize=1024M' \
        'post_max_size=1024M' \
        'max_execution_time=600' \
        'max_input_time=600' \
        > /usr/local/etc/php/conf.d/opnsentral-uploads.ini; \
    a2enmod rewrite headers; \
    apt-mark manual ca-certificates curl libcurl4t64 libsqlite3-0 libzip5; \
    apt-get purge -y --auto-remove libcurl4-openssl-dev libsqlite3-dev libzip-dev; \
    php -r 'if (!class_exists("ZipArchive")) { fwrite(STDERR, "ZipArchive lost after cleanup\\n"); exit(1); }'; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY app/ /var/www/html/
COPY apache.conf /etc/apache2/conf-available/opnsentral.conf
COPY entrypoint.sh /usr/local/bin/opnsentral-entrypoint

RUN set -eux; \
    chmod +x /usr/local/bin/opnsentral-entrypoint; \
    a2enconf opnsentral; \
    mkdir -p /var/www/data /var/www/backups; \
    chown -R www-data:www-data /var/www/html /var/www/data /var/www/backups

WORKDIR /var/www/html

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD curl -fsS http://127.0.0.1/health.php || exit 1

ENTRYPOINT ["opnsentral-entrypoint"]
CMD ["apache2-foreground"]
