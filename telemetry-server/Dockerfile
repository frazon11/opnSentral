FROM php:8.5-apache-trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libsqlite3-dev \
        sqlite3 \
        ca-certificates; \
    docker-php-ext-install -j"$(nproc)" pdo_sqlite; \
    a2enmod rewrite headers; \
    printf '%s\n' \
        'ServerTokens Prod' \
        'ServerSignature Off' \
        'TraceEnable Off' \
        'LogFormat "%r" noip' \
        'CustomLog /dev/null noip' \
        > /etc/apache2/conf-available/telemetry-privacy.conf; \
    a2enconf telemetry-privacy; \
    rm -rf /var/lib/apt/lists/*

COPY app/ /var/www/html/
COPY apache.conf /etc/apache2/conf-available/opnsentral-telemetry.conf

RUN set -eux; \
    a2enconf opnsentral-telemetry; \
    mkdir -p /var/www/data; \
    chown -R www-data:www-data /var/www/html /var/www/data

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD php -r '$pdo=new PDO("sqlite:/var/www/data/telemetry.sqlite"); echo "ok";' || exit 1
