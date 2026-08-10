<?php

declare(strict_types=1);

const TELEMETRY_DB = '/var/www/data/telemetry.sqlite';

function env_value(string $name, string $default = ''): string
{
    $value = getenv($name);
    return $value === false || $value === '' ? $default : $value;
}

function telemetry_db(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    if (!is_dir(dirname(TELEMETRY_DB))) {
        mkdir(dirname(TELEMETRY_DB), 0770, true);
    }

    $pdo = new PDO('sqlite:' . TELEMETRY_DB);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA busy_timeout=5000');

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS installations (
            installation_hash TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            version TEXT NOT NULL,
            architecture TEXT NOT NULL,
            platform TEXT NOT NULL,
            checks INTEGER NOT NULL DEFAULT 1
        )'
    );

    $pdo->exec(
        'CREATE INDEX IF NOT EXISTS idx_installations_last_seen
         ON installations(last_seen DESC)'
    );

    return $pdo;
}

function json_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode(
        $payload,
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE |
        JSON_THROW_ON_ERROR
    );
    exit;
}

function require_write_token(): void
{
    $expected = trim(env_value('TELEMETRY_WRITE_TOKEN'));

    if ($expected === '') {
        return;
    }

    $authorization = trim(
        (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '')
    );

    if (
        !preg_match('/^Bearer\s+(.+)$/i', $authorization, $matches) ||
        !hash_equals($expected, trim($matches[1]))
    ) {
        json_response(
            ['ok' => false, 'error' => 'Unauthorized.'],
            401
        );
    }
}

function require_dashboard_login(): void
{
    $expectedUser = env_value('DASHBOARD_USER', 'admin');
    $expectedPassword = env_value('DASHBOARD_PASSWORD');

    if ($expectedPassword === '') {
        http_response_code(503);
        header('Content-Type: text/plain; charset=utf-8');
        exit('DASHBOARD_PASSWORD is not configured.');
    }

    $user = (string) ($_SERVER['PHP_AUTH_USER'] ?? '');
    $password = (string) ($_SERVER['PHP_AUTH_PW'] ?? '');

    if (
        !hash_equals($expectedUser, $user) ||
        !hash_equals($expectedPassword, $password)
    ) {
        header('WWW-Authenticate: Basic realm="opnSentral Telemetry"');
        http_response_code(401);
        exit('Authentication required.');
    }
}

function cleanup_old_installations(): void
{
    $days = (int) env_value('RETENTION_DAYS', '730');

    if ($days <= 0) {
        return;
    }

    $threshold = gmdate('c', time() - ($days * 86400));
    $statement = telemetry_db()->prepare(
        'DELETE FROM installations WHERE last_seen < :threshold'
    );
    $statement->execute(['threshold' => $threshold]);
}
