<?php

declare(strict_types=1);

$root = dirname(__DIR__);

function read_required_file(string $path): string
{
    $content = is_file($path) ? file_get_contents($path) : false;
    if (!is_string($content)) {
        fwrite(STDERR, "Admin API login check failed: missing {$path}.\n");
        exit(1);
    }
    return $content;
}

function must_contain(string $content, string $needle, string $message): void
{
    if (!str_contains($content, $needle)) {
        fwrite(STDERR, "Admin API login check failed: {$message}.\n");
        exit(1);
    }
}

$login = read_required_file($root . '/app/login.php');
must_contain($login, "envv('ADMIN_API_KEY')", 'login must read ADMIN_API_KEY from the environment');
must_contain($login, "strlen(\$apiKey)>=32", 'short API keys must not enable API-key authentication');
must_contain($login, "hash_equals(\$apiKey,\$provided)", 'API-key comparison must be timing-safe');
must_contain($login, "complete_login(\$adminUser,'api_key')", 'API-key login must map to the configured administrator account');
must_contain($login, "session_regenerate_id(true)", 'successful login must regenerate the session identifier');
must_contain($login, "\$_SESSION['auth_method']=\$method", 'session must record the authentication method');
must_contain($login, 'name="api_key"', 'login page must expose the API-key field when enabled');
must_contain($login, "usleep(350000)", 'failed API-key attempts must retain the login delay');

$env = read_required_file($root . '/.env.example');
must_contain($env, 'ADMIN_API_KEY=', '.env example must expose ADMIN_API_KEY');
must_contain($env, 'openssl rand -hex 32', '.env example must document strong API-key generation');

$compose = read_required_file($root . '/docker-compose.yml');
must_contain($compose, 'ADMIN_API_KEY: ${ADMIN_API_KEY:-}', 'Compose must pass ADMIN_API_KEY into the container');

fwrite(STDOUT, "Admin API-key login checks passed.\n");
