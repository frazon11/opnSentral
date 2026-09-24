<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

function webssh_base64url(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function webssh_target_from_firewall(array $firewall): array
{
    $baseUrl = trim((string) ($firewall['base_url'] ?? ''));
    $host = parse_url($baseUrl, PHP_URL_HOST);
    $host = is_string($host) ? trim($host, '[]') : '';
    if ($host === '') {
        throw new RuntimeException('The firewall URL does not contain a usable SSH host.');
    }

    if (
        filter_var($host, FILTER_VALIDATE_IP) === false
        && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
    ) {
        throw new RuntimeException('The firewall URL contains an invalid SSH host.');
    }

    return [
        'firewall_id' => (int) ($firewall['id'] ?? 0),
        'firewall_name' => trim((string) ($firewall['name'] ?? 'Firewall')),
        'host' => $host,
        'port' => max(1, min(65535, (int) ($firewall['ssh_port'] ?? 22))),
    ];
}

function webssh_credentials_configured(array $firewall): bool
{
    $username = trim((string) ($firewall['ssh_username'] ?? ''));
    $method = (string) ($firewall['ssh_auth_method'] ?? 'password');
    if ($username === '') return false;
    if ($method === 'key') return trim((string) ($firewall['ssh_private_key_enc'] ?? '')) !== '';
    return trim((string) ($firewall['ssh_password_enc'] ?? '')) !== '';
}

function webssh_credential_blob(array $firewall): string
{
    if (!webssh_credentials_configured($firewall)) return '';

    $method = (string) ($firewall['ssh_auth_method'] ?? 'password');
    $credentials = [
        'username' => trim((string) ($firewall['ssh_username'] ?? '')),
        'auth_method' => $method === 'key' ? 'key' : 'password',
        'password' => '',
        'private_key' => '',
    ];
    if ($credentials['auth_method'] === 'key') {
        $credentials['private_key'] = decrypt_value((string) $firewall['ssh_private_key_enc']);
    } else {
        $credentials['password'] = decrypt_value((string) $firewall['ssh_password_enc']);
    }

    return encrypt_value(json_encode($credentials, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
}

function webssh_create_target_token(array $firewall, int $lifetime = 90): string
{
    $target = webssh_target_from_firewall($firewall);
    $target['port'] = max(1, min(65535, (int) ($firewall['ssh_port'] ?? 22)));
    $payload = $target + [
        'credential_blob' => webssh_credential_blob($firewall),
        'iat' => time(),
        'exp' => time() + max(30, min(120, $lifetime)),
        'nonce' => bin2hex(random_bytes(12)),
    ];
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $encoded = webssh_base64url($json);
    $signature = hash_hmac('sha256', $encoded, crypto_key());
    return $encoded . '.' . $signature;
}
