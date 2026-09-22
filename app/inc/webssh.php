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
        'port' => 22,
    ];
}

function webssh_create_target_token(array $firewall, int $lifetime = 90): string
{
    $target = webssh_target_from_firewall($firewall);
    $payload = $target + [
        'iat' => time(),
        'exp' => time() + max(30, min(120, $lifetime)),
        'nonce' => bin2hex(random_bytes(12)),
    ];
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $encoded = webssh_base64url($json);
    $signature = hash_hmac('sha256', $encoded, crypto_key());
    return $encoded . '.' . $signature;
}
