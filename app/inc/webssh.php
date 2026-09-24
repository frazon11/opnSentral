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


function webssh_ssh_string(string $value): string
{
    return pack('N', strlen($value)) . $value;
}

function webssh_ssh_mpint(string $value): string
{
    $value = ltrim($value, "\0");
    if ($value === '') $value = "\0";
    if ((ord($value[0]) & 0x80) !== 0) $value = "\0" . $value;
    return pack('N', strlen($value)) . $value;
}

function webssh_rsa_public_key_from_private(string $privateKey, string $comment = 'opnSentral'): string
{
    $key = openssl_pkey_get_private($privateKey);
    if ($key === false) {
        throw new RuntimeException('Stored private key is not an OpenSSL-readable RSA private key.');
    }
    $details = openssl_pkey_get_details($key);
    if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || !is_array($details['rsa'] ?? null)) {
        throw new RuntimeException('Stored private key is not an RSA key.');
    }
    $n = (string) ($details['rsa']['n'] ?? '');
    $e = (string) ($details['rsa']['e'] ?? '');
    if ($n === '' || $e === '') throw new RuntimeException('Could not extract RSA public-key parameters.');
    $blob = webssh_ssh_string('ssh-rsa') . webssh_ssh_mpint($e) . webssh_ssh_mpint($n);
    $comment = preg_replace('/[^A-Za-z0-9._@-]+/', '-', trim($comment)) ?: 'opnSentral';
    return 'ssh-rsa ' . base64_encode($blob) . ' ' . $comment;
}

function webssh_generate_rsa_keypair(int $bits = 3072, string $comment = 'opnSentral'): array
{
    $bits = max(2048, min(4096, $bits));
    $key = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => $bits,
    ]);
    if ($key === false) throw new RuntimeException('Could not generate RSA keypair.');
    $privateKey = '';
    if (!openssl_pkey_export($key, $privateKey) || trim($privateKey) === '') {
        throw new RuntimeException('Could not export generated RSA private key.');
    }
    $publicKey = webssh_rsa_public_key_from_private($privateKey, $comment);
    return ['private_key' => $privateKey, 'public_key' => $publicKey, 'bits' => $bits];
}

function webssh_queue_public_key_deploy(array $firewall, string $publicKey): int
{
    $username = trim((string) ($firewall['ssh_username'] ?? ''));
    if ($username === '') throw new RuntimeException('Configure the WebSSH SSH username before deploying a public key.');

    $statement = db()->prepare('SELECT * FROM agents WHERE firewall_id = ? AND enabled = 1 ORDER BY id DESC LIMIT 1');
    $statement->execute([(int) ($firewall['id'] ?? 0)]);
    $agent = $statement->fetch();
    if (!is_array($agent)) throw new RuntimeException('No enabled opnSentral agent is linked to this firewall.');

    $statement = db()->prepare('INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at) VALUES(?,?,?,?,?)');
    $statement->execute([
        (int) $agent['id'],
        'add_access_user_authorized_key',
        json_encode(['user' => $username, 'authorized_key' => $publicKey], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
        'queued',
        gmdate('c'),
    ]);
    return (int) db()->lastInsertId();
}
