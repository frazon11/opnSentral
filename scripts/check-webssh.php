<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$files = [
    'page' => $root . '/app/webssh.php',
    'token' => $root . '/app/webssh_token.php',
    'helper' => $root . '/app/inc/webssh.php',
    'bridge' => $root . '/webssh/server.js',
    'docker' => $root . '/Dockerfile',
    'apache' => $root . '/apache.conf',
    'entrypoint' => $root . '/entrypoint.sh',
    'header' => $root . '/app/inc/header.php',
    'config' => $root . '/app/inc/config.php',
    'firewall_edit' => $root . '/app/firewall_edit.php',
    'key_action' => $root . '/app/webssh_key_action.php',
    'agent' => $root . '/app/agent/opnsentral-agent',
];

foreach ($files as $label => $path) {
    if (!is_file($path)) {
        fwrite(STDERR, "WebSSH regression failed: missing {$label} file {$path}\n");
        exit(1);
    }
}

$contents = array_map(static fn(string $path): string => (string) file_get_contents($path), $files);

$checks = [
    ['page', '/webssh_token.php', 'page must request a server-signed target token'],
    ['page', '/webssh/socket', 'page must use the internal WebSocket endpoint'],
    ['page', 'Private key', 'page must offer private-key authentication'],
    ['page', 'Password', 'page must offer password authentication'],
    ['token', 'require_login()', 'target-token endpoint must require an authenticated opnSentral session'],
    ['token', 'require_csrf()', 'target-token endpoint must require CSRF validation'],
    ['token', "SELECT * FROM firewalls WHERE id = ?", 'target and stored SSH credentials must be loaded from the configured firewall database'],
    ['token', "'auto_auth' => webssh_credentials_configured", 'token endpoint must report whether automatic SSH authentication is available'],
    ['helper', "hash_hmac('sha256'", 'target token must be HMAC signed'],
    ['helper', "'exp' =>", 'target token must expire'],
    ['helper', "'credential_blob' => webssh_credential_blob", 'target token must carry only an encrypted credential blob'],
    ['helper', 'encrypt_value(json_encode($credentials', 'stored SSH credentials must be re-encrypted for the short-lived WebSSH token'],
    ['bridge', 'timingSafeEqual', 'bridge must compare token signatures in constant time'],
    ['bridge', 'decryptCredentialBlob', 'bridge must decrypt stored credentials server-side'],
    ['bridge', "crypto.createDecipheriv('aes-256-gcm'", 'bridge credential decryption must match APP_KEY AES-256-GCM storage'],
    ['bridge', 'target.credentialBlob', 'bridge must prefer stored credentials from the signed token'],
    ['bridge', 'hostVerifier', 'bridge must verify SSH host keys'],
    ['bridge', 'webssh-known-hosts.json', 'bridge must pin SSH host keys'],
    ['bridge', "LISTEN_HOST = '127.0.0.1'", 'bridge must listen only on loopback'],
    ['bridge', 'MAX_SESSIONS', 'bridge must limit concurrent sessions'],
    ['bridge', 'IDLE_TIMEOUT_MS', 'bridge must close idle sessions'],
    ['apache', 'ws://127.0.0.1:3001/', 'Apache must proxy WebSSH only to the internal bridge'],
    ['entrypoint', 'node /opt/opnsentral-webssh/server.js', 'container must start the WebSSH bridge'],
    ['docker', 'proxy_wstunnel', 'Docker image must enable WebSocket proxy support'],
    ['docker', 'node_modules/xterm/lib/xterm.js', 'Docker image must vendor xterm rather than depend on a CDN'],
    ['header', '<span class="menu-level2">Tools</span>', 'sidebar must expose an opnSentral Tools section'],
    ['header', 'href="/webssh.php"', 'sidebar must expose WebSSH'],
    ['config', "'ssh_username'=>'TEXT NOT NULL DEFAULT", 'database migration must add an SSH username field'],
    ['config', "'ssh_password_enc'=>'TEXT NOT NULL DEFAULT", 'database migration must add encrypted SSH password storage'],
    ['config', "'ssh_private_key_enc'=>'TEXT NOT NULL DEFAULT", 'database migration must add encrypted SSH private-key storage'],
    ['firewall_edit', 'WebSSH automatic login', 'firewall settings must expose WebSSH automatic-login configuration'],
    ['firewall_edit', 'encrypt_value($sshPassword)', 'SSH passwords must be encrypted before storage'],
    ['firewall_edit', 'encrypt_value($sshPrivateKey)', 'SSH private keys must be encrypted before storage'],
    ['page', "tokenData.auto_auth===true", 'WebSSH must automatically use stored credentials when configured'],
    ['page', "auth.style.display=selected.auto?'none':'grid'", 'manual credential form must stay hidden for automatic-login targets'],
    ['page', '/webssh_key_action.php', 'WebSSH page must expose public-key deployment actions'],
    ['page', 'Generate RSA + deploy', 'WebSSH page must offer one-click RSA key generation and deployment'],
    ['helper', 'webssh_generate_rsa_keypair', 'WebSSH helper must generate RSA keypairs server-side'],
    ['helper', "OPENSSL_KEYTYPE_RSA", 'generated WebSSH keys must be RSA'],
    ['helper', "'add_access_user_authorized_key'", 'public-key deployment must use the narrow agent job'],
    ['helper', "WEBSSH_KEY_AGENT_MIN_VERSION = '0.1.17'", 'public-key deployment must require the agent version that implements the narrow job'],
    ['key_action', 'require_csrf();', 'public-key deployment action must require CSRF protection'],
    ['key_action', 'webssh_public_key_deploy_agent($firewall);', 'key generation must verify agent readiness before changing stored authentication'],
    ['key_action', "webssh_generate_rsa_keypair(3072", 'generated deployment keys must use 3072-bit RSA'],
    ['key_action', 'encrypt_value((string) $pair[\'private_key\'])', 'generated private key must be encrypted before database storage'],
    ['agent', "const AGENT_VERSION = '0.1.17'", 'agent version must identify SSH public-key deployment support'],
    ['agent', 'if ($type===\'add_access_user_authorized_key\')', 'agent must execute only the narrow Authorized Key job'],
    ['agent', '$existing[]=$key', 'agent must append the opnSentral key rather than replace existing Authorized Keys'],
    ['agent', 'authorized_key_file_contains', 'agent must verify the deployed key in authorized_keys'],
];

$agentCheckPos = strpos($contents['key_action'], 'webssh_public_key_deploy_agent($firewall);');
$keyGeneratePos = strpos($contents['key_action'], 'webssh_generate_rsa_keypair(3072');
if ($agentCheckPos === false || $keyGeneratePos === false || $agentCheckPos > $keyGeneratePos) {
    fwrite(STDERR, "WebSSH regression failed: agent readiness must be checked before generating/storing a replacement key.\n");
    exit(1);
}

foreach ($checks as [$file, $needle, $message]) {
    if (!str_contains($contents[$file], $needle)) {
        fwrite(STDERR, "WebSSH regression failed: {$message}\n");
        exit(1);
    }
}

if (!str_contains($contents['page'], "new WebSocket(scheme+'//'+location.host+'/webssh/socket')")) {
    fwrite(STDERR, "WebSSH regression failed: browser must connect only to the same-origin WebSSH socket.\n");
    exit(1);
}
if (str_contains($contents['page'], 'new WebSocket(selected.host') || str_contains($contents['page'], 'new WebSocket(target.host')) {
    fwrite(STDERR, "WebSSH regression failed: browser must not construct WebSocket destinations from firewall host data.\n");
    exit(1);
}

function authorized_key_identity_for_test(string $line): string
{
    $parts = preg_split('/\s+/', trim($line), 3) ?: [];
    return (string) ($parts[0] ?? '') . ' ' . (string) ($parts[1] ?? '');
}

putenv('APP_KEY=' . str_repeat('ab', 32));
require_once $files['helper'];
$firewall = [
    'id' => 42,
    'name' => 'TestFW',
    'base_url' => 'https://192.0.2.10:444',
    'ssh_username' => 'adminfk',
    'ssh_auth_method' => 'password',
    'ssh_password_enc' => encrypt_value('test-password'),
    'ssh_private_key_enc' => '',
    'ssh_port' => 2222,
];
$target = webssh_target_from_firewall($firewall);
if (($target['host'] ?? '') !== '192.0.2.10' || ($target['port'] ?? 0) !== 2222 || ($target['firewall_id'] ?? 0) !== 42) {
    fwrite(STDERR, "WebSSH regression failed: firewall target derivation changed unexpectedly.\n");
    exit(1);
}

$token = webssh_create_target_token($firewall, 60);
[$payload, $signature] = array_pad(explode('.', $token, 2), 2, '');
$expected = hash_hmac('sha256', $payload, hex2bin(str_repeat('ab', 32)));
if ($payload === '' || !hash_equals($expected, $signature)) {
    fwrite(STDERR, "WebSSH regression failed: generated target token signature is invalid.\n");
    exit(1);
}

$padding = strlen($payload) % 4;
if ($padding !== 0) $payload .= str_repeat('=', 4 - $padding);
$decoded = json_decode(base64_decode(strtr($payload, '-_', '+/')), true);
if (!is_array($decoded) || ($decoded['host'] ?? '') !== '192.0.2.10' || ($decoded['firewall_id'] ?? 0) !== 42 || empty($decoded['credential_blob'])) {
    fwrite(STDERR, "WebSSH regression failed: generated target token payload is invalid.\n");
    exit(1);
}

$credentialBlob = (string) ($decoded['credential_blob'] ?? '');
$credentialJson = decrypt_value($credentialBlob);
$credentials = json_decode($credentialJson, true);
if (!is_array($credentials) || ($credentials['username'] ?? '') !== 'adminfk' || ($credentials['password'] ?? '') !== 'test-password') {
    fwrite(STDERR, "WebSSH regression failed: encrypted credential blob does not round-trip.\n");
    exit(1);
}
if (str_contains($token, 'test-password')) {
    fwrite(STDERR, "WebSSH regression failed: plaintext SSH password leaked into target token.\n");
    exit(1);
}

$keypair = webssh_generate_rsa_keypair(2048, 'regression-test');
if (!str_contains((string) ($keypair['private_key'] ?? ''), 'PRIVATE KEY')) {
    fwrite(STDERR, "WebSSH regression failed: RSA private key generation failed.\n");
    exit(1);
}
if (!str_starts_with((string) ($keypair['public_key'] ?? ''), 'ssh-rsa ')) {
    fwrite(STDERR, "WebSSH regression failed: RSA public key is not in OpenSSH authorized_keys format.\n");
    exit(1);
}
$derived = webssh_rsa_public_key_from_private((string) $keypair['private_key'], 'regression-test');
if (authorized_key_identity_for_test((string) $derived) !== authorized_key_identity_for_test((string) $keypair['public_key'])) {
    fwrite(STDERR, "WebSSH regression failed: generated RSA public key does not round-trip from the private key.\n");
    exit(1);
}

echo "WebSSH regression checks passed.\n";
