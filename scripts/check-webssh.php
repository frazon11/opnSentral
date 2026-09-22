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
    ['token', "SELECT id,name,base_url FROM firewalls WHERE id = ?", 'target must be loaded from the configured firewall database'],
    ['helper', "hash_hmac('sha256'", 'target token must be HMAC signed'],
    ['helper', "'exp' =>", 'target token must expire'],
    ['bridge', 'timingSafeEqual', 'bridge must compare token signatures in constant time'],
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
];

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

putenv('APP_KEY=' . str_repeat('ab', 32));
require_once $files['helper'];
$firewall = ['id' => 42, 'name' => 'TestFW', 'base_url' => 'https://192.0.2.10:444'];
$target = webssh_target_from_firewall($firewall);
if (($target['host'] ?? '') !== '192.0.2.10' || ($target['port'] ?? 0) !== 22 || ($target['firewall_id'] ?? 0) !== 42) {
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
if (!is_array($decoded) || ($decoded['host'] ?? '') !== '192.0.2.10' || ($decoded['firewall_id'] ?? 0) !== 42) {
    fwrite(STDERR, "WebSSH regression failed: generated target token payload is invalid.\n");
    exit(1);
}

echo "WebSSH regression checks passed.\n";
