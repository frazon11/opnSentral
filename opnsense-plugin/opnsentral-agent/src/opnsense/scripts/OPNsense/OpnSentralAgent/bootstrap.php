#!/usr/local/bin/php
<?php

declare(strict_types=1);

const AGENT_TARGET = '/usr/local/sbin/opnsentral-agent';
const CONFIG_TARGET = '/usr/local/etc/opnsentral-agent.json';

function fail(string $message, int $code = 1): never
{
    fwrite(STDERR, 'opnSentral plugin: ' . $message . PHP_EOL);
    exit($code);
}

function json_body(array $payload): string
{
    return json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}

function https_context(array $http = []): resource
{
    return stream_context_create([
        'http' => array_replace([
            'ignore_errors' => true,
            'timeout' => 20,
        ], $http),
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
        ],
    ]);
}

function response_status(array $headers): int
{
    if (isset($headers[0]) && preg_match('/\s(\d{3})\s/', (string) $headers[0], $match)) {
        return (int) $match[1];
    }
    return 0;
}

function post_json(string $url, array $payload): array
{
    $body = json_body($payload);
    $context = https_context([
        'method' => 'POST',
        'header' => implode("\r\n", [
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: os-opnsentral-agent-bootstrap/0.1.0',
            'Content-Length: ' . strlen($body),
        ]),
        'content' => $body,
    ]);
    $response = @file_get_contents($url, false, $context);
    $headers = $http_response_header ?? [];
    $status = response_status($headers);
    if (!is_string($response)) fail('HTTPS request failed for ' . $url . '.');
    $decoded = json_decode($response, true);
    if (!is_array($decoded)) fail('Server returned invalid JSON (HTTP ' . $status . ').');
    if ($status < 200 || $status >= 300 || ($decoded['ok'] ?? false) !== true) {
        fail((string) ($decoded['error'] ?? ('Server returned HTTP ' . $status . '.')));
    }
    return $decoded;
}

function hostname_value(): string
{
    $hostname = gethostname();
    return is_string($hostname) && $hostname !== '' ? $hostname : 'opnsense';
}

function opnsense_version(): string
{
    $output = trim((string) shell_exec('/usr/local/sbin/opnsense-version -a 2>/dev/null'));
    return $output !== '' ? substr($output, 0, 128) : php_uname('r');
}

function install_worker(string $serverUrl, array $registration): string
{
    $agentUrl = trim((string) ($registration['agent_url'] ?? ''));
    $expectedSha = strtolower(trim((string) ($registration['agent_sha256'] ?? '')));
    $expectedSize = (int) ($registration['agent_size'] ?? 0);

    if ($agentUrl === '' || !str_starts_with($agentUrl, '/')) {
        fail('Registration response did not provide a valid agent download path.');
    }
    if (!preg_match('/^[a-f0-9]{64}$/', $expectedSha)) {
        fail('Registration response did not provide a valid agent SHA-256.');
    }
    if ($expectedSize < 1000 || $expectedSize > 2 * 1024 * 1024) {
        fail('Registration response reported an invalid agent size.');
    }

    $binary = @file_get_contents(rtrim($serverUrl, '/') . $agentUrl, false, https_context(['method' => 'GET']));
    if (!is_string($binary)) fail('Could not download the canonical opnSentral agent.');
    if (strlen($binary) !== $expectedSize) fail('Downloaded agent size does not match the registration manifest.');
    if (!str_starts_with($binary, '#!/usr/local/bin/php')) fail('Downloaded agent has an invalid file signature.');
    $actualSha = hash('sha256', $binary);
    if (!hash_equals($expectedSha, $actualSha)) fail('Downloaded agent SHA-256 does not match the registration manifest.');
    if (!preg_match("/const AGENT_VERSION = '([^']+)'/", $binary, $match)) fail('Downloaded agent does not declare a version.');

    $temp = AGENT_TARGET . '.new-' . bin2hex(random_bytes(4));
    if (file_put_contents($temp, $binary, LOCK_EX) === false) fail('Could not write the agent binary.');
    chmod($temp, 0755);
    if (!rename($temp, AGENT_TARGET)) {
        @unlink($temp);
        fail('Could not activate the agent binary.');
    }

    return (string) $match[1];
}

function save_agent_config(string $serverUrl, array $registration): void
{
    $agentId = trim((string) ($registration['agent_id'] ?? ''));
    $secret = trim((string) ($registration['agent_secret'] ?? ''));
    if (!preg_match('/^[a-f0-9]{32}$/', $agentId)) fail('Registration returned an invalid agent ID.');
    if (!preg_match('/^[a-f0-9]{64}$/', $secret)) fail('Registration returned an invalid agent secret.');

    $directory = dirname(CONFIG_TARGET);
    if (!is_dir($directory) && !mkdir($directory, 0755, true) && !is_dir($directory)) {
        fail('Could not create the agent configuration directory.');
    }

    $config = [
        'server_url' => rtrim($serverUrl, '/'),
        'agent_id' => $agentId,
        'agent_secret' => $secret,
        'verify_tls' => true,
        'poll_interval' => max(30, (int) ($registration['poll_interval'] ?? 60)),
    ];
    $json = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    if (file_put_contents(CONFIG_TARGET, $json . PHP_EOL, LOCK_EX) === false) fail('Could not write the agent configuration.');
    chmod(CONFIG_TARGET, 0600);
}

function run_command(string $command, string $label): void
{
    $output = [];
    $status = 0;
    exec($command . ' 2>&1', $output, $status);
    if ($status !== 0) {
        fail($label . ' failed' . ($output ? ': ' . implode(' | ', array_slice($output, -6)) : '.'));
    }
}

$command = strtolower(trim((string) ($argv[1] ?? '')));

if ($command === 'status') {
    if (!is_file(AGENT_TARGET)) fail('Agent binary is not installed.');
    if (!is_file(CONFIG_TARGET)) fail('Agent is not registered.');
    passthru('/usr/sbin/service opnsentral_agent onestatus', $status);
    exit($status);
}

if ($command === 'once') {
    if (!is_file(AGENT_TARGET) || !is_file(CONFIG_TARGET)) fail('Agent is not installed and registered.');
    passthru(escapeshellarg(AGENT_TARGET) . ' once', $status);
    exit($status);
}

if ($command !== 'register') {
    fail('Usage: bootstrap.php register https://opnsentral.example TOKEN | status | once');
}

$serverUrl = rtrim(trim((string) ($argv[2] ?? '')), '/');
$token = trim((string) ($argv[3] ?? ''));
if (!preg_match('#^https://[^\s/]+(?::\d+)?(?:/.*)?$#i', $serverUrl)) fail('Server URL must be a valid HTTPS URL.');
if (!preg_match('/^[A-Za-z0-9_-]{40,128}$/', $token)) fail('Registration token format is invalid.');

$registration = post_json($serverUrl . '/api/agent_register.php', [
    'token' => $token,
    'hostname' => hostname_value(),
    'opnsense_version' => opnsense_version(),
    'architecture' => php_uname('m'),
    'agent_version' => 'plugin-bootstrap/0.1.0',
]);

$version = install_worker($serverUrl, $registration);
save_agent_config($serverUrl, $registration);
run_command(escapeshellarg(AGENT_TARGET) . ' once', 'Initial agent connectivity test');
run_command('/usr/sbin/service opnsentral_agent restart', 'Agent service start');

fwrite(STDOUT, 'opnSentral agent ' . $version . ' registered, verified and started.' . PHP_EOL);
