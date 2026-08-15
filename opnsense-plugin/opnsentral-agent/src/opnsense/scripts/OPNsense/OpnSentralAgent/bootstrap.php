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

function https_context(array $http = [])
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

function decode_json_response(string $url, string|false $response, array $headers): array
{
    $status = response_status($headers);
    if (!is_string($response)) fail('HTTPS request failed for ' . $url . '.');
    $decoded = json_decode($response, true);
    if (!is_array($decoded)) fail('Server returned invalid JSON (HTTP ' . $status . ').');
    if ($status < 200 || $status >= 300 || ($decoded['ok'] ?? false) !== true) {
        fail((string) ($decoded['error'] ?? ('Server returned HTTP ' . $status . '.')));
    }
    return $decoded;
}

function get_json(string $url): array
{
    $response = @file_get_contents($url, false, https_context([
        'method' => 'GET',
        'header' => "Accept: application/json\r\nUser-Agent: os-opnsentral-agent-bootstrap/0.1.0",
    ]));
    return decode_json_response($url, $response, $http_response_header ?? []);
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
    return decode_json_response($url, $response, $http_response_header ?? []);
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

function validate_manifest(array $manifest): array
{
    $agentUrl = trim((string) ($manifest['agent_url'] ?? ''));
    $expectedSha = strtolower(trim((string) ($manifest['agent_sha256'] ?? '')));
    $expectedSize = (int) ($manifest['agent_size'] ?? 0);
    $expectedVersion = trim((string) ($manifest['agent_version'] ?? ''));

    if ($agentUrl === '' || !str_starts_with($agentUrl, '/')) fail('Agent manifest contains an invalid download path.');
    if (!preg_match('/^[a-f0-9]{64}$/', $expectedSha)) fail('Agent manifest contains an invalid SHA-256.');
    if ($expectedSize < 1000 || $expectedSize > 2 * 1024 * 1024) fail('Agent manifest contains an invalid size.');
    if (!preg_match('/^[0-9A-Za-z.+_-]{1,64}$/', $expectedVersion)) fail('Agent manifest contains an invalid version.');

    return [
        'agent_url' => $agentUrl,
        'agent_sha256' => $expectedSha,
        'agent_size' => $expectedSize,
        'agent_version' => $expectedVersion,
    ];
}

function install_worker(string $serverUrl, array $manifest): string
{
    $manifest = validate_manifest($manifest);
    $binary = @file_get_contents(
        rtrim($serverUrl, '/') . $manifest['agent_url'],
        false,
        https_context(['method' => 'GET'])
    );
    if (!is_string($binary)) fail('Could not download the canonical opnSentral agent.');
    if (strlen($binary) !== $manifest['agent_size']) fail('Downloaded agent size does not match the manifest.');
    if (!str_starts_with($binary, '#!/usr/local/bin/php')) fail('Downloaded agent has an invalid file signature.');
    $actualSha = hash('sha256', $binary);
    if (!hash_equals($manifest['agent_sha256'], $actualSha)) fail('Downloaded agent SHA-256 does not match the manifest.');
    if (!preg_match("/const AGENT_VERSION = '([^']+)'/", $binary, $match)) fail('Downloaded agent does not declare a version.');
    if (!hash_equals($manifest['agent_version'], (string) $match[1])) fail('Downloaded agent version does not match the manifest.');

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

function load_agent_config(): array
{
    if (!is_file(CONFIG_TARGET)) fail('Agent is not registered.');
    $decoded = json_decode((string) file_get_contents(CONFIG_TARGET), true);
    if (!is_array($decoded)) fail('Agent configuration is invalid.');
    $serverUrl = rtrim(trim((string) ($decoded['server_url'] ?? '')), '/');
    $agentId = trim((string) ($decoded['agent_id'] ?? ''));
    $secret = trim((string) ($decoded['agent_secret'] ?? ''));
    if (!preg_match('#^https://#i', $serverUrl)) fail('Registered server URL is invalid.');
    if (!preg_match('/^[a-f0-9]{32}$/', $agentId) || !preg_match('/^[a-f0-9]{64}$/', $secret)) {
        fail('Registered agent identity is invalid.');
    }
    return $decoded;
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

function verify_and_start(): void
{
    run_command(escapeshellarg(AGENT_TARGET) . ' once', 'Agent connectivity test');
    run_command('/usr/sbin/service opnsentral_agent restart', 'Agent service start');
}

$command = strtolower(trim((string) ($argv[1] ?? '')));

if ($command === 'status') {
    $binary = is_file(AGENT_TARGET) ? 'installed' : 'missing';
    $registration = is_file(CONFIG_TARGET) ? 'registered' : 'unregistered';
    fwrite(STDOUT, 'Agent binary: ' . $binary . PHP_EOL);
    fwrite(STDOUT, 'Registration: ' . $registration . PHP_EOL);
    if ($binary === 'installed' && $registration === 'registered') {
        passthru('/usr/sbin/service opnsentral_agent onestatus', $status);
        exit($status);
    }
    exit(1);
}

if ($command === 'once') {
    if (!is_file(AGENT_TARGET) || !is_file(CONFIG_TARGET)) fail('Agent is not installed and registered.');
    passthru(escapeshellarg(AGENT_TARGET) . ' once', $status);
    exit($status);
}

if ($command === 'repair') {
    $config = load_agent_config();
    $serverUrl = rtrim((string) $config['server_url'], '/');
    $manifest = get_json($serverUrl . '/agent/manifest.php');
    $version = install_worker($serverUrl, $manifest);
    verify_and_start();
    fwrite(STDOUT, 'opnSentral agent ' . $version . ' repaired, verified and started.' . PHP_EOL);
    exit(0);
}

if ($command !== 'register') {
    fail('Usage: bootstrap.php register https://opnsentral.example TOKEN | repair | status | once');
}

if (is_file(CONFIG_TARGET)) fail('Agent is already registered. Use repair instead of creating a second identity.');

$serverUrl = rtrim(trim((string) ($argv[2] ?? '')), '/');
$token = trim((string) ($argv[3] ?? ''));
if (!preg_match('#^https://[^\s/]+(?::\d+)?(?:/.*)?$#i', $serverUrl)) fail('Server URL must be a valid HTTPS URL.');
if (!preg_match('/^[A-Za-z0-9_-]{40,128}$/', $token)) fail('Registration token format is invalid.');

$manifest = get_json($serverUrl . '/agent/manifest.php');
$registration = post_json($serverUrl . '/api/agent_register.php', [
    'token' => $token,
    'hostname' => hostname_value(),
    'opnsense_version' => opnsense_version(),
    'architecture' => php_uname('m'),
    'agent_version' => 'plugin-bootstrap/0.1.0',
]);

save_agent_config($serverUrl, $registration);
$version = install_worker($serverUrl, $manifest);
verify_and_start();

fwrite(STDOUT, 'opnSentral agent ' . $version . ' registered, verified and started.' . PHP_EOL);
