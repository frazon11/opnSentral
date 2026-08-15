#!/usr/local/bin/php
<?php

declare(strict_types=1);

const AGENT_TARGET = '/usr/local/sbin/opnsentral-agent';
const CONFIG_TARGET = '/usr/local/etc/opnsentral-agent.json';
const BOOTSTRAP_VERSION = '0.1.1';

function fail(string $message, int $code = 1): never
{
    fwrite(STDERR, 'opnSentral plugin: ' . $message . PHP_EOL);
    exit($code);
}

function json_body(array $payload): string
{
    return json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}

function curl_binary(): string
{
    foreach (['/usr/local/bin/curl', '/usr/bin/curl'] as $candidate) {
        if (is_file($candidate) && is_executable($candidate)) return $candidate;
    }
    $resolved = trim((string) shell_exec('command -v curl 2>/dev/null'));
    if ($resolved !== '' && is_executable($resolved)) return $resolved;
    fail('curl is required but was not found on OPNsense.');
}

function run_process(array $command, ?string $stdin = null): array
{
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($command, $descriptors, $pipes);
    if (!is_resource($process)) fail('Could not start HTTPS client.');

    if ($stdin !== null && $stdin !== '') fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);

    return [
        'status' => $status,
        'stdout' => is_string($stdout) ? $stdout : '',
        'stderr' => is_string($stderr) ? $stderr : '',
    ];
}

function curl_request(string $url, string $method = 'GET', ?string $body = null, array $headers = []): string
{
    if (!preg_match('#^https://#i', $url)) fail('Refusing non-HTTPS request: ' . $url);

    $command = [
        curl_binary(),
        '--silent',
        '--show-error',
        '--location',
        '--fail',
        '--connect-timeout', '10',
        '--max-time', '30',
        '--proto', '=https',
        '--user-agent', 'os-opnsentral-agent-bootstrap/' . BOOTSTRAP_VERSION,
    ];

    foreach ($headers as $header) {
        $command[] = '--header';
        $command[] = (string) $header;
    }

    if (strtoupper($method) === 'POST') {
        $command[] = '--request';
        $command[] = 'POST';
        $command[] = '--data-binary';
        $command[] = '@-';
    }

    $command[] = $url;
    $result = run_process($command, $body);
    if ((int) $result['status'] !== 0) {
        $detail = trim((string) $result['stderr']);
        if ($detail === '') $detail = trim((string) $result['stdout']);
        fail('HTTPS request failed for ' . $url . ($detail !== '' ? ': ' . substr($detail, 0, 500) : '.'));
    }
    return (string) $result['stdout'];
}

function get_json(string $url): array
{
    $response = curl_request($url, 'GET', null, ['Accept: application/json']);
    $decoded = json_decode($response, true);
    if (!is_array($decoded)) fail('Server returned invalid JSON for ' . $url . '.');
    if (($decoded['ok'] ?? false) !== true) fail((string) ($decoded['error'] ?? 'Server rejected the request.'));
    return $decoded;
}

function post_json(string $url, array $payload): array
{
    $body = json_body($payload);
    $response = curl_request($url, 'POST', $body, [
        'Content-Type: application/json',
        'Accept: application/json',
    ]);
    $decoded = json_decode($response, true);
    if (!is_array($decoded)) fail('Server returned invalid JSON for ' . $url . '.');
    if (($decoded['ok'] ?? false) !== true) fail((string) ($decoded['error'] ?? 'Server rejected the request.'));
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
    $binary = curl_request(rtrim($serverUrl, '/') . $manifest['agent_url']);
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
    'agent_version' => 'plugin-bootstrap/' . BOOTSTRAP_VERSION,
]);

save_agent_config($serverUrl, $registration);
$version = install_worker($serverUrl, $manifest);
verify_and_start();

fwrite(STDOUT, 'opnSentral agent ' . $version . ' registered, verified and started.' . PHP_EOL);
