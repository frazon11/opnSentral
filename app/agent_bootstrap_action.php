<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/agent_deployment.php';
require_login();
require_csrf();
require_configuration_unlocked(false);

$firewallId = (int) ($_POST['firewall_id'] ?? 0);
$firewall = firewall_by_id($firewallId);
$host = trim((string) ($_POST['ssh_host'] ?? ''));
$port = (int) ($_POST['ssh_port'] ?? 22);
$user = trim((string) ($_POST['ssh_user'] ?? 'root'));
$authType = (string) ($_POST['auth_type'] ?? 'password');
$password = (string) ($_POST['ssh_password'] ?? '');
$privateKey = trim((string) ($_POST['ssh_private_key'] ?? ''));
$serverUrl = rtrim(trim((string) ($_POST['server_url'] ?? '')), '/');
$hostKeyMode = (string) ($_POST['host_key_mode'] ?? 'accept-new');

$redirect = '/agent_bootstrap.php?firewall_id=' . $firewallId;
$keyFile = null;
$registration = null;

try {
    if ($host === '' || preg_match('/[\s\x00-\x1F]/', $host)) {
        throw new RuntimeException('Enter a valid SSH hostname or IP address.');
    }
    if ($port < 1 || $port > 65535) throw new RuntimeException('SSH port is invalid.');
    if ($user === '' || !preg_match('/^[A-Za-z0-9_.-]+$/', $user)) throw new RuntimeException('SSH username is invalid.');
    if (!in_array($authType, ['password', 'key'], true)) throw new RuntimeException('Unsupported SSH authentication type.');
    if (!in_array($hostKeyMode, ['accept-new', 'strict'], true)) throw new RuntimeException('Unsupported host-key mode.');
    if (!preg_match('#^https://[^/]+(?:/.*)?$#i', $serverUrl)) {
        throw new RuntimeException('Public opnSentral URL must use HTTPS.');
    }
    if ($authType === 'password' && $password === '') throw new RuntimeException('SSH password is required.');
    if ($authType === 'key' && !str_contains($privateKey, 'PRIVATE KEY')) throw new RuntimeException('A valid SSH private key is required.');

    $agentLookup = db()->prepare(
        'SELECT * FROM agents WHERE firewall_id = ? ORDER BY id DESC LIMIT 1'
    );
    $agentLookup->execute([$firewallId]);
    $existingAgent = $agentLookup->fetch() ?: null;

    if (is_array($existingAgent)) {
        $installerArgument = '--existing';
    } else {
        $registration = agent_create_registration_token(
            $firewallId,
            'SSH bootstrap for ' . (string) $firewall['name'],
            15
        );
        $installerArgument = (string) $registration['token'];
    }

    $remoteCommand = 'fetch -q -o - ' . escapeshellarg($serverUrl . '/agent/install.sh')
        . ' | /bin/sh -s -- ' . escapeshellarg($serverUrl)
        . ' ' . escapeshellarg($installerArgument);

    $knownHostsFile = DATA_DIR . '/ssh_known_hosts';
    if (!is_dir(DATA_DIR) && !mkdir(DATA_DIR, 0770, true) && !is_dir(DATA_DIR)) {
        throw new RuntimeException('Could not create the persistent data directory.');
    }
    if (!is_file($knownHostsFile) && file_put_contents($knownHostsFile, '', LOCK_EX) === false) {
        throw new RuntimeException('Could not create SSH known_hosts storage.');
    }
    chmod($knownHostsFile, 0600);

    $ssh = [
        'ssh',
        '-p', (string) $port,
        '-o', 'ConnectTimeout=12',
        '-o', 'ServerAliveInterval=5',
        '-o', 'UserKnownHostsFile=' . $knownHostsFile,
        '-o', $hostKeyMode === 'strict' ? 'StrictHostKeyChecking=yes' : 'StrictHostKeyChecking=accept-new',
    ];

    $env = getenv();
    if (!is_array($env)) $env = [];

    if ($authType === 'key') {
        $keyFile = tempnam(sys_get_temp_dir(), 'opnsentral-ssh-key-');
        if (!is_string($keyFile)) throw new RuntimeException('Could not create temporary SSH key file.');
        if (file_put_contents($keyFile, $privateKey . "\n", LOCK_EX) === false) {
            throw new RuntimeException('Could not write temporary SSH key.');
        }
        chmod($keyFile, 0600);
        $ssh[] = '-i';
        $ssh[] = $keyFile;
        $ssh[] = '-o';
        $ssh[] = 'BatchMode=yes';
    } else {
        array_unshift($ssh, '-e');
        array_unshift($ssh, 'sshpass');
        $env['SSHPASS'] = $password;
        $ssh[] = '-o';
        $ssh[] = 'PreferredAuthentications=password,keyboard-interactive';
        $ssh[] = '-o';
        $ssh[] = 'PubkeyAuthentication=no';
    }

    $ssh[] = $user . '@' . $host;
    $ssh[] = $remoteCommand;

    $descriptor = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($ssh, $descriptor, $pipes, null, $env);
    if (!is_resource($process)) throw new RuntimeException('Could not start SSH bootstrap process.');
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);

    $output = trim((string) $stdout . ($stderr !== '' ? "\n" . (string) $stderr : ''));
    if ($exitCode !== 0) {
        throw new RuntimeException('SSH bootstrap exited with status ' . $exitCode . ($output !== '' ? ': ' . $output : '.'));
    }

    $_SESSION['agent_bootstrap_result'] = [
        'ok' => true,
        'message' => is_array($existingAgent)
            ? 'Agent updated/recovered over SSH while preserving its existing registration.'
            : 'Agent installed and registered over SSH for ' . (string) $firewall['name'] . '.',
        'output' => $output,
    ];
} catch (Throwable $exception) {
    if (is_array($registration) && !empty($registration['token'])) {
        $cleanup = db()->prepare('DELETE FROM agent_registration_tokens WHERE token_hash = ? AND used_at IS NULL');
        $cleanup->execute([hash('sha256', (string) $registration['token'])]);
    }
    $_SESSION['agent_bootstrap_result'] = [
        'ok' => false,
        'message' => $exception->getMessage(),
        'output' => '',
    ];
} finally {
    if (is_string($keyFile) && is_file($keyFile)) @unlink($keyFile);
    unset($password, $privateKey);
}

header('Location: ' . $redirect);
