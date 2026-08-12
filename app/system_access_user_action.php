<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/system_access_inventory.php';
require_login();
require_csrf();
require_configuration_unlocked(false);

$sourceFirewallId = (int) ($_POST['source_firewall_id'] ?? 0);
$userName = trim((string) ($_POST['user'] ?? ''));
$targets = array_values(array_unique(array_filter(array_map('intval', $_POST['targets'] ?? []), static fn(int $id): bool => $id > 0)));
$disabled = isset($_POST['disabled']);
$shell = trim((string) ($_POST['shell'] ?? ''));
$groups = array_values(array_unique(array_filter(array_map(static fn($v): string => trim((string)$v), $_POST['groups'] ?? []), static fn(string $v): bool => $v !== '')));
$privileges = array_values(array_unique(array_filter(array_map(static fn($v): string => trim((string)$v), $_POST['privileges'] ?? []), static fn(string $v): bool => $v !== '')));
$additional = preg_split('/\R+/', trim((string)($_POST['additional_privileges'] ?? ''))) ?: [];
foreach ($additional as $priv) {
    $priv = trim((string)$priv);
    if ($priv !== '') $privileges[] = $priv;
}
$privileges = array_values(array_unique($privileges));

$redirect = '/system_access_user_edit.php?firewall_id=' . $sourceFirewallId . '&user=' . rawurlencode($userName);

try {
    if ($sourceFirewallId <= 0 || $userName === '') throw new RuntimeException('Source firewall and user are required.');
    if ($targets === []) throw new RuntimeException('Select at least one target firewall.');
    if (count($targets) > 100) throw new RuntimeException('Too many target firewalls.');
    if (!preg_match('/^[^\x00-\x1F\x7F]{1,128}$/u', $userName)) throw new RuntimeException('User name is invalid.');

    $allowedShells = ['', '/bin/csh', '/bin/tcsh', '/bin/sh', '/sbin/nologin', '/usr/local/bin/scponly', '/usr/local/sbin/scponlyc', '/usr/local/sbin/ssh_tunnel_shell'];
    if (!in_array($shell, $allowedShells, true)) throw new RuntimeException('Unsupported login shell.');
    foreach (array_merge($groups, $privileges) as $value) {
        if (!preg_match('/^[A-Za-z0-9_.:\/@+-]{1,160}$/', $value)) {
            throw new RuntimeException('Group or privilege value contains unsupported characters: ' . $value);
        }
    }
    if (count($groups) > 100 || count($privileges) > 250) throw new RuntimeException('Too many groups or privileges selected.');

    $marks = implode(',', array_fill(0, count($targets), '?'));
    $statement = db()->prepare('SELECT * FROM firewalls WHERE id IN (' . $marks . ') ORDER BY name');
    $statement->execute($targets);
    $firewalls = $statement->fetchAll();
    if (count($firewalls) !== count($targets)) throw new RuntimeException('One or more target firewalls no longer exist.');

    $fleet = access_load_fleet_inventory($firewalls);
    $agentStatement = db()->prepare('SELECT * FROM agents WHERE firewall_id = ? ORDER BY id DESC LIMIT 1');
    $jobs = [];
    $failures = [];

    foreach ($firewalls as $firewall) {
        $fid = (int)$firewall['id'];
        try {
            $entry = $fleet[$fid] ?? null;
            $user = is_array($entry) ? ($entry['users'][$userName] ?? null) : null;
            if (!is_array($entry) || ($entry['ok'] ?? false) !== true || !is_array($user)) {
                throw new RuntimeException('User does not exist or current Access configuration could not be read.');
            }
            if ((string)($user['uid'] ?? '') === '0' && $disabled) {
                throw new RuntimeException('UID 0 cannot be disabled through opnSentral.');
            }

            $availableGroups = array_keys($entry['groups'] ?? []);
            foreach ($groups as $group) {
                if (!in_array($group, $availableGroups, true)) {
                    throw new RuntimeException('Group ' . $group . ' does not exist on this firewall.');
                }
            }

            $agentStatement->execute([$fid]);
            $agent = $agentStatement->fetch();
            $agentVersion = is_array($agent) ? trim((string)($agent['last_agent_version'] ?? '')) : '';
            if (!is_array($agent) || (int)($agent['enabled'] ?? 0) !== 1 || $agentVersion === '' || version_compare($agentVersion, '0.1.3', '<')) {
                throw new RuntimeException('Enabled agent 0.1.3 or newer is required.');
            }

            backup_before_change($firewall, 'access-user-' . preg_replace('/[^A-Za-z0-9._-]+/', '_', $userName));

            $payload = json_encode([
                'user' => $userName,
                'disabled' => $disabled,
                'shell' => $shell,
                'groups' => $groups,
                'privileges' => $privileges,
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $insert = db()->prepare(
                'INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at)
                 VALUES(?, ?, ?, ?, ?)'
            );
            $insert->execute([(int)$agent['id'], 'set_access_user', $payload, 'queued', gmdate('c')]);
            $jobs[] = [
                'job_id' => (int)db()->lastInsertId(),
                'firewall_id' => $fid,
                'firewall_name' => (string)$firewall['name'],
            ];
        } catch (Throwable $exception) {
            $failures[] = [
                'firewall_id' => $fid,
                'firewall_name' => (string)$firewall['name'],
                'error' => $exception->getMessage(),
            ];
        }
    }

    $_SESSION['access_user_edit_result'] = [
        'jobs' => $jobs,
        'failures' => $failures,
        'message' => count($jobs) . ' firewall job' . (count($jobs) === 1 ? '' : 's') . ' queued' . ($failures ? ' · ' . count($failures) . ' target' . (count($failures) === 1 ? '' : 's') . ' failed before queueing.' : '.'),
    ];
} catch (Throwable $exception) {
    $_SESSION['access_user_edit_result'] = [
        'jobs' => [],
        'failures' => [['firewall_name' => 'Deployment', 'error' => $exception->getMessage()]],
        'message' => 'User deployment could not be started.',
    ];
}

header('Location: ' . $redirect);
