<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_login();
require_csrf();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function fleet_settings_definitions(string $scope): array
{
    if ($scope === 'general') {
        return [
            'hostname' => 'text', 'domain' => 'text', 'timezone' => 'text', 'language' => 'text', 'theme' => 'text',
            'prefer_ipv4' => 'boolean', 'dns' => 'text', 'dnssearchdomain' => 'text', 'dnsallowoverride' => 'boolean',
            'dnsallowoverride_exclude' => 'text', 'dnslocalhost' => 'boolean', 'gw_switch_default' => 'boolean',
        ];
    }
    if ($scope === 'advanced') {
        return [
            'natreflection' => 'boolean', 'binatreflection' => 'boolean', 'natreflectionhelper' => 'boolean',
            'bogons_interval' => 'text', 'skip_rules_gw_down' => 'boolean', 'lb_use_sticky' => 'boolean',
            'srctrack' => 'text', 'pf_share_forward' => 'boolean', 'pf_disable_force_gw' => 'boolean',
            'schedule_states' => 'boolean', 'log_default_block' => 'boolean', 'log_default_pass' => 'boolean',
            'logoutboundnat' => 'boolean', 'log_bogons' => 'boolean', 'log_privatenets' => 'boolean',
            'keepcounters' => 'boolean', 'pfdebug' => 'text', 'optimization' => 'text', 'state_policy' => 'boolean',
            'disablefilter' => 'boolean', 'adaptivestart' => 'text', 'adaptiveend' => 'text', 'maximumstates' => 'text',
            'maximumfrags' => 'text', 'maximumtableentries' => 'text', 'bypassstaticroutes' => 'boolean',
            'disablereplyto' => 'boolean', 'noantilockout' => 'boolean', 'no_ipv6_rfc4890_req' => 'boolean',
            'no_port0_block' => 'boolean', 'no_sshlockout' => 'boolean', 'no_virusprot' => 'boolean',
            'aliasesresolveinterval' => 'text', 'checkaliasesurlcert' => 'boolean', 'syncookies' => 'text',
            'syncookies_adaptstart' => 'text', 'syncookies_adaptend' => 'text',
        ];
    }
    throw new RuntimeException('Unsupported fleet settings scope.');
}

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') throw new RuntimeException('POST required.');

    $scope = trim((string) ($_POST['scope'] ?? ''));
    $definitions = fleet_settings_definitions($scope);
    $changes = json_decode((string) ($_POST['changes'] ?? ''), true);
    if (!is_array($changes) || $changes === []) throw new RuntimeException('No settings changes supplied.');
    if (count($changes) > 1000) throw new RuntimeException('Too many changes in one deployment.');

    $byFirewall = [];
    foreach ($changes as $change) {
        if (!is_array($change)) continue;
        $firewallId = (int) ($change['firewall_id'] ?? 0);
        $setting = trim((string) ($change['setting'] ?? ''));
        if ($firewallId <= 0 || !isset($definitions[$setting])) throw new RuntimeException('Invalid settings change payload.');
        $type = $definitions[$setting];
        if ($type === 'boolean') {
            $value = filter_var($change['value'] ?? null, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
            if ($value === null) throw new RuntimeException('Invalid boolean value for ' . $setting . '.');
        } else {
            $value = trim((string) ($change['value'] ?? ''));
            if (strlen($value) > 2048 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value)) {
                throw new RuntimeException('Invalid text value for ' . $setting . '.');
            }
        }
        $byFirewall[$firewallId][$setting] = $value;
    }
    if ($byFirewall === []) throw new RuntimeException('No valid settings changes supplied.');

    $pdo = db();
    $jobs = [];
    $failures = [];
    foreach ($byFirewall as $firewallId => $settings) {
        $firewallName = 'Firewall #' . $firewallId;
        try {
            $firewall = firewall_by_id((int) $firewallId);
            $firewallName = (string) $firewall['name'];
            $agentStatement = $pdo->prepare('SELECT * FROM agents WHERE firewall_id = ? AND enabled = 1 ORDER BY id DESC LIMIT 1');
            $agentStatement->execute([(int) $firewallId]);
            $agent = $agentStatement->fetch();
            if (!$agent) throw new RuntimeException('No enabled opnSentral agent is associated with this firewall.');
            $agentVersion = trim((string) ($agent['last_version'] ?? ''));
            if ($agentVersion === '' || version_compare($agentVersion, '0.1.6', '<')) {
                throw new RuntimeException('Agent 0.1.6 or newer is required for fleet settings writes.');
            }

            backup_before_change($firewall, $scope === 'general' ? 'system-general-fleet' : 'firewall-advanced-fleet');
            $payload = json_encode(['settings' => $settings], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $jobType = $scope === 'general' ? 'set_general_settings' : 'set_firewall_advanced_settings';
            $statement = $pdo->prepare('INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at) VALUES(?, ?, ?, ?, ?)');
            $statement->execute([(int) $agent['id'], $jobType, $payload, 'queued', gmdate('c')]);
            $jobs[] = [
                'job_id' => (int) $pdo->lastInsertId(),
                'firewall_id' => (int) $firewallId,
                'firewall_name' => $firewallName,
                'settings' => array_keys($settings),
            ];
        } catch (Throwable $exception) {
            $failures[] = ['firewall_id' => (int) $firewallId, 'firewall_name' => $firewallName, 'error' => $exception->getMessage()];
        }
    }

    echo json_encode(['ok' => true, 'jobs' => $jobs, 'failures' => $failures], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => $exception->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
