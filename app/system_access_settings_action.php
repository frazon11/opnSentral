<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';

require_login();
require_csrf();
require_configuration_unlocked();

$firewallId = (int) ($_POST['firewall_id'] ?? 0);
$action = trim((string) ($_POST['action'] ?? ''));
if ($firewallId < 1 || !in_array($action, ['set_administration', 'set_server'], true)) {
    http_response_code(400);
    exit('Invalid System Access request.');
}

$firewall = firewall_by_id($firewallId);

function access_action_success(array $response): bool
{
    if (($response['status'] ?? '') !== 'ok') return false;
    if (!empty($response['validations'])) return false;
    return true;
}

function access_action_error(array $response): string
{
    if (is_array($response['validations'] ?? null) && $response['validations'] !== []) {
        return implode(' | ', array_map(static fn($v): string => trim((string) $v), $response['validations']));
    }
    return trim((string) ($response['error'] ?? $response['message'] ?? 'OPNsense rejected the change.'));
}

function access_action_list(mixed $value): array
{
    if (!is_array($value)) return [];
    return array_values(array_unique(array_filter(array_map(static fn($v): string => trim((string) $v), $value), static fn(string $v): bool => $v !== '')));
}

try {
    if ($action === 'set_administration') {
        $payload = [
            'autologout' => trim((string) ($_POST['autologout'] ?? '')),
            'authmode' => access_action_list($_POST['authmode'] ?? []),
            'sudo_allow_wheel' => !empty($_POST['sudo_allow_wheel']) ? '1' : '',
            'sudo_allow_group' => trim((string) ($_POST['sudo_allow_group'] ?? '')),
            'user_allow_gen_token' => access_action_list($_POST['user_allow_gen_token'] ?? []),
        ];

        backup_before_change($firewall, 'system-administration-authentication');

        $response = opn_raw_request(
            $firewall,
            'opnsentralagent/access/setAdministration',
            'POST',
            $payload,
            30
        );
        if (!access_action_success($response)) {
            throw new RuntimeException(access_action_error($response));
        }

        $admin = is_array($response['administration'] ?? null) ? $response['administration'] : [];
        $expectedAuth = $payload['authmode'];
        $actualAuth = access_action_list($admin['authmode'] ?? []);
        sort($expectedAuth); sort($actualAuth);
        $expectedOtp = $payload['user_allow_gen_token'];
        $actualOtp = access_action_list($admin['user_allow_gen_token'] ?? []);
        sort($expectedOtp); sort($actualOtp);

        if (
            trim((string) ($admin['autologout'] ?? '')) !== $payload['autologout']
            || $expectedAuth !== $actualAuth
            || trim((string) ($admin['sudo_allow_wheel'] ?? '')) !== $payload['sudo_allow_wheel']
            || trim((string) ($admin['sudo_allow_group'] ?? '')) !== $payload['sudo_allow_group']
            || $expectedOtp !== $actualOtp
        ) {
            throw new RuntimeException('Read-back verification failed for System → Settings → Administration.');
        }

        $_SESSION['system_access_result'] = ['ok' => true, 'message' => 'Administration authentication settings saved and verified.'];
        header('Location: /system_administration.php?firewall_id=' . $firewallId);
        exit;
    }

    $index = trim((string) ($_POST['server_index'] ?? ''));
    if ($index !== 'local' && !ctype_digit($index)) {
        throw new RuntimeException('Invalid authentication server index.');
    }

    $payload = [];
    foreach ([
        'name','password_policy_duration','password_policy_length',
        'otpLength','timeWindow','graceperiod',
        'host','ldap_port','ldap_urltype','ldap_protver','ldap_scope','ldap_basedn','ldap_authcn',
        'ldap_extended_query','ldap_attr_user','ldap_binddn','ldap_bindpw','ldap_attr_memberof',
        'ldap_sync_memberof_groups','ldap_sync_default_groups',
        'radius_auth_port','radius_acct_port','radius_timeout','radius_stationid','radius_secret',
        'sync_memberof_groups','sync_default_groups'
    ] as $field) {
        $payload[$field] = trim((string) ($_POST[$field] ?? ''));
    }
    foreach ([
        'enable_password_policy_constraints','password_policy_complexity','password_policy_compliance',
        'passwordFirst','ldap_read_properties','ldap_sync_memberof','ldap_sync_memberof_constraint',
        'ldap_sync_create_local_users','sync_memberof','sync_create_local_users'
    ] as $field) {
        $payload[$field] = !empty($_POST[$field]);
    }

    backup_before_change($firewall, 'system-access-server-' . ($index === 'local' ? 'local' : $index));

    $response = opn_raw_request(
        $firewall,
        'opnsentralagent/access/setServer/' . rawurlencode($index),
        'POST',
        $payload,
        30
    );
    if (!access_action_success($response)) {
        throw new RuntimeException(access_action_error($response));
    }

    $servers = is_array($response['servers'] ?? null) ? $response['servers'] : [];
    $found = null;
    foreach ($servers as $server) {
        if ((string) ($server['index'] ?? '') === $index) {
            $found = $server;
            break;
        }
    }
    if (!is_array($found)) {
        throw new RuntimeException('Read-back verification could not find the edited authentication server.');
    }

    if ($index === 'local') {
        foreach (['password_policy_duration','password_policy_length'] as $field) {
            if (trim((string) ($found[$field] ?? '')) !== $payload[$field]) {
                throw new RuntimeException('Read-back verification failed for Local Database ' . $field . '.');
            }
        }
        foreach (['enable_password_policy_constraints','password_policy_complexity','password_policy_compliance'] as $field) {
            if ((bool) ($found[$field] ?? false) !== (bool) $payload[$field]) {
                throw new RuntimeException('Read-back verification failed for Local Database ' . $field . '.');
            }
        }
    } else {
        if (trim((string) ($found['name'] ?? '')) !== $payload['name']) {
            throw new RuntimeException('Read-back verification failed for authentication server name.');
        }
        $type = trim((string) ($found['type'] ?? ''));
        if ($type === 'totp' || $type === 'ldap-totp') {
            foreach (['otpLength','timeWindow','graceperiod'] as $field) {
                if (trim((string) ($found[$field] ?? '')) !== $payload[$field]) {
                    throw new RuntimeException('Read-back verification failed for TOTP ' . $field . '.');
                }
            }
        }
        if (in_array($type, ['ldap','ldap-totp','radius'], true) && trim((string) ($found['host'] ?? '')) !== $payload['host']) {
            throw new RuntimeException('Read-back verification failed for authentication server host.');
        }
    }

    $_SESSION['system_access_result'] = ['ok' => true, 'message' => 'Authentication server settings saved and verified.'];
    header('Location: /system_access_servers.php?firewall_id=' . $firewallId);
    exit;
} catch (Throwable $exception) {
    $_SESSION['system_access_result'] = ['ok' => false, 'message' => $exception->getMessage()];
    $target = $action === 'set_administration' ? '/system_administration.php' : '/system_access_servers.php';
    header('Location: ' . $target . '?firewall_id=' . $firewallId);
    exit;
}
