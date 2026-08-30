<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/opnsense.php';
require_once __DIR__ . '/mailer.php';
require_once __DIR__ . '/notification_settings.php';
require_once __DIR__ . '/firewall_notifications.php';

function alerts_prepare_database(): void
{
    db()->exec('CREATE TABLE IF NOT EXISTS alert_states (
        state_key TEXT PRIMARY KEY,
        state_value TEXT NOT NULL,
        failure_count INTEGER NOT NULL DEFAULT 0,
        details TEXT NOT NULL DEFAULT "",
        updated_at TEXT NOT NULL
    )');
    db()->exec('CREATE TABLE IF NOT EXISTS alert_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        state_key TEXT NOT NULL,
        event_type TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        sent_ok INTEGER NOT NULL DEFAULT 0,
        error TEXT NOT NULL DEFAULT "",
        created_at TEXT NOT NULL
    )');
}

function alerts_enabled(): bool
{
    $settings = notification_settings();
    return (bool) $settings['alerts_enabled'] && smtp_is_configured();
}

function alert_threshold(): int
{
    return max(1, (int) notification_settings()['failure_threshold']);
}

function alert_record(string $key, string $event, string $subject, string $message): void
{
    $sent = 0;
    $error = '';
    try {
        smtp_send($subject, $message);
        $sent = 1;
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }

    $statement = db()->prepare('INSERT INTO alert_log
        (state_key,event_type,subject,message,sent_ok,error,created_at)
        VALUES (?,?,?,?,?,?,?)');
    $statement->execute([$key, $event, $subject, $message, $sent, $error, gmdate('c')]);
}

function alert_transition(string $key, string $newState, string $details, string $downSubject, string $downMessage, string $upSubject, string $upMessage): void
{
    alerts_prepare_database();
    $statement = db()->prepare('SELECT * FROM alert_states WHERE state_key = ?');
    $statement->execute([$key]);
    $old = $statement->fetch();
    $now = gmdate('c');

    if (!$old) {
        $insert = db()->prepare('INSERT INTO alert_states
            (state_key,state_value,failure_count,details,updated_at) VALUES (?,?,?,?,?)');
        $insert->execute([$key, $newState === 'down' ? 'unknown' : 'up', $newState === 'down' ? 1 : 0, $details, $now]);
        return;
    }

    $oldState = (string) $old['state_value'];
    $failures = (int) $old['failure_count'];

    if ($newState === 'down') {
        $failures++;
        if ($oldState !== 'down' && $failures >= alert_threshold()) {
            alert_record($key, 'down', $downSubject, $downMessage);
            $oldState = 'down';
        }
    } else {
        if ($oldState === 'down') {
            alert_record($key, 'up', $upSubject, $upMessage);
        }
        $oldState = 'up';
        $failures = 0;
    }

    $update = db()->prepare('UPDATE alert_states SET state_value=?,failure_count=?,details=?,updated_at=? WHERE state_key=?');
    $update->execute([$oldState, $failures, $details, $now, $key]);
}

function alert_rows(array $payload): array
{
    foreach (['rows', 'items', 'data', 'sessions', 'tunnels', 'peers'] as $key) {
        if (isset($payload[$key]) && is_array($payload[$key])) {
            return array_values(array_filter($payload[$key], 'is_array'));
        }
    }
    if (array_is_list($payload)) {
        return array_values(array_filter($payload, 'is_array'));
    }
    return [];
}

function alert_row_name(array $row, string $fallback): string
{
    foreach (['name', 'description', 'instance', 'id', 'common_name', 'remote', 'endpoint'] as $key) {
        if (isset($row[$key]) && trim((string) $row[$key]) !== '') {
            return trim((string) $row[$key]);
        }
    }
    return $fallback;
}

function alert_row_connected(array $row): bool
{
    $values = [];
    foreach (['status', 'state', 'connected', 'active', 'running', 'latest_handshake', 'last_handshake', 'handshake'] as $key) {
        if (array_key_exists($key, $row)) {
            $values[] = strtolower((string) $row[$key]);
        }
    }
    $combined = implode(' ', $values);
    foreach (['up', 'established', 'connected', 'active', 'true', 'running'] as $needle) {
        if (str_contains($combined, $needle)) {
            return true;
        }
    }
    foreach (['latest_handshake', 'last_handshake', 'handshake'] as $key) {
        if (isset($row[$key]) && is_numeric($row[$key]) && (float) $row[$key] > 0) {
            return true;
        }
    }
    return false;
}

function monitor_vpn_type(array $firewall, string $type, array $paths): void
{
    $allRows = [];
    $success = false;
    foreach ($paths as $path) {
        try {
            $payload = opn_request($firewall, $path, 'GET', [], 6);
            $success = true;
            $allRows = array_merge($allRows, alert_rows($payload));
        } catch (Throwable) {
            // A missing plug-in or unavailable endpoint must not create a false VPN alert.
        }
    }
    if (!$success) {
        return;
    }

    $prefix = 'vpn:' . $firewall['id'] . ':' . $type . ':';
    $seen = [];
    foreach ($allRows as $index => $row) {
        $name = alert_row_name($row, $type . '-' . ($index + 1));
        $safe = hash('sha256', $name);
        $key = $prefix . $safe;
        $seen[$key] = true;
        $connected = alert_row_connected($row);
        $label = $firewall['name'] . ' / ' . strtoupper($type) . ' / ' . $name;
        alert_transition(
            $key,
            $connected ? 'up' : 'down',
            json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '',
            '[opnCentral] VPN tunnel down: ' . $label,
            "VPN tunnel is down.\n\nFirewall: {$firewall['name']}\nType: " . strtoupper($type) . "\nTunnel: {$name}\nTime: " . date(DATE_RFC2822),
            '[opnCentral] VPN tunnel restored: ' . $label,
            "VPN tunnel has recovered.\n\nFirewall: {$firewall['name']}\nType: " . strtoupper($type) . "\nTunnel: {$name}\nTime: " . date(DATE_RFC2822)
        );
    }

    $statement = db()->prepare('SELECT state_key FROM alert_states WHERE state_key LIKE ?');
    $statement->execute([$prefix . '%']);
    foreach ($statement->fetchAll() as $stored) {
        $key = (string) $stored['state_key'];
        if (!isset($seen[$key])) {
            alert_transition(
                $key,
                'down',
                'Tunnel no longer returned by the OPNsense API.',
                '[opnCentral] VPN tunnel down on ' . $firewall['name'],
                "A previously known " . strtoupper($type) . " tunnel is no longer active.\n\nFirewall: {$firewall['name']}\nTime: " . date(DATE_RFC2822),
                '[opnCentral] VPN tunnel restored on ' . $firewall['name'],
                "A previously unavailable " . strtoupper($type) . " tunnel has recovered.\n\nFirewall: {$firewall['name']}\nTime: " . date(DATE_RFC2822)
            );
        }
    }
}

function run_alert_checks(): void
{
    alerts_prepare_database();
    if (!alerts_enabled()) {
        return;
    }

    firewall_notifications_prepare_database();
    $firewalls = db()->query('SELECT * FROM firewalls ORDER BY id')->fetchAll();
    foreach ($firewalls as $firewall) {
        if ((int)($firewall['notifications_enabled'] ?? 1) !== 1) {
            continue;
        }

        $online = false;
        $details = '';
        try {
            $status = opn_request($firewall, 'core/system/status', 'GET', [], 7);
            $online = true;
            $details = json_encode($status, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '';
        } catch (Throwable $exception) {
            $details = $exception->getMessage();
        }

        $key = 'firewall:' . $firewall['id'];
        alert_transition(
            $key,
            $online ? 'up' : 'down',
            $details,
            '[opnCentral] Firewall offline: ' . $firewall['name'],
            "Firewall is unreachable.\n\nName: {$firewall['name']}\nURL: {$firewall['base_url']}\nError: {$details}\nTime: " . date(DATE_RFC2822),
            '[opnCentral] Firewall restored: ' . $firewall['name'],
            "Firewall is reachable again.\n\nName: {$firewall['name']}\nURL: {$firewall['base_url']}\nTime: " . date(DATE_RFC2822)
        );

        if (!$online || !(bool) notification_settings()['alert_vpn']) {
            continue;
        }

        monitor_vpn_type($firewall, 'wireguard', ['wireguard/service/show']);
        monitor_vpn_type($firewall, 'ipsec', ['ipsec/sessions/search_phase1', 'ipsec/sessions/search_phase2']);
        monitor_vpn_type($firewall, 'openvpn', ['openvpn/service/search_sessions']);
    }
}
