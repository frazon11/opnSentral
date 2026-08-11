<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function notification_settings_prepare_database(): void
{
    db()->exec('CREATE TABLE IF NOT EXISTS notification_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        alerts_enabled INTEGER,
        alert_vpn INTEGER,
        check_interval INTEGER,
        failure_threshold INTEGER,
        smtp_host TEXT,
        smtp_port INTEGER,
        smtp_security TEXT,
        smtp_username TEXT,
        smtp_password_enc TEXT,
        smtp_from TEXT,
        smtp_from_name TEXT,
        notify_to TEXT,
        updated_at TEXT NOT NULL
    )');
}

function notification_env_defaults(): array
{
    return [
        'alerts_enabled' => filter_var(envv('ALERTS_ENABLED', 'false'), FILTER_VALIDATE_BOOL),
        'alert_vpn' => filter_var(envv('ALERT_VPN', 'true'), FILTER_VALIDATE_BOOL),
        'check_interval' => max(60, (int) envv('ALERT_CHECK_INTERVAL', '300')),
        'failure_threshold' => max(1, (int) envv('ALERT_FAILURE_THRESHOLD', '2')),
        'smtp_host' => envv('SMTP_HOST'),
        'smtp_port' => max(1, min(65535, (int) envv('SMTP_PORT', '587'))),
        'smtp_security' => in_array(strtolower(envv('SMTP_SECURITY', 'tls')), ['tls', 'ssl', 'none'], true)
            ? strtolower(envv('SMTP_SECURITY', 'tls'))
            : 'tls',
        'smtp_username' => envv('SMTP_USERNAME'),
        'smtp_password' => envv('SMTP_PASSWORD'),
        'smtp_from' => envv('SMTP_FROM'),
        'smtp_from_name' => envv('SMTP_FROM_NAME', 'opnCentral'),
        'notify_to' => envv('NOTIFY_TO'),
        'source' => 'environment',
    ];
}

function notification_settings(): array
{
    notification_settings_prepare_database();
    $defaults = notification_env_defaults();
    $row = db()->query('SELECT * FROM notification_settings WHERE id = 1')->fetch();
    if (!$row) {
        return $defaults;
    }

    $password = '';
    if ((string) ($row['smtp_password_enc'] ?? '') !== '') {
        try {
            $password = decrypt_value((string) $row['smtp_password_enc']);
        } catch (Throwable $exception) {
            error_log('[opnCentral notifications] Could not decrypt SMTP password: ' . $exception->getMessage());
            $password = $defaults['smtp_password'];
        }
    }

    return [
        'alerts_enabled' => (bool) $row['alerts_enabled'],
        'alert_vpn' => (bool) $row['alert_vpn'],
        'check_interval' => max(60, (int) $row['check_interval']),
        'failure_threshold' => max(1, (int) $row['failure_threshold']),
        'smtp_host' => (string) $row['smtp_host'],
        'smtp_port' => max(1, min(65535, (int) $row['smtp_port'])),
        'smtp_security' => in_array((string) $row['smtp_security'], ['tls', 'ssl', 'none'], true)
            ? (string) $row['smtp_security']
            : 'tls',
        'smtp_username' => (string) $row['smtp_username'],
        'smtp_password' => $password,
        'smtp_from' => (string) $row['smtp_from'],
        'smtp_from_name' => (string) $row['smtp_from_name'],
        'notify_to' => (string) $row['notify_to'],
        'source' => 'database',
    ];
}

function notification_validate_recipients(string $value): string
{
    $recipients = array_values(array_filter(array_map('trim', explode(',', $value))));
    foreach ($recipients as $recipient) {
        if (filter_var($recipient, FILTER_VALIDATE_EMAIL) === false) {
            throw new InvalidArgumentException('Invalid recipient email address: ' . $recipient);
        }
    }
    return implode(',', $recipients);
}

function notification_save_settings(array $input): void
{
    notification_settings_prepare_database();
    $current = notification_settings();

    $host = trim((string) ($input['smtp_host'] ?? ''));
    $port = (int) ($input['smtp_port'] ?? 587);
    $security = strtolower(trim((string) ($input['smtp_security'] ?? 'tls')));
    $username = trim((string) ($input['smtp_username'] ?? ''));
    $passwordInput = (string) ($input['smtp_password'] ?? '');
    $from = trim((string) ($input['smtp_from'] ?? ''));
    $fromName = trim((string) ($input['smtp_from_name'] ?? 'opnCentral'));
    $notifyTo = notification_validate_recipients((string) ($input['notify_to'] ?? ''));
    $interval = max(60, min(86400, (int) ($input['check_interval'] ?? 300)));
    $threshold = max(1, min(100, (int) ($input['failure_threshold'] ?? 2)));

    if ($port < 1 || $port > 65535) {
        throw new InvalidArgumentException('SMTP port must be between 1 and 65535.');
    }
    if (!in_array($security, ['tls', 'ssl', 'none'], true)) {
        throw new InvalidArgumentException('Invalid SMTP security mode.');
    }
    if ($from !== '' && filter_var($from, FILTER_VALIDATE_EMAIL) === false) {
        throw new InvalidArgumentException('Invalid sender email address.');
    }

    $password = $passwordInput !== '' ? $passwordInput : (string) $current['smtp_password'];
    $passwordEnc = $password !== '' ? encrypt_value($password) : '';

    $statement = db()->prepare('INSERT INTO notification_settings (
        id, alerts_enabled, alert_vpn, check_interval, failure_threshold,
        smtp_host, smtp_port, smtp_security, smtp_username, smtp_password_enc,
        smtp_from, smtp_from_name, notify_to, updated_at
    ) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET
        alerts_enabled=excluded.alerts_enabled,
        alert_vpn=excluded.alert_vpn,
        check_interval=excluded.check_interval,
        failure_threshold=excluded.failure_threshold,
        smtp_host=excluded.smtp_host,
        smtp_port=excluded.smtp_port,
        smtp_security=excluded.smtp_security,
        smtp_username=excluded.smtp_username,
        smtp_password_enc=excluded.smtp_password_enc,
        smtp_from=excluded.smtp_from,
        smtp_from_name=excluded.smtp_from_name,
        notify_to=excluded.notify_to,
        updated_at=excluded.updated_at');
    $statement->execute([
        isset($input['alerts_enabled']) ? 1 : 0,
        isset($input['alert_vpn']) ? 1 : 0,
        $interval,
        $threshold,
        $host,
        $port,
        $security,
        $username,
        $passwordEnc,
        $from,
        $fromName,
        $notifyTo,
        gmdate('c'),
    ]);
}
