#!/usr/local/bin/php
<?php

declare(strict_types=1);

const TABLE_NAME = 'sshlockout';
const TRUST_DIR = '/conf/opnsentral';
const TRUST_FILE = TRUST_DIR . '/ssh-trusted.txt';
const PFCTL = '/sbin/pfctl';

function fail(string $message, int $code = 1): never
{
    fwrite(STDERR, $message . "\n");
    exit($code);
}

function valid_host(string $value): string
{
    $value = trim($value);
    if ($value === '' || str_contains($value, '/')) {
        throw new RuntimeException('Trusted hosts must be exact IPv4 or IPv6 addresses; CIDR ranges are not allowed.');
    }
    if (filter_var($value, FILTER_VALIDATE_IP) === false) {
        throw new RuntimeException('Invalid IPv4 or IPv6 address.');
    }
    return $value;
}

function run_process(array $command): array
{
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Could not start pfctl.');
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);
    return [
        'status' => $status,
        'stdout' => is_string($stdout) ? trim($stdout) : '',
        'stderr' => is_string($stderr) ? trim($stderr) : '',
    ];
}

function pfctl(array $arguments, bool $allowFailure = false): array
{
    if (!is_file(PFCTL) || !is_executable(PFCTL)) {
        throw new RuntimeException('pfctl is unavailable.');
    }
    $result = run_process(array_merge([PFCTL], $arguments));
    if (!$allowFailure && (int)$result['status'] !== 0) {
        $detail = trim((string)$result['stderr']);
        if ($detail === '') $detail = trim((string)$result['stdout']);
        throw new RuntimeException('pfctl failed' . ($detail !== '' ? ': ' . substr($detail, 0, 500) : '.'));
    }
    return $result;
}

function trusted_file_read(): array
{
    if (!is_file(TRUST_FILE)) return [];
    $contents = file_get_contents(TRUST_FILE);
    if (!is_string($contents)) throw new RuntimeException('Could not read trusted-host file.');
    $hosts = [];
    foreach (preg_split('/\R+/', $contents) ?: [] as $line) {
        $line = trim((string)$line);
        if ($line === '' || str_starts_with($line, '#')) continue;
        $hosts[] = valid_host($line);
    }
    $hosts = array_values(array_unique($hosts));
    sort($hosts, SORT_NATURAL | SORT_FLAG_CASE);
    return $hosts;
}

function trusted_file_write(array $hosts): void
{
    $clean = [];
    foreach ($hosts as $host) $clean[] = valid_host((string)$host);
    $clean = array_values(array_unique($clean));
    sort($clean, SORT_NATURAL | SORT_FLAG_CASE);

    if (!is_dir(TRUST_DIR) && !mkdir(TRUST_DIR, 0700, true) && !is_dir(TRUST_DIR)) {
        throw new RuntimeException('Could not create trusted-host directory.');
    }
    chmod(TRUST_DIR, 0700);

    $temp = TRUST_FILE . '.tmp-' . bin2hex(random_bytes(4));
    $content = $clean === [] ? '' : implode("\n", $clean) . "\n";
    if (file_put_contents($temp, $content, LOCK_EX) === false) {
        throw new RuntimeException('Could not stage trusted-host file.');
    }
    chmod($temp, 0600);
    if (!rename($temp, TRUST_FILE)) {
        @unlink($temp);
        throw new RuntimeException('Could not activate trusted-host file.');
    }
    chmod(TRUST_FILE, 0600);
}

function table_snapshot(): array
{
    $result = pfctl(['-t', TABLE_NAME, '-T', 'show']);
    $blocked = [];
    $trustedActive = [];

    foreach (preg_split('/\R+/', (string)$result['stdout']) ?: [] as $line) {
        $line = trim((string)$line);
        if ($line === '') continue;
        if (preg_match('/^!\s*(.+)$/', $line, $match) === 1) {
            $candidate = trim((string)$match[1]);
            if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) $trustedActive[] = $candidate;
            continue;
        }
        $candidate = preg_replace('/\/(32|128)$/', '', $line) ?? $line;
        if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) $blocked[] = $candidate;
    }

    $blocked = array_values(array_unique($blocked));
    $trustedActive = array_values(array_unique($trustedActive));
    sort($blocked, SORT_NATURAL | SORT_FLAG_CASE);
    sort($trustedActive, SORT_NATURAL | SORT_FLAG_CASE);

    return ['blocked' => $blocked, 'trusted_active' => $trustedActive];
}

function snapshot(string $message = ''): array
{
    $table = table_snapshot();
    $configured = trusted_file_read();
    return [
        'ok' => true,
        'table' => TABLE_NAME,
        'blocked' => $table['blocked'],
        'trusted' => $configured,
        'trusted_active' => $table['trusted_active'],
        'trusted_in_sync' => array_values(array_diff($configured, $table['trusted_active'])) === []
            && array_values(array_diff($table['trusted_active'], $configured)) === [],
        'message' => $message,
        'checked_at' => gmdate('c'),
    ];
}

function table_delete_positive(string $ip): void
{
    pfctl(['-t', TABLE_NAME, '-T', 'delete', $ip], true);
}

function table_add_negative(string $ip): void
{
    $result = pfctl(['-v', '-t', TABLE_NAME, '-T', 'add', '!' . $ip], true);
    if ((int)$result['status'] !== 0) {
        $detail = trim((string)$result['stderr']);
        if ($detail === '') $detail = trim((string)$result['stdout']);
        throw new RuntimeException('Could not activate trusted host ' . $ip . ($detail !== '' ? ': ' . substr($detail, 0, 500) : '.'));
    }
}

function table_delete_negative(string $ip): void
{
    pfctl(['-t', TABLE_NAME, '-T', 'delete', '!' . $ip], true);
}

function sync_trusted_hosts(): array
{
    $configured = trusted_file_read();
    $before = table_snapshot();

    foreach ($before['trusted_active'] as $active) {
        if (!in_array($active, $configured, true)) table_delete_negative($active);
    }

    foreach ($configured as $ip) {
        $current = table_snapshot();
        if (!in_array($ip, $current['trusted_active'], true)) {
            if (in_array($ip, $current['blocked'], true)) table_delete_positive($ip);
            table_add_negative($ip);
        }
    }

    $after = snapshot('Trusted hosts synchronized with the sshlockout PF table.');
    if (($after['trusted_in_sync'] ?? false) !== true) {
        throw new RuntimeException('Trusted-host verification failed after synchronization.');
    }
    foreach ($configured as $ip) {
        if (in_array($ip, $after['blocked'], true)) {
            throw new RuntimeException('Trusted-host verification failed: ' . $ip . ' is still blocked.');
        }
    }
    return $after;
}

function trust_host(string $ip): array
{
    $ip = valid_host($ip);
    $before = trusted_file_read();
    if (!in_array($ip, $before, true)) {
        $updated = $before;
        $updated[] = $ip;
        trusted_file_write($updated);
    }

    try {
        $state = table_snapshot();
        if (in_array($ip, $state['blocked'], true)) table_delete_positive($ip);
        if (!in_array($ip, $state['trusted_active'], true)) table_add_negative($ip);
        $verify = snapshot('Trusted host added and verified.');
        if (!in_array($ip, $verify['trusted'], true)
            || !in_array($ip, $verify['trusted_active'], true)
            || in_array($ip, $verify['blocked'], true)) {
            throw new RuntimeException('Trusted-host read-back verification failed.');
        }
        return $verify;
    } catch (Throwable $exception) {
        trusted_file_write($before);
        table_delete_negative($ip);
        throw $exception;
    }
}

function untrust_host(string $ip): array
{
    $ip = valid_host($ip);
    $before = trusted_file_read();
    $updated = array_values(array_filter($before, static fn(string $value): bool => $value !== $ip));
    trusted_file_write($updated);

    try {
        table_delete_negative($ip);
        $verify = snapshot('Trusted host removed and verified.');
        if (in_array($ip, $verify['trusted'], true) || in_array($ip, $verify['trusted_active'], true)) {
            throw new RuntimeException('Trusted-host removal read-back verification failed.');
        }
        return $verify;
    } catch (Throwable $exception) {
        trusted_file_write($before);
        if (in_array($ip, $before, true)) {
            try { table_add_negative($ip); } catch (Throwable) {}
        }
        throw $exception;
    }
}

try {
    $action = strtolower(trim((string)($argv[1] ?? 'status')));
    if ($action === 'status') {
        $result = snapshot();
    } elseif ($action === 'sync') {
        $result = sync_trusted_hosts();
    } elseif ($action === 'trust') {
        $result = trust_host((string)($argv[2] ?? ''));
    } elseif ($action === 'untrust') {
        $result = untrust_host((string)($argv[2] ?? ''));
    } else {
        throw new RuntimeException('Supported actions: status, sync, trust, untrust.');
    }
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
} catch (Throwable $exception) {
    fail($exception->getMessage());
}
