<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/opnsense.php';

function sshlockout_prepare_database(): void
{
    static $prepared = false;
    if ($prepared) return;

    db()->exec('CREATE TABLE IF NOT EXISTS sshlockout_trusted_hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firewall_id INTEGER NOT NULL,
        address TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(firewall_id, address)
    )');
    db()->exec('CREATE INDEX IF NOT EXISTS idx_sshlockout_trusted_firewall ON sshlockout_trusted_hosts(firewall_id)');
    $prepared = true;
}

function sshlockout_normalize_ip(string $value): string
{
    $value = trim($value);
    if ($value === '' || filter_var($value, FILTER_VALIDATE_IP) === false) {
        throw new RuntimeException('Enter one IPv4 or IPv6 host address. CIDR networks and hostnames are not accepted.');
    }

    $packed = @inet_pton($value);
    $normalized = is_string($packed) ? @inet_ntop($packed) : false;
    if (!is_string($normalized) || $normalized === '') {
        throw new RuntimeException('Invalid IP address.');
    }
    return $normalized;
}

function sshlockout_trusted_hosts(int $firewallId): array
{
    sshlockout_prepare_database();
    $statement = db()->prepare('SELECT address,created_at FROM sshlockout_trusted_hosts WHERE firewall_id = ? ORDER BY address');
    $statement->execute([$firewallId]);
    return $statement->fetchAll();
}

function sshlockout_live_entries(array $firewall): array
{
    $response = opn_request($firewall, 'firewall/alias_util/list/sshlockout', 'GET', [], 12);
    $result = [];
    foreach (($response['rows'] ?? []) as $row) {
        if (!is_array($row)) continue;
        $raw = trim((string)($row['ip'] ?? $row['address'] ?? ''));
        if ($raw === '') continue;

        // PF tables can contain negated entries. They are not blocked hosts.
        $negated = str_starts_with($raw, '!');
        $address = trim(ltrim($raw, '!'));
        if ($address === '' || filter_var($address, FILTER_VALIDATE_IP) === false) continue;
        if (!$negated) $result[] = sshlockout_normalize_ip($address);
    }
    $result = array_values(array_unique($result));
    sort($result, SORT_NATURAL | SORT_FLAG_CASE);
    return $result;
}

function sshlockout_delete_runtime(array $firewall, string $address): void
{
    $address = sshlockout_normalize_ip($address);
    $response = opn_raw_request(
        $firewall,
        'firewall/alias_util/delete/sshlockout',
        'POST',
        ['address' => $address],
        15
    );
    if (($response['status'] ?? '') !== 'done') {
        throw new RuntimeException('OPNsense did not confirm removal from the sshlockout table.');
    }

    $remaining = sshlockout_live_entries($firewall);
    if (in_array($address, $remaining, true)) {
        throw new RuntimeException('Read-back verification failed: the address is still present in sshlockout.');
    }
}

function sshlockout_add_trusted_host(int $firewallId, string $address): array
{
    sshlockout_prepare_database();
    $address = sshlockout_normalize_ip($address);
    $statement = db()->prepare('INSERT OR IGNORE INTO sshlockout_trusted_hosts(firewall_id,address,created_at) VALUES(?,?,?)');
    $statement->execute([$firewallId, $address, gmdate('c')]);

    $warning = '';
    try {
        $firewall = firewall_by_id($firewallId);
        $blocked = sshlockout_live_entries($firewall);
        if (in_array($address, $blocked, true)) {
            sshlockout_delete_runtime($firewall, $address);
        }
    } catch (Throwable $exception) {
        $warning = $exception->getMessage();
    }

    return ['address' => $address, 'warning' => $warning];
}

function sshlockout_remove_trusted_host(int $firewallId, string $address): void
{
    sshlockout_prepare_database();
    $address = sshlockout_normalize_ip($address);
    $statement = db()->prepare('DELETE FROM sshlockout_trusted_hosts WHERE firewall_id = ? AND address = ?');
    $statement->execute([$firewallId, $address]);
}

function sshlockout_enforce_firewall(array $firewall): array
{
    $trusted = array_map(
        static fn(array $row): string => (string)$row['address'],
        sshlockout_trusted_hosts((int)$firewall['id'])
    );
    if ($trusted === []) return ['checked' => 0, 'removed' => 0];

    $blocked = sshlockout_live_entries($firewall);
    $removed = 0;
    foreach ($trusted as $address) {
        if (!in_array($address, $blocked, true)) continue;
        sshlockout_delete_runtime($firewall, $address);
        $removed++;
    }
    return ['checked' => count($trusted), 'removed' => $removed];
}

function sshlockout_enforce_all(): void
{
    sshlockout_prepare_database();
    $rows = db()->query('SELECT DISTINCT firewall_id FROM sshlockout_trusted_hosts ORDER BY firewall_id')->fetchAll();
    foreach ($rows as $row) {
        $firewallId = (int)($row['firewall_id'] ?? 0);
        if ($firewallId < 1) continue;
        try {
            sshlockout_enforce_firewall(firewall_by_id($firewallId));
        } catch (Throwable $exception) {
            error_log('[opnSentral sshlockout] firewall '.$firewallId.': '.$exception->getMessage());
        }
    }
}
