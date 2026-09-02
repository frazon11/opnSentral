<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$message = '';
$error = '';

function blocked_ips_collect(mixed $value, array &$result): void
{
    if (is_array($value)) {
        foreach ($value as $nested) {
            blocked_ips_collect($nested, $result);
        }
        return;
    }

    if (!is_string($value) && !is_int($value)) {
        return;
    }

    $candidate = trim((string)$value);
    if ($candidate === '' || str_starts_with($candidate, '!')) {
        return;
    }

    $candidate = preg_replace('/\/(32|128)$/', '', $candidate) ?? $candidate;
    if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
        $result[] = $candidate;
    }
}

function blocked_ips_for_firewall(array $firewall): array
{
    $response = opn_raw_request(
        $firewall,
        'firewall/alias_util/list/sshlockout',
        'GET',
        [],
        15
    );

    $result = [];
    blocked_ips_collect($response['rows'] ?? $response, $result);
    $result = array_values(array_unique($result));
    sort($result, SORT_NATURAL | SORT_FLAG_CASE);
    return $result;
}

function blocked_ips_remove(array $firewall, string $address): void
{
    if (filter_var($address, FILTER_VALIDATE_IP) === false || str_contains($address, '/')) {
        throw new RuntimeException('Invalid IP address.');
    }

    $response = opn_raw_request(
        $firewall,
        'firewall/alias_util/delete/sshlockout',
        'POST',
        ['address' => $address],
        15
    );

    if (strtolower(trim((string)($response['status'] ?? ''))) !== 'done') {
        throw new RuntimeException('OPNsense did not confirm removal from sshlockout.');
    }

    if (in_array($address, blocked_ips_for_firewall($firewall), true)) {
        throw new RuntimeException('Read-back verification failed: the IP is still blocked.');
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    try {
        $firewallId = (int)($_POST['firewall_id'] ?? 0);
        $address = trim((string)($_POST['address'] ?? ''));
        $firewall = firewall_by_id($firewallId);
        blocked_ips_remove($firewall, $address);
        $message = $address . ' removed from ' . (string)$firewall['name'] . ' and verified.';
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name, id')->fetchAll();
$rows = [];
$totalBlocked = 0;

foreach ($firewalls as $firewall) {
    try {
        $blocked = blocked_ips_for_firewall($firewall);
        $totalBlocked += count($blocked);
        $rows[] = [
            'firewall' => $firewall,
            'blocked' => $blocked,
            'error' => '',
        ];
    } catch (Throwable $exception) {
        $rows[] = [
            'firewall' => $firewall,
            'blocked' => [],
            'error' => $exception->getMessage(),
        ];
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.blocked-summary{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:16px}.blocked-count{font-size:1.35rem;font-weight:800}.blocked-fw{margin-bottom:16px;padding:0;overflow:hidden}.blocked-fw-head{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:14px 16px;background:#10131a;border-bottom:1px solid #343943}.blocked-fw-head h2{margin:0}.blocked-fw-meta{font-size:.88rem;opacity:.75}.blocked-table{width:100%;border-collapse:collapse}.blocked-table th,.blocked-table td{padding:10px 12px;border-bottom:1px solid #343943;text-align:left}.blocked-table th{background:#0f1218}.blocked-empty{padding:16px;color:#aeb5bd}.blocked-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.blocked-actions form{margin:0}
</style>

<div class="page-title">
    <div>
        <h1>Blocked IPs</h1>
        <p>Live SSH / WebGUI brute-force lockouts from the OPNsense <code>sshlockout</code> table.</p>
    </div>
    <a class="button secondary" href="/">Dashboard</a>
</div>

<?php if ($message): ?><div class="alert goodbox"><?= h($message) ?></div><?php endif; ?>
<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<div class="card blocked-summary">
    <span class="blocked-count"><?= (int)$totalBlocked ?></span>
    <span>currently blocked IP address<?= $totalBlocked === 1 ? '' : 'es' ?> across <?= count($firewalls) ?> firewall<?= count($firewalls) === 1 ? '' : 's' ?>.</span>
</div>

<?php if (!$rows): ?>
    <section class="card"><div class="blocked-empty">No firewalls configured.</div></section>
<?php endif; ?>

<?php foreach ($rows as $row):
    $firewall = $row['firewall'];
    $blocked = $row['blocked'];
    $rowError = (string)$row['error'];
?>
<section class="card blocked-fw">
    <div class="blocked-fw-head">
        <div>
            <h2><?= h((string)$firewall['name']) ?></h2>
            <div class="blocked-fw-meta"><?= h((string)$firewall['base_url']) ?></div>
        </div>
        <div class="blocked-actions">
            <span><?= count($blocked) ?> blocked</span>
            <a class="button secondary" href="/ssh_lockout.php?firewall_id=<?= (int)$firewall['id'] ?>">Lockout details</a>
            <a class="button secondary" href="/firewall_view.php?id=<?= (int)$firewall['id'] ?>">Manage firewall</a>
        </div>
    </div>

    <?php if ($rowError !== ''): ?>
        <div class="alert error" style="margin:14px"><?= h($rowError) ?></div>
    <?php elseif (!$blocked): ?>
        <div class="blocked-empty">No blocked IP addresses.</div>
    <?php else: ?>
        <table class="blocked-table">
            <thead><tr><th>IP address</th><th>Table</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach ($blocked as $address): ?>
                <tr>
                    <td><code><?= h((string)$address) ?></code></td>
                    <td><code>sshlockout</code></td>
                    <td>
                        <form method="post" onsubmit="return confirm('Unblock <?= h((string)$address) ?> on <?= h((string)$firewall['name']) ?>?');">
                            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                            <input type="hidden" name="firewall_id" value="<?= (int)$firewall['id'] ?>">
                            <input type="hidden" name="address" value="<?= h((string)$address) ?>">
                            <button type="submit" class="secondary">Unblock</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</section>
<?php endforeach; ?>

<?php require __DIR__ . '/inc/footer.php'; ?>
