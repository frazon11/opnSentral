<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$firewallId = (int)($_GET['firewall_id'] ?? $_POST['firewall_id'] ?? 0);
$firewall = firewall_by_id($firewallId);
$message = '';
$error = '';
$pluginAvailable = false;
$lockout = ['blocked' => [], 'trusted' => [], 'trusted_active' => [], 'trusted_in_sync' => false];

function ssh_lockout_exact_ip(mixed $value): string
{
    $value = trim((string)$value);
    if ($value === '' || str_contains($value, '/') || filter_var($value, FILTER_VALIDATE_IP) === false) {
        throw new RuntimeException('Enter one exact IPv4 or IPv6 address. CIDR ranges are not accepted for trusted hosts.');
    }
    return $value;
}

function ssh_lockout_collect_ips(mixed $value, array &$result): void
{
    if (is_array($value)) {
        foreach ($value as $nested) ssh_lockout_collect_ips($nested, $result);
        return;
    }
    if (!is_string($value) && !is_int($value)) return;
    $candidate = trim((string)$value);
    if ($candidate === '' || str_starts_with($candidate, '!')) return;
    $candidate = preg_replace('/\/(32|128)$/', '', $candidate) ?? $candidate;
    if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) $result[] = $candidate;
}

function ssh_lockout_official_list(array $firewall): array
{
    $response = opn_raw_request($firewall, 'firewall/alias_util/list/sshlockout', 'GET', [], 15);
    $result = [];
    ssh_lockout_collect_ips($response['rows'] ?? $response, $result);
    $result = array_values(array_unique($result));
    sort($result, SORT_NATURAL | SORT_FLAG_CASE);
    return $result;
}

function ssh_lockout_status(array $firewall): array
{
    try {
        $response = opn_raw_request($firewall, 'opnsentralagent/lockout/status', 'GET', [], 15);
        if (($response['ok'] ?? false) !== true || !isset($response['blocked'], $response['trusted'])) {
            throw new RuntimeException('Trusted-host API returned an invalid response.');
        }
        return ['plugin_available' => true, 'data' => $response];
    } catch (Throwable $exception) {
        return [
            'plugin_available' => false,
            'data' => [
                'blocked' => ssh_lockout_official_list($firewall),
                'trusted' => [],
                'trusted_active' => [],
                'trusted_in_sync' => false,
                'plugin_error' => $exception->getMessage(),
            ],
        ];
    }
}

function ssh_lockout_remove(array $firewall, string $ip): void
{
    // Use OPNsense's standard runtime table API directly. opn_raw_request()
    // deliberately avoids opnSentral's managed-category preparation because
    // removing a lockout must not create or modify unrelated firewall config.
    $response = opn_raw_request($firewall, 'firewall/alias_util/delete/sshlockout', 'POST', ['address' => $ip], 15);
    if (strtolower(trim((string)($response['status'] ?? ''))) !== 'done') {
        throw new RuntimeException('OPNsense did not confirm removal from sshlockout.');
    }
    $remaining = ssh_lockout_official_list($firewall);
    if (in_array($ip, $remaining, true)) {
        throw new RuntimeException('Read-back verification failed: ' . $ip . ' is still present in sshlockout.');
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    try {
        $action = trim((string)($_POST['action'] ?? ''));
        $ip = ssh_lockout_exact_ip($_POST['address'] ?? '');

        if ($action === 'remove') {
            ssh_lockout_remove($firewall, $ip);
            $message = $ip . ' removed from the sshlockout table and verified.';
        } elseif ($action === 'trust') {
            $response = opn_raw_request($firewall, 'opnsentralagent/lockout/trust', 'POST', ['address' => $ip], 20);
            if (($response['ok'] ?? false) !== true
                || !in_array($ip, (array)($response['trusted'] ?? []), true)
                || !in_array($ip, (array)($response['trusted_active'] ?? []), true)
                || in_array($ip, (array)($response['blocked'] ?? []), true)) {
                throw new RuntimeException('Trusted-host read-back verification failed.');
            }
            $message = $ip . ' is now always trusted for OPNsense SSH/WebGUI lockout protection.';
        } elseif ($action === 'untrust') {
            $response = opn_raw_request($firewall, 'opnsentralagent/lockout/untrust', 'POST', ['address' => $ip], 20);
            if (($response['ok'] ?? false) !== true
                || in_array($ip, (array)($response['trusted'] ?? []), true)
                || in_array($ip, (array)($response['trusted_active'] ?? []), true)) {
                throw new RuntimeException('Trusted-host removal read-back verification failed.');
            }
            $message = $ip . ' removed from the trusted-host list.';
        } else {
            throw new RuntimeException('Unknown lockout action.');
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

try {
    $status = ssh_lockout_status($firewall);
    $pluginAvailable = (bool)$status['plugin_available'];
    $lockout = array_replace($lockout, (array)$status['data']);
} catch (Throwable $exception) {
    if ($error === '') $error = $exception->getMessage();
}

require __DIR__ . '/inc/header.php';
?>
<style>
.lockout-grid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(320px,.75fr);gap:16px;align-items:start}.lockout-table{width:100%;border-collapse:collapse}.lockout-table th,.lockout-table td{padding:10px 12px;border-bottom:1px solid #343943;text-align:left;vertical-align:middle}.lockout-table th{background:#10131a}.lockout-actions{display:flex;gap:7px;flex-wrap:wrap;align-items:center}.lockout-actions form{margin:0}.lockout-empty{padding:18px;color:#aeb5bd}.lockout-form{display:flex;gap:8px;align-items:end;flex-wrap:wrap}.lockout-form label{display:grid;gap:6px;flex:1;min-width:230px}.lockout-form input{width:100%;box-sizing:border-box}.lockout-note{font-size:.9rem;color:#aeb5bd}.lockout-good{color:#74d68f}.lockout-warning{color:#f0b35a}@media(max-width:900px){.lockout-grid{grid-template-columns:1fr}}
</style>

<div class="page-title">
    <div>
        <h1>SSH / WebGUI Lockout</h1>
        <p><?= h((string)$firewall['name']) ?> · <?= h((string)$firewall['base_url']) ?></p>
    </div>
    <a class="button secondary" href="/firewall_view.php?id=<?= $firewallId ?>">Back to Manage</a>
</div>

<?php if ($message): ?><div class="alert goodbox"><?= h($message) ?></div><?php endif; ?>
<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<div class="lockout-grid">
    <section class="card" style="padding:0;overflow:hidden">
        <div style="padding:16px;border-bottom:1px solid #343943">
            <h2 style="margin:0 0 6px">Blocked IPs</h2>
            <div class="lockout-note">Live contents of OPNsense PF table <code>sshlockout</code>. This table protects both SSH and the WebGUI against repeated failed logins.</div>
        </div>
        <?php if (empty($lockout['blocked'])): ?>
            <div class="lockout-empty">No blocked IP addresses.</div>
        <?php else: ?>
        <table class="lockout-table">
            <thead><tr><th>IP address</th><th>Actions</th></tr></thead>
            <tbody>
            <?php foreach ((array)$lockout['blocked'] as $ip): ?>
                <tr>
                    <td><code><?= h((string)$ip) ?></code></td>
                    <td><div class="lockout-actions">
                        <form method="post" onsubmit="return confirm('Remove <?= h((string)$ip) ?> from the current sshlockout table?');">
                            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                            <input type="hidden" name="firewall_id" value="<?= $firewallId ?>">
                            <input type="hidden" name="address" value="<?= h((string)$ip) ?>">
                            <button type="submit" name="action" value="remove" class="secondary">Remove block</button>
                        </form>
                        <?php if ($pluginAvailable): ?>
                        <form method="post" onsubmit="return confirm('Always trust <?= h((string)$ip) ?> on this firewall? It will be removed from sshlockout and protected from future lockouts.');">
                            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                            <input type="hidden" name="firewall_id" value="<?= $firewallId ?>">
                            <input type="hidden" name="address" value="<?= h((string)$ip) ?>">
                            <button type="submit" name="action" value="trust">Trust permanently</button>
                        </form>
                        <?php endif; ?>
                    </div></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </section>

    <section class="card">
        <h2>Always trusted hosts</h2>
        <?php if (!$pluginAvailable): ?>
            <div class="alert warningbox">Trusted-host support is not installed on this firewall yet. Re-run the opnSentral plugin repair installer. Viewing and removing current lockouts still uses the standard OPNsense firewall API.</div>
        <?php else: ?>
            <p class="<?= !empty($lockout['trusted_in_sync']) ? 'lockout-good' : 'lockout-warning' ?>">
                <?= !empty($lockout['trusted_in_sync']) ? 'Trusted-host PF state is synchronized.' : 'Trusted-host PF state is not fully synchronized.' ?>
            </p>
            <form method="post" class="lockout-form">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                <input type="hidden" name="firewall_id" value="<?= $firewallId ?>">
                <label><strong>Exact IPv4 / IPv6 address</strong><input type="text" name="address" required placeholder="192.0.2.10" autocomplete="off"></label>
                <button type="submit" name="action" value="trust">Add trusted host</button>
            </form>
            <p class="lockout-note">Only exact host addresses are accepted. Networks/CIDR ranges are deliberately rejected because they cannot provide the same lockout guarantee.</p>

            <?php if (empty($lockout['trusted'])): ?>
                <div class="lockout-empty" style="padding-left:0">No trusted hosts configured.</div>
            <?php else: ?>
                <table class="lockout-table" style="margin-top:10px">
                    <thead><tr><th>Trusted IP</th><th>PF state</th><th></th></tr></thead>
                    <tbody>
                    <?php foreach ((array)$lockout['trusted'] as $ip): $active = in_array($ip, (array)$lockout['trusted_active'], true); ?>
                        <tr>
                            <td><code><?= h((string)$ip) ?></code></td>
                            <td><?= $active ? '<span class="lockout-good">Active</span>' : '<span class="lockout-warning">Needs sync</span>' ?></td>
                            <td><form method="post" onsubmit="return confirm('Remove <?= h((string)$ip) ?> from always trusted hosts?');">
                                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                                <input type="hidden" name="firewall_id" value="<?= $firewallId ?>">
                                <input type="hidden" name="address" value="<?= h((string)$ip) ?>">
                                <button type="submit" name="action" value="untrust" class="secondary">Remove trusted</button>
                            </form></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        <?php endif; ?>
    </section>
</div>

<section class="card" style="margin-top:16px">
    <h2>How trusted hosts work</h2>
    <p>opnSentral stores the exact trusted IPs locally on this OPNsense in <code>/conf/opnsentral/ssh-trusted.txt</code> and represents them as negated entries in the existing <code>sshlockout</code> PF table. A negated exact host does not match the lockout table, and PF refuses a later positive entry with the same address because the <code>!</code> attribute conflicts.</p>
    <p class="lockout-note">The list is reapplied by the opnSentral OPNsense startup hook after boot or firmware upgrade. Removing a normal block does not add the address to this whitelist.</p>
</section>

<?php require __DIR__ . '/inc/footer.php'; ?>
