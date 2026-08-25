<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/plugin_features.php';
require_login();

$firewalls = db()
    ->query('SELECT id,name,base_url FROM firewalls ORDER BY name')
    ->fetchAll();

function dyndns_plugin_find(mixed $node): ?array
{
    if (!is_array($node)) return null;

    $name = trim((string) ($node['name'] ?? $node['pkg_name'] ?? $node['package'] ?? ''));
    if ($name === 'os-ddclient') {
        $status = strtolower(trim((string) ($node['status'] ?? '')));
        $current = trim((string) ($node['current'] ?? ''));
        $installed = array_key_exists('installed', $node)
            ? (bool) $node['installed']
            : ($status === 'installed' || $current !== '');

        return [
            'installed' => $installed,
            'version' => trim((string) ($node['version'] ?? $node['installed_version'] ?? $current)),
        ];
    }

    foreach ($node as $value) {
        $found = dyndns_plugin_find($value);
        if ($found !== null) return $found;
    }

    return null;
}

$cachedInstalledIds = plugin_feature_installed_firewall_ids('os-ddclient');
$requestedId = (int) ($_GET['firewall_id'] ?? 0);
$selectedId = $requestedId > 0
    ? $requestedId
    : ($cachedInstalledIds[0] ?? (int) ($firewalls[0]['id'] ?? 0));

$selectedFirewall = null;
foreach ($firewalls as $firewall) {
    if ((int) $firewall['id'] === $selectedId) {
        $selectedFirewall = firewall_by_id($selectedId);
        break;
    }
}

$error = '';
$plugin = null;
$accounts = [];
$serviceStatus = [];
$general = [];

if ($selectedFirewall !== null) {
    try {
        $firmware = opn_request($selectedFirewall, 'core/firmware/info', 'GET', [], 30);
        $plugin = dyndns_plugin_find($firmware);

        if ($plugin === null || ($plugin['installed'] ?? false) !== true) {
            throw new RuntimeException(
                'os-ddclient is not installed on ' . (string) $selectedFirewall['name'] . '.'
            );
        }

        $accountResponse = opn_request(
            $selectedFirewall,
            'dyndns/accounts/search_item',
            'POST',
            ['current' => 1, 'rowCount' => 500, 'searchPhrase' => ''],
            30
        );
        $accounts = is_array($accountResponse['rows'] ?? null)
            ? $accountResponse['rows']
            : [];

        $serviceStatus = opn_request($selectedFirewall, 'dyndns/service/status', 'GET', [], 20);
        $settings = opn_request($selectedFirewall, 'dyndns/settings/get', 'GET', [], 20);
        $general = is_array($settings['ddclient']['general'] ?? null)
            ? $settings['ddclient']['general']
            : [];
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>

<style>
.dyndns-toolbar{display:flex;gap:10px;align-items:end;justify-content:space-between;flex-wrap:wrap;margin-bottom:14px}
.dyndns-toolbar form{display:flex;gap:10px;align-items:end;flex-wrap:wrap}.dyndns-toolbar label{display:block;font-weight:700}.dyndns-toolbar select{min-width:240px;margin-top:5px}
.dyndns-summary{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}.dyndns-summary .card{padding:12px 15px;min-width:160px}.dyndns-summary strong{display:block;font-size:1.05rem}.dyndns-summary small{display:block;color:var(--muted);margin-top:3px}
.dyndns-table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}.dyndns-table{width:100%;border-collapse:collapse;min-width:980px}.dyndns-table th,.dyndns-table td{padding:10px 12px;border-bottom:1px solid var(--border);text-align:left;vertical-align:middle}.dyndns-table th{background:var(--table-head)}.dyndns-table tr:last-child td{border-bottom:0}.dyndns-hosts{max-width:310px;overflow-wrap:anywhere}.dyndns-muted{color:var(--muted)}
</style>

<div class="page-title">
    <div>
        <h1>Services → Dynamic DNS</h1>
        <p>Read-only Dynamic DNS status from the OPNsense <code>os-ddclient</code> plugin.</p>
    </div>
</div>

<div class="dyndns-toolbar">
    <form method="get">
        <div>
            <label for="firewall_id">Firewall</label>
            <select id="firewall_id" name="firewall_id" onchange="this.form.submit()">
                <?php foreach ($firewalls as $firewall): ?>
                    <option value="<?= (int) $firewall['id'] ?>" <?= (int) $firewall['id'] === $selectedId ? 'selected' : '' ?>>
                        <?= h((string) $firewall['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <button type="submit" class="button secondary">Refresh</button>
    </form>
</div>

<?php if ($error !== ''): ?>
    <div class="alert error"><?= h($error) ?></div>
<?php elseif ($selectedFirewall !== null): ?>
    <div class="alert goodbox">
        <strong>Dynamic DNS plugin detected.</strong>
        <code>os-ddclient<?= !empty($plugin['version']) ? ' ' . h((string) $plugin['version']) : '' ?></code>
        on <?= h((string) $selectedFirewall['name']) ?>.
    </div>

    <?php
    $enabled = in_array(strtolower(trim((string) ($general['enabled'] ?? ''))), ['1','true','yes','on'], true);
    $enabledAccounts = count(array_filter($accounts, static fn(array $row): bool => in_array(strtolower(trim((string) ($row['enabled'] ?? ''))), ['1','true','yes','on'], true)));
    $statusText = strtolower((string) json_encode($serviceStatus, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    $running = str_contains($statusText, 'running') || str_contains($statusText, 'ok');
    ?>

    <div class="dyndns-summary">
        <div class="card"><strong><?= $enabled ? 'Enabled' : 'Disabled' ?></strong><small>Global service</small></div>
        <div class="card"><strong><?= $running ? 'Running' : 'Status unknown' ?></strong><small>Service state</small></div>
        <div class="card"><strong><?= count($accounts) ?></strong><small>Configured accounts</small></div>
        <div class="card"><strong><?= $enabledAccounts ?></strong><small>Enabled accounts</small></div>
    </div>

    <div class="dyndns-table-wrap">
        <table class="dyndns-table">
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Description</th>
                    <th>Service</th>
                    <th>Hostname(s)</th>
                    <th>Current IP</th>
                    <th>Last update</th>
                    <th>Interface</th>
                </tr>
            </thead>
            <tbody>
            <?php if ($accounts === []): ?>
                <tr><td colspan="7" class="dyndns-muted">No Dynamic DNS accounts configured.</td></tr>
            <?php else: ?>
                <?php foreach ($accounts as $account): ?>
                    <?php $accountEnabled = in_array(strtolower(trim((string) ($account['enabled'] ?? ''))), ['1','true','yes','on'], true); ?>
                    <tr>
                        <td><span class="badge <?= $accountEnabled ? 'good' : 'neutral' ?>"><?= $accountEnabled ? 'Enabled' : 'Disabled' ?></span></td>
                        <td><?= h((string) (($account['description'] ?? '') ?: '—')) ?></td>
                        <td><?= h((string) (($account['service'] ?? '') ?: '—')) ?></td>
                        <td class="dyndns-hosts"><?= h((string) (($account['hostnames'] ?? '') ?: '—')) ?></td>
                        <td><code><?= h((string) (($account['current_ip'] ?? '') ?: '—')) ?></code></td>
                        <td><?= h((string) (($account['current_mtime'] ?? '') ?: '—')) ?></td>
                        <td><?= h((string) (($account['interface'] ?? '') ?: '—')) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>

<?php require __DIR__ . '/inc/footer.php'; ?>
