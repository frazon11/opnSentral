<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/plugin_features.php';
require_login();

$firewalls = db()
    ->query('SELECT id,name,base_url FROM firewalls ORDER BY name')
    ->fetchAll();
$installedIds = plugin_feature_installed_firewall_ids('os-acme-client');
$installedLookup = array_fill_keys($installedIds, true);
$columns = [];

function acme_scalar(mixed $value): string
{
    if ($value === null) return '';
    if (is_string($value) || is_int($value) || is_float($value)) return trim((string) $value);
    if (is_bool($value)) return $value ? '1' : '0';
    if (!is_array($value)) return '';

    foreach (['selected','value','name','id','uuid'] as $key) {
        if (array_key_exists($key, $value) && !is_array($value[$key]) && !is_object($value[$key])) {
            $text = trim((string) $value[$key]);
            if ($text !== '') return $text;
        }
    }

    foreach ($value as $key => $item) {
        if (!is_array($item)) continue;
        if (!acme_bool($item['selected'] ?? false)) continue;
        if (isset($item['value']) && !is_array($item['value']) && !is_object($item['value'])) {
            $text = trim((string) $item['value']);
            if ($text !== '') return $text;
        }
        if (is_string($key) && $key !== '') return $key;
    }

    foreach ($value as $item) {
        if (is_array($item) || is_object($item)) continue;
        $text = trim((string) $item);
        if ($text !== '') return $text;
    }

    return '';
}

function acme_bool(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    if (is_array($value)) $value = acme_scalar($value);
    return in_array(strtolower(trim((string) $value)), ['1','true','yes','on','enabled','selected'], true);
}

function acme_setting(array $column, string $key, string $fallback = '—'): string
{
    $value = acme_scalar($column['settings'][$key] ?? '');
    return $value !== '' ? $value : $fallback;
}

foreach ($firewalls as $firewallRow) {
    $id = (int) $firewallRow['id'];
    if (!isset($installedLookup[$id])) continue;

    $column = [
        'id' => $id,
        'name' => (string) $firewallRow['name'],
        'base_url' => rtrim((string) $firewallRow['base_url'], '/'),
        'ok' => false,
        'error' => null,
        'settings' => [],
        'certificates' => [],
    ];

    try {
        $firewall = firewall_by_id($id);
        $settingsResponse = opn_request($firewall, 'acmeclient/settings/get', 'GET', [], 25);
        $settings = is_array($settingsResponse['acmeclient']['settings'] ?? null)
            ? $settingsResponse['acmeclient']['settings']
            : [];
        if ($settings === []) {
            throw new RuntimeException('Unexpected ACME settings response.');
        }

        $certResponse = opn_request(
            $firewall,
            'acmeclient/certificates/search',
            'POST',
            ['current' => 1, 'rowCount' => 500, 'searchPhrase' => ''],
            25
        );

        $column['settings'] = $settings;
        $column['certificates'] = is_array($certResponse['rows'] ?? null) ? $certResponse['rows'] : [];
        $column['ok'] = true;
    } catch (Throwable $exception) {
        $column['error'] = $exception->getMessage();
    }

    $columns[] = $column;
}

require __DIR__ . '/inc/header.php';
?>

<style>
.acme-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.acme-matrix{border-collapse:separate;border-spacing:0;min-width:max(980px,100%);width:100%}
.acme-matrix th,.acme-matrix td{padding:10px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:top}
.acme-matrix th:last-child,.acme-matrix td:last-child{border-right:0}.acme-matrix tr:last-child td{border-bottom:0}
.acme-matrix thead th{position:sticky;top:0;z-index:3;background:var(--table-head);text-align:center;min-width:210px}
.acme-matrix .setting-col{position:sticky;left:0;z-index:2;background:var(--card);min-width:210px;font-weight:700}
.acme-matrix thead .setting-col{z-index:4;background:var(--table-head);text-align:left}
.acme-fw small{display:block;margin-top:3px;color:var(--muted);font-weight:400}.acme-cert{padding:7px 0;border-bottom:1px solid var(--border)}.acme-cert:last-child{border-bottom:0}.acme-cert small{display:block;color:var(--muted);margin-top:3px}.acme-error{color:#b3261e}
</style>

<div class="page-title">
    <div>
        <h1>Services → ACME Client</h1>
        <p>Fleet overview for OPNsense firewalls with <code>os-acme-client</code> installed.</p>
    </div>
</div>

<?php if ($columns === []): ?>
    <div class="alert warningbox"><strong>ACME Client is not installed on any managed firewall.</strong></div>
<?php else: ?>
<div class="acme-wrap">
<table class="acme-matrix">
    <thead>
        <tr>
            <th class="setting-col">Setting</th>
            <?php foreach ($columns as $column): ?>
                <th class="acme-fw">
                    <strong><?= h($column['name']) ?></strong>
                    <small><?= h($column['base_url']) ?></small>
                </th>
            <?php endforeach; ?>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td class="setting-col">Plugin</td>
            <?php foreach ($columns as $column): ?><td><span class="badge good">os-acme-client</span></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Status</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if ($column['ok']): ?>
                        <span class="badge <?= acme_bool($column['settings']['enabled'] ?? false) ? 'good' : 'neutral' ?>"><?= acme_bool($column['settings']['enabled'] ?? false) ? 'Enabled' : 'Disabled' ?></span>
                    <?php else: ?>
                        <span class="badge bad">Read failed</span><div class="acme-error"><?= h((string) $column['error']) ?></div>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Auto renewal</td>
            <?php foreach ($columns as $column): ?><td><?= $column['ok'] ? (acme_bool($column['settings']['autoRenewal'] ?? false) ? 'Enabled' : 'Disabled') : '—' ?></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Environment</td>
            <?php foreach ($columns as $column): ?><td><?= $column['ok'] ? h(acme_setting($column, 'environment')) : '—' ?></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">HTTP-01 challenge port</td>
            <?php foreach ($columns as $column): ?><td><?= $column['ok'] ? h(acme_setting($column, 'challengePort')) : '—' ?></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">TLS-ALPN challenge port</td>
            <?php foreach ($columns as $column): ?><td><?= $column['ok'] ? h(acme_setting($column, 'TLSchallengePort')) : '—' ?></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Restart timeout</td>
            <?php foreach ($columns as $column): ?><td><?= $column['ok'] ? h(acme_setting($column, 'restartTimeout')) . ' s' : '—' ?></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">HAProxy integration</td>
            <?php foreach ($columns as $column): ?><td><?= $column['ok'] ? (acme_bool($column['settings']['haproxyIntegration'] ?? false) ? 'Enabled' : 'Disabled') : '—' ?></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Certificates</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if (!$column['ok']): ?>—
                    <?php elseif ($column['certificates'] === []): ?><span class="muted">No certificates</span>
                    <?php else: ?>
                        <?php foreach ($column['certificates'] as $certificate): ?>
                            <?php
                                $certificateName = acme_scalar($certificate['name'] ?? '');
                                $certificateName = $certificateName !== '' ? $certificateName : 'Unnamed certificate';
                                $lastUpdate = acme_scalar($certificate['lastUpdate'] ?? '');
                            ?>
                            <div class="acme-cert">
                                <strong><?= h($certificateName) ?></strong>
                                <small><?= acme_bool($certificate['enabled'] ?? false) ? 'Enabled' : 'Disabled' ?><?= $lastUpdate !== '' ? ' · Last update: ' . h($lastUpdate) : '' ?></small>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Edit</td>
            <?php foreach ($columns as $column): ?>
                <td><a class="button secondary" href="<?= h($column['base_url'] . '/ui/acmeclient') ?>" target="_blank" rel="noopener noreferrer">Open ACME settings</a></td>
            <?php endforeach; ?>
        </tr>
    </tbody>
</table>
</div>
<?php endif; ?>

<?php require __DIR__ . '/inc/footer.php'; ?>
