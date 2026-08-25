<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

function dyndns_truthy_scalar(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    if (!is_string($value)) return false;
    return in_array(strtolower(trim($value)), ['1','true','yes','on','installed','running','selected'], true);
}

function dyndns_value(mixed $value, mixed $default = ''): mixed
{
    if (!is_array($value)) return $value;

    if (array_key_exists('selected', $value) && dyndns_truthy_scalar($value['selected'])) {
        $selectedValue = $value['value'] ?? $default;
        return is_array($selectedValue) ? $default : $selectedValue;
    }

    foreach ($value as $key => $option) {
        if (!is_array($option) || !dyndns_truthy_scalar($option['selected'] ?? false)) continue;
        return is_string($key) || is_int($key) ? (string) $key : $default;
    }

    if (array_key_exists('value', $value) && !is_array($value['value'])) {
        return $value['value'];
    }

    if (count($value) === 1) {
        $only = reset($value);
        if (!is_array($only)) return $only;
        if (array_key_exists('value', $only) && !is_array($only['value'])) return $only['value'];
    }

    return $default;
}

function dyndns_text(mixed $value, string $default = ''): string
{
    $value = dyndns_value($value, $default);
    if (is_bool($value)) return $value ? '1' : '0';
    if (!is_scalar($value) && $value !== null) return $default;
    $text = trim((string) $value);
    return $text === '' ? $default : $text;
}

function dyndns_bool(mixed $value): bool
{
    $value = dyndns_value($value, false);
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    if (!is_string($value)) return false;
    return in_array(strtolower(trim($value)), ['1','true','yes','on','installed','running'], true);
}

function dyndns_plugin_find(mixed $node): ?array
{
    if (!is_array($node)) return null;
    $name = dyndns_text($node['name'] ?? $node['pkg_name'] ?? $node['package'] ?? '');
    if ($name === 'os-ddclient') {
        $status = strtolower(dyndns_text($node['status'] ?? ''));
        $current = dyndns_text($node['current'] ?? '');
        return [
            'installed' => array_key_exists('installed', $node)
                ? dyndns_bool($node['installed'])
                : ($status === 'installed' || $current !== ''),
            'version' => dyndns_text($node['version'] ?? $node['installed_version'] ?? $current),
        ];
    }
    foreach ($node as $value) {
        $found = dyndns_plugin_find($value);
        if ($found !== null) return $found;
    }
    return null;
}

$firewalls = db()->query(
    'SELECT id,name,base_url,api_key_enc,api_secret_enc,verify_tls FROM firewalls ORDER BY name'
)->fetchAll();

$firmwareRequests = [];
foreach ($firewalls as $firewall) {
    $firmwareRequests['fw-' . (int) $firewall['id']] = [
        'firewall' => $firewall,
        'path' => 'core/firmware/info',
        'timeout' => 30,
    ];
}
$firmwareResponses = $firmwareRequests ? opn_requests_parallel($firmwareRequests) : [];

$states = [];
$dataRequests = [];
foreach ($firewalls as $firewall) {
    $id = (int) $firewall['id'];
    $firmwareResult = $firmwareResponses['fw-' . $id] ?? ['ok'=>false,'error'=>'No firmware result'];
    $plugin = ($firmwareResult['ok'] ?? false) === true
        ? dyndns_plugin_find($firmwareResult['value'] ?? [])
        : null;
    $installed = $plugin !== null && ($plugin['installed'] ?? false) === true;

    $states[$id] = [
        'firewall' => $firewall,
        'plugin' => $plugin,
        'installed' => $installed,
        'error' => ($firmwareResult['ok'] ?? false) === true ? '' : dyndns_text($firmwareResult['error'] ?? 'Firmware inventory failed.', 'Firmware inventory failed.'),
        'general' => [],
        'accounts' => [],
        'service' => [],
    ];

    if (!$installed) continue;
    $dataRequests['settings-' . $id] = ['firewall'=>$firewall,'path'=>'dyndns/settings/get','timeout'=>25];
    $dataRequests['accounts-' . $id] = [
        'firewall'=>$firewall,
        'path'=>'dyndns/accounts/search_item',
        'method'=>'POST',
        'payload'=>['current'=>1,'rowCount'=>500,'searchPhrase'=>''],
        'timeout'=>30,
    ];
    $dataRequests['service-' . $id] = ['firewall'=>$firewall,'path'=>'dyndns/service/status','timeout'=>20];
}

$dataResponses = $dataRequests ? opn_requests_parallel($dataRequests) : [];
foreach ($states as $id => &$state) {
    if (!$state['installed']) continue;

    $settingsResult = $dataResponses['settings-' . $id] ?? ['ok'=>false,'error'=>'No settings result'];
    $accountsResult = $dataResponses['accounts-' . $id] ?? ['ok'=>false,'error'=>'No accounts result'];
    $serviceResult = $dataResponses['service-' . $id] ?? ['ok'=>false,'error'=>'No service result'];

    if (($settingsResult['ok'] ?? false) === true) {
        $settings = $settingsResult['value'] ?? [];
        $state['general'] = is_array($settings['ddclient']['general'] ?? null) ? $settings['ddclient']['general'] : [];
    } else {
        $state['error'] = dyndns_text($settingsResult['error'] ?? 'Could not read Dynamic DNS settings.', 'Could not read Dynamic DNS settings.');
    }

    if (($accountsResult['ok'] ?? false) === true) {
        $accountData = $accountsResult['value'] ?? [];
        $state['accounts'] = is_array($accountData['rows'] ?? null) ? $accountData['rows'] : [];
    } elseif ($state['error'] === '') {
        $state['error'] = dyndns_text($accountsResult['error'] ?? 'Could not read Dynamic DNS accounts.', 'Could not read Dynamic DNS accounts.');
    }

    if (($serviceResult['ok'] ?? false) === true) {
        $state['service'] = is_array($serviceResult['value'] ?? null) ? $serviceResult['value'] : [];
    }
}
unset($state);

require __DIR__ . '/inc/header.php';
?>
<style>
.dyndns-matrix-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.dyndns-matrix{border-collapse:separate;border-spacing:0;min-width:max(1100px,100%);width:100%}
.dyndns-matrix th,.dyndns-matrix td{padding:10px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:top;text-align:left}
.dyndns-matrix th:last-child,.dyndns-matrix td:last-child{border-right:0}.dyndns-matrix tr:last-child td{border-bottom:0}
.dyndns-matrix thead th{position:sticky;top:0;z-index:3;background:var(--table-head);text-align:center;min-width:230px}
.dyndns-matrix .setting-col{position:sticky;left:0;z-index:2;background:var(--card);min-width:190px;font-weight:700}
.dyndns-matrix thead .setting-col{z-index:4;background:var(--table-head)}
.dyndns-fw-head strong,.dyndns-fw-head small{display:block}.dyndns-fw-head small{margin-top:3px;color:var(--muted);font-weight:400}
.dyndns-account{padding:9px 10px;margin:0 0 8px;border-radius:7px;background:rgba(127,127,127,.08)}.dyndns-account:last-child{margin-bottom:0}
.dyndns-account-head{display:flex;justify-content:space-between;gap:8px;align-items:center}.dyndns-account small{display:block;color:var(--muted);margin-top:4px;overflow-wrap:anywhere}
.dyndns-actions{margin-top:8px}.dyndns-actions .button{padding:5px 9px;font-size:.82rem}
.dyndns-na{color:var(--muted)}
</style>
<div class="page-title">
    <div>
        <h1>Services → DynDNS</h1>
        <p>Dynamic DNS settings across all managed OPNsense firewalls.</p>
    </div>
</div>

<div class="dyndns-matrix-wrap">
<table class="dyndns-matrix">
<thead><tr><th class="setting-col">Setting</th>
<?php foreach ($states as $state): $fw=$state['firewall']; ?>
<th class="dyndns-fw-head"><strong><?= h((string)$fw['name']) ?></strong><small><?= h((string)$fw['base_url']) ?></small></th>
<?php endforeach; ?>
</tr></thead>
<tbody>
<tr><td class="setting-col">Plugin</td><?php foreach($states as $state): ?><td><?php if($state['installed']): ?><span class="badge good">os-ddclient <?= h(dyndns_text($state['plugin']['version']??'')) ?></span><?php else: ?><span class="badge neutral">Not installed</span><?php endif; ?></td><?php endforeach; ?></tr>
<tr><td class="setting-col">Global service</td><?php foreach($states as $state): ?><td><?php if(!$state['installed']): ?><span class="dyndns-na">—</span><?php elseif($state['error']!==''): ?><span class="badge bad">Read failed</span><small><?= h($state['error']) ?></small><?php else: $enabled=dyndns_bool($state['general']['enabled']??false); ?><span class="badge <?= $enabled?'good':'neutral' ?>"><?= $enabled?'Enabled':'Disabled' ?></span><div class="dyndns-actions"><a class="button secondary" href="/dyndns_edit.php?firewall_id=<?= (int)$state['firewall']['id'] ?>&mode=general">Edit settings</a></div><?php endif; ?></td><?php endforeach; ?></tr>
<tr><td class="setting-col">Backend</td><?php foreach($states as $state): ?><td><?= $state['installed']&&$state['error']==='' ? h(dyndns_text($state['general']['backend']??'—','—')) : '<span class="dyndns-na">—</span>' ?></td><?php endforeach; ?></tr>
<tr><td class="setting-col">Daemon delay</td><?php foreach($states as $state): ?><td><?= $state['installed']&&$state['error']==='' ? h(dyndns_text($state['general']['daemon_delay']??'—','—')).' s' : '<span class="dyndns-na">—</span>' ?></td><?php endforeach; ?></tr>
<tr><td class="setting-col">Verbose</td><?php foreach($states as $state): ?><td><?= $state['installed']&&$state['error']==='' ? (dyndns_bool($state['general']['verbose']??false)?'Yes':'No') : '<span class="dyndns-na">—</span>' ?></td><?php endforeach; ?></tr>
<tr><td class="setting-col">IPv6 allowed</td><?php foreach($states as $state): ?><td><?= $state['installed']&&$state['error']==='' ? (dyndns_bool($state['general']['allowipv6']??false)?'Yes':'No') : '<span class="dyndns-na">—</span>' ?></td><?php endforeach; ?></tr>
<tr><td class="setting-col">Service state</td><?php foreach($states as $state): ?><td><?php if($state['installed']&&$state['error']===''): $status=strtolower((string)json_encode($state['service'])); ?><span class="badge <?= str_contains($status,'running')?'good':'neutral' ?>"><?= str_contains($status,'running')?'Running':'Unknown / stopped' ?></span><?php else: ?><span class="dyndns-na">—</span><?php endif; ?></td><?php endforeach; ?></tr>
<tr><td class="setting-col">Accounts</td><?php foreach($states as $state): ?><td><?php if(!$state['installed']||$state['error']!==''): ?><span class="dyndns-na">—</span><?php elseif($state['accounts']===[]): ?><span class="dyndns-na">No accounts configured</span><?php else: ?><?php foreach($state['accounts'] as $account): $uuid=dyndns_text($account['uuid']??$account['id']??''); $on=dyndns_bool($account['enabled']??false); $description=dyndns_text($account['description']??''); $hostnames=dyndns_text($account['hostnames']??'DynDNS account','DynDNS account'); ?><div class="dyndns-account"><div class="dyndns-account-head"><strong><?= h($description!==''?$description:$hostnames) ?></strong><span class="badge <?= $on?'good':'neutral' ?>"><?= $on?'Enabled':'Disabled' ?></span></div><small><?= h(dyndns_text($account['service']??'—','—')) ?> · <?= h(dyndns_text($account['hostnames']??'—','—')) ?></small><small>IP: <?= h(dyndns_text($account['current_ip']??'—','—')) ?> · Interface: <?= h(dyndns_text($account['interface']??'—','—')) ?></small><?php if($uuid!==''): ?><div class="dyndns-actions"><a class="button secondary" href="/dyndns_edit.php?firewall_id=<?= (int)$state['firewall']['id'] ?>&mode=account&uuid=<?= rawurlencode($uuid) ?>">Edit</a></div><?php endif; ?></div><?php endforeach; ?><?php endif; ?></td><?php endforeach; ?></tr>
</tbody>
</table>
</div>
<?php require __DIR__ . '/inc/footer.php'; ?>
