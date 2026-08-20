<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();

function general_matrix_value(SimpleXMLElement $xml, string $path, string $default = '—'): string
{
    $nodes = $xml->xpath($path);
    if (!is_array($nodes) || !isset($nodes[0])) return $default;
    $value = trim((string) $nodes[0]);
    return $value === '' ? $default : $value;
}

function general_matrix_values(SimpleXMLElement $xml, string $path): array
{
    $nodes = $xml->xpath($path);
    if (!is_array($nodes)) return [];
    return array_values(array_filter(array_map(
        static fn(SimpleXMLElement $node): string => trim((string) $node),
        $nodes
    ), static fn(string $value): bool => $value !== ''));
}

function general_matrix_exists(SimpleXMLElement $xml, string $path): bool
{
    $nodes = $xml->xpath($path);
    return is_array($nodes) && isset($nodes[0]);
}

$settings = [
    'System' => [
        'hostname' => ['label' => 'Hostname', 'type' => 'text'],
        'domain' => ['label' => 'Domain', 'type' => 'text'],
        'timezone' => ['label' => 'Time zone', 'type' => 'text'],
        'language' => ['label' => 'Language', 'type' => 'text'],
        'theme' => ['label' => 'Theme', 'type' => 'text'],
    ],
    'Networking' => [
        'prefer_ipv4' => ['label' => 'Prefer IPv4 over IPv6', 'type' => 'boolean', 'help' => 'Prefer IPv4 when both IPv4 and IPv6 are available.'],
        'dns' => ['label' => 'DNS servers', 'type' => 'text'],
        'dnssearchdomain' => ['label' => 'DNS search domains', 'type' => 'text'],
        'dnsallowoverride' => ['label' => 'Allow DNS server list override by DHCP/PPP on WAN', 'type' => 'boolean'],
        'dnsallowoverride_exclude' => ['label' => 'DNS override excluded interfaces', 'type' => 'text'],
        'dnslocalhost' => ['label' => 'Do not use local DNS service as system nameserver', 'type' => 'boolean'],
        'gw_switch_default' => ['label' => 'Allow default gateway switching', 'type' => 'boolean'],
    ],
];

$requests = [];
foreach ($firewalls as $firewall) {
    $requests[(string) $firewall['id']] = [
        'firewall' => $firewall,
        'path' => 'core/backup/download/this',
        'timeout' => 60,
    ];
}
$downloads = opn_downloads_parallel($requests);
$matrix = [];

foreach ($firewalls as $firewall) {
    $fid = (int) $firewall['id'];
    $entry = ['firewall' => $firewall, 'ok' => false, 'error' => '', 'values' => []];
    $download = $downloads[(string) $fid] ?? $downloads[$fid] ?? ['ok' => false, 'error' => 'No response.'];
    if (($download['ok'] ?? false) !== true) {
        $entry['error'] = (string) ($download['error'] ?? 'Could not read configuration.');
        $matrix[$fid] = $entry;
        continue;
    }
    try {
        $xml = simplexml_load_string((string) ($download['value'] ?? ''), SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        if (!$xml instanceof SimpleXMLElement) throw new RuntimeException('Could not parse configuration XML.');

        $dnsServers = general_matrix_values($xml, '/opnsense/system/dnsserver');
        $dnsDisplay = [];
        foreach ($dnsServers as $index => $server) {
            $gateway = general_matrix_value($xml, '/opnsense/system/dns' . ($index + 1) . 'gw', 'none');
            $dnsDisplay[] = strtolower($gateway) !== 'none' ? $server . ' via ' . $gateway : $server;
        }

        $entry['values'] = [
            'hostname' => general_matrix_value($xml, '/opnsense/system/hostname'),
            'domain' => general_matrix_value($xml, '/opnsense/system/domain'),
            'timezone' => general_matrix_value($xml, '/opnsense/system/timezone', 'Etc/UTC'),
            'language' => general_matrix_value($xml, '/opnsense/system/language', 'Default'),
            'theme' => general_matrix_value($xml, '/opnsense/theme', 'Default'),
            'prefer_ipv4' => general_matrix_exists($xml, '/opnsense/system/prefer_ipv4'),
            'dns' => $dnsDisplay !== [] ? implode(', ', $dnsDisplay) : 'None configured',
            'dnssearchdomain' => general_matrix_value($xml, '/opnsense/system/dnssearchdomain', 'None configured'),
            'dnsallowoverride' => general_matrix_value($xml, '/opnsense/system/dnsallowoverride', '0') === '1',
            'dnsallowoverride_exclude' => general_matrix_value($xml, '/opnsense/system/dnsallowoverride_exclude', 'None'),
            'dnslocalhost' => general_matrix_exists($xml, '/opnsense/system/dnslocalhost'),
            'gw_switch_default' => general_matrix_exists($xml, '/opnsense/system/gw_switch_default'),
        ];
        $entry['ok'] = true;
    } catch (Throwable $exception) {
        $entry['error'] = $exception->getMessage();
    }
    $matrix[$fid] = $entry;
}

require __DIR__ . '/inc/header.php';
?>
<style>
.fleet-settings-toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:12px}
.fleet-settings-table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.fleet-settings-table{border-collapse:separate;border-spacing:0;min-width:max(980px,100%);width:100%}
.fleet-settings-table th,.fleet-settings-table td{padding:10px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:middle;text-align:center}
.fleet-settings-table th:last-child,.fleet-settings-table td:last-child{border-right:0}.fleet-settings-table tr:last-child td{border-bottom:0}
.fleet-settings-table thead th{position:sticky;top:0;z-index:3;background:var(--table-head)}
.fleet-settings-table .setting-col{position:sticky;left:0;z-index:2;text-align:left;min-width:300px;background:var(--card)}
.fleet-settings-table thead .setting-col{z-index:4;background:var(--table-head)}
.fleet-settings-table .firewall-col{min-width:170px}.fleet-settings-table .firewall-col a{display:block;font-weight:700}.fleet-settings-table .firewall-col small{display:block;margin-top:3px;color:var(--muted);font-weight:400}
.fleet-settings-section td{background:var(--table-head);font-weight:800;text-align:left!important;padding:9px 12px!important}
.fleet-setting strong{display:block}.fleet-setting small{display:block;margin-top:4px;color:var(--muted);font-weight:400;line-height:1.3}
.fleet-value{white-space:normal;overflow-wrap:anywhere}.fleet-value .badge{white-space:nowrap}
</style>

<div class="page-title">
    <div><h1>System → Settings → General</h1><p>Compare general settings across all managed OPNsense firewalls.</p></div>
</div>

<div class="fleet-settings-toolbar">
    <div><strong><?= count($firewalls) ?> managed firewall<?= count($firewalls) === 1 ? '' : 's' ?></strong><span class="muted"> · Fleet overview, same structure as Administration.</span></div>
    <button type="button" class="button secondary" onclick="window.location.reload()">Refresh</button>
</div>

<div class="fleet-settings-table-wrap">
<table class="fleet-settings-table">
<thead><tr><th class="setting-col">Setting</th><?php foreach ($matrix as $fid => $entry): ?><th class="firewall-col"><a href="/firewall_view.php?id=<?= $fid ?>"><?= h((string) $entry['firewall']['name']) ?></a><?php if ($entry['ok']): ?><small><span class="badge good">Read OK</span></small><?php else: ?><small><span class="badge bad">Read failed</span></small><?php endif; ?></th><?php endforeach; ?></tr></thead>
<tbody>
<?php foreach ($settings as $section => $definitions): ?>
<tr class="fleet-settings-section"><td colspan="<?= count($matrix) + 1 ?>"><?= h($section) ?></td></tr>
<?php foreach ($definitions as $key => $definition): ?>
<tr><td class="setting-col fleet-setting"><strong><?= h((string) $definition['label']) ?></strong><?php if (($definition['help'] ?? '') !== ''): ?><small><?= h((string) $definition['help']) ?></small><?php endif; ?></td>
<?php foreach ($matrix as $entry): ?><td class="fleet-value"><?php if (!$entry['ok']): ?><span class="badge bad" title="<?= h((string) $entry['error']) ?>">Unavailable</span><?php elseif (($definition['type'] ?? '') === 'boolean'): ?><?php $enabled = (bool) ($entry['values'][$key] ?? false); ?><span class="badge <?= $enabled ? 'good' : 'neutral' ?>"><?= $enabled ? 'Enabled' : 'Disabled' ?></span><?php else: ?><?= h((string) ($entry['values'][$key] ?? '—')) ?><?php endif; ?></td><?php endforeach; ?></tr>
<?php endforeach; endforeach; ?>
</tbody></table></div>

<?php require __DIR__ . '/inc/footer.php'; ?>
