<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();

function advanced_matrix_value(SimpleXMLElement $xml, string $path, string $default = '—'): string
{
    $nodes = $xml->xpath($path);
    if (!is_array($nodes) || !isset($nodes[0])) return $default;
    $value = trim((string) $nodes[0]);
    return $value === '' ? $default : $value;
}

function advanced_matrix_exists(SimpleXMLElement $xml, string $path): bool
{
    $nodes = $xml->xpath($path);
    return is_array($nodes) && isset($nodes[0]);
}

$settings = [
    'Network Address Translation' => [
        'natreflection' => ['label' => 'Reflection for destination NAT', 'type' => 'boolean'],
        'binatreflection' => ['label' => 'Reflection for 1:1', 'type' => 'boolean'],
        'natreflectionhelper' => ['label' => 'Automatic outbound NAT for Reflection', 'type' => 'boolean'],
    ],
    'Bogon Networks' => [
        'bogons_interval' => ['label' => 'Update Frequency', 'type' => 'text'],
    ],
    'Gateway Monitoring' => [
        'skip_rules_gw_down' => ['label' => 'Skip rules', 'type' => 'boolean', 'help' => 'Skip rules when gateway is down.'],
    ],
    'Multi-WAN' => [
        'lb_use_sticky' => ['label' => 'Sticky connections', 'type' => 'boolean'],
        'srctrack' => ['label' => 'Source tracking timeout', 'type' => 'text'],
        'pf_share_forward' => ['label' => 'Shared forwarding', 'type' => 'boolean'],
        'pf_disable_force_gw' => ['label' => 'Disable force gateway', 'type' => 'boolean'],
    ],
    'Schedules' => [
        'schedule_states' => ['label' => 'Schedule States', 'type' => 'boolean'],
    ],
    'Logging' => [
        'log_default_block' => ['label' => 'Default block', 'type' => 'boolean'],
        'log_default_pass' => ['label' => 'Default pass', 'type' => 'boolean'],
        'logoutboundnat' => ['label' => 'Outbound NAT', 'type' => 'boolean'],
        'log_bogons' => ['label' => 'Bogon networks', 'type' => 'boolean'],
        'log_privatenets' => ['label' => 'Private networks', 'type' => 'boolean'],
    ],
    'Miscellaneous' => [
        'keepcounters' => ['label' => 'Keep counters', 'type' => 'boolean'],
        'pfdebug' => ['label' => 'Debug', 'type' => 'text'],
        'optimization' => ['label' => 'Firewall Optimization', 'type' => 'text'],
        'state_policy' => ['label' => 'Bind states to interface', 'type' => 'boolean'],
        'disablefilter' => ['label' => 'Disable Firewall', 'type' => 'boolean'],
        'adaptivestart' => ['label' => 'Firewall Adaptive Timeouts — start', 'type' => 'text'],
        'adaptiveend' => ['label' => 'Firewall Adaptive Timeouts — end', 'type' => 'text'],
        'maximumstates' => ['label' => 'Firewall Maximum States', 'type' => 'text'],
        'maximumfrags' => ['label' => 'Firewall Maximum Fragments', 'type' => 'text'],
        'maximumtableentries' => ['label' => 'Firewall Maximum Table Entries', 'type' => 'text'],
        'bypassstaticroutes' => ['label' => 'Static route filtering', 'type' => 'boolean'],
        'disablereplyto' => ['label' => 'Disable reply-to', 'type' => 'boolean'],
        'noantilockout' => ['label' => 'Disable anti-lockout', 'type' => 'boolean'],
        'no_ipv6_rfc4890_req' => ['label' => 'Disable RFC4890 requirement rules', 'type' => 'boolean'],
        'no_port0_block' => ['label' => 'Disable port 0 block', 'type' => 'boolean'],
        'no_sshlockout' => ['label' => 'Disable sshlockout', 'type' => 'boolean'],
        'no_virusprot' => ['label' => 'Disable rate limit rule', 'type' => 'boolean'],
        'aliasesresolveinterval' => ['label' => 'Aliases Resolve Interval', 'type' => 'text'],
        'checkaliasesurlcert' => ['label' => 'Check certificate of aliases URLs', 'type' => 'boolean'],
    ],
    'Anti DDOS' => [
        'syncookies' => ['label' => 'Enable syncookies', 'type' => 'text'],
        'syncookies_adaptstart' => ['label' => 'Syncookie Adaptive Start', 'type' => 'text'],
        'syncookies_adaptend' => ['label' => 'Syncookie Adaptive End', 'type' => 'text'],
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
        $entry['values'] = [
            'natreflection' => !advanced_matrix_exists($xml, '/opnsense/system/disablenatreflection'),
            'binatreflection' => advanced_matrix_exists($xml, '/opnsense/system/enablebinatreflection'),
            'natreflectionhelper' => advanced_matrix_exists($xml, '/opnsense/system/enablenatreflectionhelper'),
            'bogons_interval' => ucfirst(advanced_matrix_value($xml, '/opnsense/system/bogons/interval', 'monthly')),
            'skip_rules_gw_down' => advanced_matrix_exists($xml, '/opnsense/system/skip_rules_gw_down'),
            'lb_use_sticky' => advanced_matrix_exists($xml, '/opnsense/system/lb_use_sticky'),
            'srctrack' => advanced_matrix_value($xml, '/opnsense/system/srctrack', '0'),
            'pf_share_forward' => advanced_matrix_exists($xml, '/opnsense/system/pf_share_forward'),
            'pf_disable_force_gw' => advanced_matrix_exists($xml, '/opnsense/system/pf_disable_force_gw'),
            'schedule_states' => advanced_matrix_exists($xml, '/opnsense/system/schedule_states'),
            'log_default_block' => !advanced_matrix_exists($xml, '/opnsense/syslog/nologdefaultblock'),
            'log_default_pass' => !advanced_matrix_exists($xml, '/opnsense/syslog/nologdefaultpass'),
            'logoutboundnat' => advanced_matrix_exists($xml, '/opnsense/syslog/logoutboundnat'),
            'log_bogons' => !advanced_matrix_exists($xml, '/opnsense/syslog/nologbogons'),
            'log_privatenets' => !advanced_matrix_exists($xml, '/opnsense/syslog/nologprivatenets'),
            'keepcounters' => advanced_matrix_exists($xml, '/opnsense/system/keepcounters'),
            'pfdebug' => advanced_matrix_value($xml, '/opnsense/system/pfdebug', 'urgent'),
            'optimization' => advanced_matrix_value($xml, '/opnsense/system/optimization', 'normal'),
            'state_policy' => advanced_matrix_exists($xml, '/opnsense/system/state-policy'),
            'disablefilter' => advanced_matrix_exists($xml, '/opnsense/system/disablefilter'),
            'adaptivestart' => advanced_matrix_value($xml, '/opnsense/system/adaptivestart', 'Default'),
            'adaptiveend' => advanced_matrix_value($xml, '/opnsense/system/adaptiveend', 'Default'),
            'maximumstates' => advanced_matrix_value($xml, '/opnsense/system/maximumstates', 'Default'),
            'maximumfrags' => advanced_matrix_value($xml, '/opnsense/system/maximumfrags', 'Default'),
            'maximumtableentries' => advanced_matrix_value($xml, '/opnsense/system/maximumtableentries', 'Default'),
            'bypassstaticroutes' => advanced_matrix_exists($xml, '/opnsense/filter/bypassstaticroutes'),
            'disablereplyto' => advanced_matrix_exists($xml, '/opnsense/system/disablereplyto'),
            'noantilockout' => advanced_matrix_exists($xml, '/opnsense/system/webgui/noantilockout'),
            'no_ipv6_rfc4890_req' => advanced_matrix_exists($xml, '/opnsense/system/no_ipv6_rfc4890_req'),
            'no_port0_block' => advanced_matrix_exists($xml, '/opnsense/system/no_port0_block'),
            'no_sshlockout' => advanced_matrix_exists($xml, '/opnsense/system/no_sshlockout'),
            'no_virusprot' => advanced_matrix_exists($xml, '/opnsense/system/no_virusprot'),
            'aliasesresolveinterval' => advanced_matrix_value($xml, '/opnsense/system/aliasesresolveinterval', '300'),
            'checkaliasesurlcert' => advanced_matrix_exists($xml, '/opnsense/system/checkaliasesurlcert'),
            'syncookies' => advanced_matrix_value($xml, '/opnsense/system/syncookies', 'never (default)'),
            'syncookies_adaptstart' => advanced_matrix_value($xml, '/opnsense/system/syncookies_adaptstart', 'Default'),
            'syncookies_adaptend' => advanced_matrix_value($xml, '/opnsense/system/syncookies_adaptend', 'Default'),
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
    <div><h1>Firewall → Settings → Advanced</h1><p>Compare advanced firewall settings across all managed OPNsense firewalls.</p></div>
</div>

<div class="fleet-settings-toolbar">
    <div><strong><?= count($firewalls) ?> managed firewall<?= count($firewalls) === 1 ? '' : 's' ?></strong><span class="muted"> · Fleet overview, same structure as Administration.</span></div>
    <button type="button" class="button secondary" onclick="window.location.reload()">Refresh</button>
</div>

<div class="fleet-settings-table-wrap"><table class="fleet-settings-table">
<thead><tr><th class="setting-col">Setting</th><?php foreach ($matrix as $fid => $entry): ?><th class="firewall-col"><a href="/firewall_view.php?id=<?= $fid ?>"><?= h((string) $entry['firewall']['name']) ?></a><?php if ($entry['ok']): ?><small><span class="badge good">Read OK</span></small><?php else: ?><small><span class="badge bad">Read failed</span></small><?php endif; ?></th><?php endforeach; ?></tr></thead>
<tbody>
<?php foreach ($settings as $section => $definitions): ?><tr class="fleet-settings-section"><td colspan="<?= count($matrix) + 1 ?>"><?= h($section) ?></td></tr>
<?php foreach ($definitions as $key => $definition): ?><tr><td class="setting-col fleet-setting"><strong><?= h((string) $definition['label']) ?></strong><?php if (($definition['help'] ?? '') !== ''): ?><small><?= h((string) $definition['help']) ?></small><?php endif; ?></td>
<?php foreach ($matrix as $entry): ?><td class="fleet-value"><?php if (!$entry['ok']): ?><span class="badge bad" title="<?= h((string) $entry['error']) ?>">Unavailable</span><?php elseif (($definition['type'] ?? '') === 'boolean'): ?><?php $enabled = (bool) ($entry['values'][$key] ?? false); ?><span class="badge <?= $enabled ? 'good' : 'neutral' ?>"><?= $enabled ? 'Enabled' : 'Disabled' ?></span><?php else: ?><?= h((string) ($entry['values'][$key] ?? '—')) ?><?php endif; ?></td><?php endforeach; ?></tr>
<?php endforeach; endforeach; ?>
</tbody></table></div>

<?php require __DIR__ . '/inc/footer.php'; ?>
