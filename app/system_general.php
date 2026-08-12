<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';

require_login();

$firewalls = db()->query(
    'SELECT id,name,base_url FROM firewalls ORDER BY name'
)->fetchAll();

$id = (int) ($_GET['firewall_id'] ?? 0);
$firewall = $id > 0 ? firewall_by_id($id) : null;
$error = '';
$sections = [];

function general_value(
    SimpleXMLElement $xml,
    string $path,
    string $default = ''
): string {
    $nodes = $xml->xpath($path);
    if (!is_array($nodes) || !isset($nodes[0])) {
        return $default;
    }

    $value = trim((string) $nodes[0]);
    return $value === '' ? $default : $value;
}

function general_values(SimpleXMLElement $xml, string $path): array
{
    $nodes = $xml->xpath($path);
    if (!is_array($nodes)) {
        return [];
    }

    return array_values(array_filter(array_map(
        static fn(SimpleXMLElement $node): string => trim((string) $node),
        $nodes
    ), static fn(string $value): bool => $value !== ''));
}

function general_exists(SimpleXMLElement $xml, string $path): bool
{
    $nodes = $xml->xpath($path);
    return is_array($nodes) && isset($nodes[0]);
}

function general_bool(bool $value): string
{
    return $value ? 'Enabled' : 'Disabled';
}

function general_field(
    string $label,
    string $value,
    string $type = 'text',
    string $help = ''
): array {
    return compact('label', 'value', 'type', 'help');
}

if ($firewall !== null) {
    try {
        $rawXml = opn_download(
            $firewall,
            'core/backup/download/this'
        );

        libxml_use_internal_errors(true);
        $xml = simplexml_load_string(
            $rawXml,
            SimpleXMLElement::class,
            LIBXML_NONET | LIBXML_NOCDATA
        );

        if (!$xml instanceof SimpleXMLElement) {
            throw new RuntimeException('Could not parse the OPNsense configuration.');
        }

        $dnsServers = general_values($xml, '/opnsense/system/dnsserver');
        $dnsDisplay = [];
        foreach ($dnsServers as $index => $server) {
            $gateway = general_value(
                $xml,
                '/opnsense/system/dns' . ($index + 1) . 'gw',
                'none'
            );
            $dnsDisplay[] = $gateway !== '' && strtolower($gateway) !== 'none'
                ? $server . ' via ' . $gateway
                : $server;
        }

        $sections = [
            'System' => [
                general_field(
                    'Hostname',
                    general_value($xml, '/opnsense/system/hostname', '—')
                ),
                general_field(
                    'Domain',
                    general_value($xml, '/opnsense/system/domain', '—')
                ),
                general_field(
                    'Time zone',
                    general_value($xml, '/opnsense/system/timezone', 'Etc/UTC')
                ),
                general_field(
                    'Language',
                    general_value($xml, '/opnsense/system/language', 'Default')
                ),
                general_field(
                    'Theme',
                    general_value($xml, '/opnsense/theme', 'Default')
                ),
            ],
            'Networking' => [
                general_field(
                    'Prefer IPv4 over IPv6',
                    general_bool(general_exists($xml, '/opnsense/system/prefer_ipv4')),
                    'boolean',
                    'Prefer IPv4 when both IPv4 and IPv6 are available.'
                ),
                general_field(
                    'DNS servers',
                    $dnsDisplay !== [] ? implode("\n", $dnsDisplay) : 'None configured',
                    'multiline'
                ),
                general_field(
                    'DNS search domains',
                    general_value($xml, '/opnsense/system/dnssearchdomain', 'None configured')
                ),
                general_field(
                    'Allow DNS server list override by DHCP/PPP on WAN',
                    general_bool(
                        general_value($xml, '/opnsense/system/dnsallowoverride', '0') === '1'
                    ),
                    'boolean'
                ),
                general_field(
                    'DNS override excluded interfaces',
                    general_value(
                        $xml,
                        '/opnsense/system/dnsallowoverride_exclude',
                        'None'
                    )
                ),
                general_field(
                    'Do not use local DNS service as system nameserver',
                    general_bool(general_exists($xml, '/opnsense/system/dnslocalhost')),
                    'boolean'
                ),
                general_field(
                    'Allow default gateway switching',
                    general_bool(general_exists($xml, '/opnsense/system/gw_switch_default')),
                    'boolean'
                ),
            ],
        ];
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>

<style>
.settings-page-grid{display:grid;grid-template-columns:240px minmax(0,1fr);gap:14px}
.settings-tree{padding:0;overflow:hidden}
.settings-tree-title{padding:14px 16px;background:#10131a;color:#fff;font-weight:800}
.settings-tree a,.settings-tree span{display:block;padding:10px 16px;text-decoration:none}
.settings-tree .tree-group{font-weight:800;background:var(--table-head)}
.settings-tree .tree-child{padding-left:30px}
.settings-tree .tree-subgroup{padding-left:30px;font-weight:750;color:var(--muted)}
.settings-tree .tree-grandchild{padding-left:46px}
.settings-tree a.active{background:#3b4851;color:#fff}
.opn-general-shell{border:1px solid #2e3238;border-radius:6px;overflow:hidden;background:#0d1016;color:#f3f3f3}
.opn-general-title{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:60px;padding:0 17px;background:#10131a;border-bottom:1px solid #b6bbc3}
.opn-general-title h2{margin:0;color:#fff}
.opn-general-toolbar{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#3c3c3b}
.opn-general-toolbar label{margin:0}
.opn-general-toolbar select{width:min(420px,100%);margin:0}
.opn-general-section{border-bottom:1px solid #333740}
.opn-general-section>summary{display:flex;align-items:center;gap:10px;min-height:54px;padding:0 15px;background:#10131a;color:#fff;font-weight:750;cursor:pointer;list-style:none}
.opn-general-section>summary::-webkit-details-marker{display:none}
.opn-general-section>summary::before{content:"›";font-size:1.4rem}
.opn-general-section[open]>summary::before{transform:rotate(90deg)}
.opn-general-row{display:grid;grid-template-columns:minmax(280px,31%) minmax(0,1fr);min-height:56px}
.opn-general-row:nth-child(odd){background:#3e3e3d}
.opn-general-row:nth-child(even){background:#0f1218}
.opn-general-label{display:flex;align-items:center;gap:7px;padding:10px 15px;font-weight:700}
.opn-general-info{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;flex:0 0 auto;border-radius:50%;background:#d6532f;color:#17191d;font-family:Georgia,serif;font-weight:900}
.opn-general-value{display:flex;align-items:center;padding:8px 18px}
.opn-general-control{display:flex;align-items:center;gap:9px;width:min(650px,100%);min-height:40px;padding:7px 13px;border:1px solid #c5c9cf;border-radius:4px;background:#1b1f2a;color:#e9eaed;white-space:pre-line}
.opn-general-checkbox{width:18px;height:18px;flex:0 0 auto;border:1px solid #bfc3c9;border-radius:2px;background:#fff}
.opn-general-checkbox.enabled{background:#368df7;border-color:#368df7;position:relative}
.opn-general-checkbox.enabled::after{content:"✓";position:absolute;left:2px;top:-3px;color:#fff;font-weight:900}
@media(max-width:900px){.settings-page-grid{grid-template-columns:1fr}.opn-general-row{grid-template-columns:1fr}.opn-general-value{padding-top:0}}
</style>

<div class="page-title">
    <div>
        <h1>System → Settings → General</h1>
        <p>Current general settings for one managed OPNsense firewall.</p>
    </div>
</div>

<div class="settings-page-grid">
    <aside class="card settings-tree">
        <div class="settings-tree-title">Settings</div>
        <span class="tree-group">Firewall</span>
        <a class="tree-child"
           href="/firewall_advanced.php<?= $id ? '?firewall_id=' . $id : '' ?>">
            Advanced
        </a>
        <span class="tree-group">System</span>
        <span class="tree-subgroup">Settings</span>
        <a class="tree-grandchild active"
           href="/system_general.php<?= $id ? '?firewall_id=' . $id : '' ?>">
            General
        </a>
        <a class="tree-grandchild"
           href="/system_administration.php<?= $id ? '?firewall_id=' . $id : '' ?>">
            Administration
        </a>
    </aside>

    <main>
        <section class="opn-general-shell">
            <div class="opn-general-title">
                <h2>General</h2>
                <span class="badge neutral">Read-only</span>
            </div>

            <form method="get" class="opn-general-toolbar">
                <label for="firewall_id">OPNsense</label>
                <select id="firewall_id" name="firewall_id" onchange="this.form.submit()">
                    <option value="">Select firewall</option>
                    <?php foreach ($firewalls as $item): ?>
                        <option value="<?= (int) $item['id'] ?>"
                            <?= $id === (int) $item['id'] ? 'selected' : '' ?>>
                            <?= h((string) $item['name']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </form>

            <?php if ($error !== ''): ?>
                <div class="alert error"><?= h($error) ?></div>
            <?php elseif ($firewall === null): ?>
                <div class="empty">Select an OPNsense firewall.</div>
            <?php else: ?>
                <?php foreach ($sections as $section => $fields): ?>
                    <details class="opn-general-section" open>
                        <summary><?= h($section) ?></summary>
                        <?php foreach ($fields as $field): ?>
                            <?php $enabled = $field['value'] === 'Enabled'; ?>
                            <div class="opn-general-row">
                                <div class="opn-general-label">
                                    <?php if (($field['help'] ?? '') !== ''): ?>
                                        <span class="opn-general-info" title="<?= h((string) $field['help']) ?>">i</span>
                                    <?php endif; ?>
                                    <?= h((string) $field['label']) ?>
                                </div>
                                <div class="opn-general-value">
                                    <div class="opn-general-control">
                                        <?php if (($field['type'] ?? '') === 'boolean'): ?>
                                            <span class="opn-general-checkbox <?= $enabled ? 'enabled' : '' ?>"></span>
                                        <?php endif; ?>
                                        <span><?= h((string) $field['value']) ?></span>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </details>
                <?php endforeach; ?>
            <?php endif; ?>
        </section>
    </main>
</div>

<?php require __DIR__ . '/inc/footer.php'; ?>
