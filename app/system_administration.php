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
$rawXml = '';

function admin_value(
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

function admin_exists(SimpleXMLElement $xml, string $path): bool
{
    $nodes = $xml->xpath($path);
    return is_array($nodes) && isset($nodes[0]);
}

function admin_bool(bool $value): string
{
    return $value ? 'Enabled' : 'Disabled';
}

function admin_field(
    string $label,
    string $value,
    string $type = 'text'
): array {
    return compact('label', 'value', 'type');
}

if ($firewall !== null) {
    try {
        $rawXml = opn_download(
            $firewall,
            'core/backup/download/this'
        );

        $xml = simplexml_load_string(
            $rawXml,
            SimpleXMLElement::class,
            LIBXML_NONET | LIBXML_NOCDATA
        );

        if (!$xml instanceof SimpleXMLElement) {
            throw new RuntimeException(
                'Could not parse the OPNsense configuration.'
            );
        }

        $protocol = admin_value(
            $xml,
            '/opnsense/system/webgui/protocol',
            'https'
        );
        $webPort = admin_value(
            $xml,
            '/opnsense/system/webgui/port',
            $protocol === 'https' ? '443' : '80'
        );

        $sections = [
            'Web GUI' => [
                admin_field('Protocol', strtoupper($protocol)),
                admin_field(
                    'SSL Certificate',
                    admin_value(
                        $xml,
                        '/opnsense/system/webgui/ssl-certref',
                        'System default'
                    )
                ),
                admin_field(
                    'SSL Ciphers',
                    admin_value(
                        $xml,
                        '/opnsense/system/webgui/ssl-ciphers',
                        'System defaults'
                    )
                ),
                admin_field(
                    'HTTP Strict Transport Security',
                    admin_bool(
                        admin_exists(
                            $xml,
                            '/opnsense/system/webgui/ssl-hsts'
                        )
                    ),
                    'boolean'
                ),
                admin_field('TCP port', $webPort),
                admin_field(
                    'HTTP Redirect',
                    admin_bool(
                        !admin_exists(
                            $xml,
                            '/opnsense/system/webgui/disablehttpredirect'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'HTTP Compression',
                    admin_value(
                        $xml,
                        '/opnsense/system/webgui/compression',
                        'Disabled'
                    )
                ),
                admin_field(
                    'Access log',
                    admin_bool(
                        admin_exists(
                            $xml,
                            '/opnsense/system/webgui/httpaccesslog'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'Listen interfaces',
                    admin_value(
                        $xml,
                        '/opnsense/system/webgui/interfaces',
                        'All interfaces'
                    )
                ),
                admin_field(
                    'DNS Rebind Check',
                    admin_bool(
                        !admin_exists(
                            $xml,
                            '/opnsense/system/webgui/nodnsrebindcheck'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'HTTP_REFERER enforcement',
                    admin_bool(
                        !admin_exists(
                            $xml,
                            '/opnsense/system/webgui/nohttpreferercheck'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'Browser autocomplete',
                    admin_bool(
                        !admin_exists(
                            $xml,
                            '/opnsense/system/webgui/noroot'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'Alternate Hostnames',
                    admin_value(
                        $xml,
                        '/opnsense/system/webgui/althostnames',
                        '—'
                    )
                ),
                admin_field(
                    'Session timeout',
                    admin_value(
                        $xml,
                        '/opnsense/system/webgui/session_timeout',
                        'Default'
                    )
                ),
                admin_field(
                    'Quiet login',
                    admin_bool(
                        admin_exists(
                            $xml,
                            '/opnsense/system/webgui/quietlogin'
                        )
                    ),
                    'boolean'
                ),
            ],
            'Secure Shell' => [
                admin_field(
                    'Secure Shell Server',
                    admin_bool(
                        admin_exists(
                            $xml,
                            '/opnsense/system/ssh/enabled'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'SSH port',
                    admin_value(
                        $xml,
                        '/opnsense/system/ssh/port',
                        '22'
                    )
                ),
                admin_field(
                    'Listen interfaces',
                    admin_value(
                        $xml,
                        '/opnsense/system/ssh/interfaces',
                        'All interfaces'
                    )
                ),
                admin_field(
                    'Permit root user login',
                    admin_bool(
                        admin_exists(
                            $xml,
                            '/opnsense/system/ssh/permitrootlogin'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'Permit password login',
                    admin_bool(
                        admin_exists(
                            $xml,
                            '/opnsense/system/ssh/passwordauth'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'Key exchange algorithms',
                    admin_value(
                        $xml,
                        '/opnsense/system/ssh/kex',
                        'System defaults'
                    )
                ),
                admin_field(
                    'Ciphers',
                    admin_value(
                        $xml,
                        '/opnsense/system/ssh/ciphers',
                        'System defaults'
                    )
                ),
                admin_field(
                    'Message authentication codes',
                    admin_value(
                        $xml,
                        '/opnsense/system/ssh/macs',
                        'System defaults'
                    )
                ),
                admin_field(
                    'Host key algorithms',
                    admin_value(
                        $xml,
                        '/opnsense/system/ssh/keys',
                        'System defaults'
                    )
                ),
                admin_field(
                    'Public key signature algorithms',
                    admin_value(
                        $xml,
                        '/opnsense/system/ssh/keysig',
                        'System defaults'
                    )
                ),
                admin_field(
                    'Rekey limit',
                    admin_value(
                        $xml,
                        '/opnsense/system/ssh/rekeylimit',
                        'System defaults'
                    )
                ),
            ],
            'Authentication' => [
                admin_field(
                    'Server',
                    admin_value(
                        $xml,
                        '/opnsense/system/webgui/authmode',
                        'Local Database'
                    )
                ),
                admin_field(
                    'Sudo',
                    admin_value(
                        $xml,
                        '/opnsense/system/sudo_allow_wheel',
                        'Disabled'
                    )
                ),
                admin_field(
                    'Sudo group',
                    admin_value(
                        $xml,
                        '/opnsense/system/sudo_allow_group',
                        '—'
                    )
                ),
                admin_field(
                    'API key generation',
                    admin_value(
                        $xml,
                        '/opnsense/system/user_allow_gen_token',
                        'Administrators only'
                    )
                ),
            ],
            'Console' => [
                admin_field(
                    'Console menu',
                    admin_bool(
                        !admin_exists(
                            $xml,
                            '/opnsense/system/disableconsolemenu'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'Primary Console',
                    admin_value(
                        $xml,
                        '/opnsense/system/primaryconsole',
                        'Video Console'
                    )
                ),
                admin_field(
                    'Secondary Console',
                    admin_value(
                        $xml,
                        '/opnsense/system/secondaryconsole',
                        'None'
                    )
                ),
                admin_field(
                    'Serial Speed',
                    admin_value(
                        $xml,
                        '/opnsense/system/serialspeed',
                        '115200'
                    )
                ),
                admin_field(
                    'USB-based serial',
                    admin_bool(
                        admin_exists(
                            $xml,
                            '/opnsense/system/serialusb'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'Virtual terminal',
                    admin_bool(
                        admin_exists(
                            $xml,
                            '/opnsense/system/usevirtualterminal'
                        )
                    ),
                    'boolean'
                ),
                admin_field(
                    'Inactivity timeout',
                    admin_value(
                        $xml,
                        '/opnsense/system/autologout',
                        'Disabled'
                    )
                ),
            ],
            'Deployment' => [
                admin_field(
                    'Deployment type',
                    admin_value(
                        $xml,
                        '/opnsense/system/deployment',
                        'Default'
                    )
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
.settings-tree .tree-grandchild{padding-left:46px}
.settings-tree a.active{background:#3b4851;color:#fff}
.opn-admin-shell{border:1px solid #2e3238;border-radius:6px;overflow:hidden;background:#0d1016;color:#f3f3f3}
.opn-admin-title{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:60px;padding:0 17px;background:#10131a;border-bottom:1px solid #b6bbc3}
.opn-admin-title h2{margin:0;color:#fff}
.opn-admin-toolbar{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#3c3c3b}
.opn-admin-toolbar select{width:min(420px,100%);margin:0}
.opn-admin-section{border-bottom:1px solid #333740}
.opn-admin-section>summary{display:flex;align-items:center;gap:10px;min-height:54px;padding:0 15px;background:#10131a;color:#fff;font-weight:750;cursor:pointer;list-style:none}
.opn-admin-section>summary::-webkit-details-marker{display:none}
.opn-admin-section>summary::before{content:"›";font-size:1.4rem}
.opn-admin-section[open]>summary::before{transform:rotate(90deg)}
.opn-admin-row{display:grid;grid-template-columns:minmax(250px,28%) minmax(0,1fr);min-height:56px}
.opn-admin-row:nth-child(odd){background:#3e3e3d}
.opn-admin-row:nth-child(even){background:#0f1218}
.opn-admin-label{display:flex;align-items:center;gap:7px;padding:10px 15px;font-weight:700}
.opn-admin-info{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:#d6532f;color:#17191d;font-family:Georgia,serif;font-weight:900}
.opn-admin-value{display:flex;align-items:center;padding:8px 18px}
.opn-admin-control{display:flex;align-items:center;gap:9px;width:min(570px,100%);min-height:40px;padding:7px 13px;border:1px solid #c5c9cf;border-radius:4px;background:#1b1f2a;color:#e9eaed}
.opn-admin-checkbox{width:18px;height:18px;border:1px solid #bfc3c9;border-radius:2px;background:#fff}
.opn-admin-checkbox.enabled{background:#368df7;border-color:#368df7;position:relative}
.opn-admin-checkbox.enabled::after{content:"✓";position:absolute;left:2px;top:-3px;color:#fff;font-weight:900}
@media(max-width:900px){.settings-page-grid{grid-template-columns:1fr}.opn-admin-row{grid-template-columns:1fr}.opn-admin-value{padding-top:0}}
</style>

<div class="page-title">
    <div>
        <h1>System → Settings → Administration</h1>
        <p>Current administration settings for one managed OPNsense firewall.</p>
    </div>
</div>

<div class="settings-page-grid">
    <aside class="card settings-tree">
        <div class="settings-tree-title">Settings</div>
        <span class="tree-group">Firewall</span>
        <a class="tree-child tree-grandchild"
           href="/firewall_advanced.php<?= $id ? '?firewall_id=' . $id : '' ?>">
            Advanced
        </a>
        <span class="tree-group">System</span>
        <a class="tree-child tree-grandchild active"
           href="/system_administration.php<?= $id ? '?firewall_id=' . $id : '' ?>">
            Administration
        </a>
    </aside>

    <main>
        <section class="opn-admin-shell">
            <div class="opn-admin-title">
                <h2>Administration</h2>
                <span class="badge neutral">Read-only</span>
            </div>

            <form method="get" class="opn-admin-toolbar">
                <label for="firewall_id">OPNsense</label>
                <select id="firewall_id" name="firewall_id"
                        onchange="this.form.submit()">
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
                    <details class="opn-admin-section" open>
                        <summary><?= h($section) ?></summary>
                        <?php foreach ($fields as $field): ?>
                            <?php $enabled = $field['value'] === 'Enabled'; ?>
                            <div class="opn-admin-row">
                                <div class="opn-admin-label">
                                    <span class="opn-admin-info">i</span>
                                    <?= h($field['label']) ?>
                                </div>
                                <div class="opn-admin-value">
                                    <div class="opn-admin-control">
                                        <?php if ($field['type'] === 'boolean'): ?>
                                            <span class="opn-admin-checkbox <?= $enabled ? 'enabled' : '' ?>"></span>
                                        <?php endif; ?>
                                        <span><?= h($field['value']) ?></span>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </details>
                <?php endforeach; ?>

                <details class="opn-admin-section">
                    <summary>Advanced / Raw configuration XML</summary>
                    <pre><?= h($rawXml) ?></pre>
                </details>
            <?php endif; ?>
        </section>
    </main>
</div>

<?php require __DIR__ . '/inc/footer.php'; ?>
