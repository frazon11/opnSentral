<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';

require_login();

$firewalls = db()->query('SELECT id,name,base_url FROM firewalls ORDER BY name')->fetchAll();

$id = (int) ($_GET['firewall_id'] ?? $_GET['id'] ?? 0);
$firewall = firewall_by_id($id);
$error = '';
$rawXml = '';
$sections = [];

function advanced_xpath_value(
    SimpleXMLElement $xml,
    string $path,
    ?string $default = null
): ?string {
    $nodes = $xml->xpath($path);

    if (!is_array($nodes) || !isset($nodes[0])) {
        return $default;
    }

    $value = trim((string) $nodes[0]);
    return $value === '' ? $default : $value;
}

function advanced_xpath_exists(
    SimpleXMLElement $xml,
    string $path
): bool {
    $nodes = $xml->xpath($path);
    return is_array($nodes) && isset($nodes[0]);
}

function advanced_bool_label(bool $enabled): string
{
    return $enabled ? 'Enabled' : 'Disabled';
}

function advanced_field(
    string $label,
    string $value,
    string $type = 'text',
    string $help = ''
): array {
    return [
        'label' => $label,
        'value' => $value,
        'type' => $type,
        'help' => $help,
    ];
}

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
        $messages = array_map(
            static fn(LibXMLError $item): string =>
                trim($item->message),
            libxml_get_errors()
        );

        throw new RuntimeException(
            'Could not parse the OPNsense configuration: ' .
            implode(' | ', $messages)
        );
    }

    $sections = [
        'Network Address Translation' => [
            advanced_field(
                'Reflection for destination NAT',
                advanced_bool_label(
                    !advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/disablenatreflection'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Reflection for 1:1',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/enablebinatreflection'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Automatic outbound NAT for Reflection',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/enablenatreflectionhelper'
                    )
                ),
                'boolean'
            ),
        ],
        'Bogon Networks' => [
            advanced_field(
                'Update Frequency',
                ucfirst(
                    advanced_xpath_value(
                        $xml,
                        '/opnsense/system/bogons/interval',
                        'monthly'
                    ) ?? 'monthly'
                )
            ),
        ],
        'Gateway Monitoring' => [
            advanced_field(
                'Skip rules',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/skip_rules_gw_down'
                    )
                ),
                'boolean',
                'Skip rules when gateway is down'
            ),
        ],
        'Multi-WAN' => [
            advanced_field(
                'Sticky connections',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/lb_use_sticky'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Source tracking timeout',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/srctrack',
                    '0'
                ) ?? '0'
            ),
            advanced_field(
                'Shared forwarding',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/pf_share_forward'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Disable force gateway',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/pf_disable_force_gw'
                    )
                ),
                'boolean'
            ),
        ],
        'Schedules' => [
            advanced_field(
                'Schedule States',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/schedule_states'
                    )
                ),
                'boolean'
            ),
        ],
        'Logging' => [
            advanced_field(
                'Default block',
                advanced_bool_label(
                    !advanced_xpath_exists(
                        $xml,
                        '/opnsense/syslog/nologdefaultblock'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Default pass',
                advanced_bool_label(
                    !advanced_xpath_exists(
                        $xml,
                        '/opnsense/syslog/nologdefaultpass'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Outbound NAT',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/syslog/logoutboundnat'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Bogon networks',
                advanced_bool_label(
                    !advanced_xpath_exists(
                        $xml,
                        '/opnsense/syslog/nologbogons'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Private networks',
                advanced_bool_label(
                    !advanced_xpath_exists(
                        $xml,
                        '/opnsense/syslog/nologprivatenets'
                    )
                ),
                'boolean'
            ),
        ],
        'Miscellaneous' => [
            advanced_field(
                'Keep counters',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/keepcounters'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Debug',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/pfdebug',
                    'urgent'
                ) ?? 'urgent'
            ),
            advanced_field(
                'Firewall Optimization',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/optimization',
                    'normal'
                ) ?? 'normal'
            ),
            advanced_field(
                'Bind states to interface',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/state-policy'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Disable Firewall',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/disablefilter'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Firewall Adaptive Timeouts — start',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/adaptivestart',
                    'Default'
                ) ?? 'Default'
            ),
            advanced_field(
                'Firewall Adaptive Timeouts — end',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/adaptiveend',
                    'Default'
                ) ?? 'Default'
            ),
            advanced_field(
                'Firewall Maximum States',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/maximumstates',
                    'Default'
                ) ?? 'Default'
            ),
            advanced_field(
                'Firewall Maximum Fragments',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/maximumfrags',
                    'Default'
                ) ?? 'Default'
            ),
            advanced_field(
                'Firewall Maximum Table Entries',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/maximumtableentries',
                    'Default'
                ) ?? 'Default'
            ),
            advanced_field(
                'Static route filtering',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/filter/bypassstaticroutes'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Disable reply-to',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/disablereplyto'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Disable anti-lockout',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/webgui/noantilockout'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Disable RFC4890 requirement rules',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/no_ipv6_rfc4890_req'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Disable port 0 block',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/no_port0_block'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Disable sshlockout',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/no_sshlockout'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Disable rate limit rule',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/no_virusprot'
                    )
                ),
                'boolean'
            ),
            advanced_field(
                'Aliases Resolve Interval',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/aliasesresolveinterval',
                    '300'
                ) ?? '300'
            ),
            advanced_field(
                'Check certificate of aliases URLs',
                advanced_bool_label(
                    advanced_xpath_exists(
                        $xml,
                        '/opnsense/system/checkaliasesurlcert'
                    )
                ),
                'boolean'
            ),
        ],
        'Anti DDOS' => [
            advanced_field(
                'Enable syncookies',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/syncookies',
                    'never (default)'
                ) ?? 'never (default)'
            ),
            advanced_field(
                'Syncookie Adaptive Start',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/syncookies_adaptstart',
                    'Default'
                ) ?? 'Default'
            ),
            advanced_field(
                'Syncookie Adaptive End',
                advanced_xpath_value(
                    $xml,
                    '/opnsense/system/syncookies_adaptend',
                    'Default'
                ) ?? 'Default'
            ),
        ],
    ];
} catch (Throwable $exception) {
    $error = $exception->getMessage();
}

require __DIR__ . '/inc/header.php';

?>

<style>
.advanced-page-actions{
    display:flex;
    align-items:center;
    gap:8px;
    flex-wrap:wrap
}
.advanced-settings-shell{
    border:1px solid #2e3238;
    border-radius:6px;
    overflow:hidden;
    background:#0d1016;
    color:#f3f3f3;
    box-shadow:0 10px 30px rgba(0,0,0,.25)
}
.advanced-settings-title{
    min-height:62px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;
    padding:0 18px;
    background:#10131a;
    border-bottom:1px solid #b6bbc3
}
.advanced-settings-title h2{
    margin:0;
    color:#f7f7f8
}
.advanced-settings-note{
    padding:9px 15px;
    background:#3c3c3b;
    border-bottom:1px solid #24272d;
    color:#dfe2e6;
    font-size:.86rem
}
.advanced-settings-section{
    border-bottom:1px solid #333740
}
.advanced-settings-section:last-child{
    border-bottom:0
}
.advanced-settings-section>summary{
    display:flex;
    align-items:center;
    gap:11px;
    min-height:56px;
    padding:0 16px;
    background:#10131a;
    color:#f5f5f5;
    font-size:1.02rem;
    font-weight:750;
    cursor:pointer;
    list-style:none
}
.advanced-settings-section>summary::-webkit-details-marker{
    display:none
}
.advanced-settings-section>summary::before{
    content:"›";
    font-size:1.45rem;
    transition:transform .15s
}
.advanced-settings-section[open]>summary::before{
    transform:rotate(90deg)
}
.advanced-setting-row{
    display:grid;
    grid-template-columns:minmax(260px,28%) minmax(0,1fr);
    min-height:58px
}
.advanced-setting-row:nth-child(odd){
    background:#3e3e3d
}
.advanced-setting-row:nth-child(even){
    background:#0f1218
}
.advanced-setting-label{
    display:flex;
    align-items:center;
    gap:7px;
    padding:10px 15px;
    font-weight:700
}
.advanced-setting-info{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    width:22px;
    height:22px;
    flex:0 0 auto;
    border-radius:50%;
    background:#d6532f;
    color:#17191d;
    font-family:Georgia,serif;
    font-weight:900
}
.advanced-setting-value{
    display:flex;
    align-items:center;
    padding:8px 18px
}
.advanced-setting-control{
    display:flex;
    align-items:center;
    width:min(560px,100%);
    min-height:40px;
    padding:7px 13px;
    border:1px solid #c5c9cf;
    border-radius:4px;
    background:#1b1f2a;
    color:#e9eaed
}
.advanced-setting-boolean{
    gap:9px
}
.advanced-setting-checkbox{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    width:18px;
    height:18px;
    border:1px solid #bfc3c9;
    border-radius:2px;
    background:#fff;
    color:#fff;
    font-weight:900
}
.advanced-setting-checkbox.enabled{
    background:#368df7;
    border-color:#368df7
}
.advanced-raw pre{
    margin:0;
    border-radius:0;
    max-height:420px
}
@media(max-width:760px){
    .advanced-setting-row{
        grid-template-columns:1fr
    }
    .advanced-setting-value{
        padding-top:0
    }
}
</style>

<div class="page-title">
    <div>
        <h1>Firewall → Settings → Advanced</h1>
        <p>
            <?= h((string) $firewall['name']) ?> ·
            <?= h((string) $firewall['base_url']) ?>
        </p>
    </div>

    <div class="advanced-page-actions">
        <a
            class="button secondary"
            href="/firewall_view.php?id=<?= (int) $firewall['id'] ?>"
        >
            Back to firewall
        </a>
        <a
            class="button secondary"
            target="_blank"
            rel="noopener"
            href="<?= h(
                rtrim((string) $firewall['base_url'], '/') .
                '/system_advanced_firewall.php'
            ) ?>"
        >
            Open OPNsense page
        </a>
    </div>
</div>

<div class="settings-page-grid">
    <aside class="card settings-tree">
        <div class="settings-tree-title">Settings</div>
        <span class="tree-group">Firewall</span>
        <a class="tree-child tree-grandchild active"
           href="/firewall_advanced.php?firewall_id=<?= (int) $firewall['id'] ?>">
            Advanced
        </a>
        <span class="tree-group">System</span>
        <a class="tree-child tree-grandchild"
           href="/system_administration.php?firewall_id=<?= (int) $firewall['id'] ?>">
            Administration
        </a>
    </aside>
    <main>
        <form method="get" class="card" style="margin-bottom:14px">
            <label for="firewall_id">OPNsense</label>
            <select id="firewall_id" name="firewall_id"
                    onchange="this.form.submit()">
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
<?php else: ?>
    <section class="advanced-settings-shell">
        <div class="advanced-settings-title">
            <h2>Firewall Advanced Settings</h2>
            <span class="badge neutral">Read-only</span>
        </div>

        <div class="advanced-settings-note">
            Current values loaded from this firewall’s OPNsense configuration.
            Missing values are shown using the OPNsense page defaults.
        </div>

        <?php foreach ($sections as $sectionName => $fields): ?>
            <details class="advanced-settings-section" open>
                <summary><?= h($sectionName) ?></summary>

                <?php foreach ($fields as $field): ?>
                    <?php
                    $enabled = $field['value'] === 'Enabled';
                    ?>
                    <div class="advanced-setting-row">
                        <div class="advanced-setting-label">
                            <span class="advanced-setting-info">i</span>
                            <span><?= h((string) $field['label']) ?></span>
                        </div>

                        <div class="advanced-setting-value">
                            <div class="advanced-setting-control <?= $field['type'] === 'boolean'
                                ? 'advanced-setting-boolean'
                                : '' ?>">
                                <?php if ($field['type'] === 'boolean'): ?>
                                    <span class="advanced-setting-checkbox <?= $enabled
                                        ? 'enabled'
                                        : '' ?>">
                                        <?= $enabled ? '✓' : '' ?>
                                    </span>
                                <?php endif; ?>

                                <span><?= h((string) $field['value']) ?></span>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </details>
        <?php endforeach; ?>

        <details class="advanced-settings-section advanced-raw">
            <summary>Advanced / Raw configuration XML</summary>
            <pre><?= h($rawXml) ?></pre>
        </details>
    </section>
<?php endif; ?>

    </main>
</div>
<?php require __DIR__ . '/inc/footer.php'; ?>
