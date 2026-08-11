<?php

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';

require_login();

$id = (int) ($_GET['id'] ?? 0);
$firewall = firewall_by_id($id);

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    try {
        $action = (string) ($_POST['action'] ?? '');

        if ($action === 'backup') {
            $created = backup_create($firewall, 'manual', 'single-firewall');
            $message = 'Backup saved: ' . $created['filename'];
        } elseif ($action === 'reboot') {
            opn_request(
                $firewall,
                'core/system/reboot',
                'POST',
                []
            );

            $message = 'Reboot command submitted.';
        } elseif ($action === 'delete') {
            $statement = db()->prepare(
                'DELETE FROM firewalls WHERE id = ?'
            );
            $statement->execute([$id]);

            header('Location: /');
            exit;
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';

?>

<style>
.page-title-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.firewall-opn-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;align-items:start}
.firewall-opn-wide{grid-column:1/-1}
.firewall-opn-panel{
    padding:0;
    overflow:hidden;
    border:1px solid #2e3238;
    border-radius:6px;
    background:#0d1016;
    color:#f3f3f3;
    box-shadow:0 8px 24px rgba(0,0,0,.18)
}
.firewall-opn-titlebar{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;
    min-height:58px;
    padding:0 16px;
    background:#10131a;
    border-bottom:1px solid #343943
}
.firewall-opn-titlebar h2,.firewall-opn-titlebar h3{margin:0;color:#f7f7f8}
.firewall-opn-titlebar .button,.firewall-opn-titlebar button{margin:0}
.firewall-opn-status{
    min-height:32px;
    padding:7px 14px;
    border-bottom:1px solid #24272d;
    background:#3c3c3b;
    color:#dfe2e6;
    font-size:.86rem
}
.firewall-opn-status.loading::before{content:"● ";animation:pulse 1s infinite}
.firewall-opn-status.good{background:#23392a;color:#b9e8c4}
.firewall-opn-status.bad{background:#4a2727;color:#ffc0c0}
.firewall-opn-section{
    border-bottom:1px solid #333740
}
.firewall-opn-section:last-child{border-bottom:0}
.firewall-opn-section>summary{
    display:flex;
    align-items:center;
    gap:10px;
    min-height:52px;
    padding:0 15px;
    background:#10131a;
    color:#f5f5f5;
    font-weight:750;
    cursor:pointer;
    list-style:none
}
.firewall-opn-section>summary::-webkit-details-marker{display:none}
.firewall-opn-section>summary::before{content:"›";font-size:1.4rem;transition:transform .15s}
.firewall-opn-section[open]>summary::before{transform:rotate(90deg)}
.firewall-opn-fields{display:block}
.firewall-opn-row{
    display:grid;
    grid-template-columns:minmax(210px,35%) minmax(0,1fr);
    min-height:52px
}
.firewall-opn-row:nth-child(odd){background:#3e3e3d}
.firewall-opn-row:nth-child(even){background:#0f1218}
.firewall-opn-label{
    display:flex;
    align-items:center;
    gap:7px;
    padding:10px 14px;
    font-weight:700
}
.firewall-opn-info{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    width:21px;
    height:21px;
    flex:0 0 auto;
    border-radius:50%;
    background:#d6532f;
    color:#17191d;
    font-family:Georgia,serif;
    font-weight:900
}
.firewall-opn-value{
    display:flex;
    align-items:center;
    padding:8px 16px;
    min-width:0
}
.firewall-opn-control{
    width:min(560px,100%);
    min-height:38px;
    display:flex;
    align-items:center;
    padding:7px 12px;
    border:1px solid #c5c9cf;
    border-radius:4px;
    background:#1b1f2a;
    color:#e9eaed;
    overflow-wrap:anywhere
}
.firewall-opn-control.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.firewall-opn-version-grid{
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:0
}
.firewall-opn-version-grid .firewall-opn-row{grid-template-columns:1fr}
.firewall-opn-version-grid .firewall-opn-value{padding-top:0}
.firewall-opn-message{padding:12px 15px;background:#0f1218;color:#cbd0d6}
.firewall-opn-actions{display:flex;gap:8px;flex-wrap:wrap;padding:14px;background:#0f1218}
.firewall-opn-raw pre{margin:0;border-radius:0;max-height:360px}
.firewall-plugin-body{padding:14px 16px;background:#0f1218}
.firewall-plugin-body p{margin-top:0;color:#cbd0d6}
.live-card pre{min-height:110px}
.hidden{display:none!important}
.vpn-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;padding:14px;background:#0f1218}
.vpn-panel{padding:0;border:1px solid #343943;border-radius:5px;background:#10131a;overflow:hidden}
.vpn-panel h3{margin:0;padding:12px 14px;border-bottom:1px solid #343943}
.vpn-summary{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:12px 14px;border-bottom:1px solid #343943}
.vpn-list{display:grid;gap:8px;padding:12px 14px}
.vpn-row{padding:9px;border:1px solid #343943;border-radius:4px;background:#1b1f2a}
.vpn-row strong{display:block;margin-bottom:3px}
.vpn-meta{font-size:.88rem;opacity:.78;word-break:break-word}
.vpn-empty{opacity:.7}
.vpn-raw{margin:0;border-top:1px solid #343943}
.vpn-raw summary{padding:10px 14px;cursor:pointer}
.vpn-raw pre{margin:0;border-radius:0}
.vpn-actions{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-top:8px}
.vpn-actions button{padding:6px 9px;font-size:.84rem}
.vpn-managed{font-size:.82rem;opacity:.82}
.vpn-section-title{margin:16px 0 7px;padding-top:10px;border-top:1px solid #dce1e5;font-size:.92rem}
@keyframes pulse{0%,100%{opacity:.25}50%{opacity:1}}
@media(max-width:1000px){.firewall-opn-grid{grid-template-columns:1fr}.firewall-opn-wide{grid-column:auto}}
@media(max-width:700px){
    .firewall-opn-row{grid-template-columns:1fr}
    .firewall-opn-value{padding-top:0}
    .firewall-opn-version-grid{grid-template-columns:1fr}
}
</style>

<div class="page-title">
    <div>
        <h1><?= h((string) $firewall['name']) ?></h1>
        <p><?= h((string) $firewall['base_url']) ?></p>
    </div>

    <div class="page-title-actions">
        <a
            class="button secondary"
            href="/firewall_advanced.php?firewall_id=<?= (int) $firewall['id'] ?>"
        >
            Firewall → Settings → Advanced
        </a>

        <a
            class="button secondary"
            href="/plugins.php?firewall_id=<?= (int) $firewall['id'] ?>"
        >
            Plugins
        </a>

        <a
            class="button secondary"
            target="_blank"
            rel="noopener"
            href="<?= h((string) $firewall['base_url']) ?>"
        >
            Open WebGUI
        </a>
    </div>
</div>

<?php if ($message): ?>
    <div class="alert goodbox"><?= h($message) ?></div>
<?php endif; ?>

<?php if ($error): ?>
    <div class="alert error"><?= h($error) ?></div>
<?php endif; ?>

<div id="ajax-message" class="alert goodbox hidden"></div>
<div id="ajax-error" class="alert error hidden"></div>

<div class="firewall-opn-grid">
    <section class="firewall-opn-panel">
        <div class="firewall-opn-titlebar">
            <h2><?= h(t('common.system')) ?></h2>
        </div>
        <div id="system-state"
             class="firewall-opn-status loading">
            Loading live system status…
        </div>

        <details class="firewall-opn-section" open>
            <summary>System status</summary>
            <div id="system-fields" class="firewall-opn-fields">
                <div class="firewall-opn-row">
                    <div class="firewall-opn-label">
                        <span class="firewall-opn-info">i</span>
                        Loading
                    </div>
                    <div class="firewall-opn-value">
                        <div class="firewall-opn-control">
                            <?= h(t('common.loading')) ?>
                        </div>
                    </div>
                </div>
            </div>
        </details>

        <details class="firewall-opn-section firewall-opn-raw">
            <summary>Advanced / Raw API data</summary>
            <pre id="system-output"><?= h(t('common.loading')) ?></pre>
        </details>
    </section>

    <section class="firewall-opn-panel">
        <div class="firewall-opn-titlebar">
            <h2><?= h(t('details.firmware')) ?></h2>
        </div>
        <div id="firmware-state"
             class="firewall-opn-status loading">
            Loading firmware information…
        </div>

        <div class="firewall-opn-version-grid">
            <div class="firewall-opn-row">
                <div class="firewall-opn-label">
                    <span class="firewall-opn-info">i</span>
                    <?= h(t('dashboard.current_version')) ?>
                </div>
                <div class="firewall-opn-value">
                    <div id="current-version"
                         class="firewall-opn-control mono">
                        <?= h(t('common.loading')) ?>
                    </div>
                </div>
            </div>
            <div class="firewall-opn-row">
                <div class="firewall-opn-label">
                    <span class="firewall-opn-info">i</span>
                    <?= h(t('dashboard.available_version')) ?>
                </div>
                <div class="firewall-opn-value">
                    <div id="available-version"
                         class="firewall-opn-control mono">
                        Not checked
                    </div>
                </div>
            </div>
        </div>

        <div id="firmware-message"
             class="firewall-opn-message">
            <?= h(t('common.loading')) ?>
        </div>

        <details class="firewall-opn-section">
            <summary>Firmware details</summary>
            <div id="firmware-fields" class="firewall-opn-fields"></div>
        </details>

        <details class="firewall-opn-section firewall-opn-raw">
            <summary>Advanced / Raw API data</summary>
            <pre id="firmware-output"><?= h(t('common.loading')) ?></pre>
        </details>

        <div class="firewall-opn-actions">
            <div id="check-state" class="muted">
                Ready. Click “Check for updates”.
            </div>
            <button type="button" id="firmware-check-button">
                Check for updates
            </button>
            <button
                type="button"
                id="firmware-install-button"
                class="warning hidden"
            >
                Update now
            </button>
        </div>
    </section>

    <section class="firewall-opn-panel">
        <div class="firewall-opn-titlebar">
            <h2>Plugins</h2>
        </div>
        <div class="firewall-opn-status good">
            Plugin management is available for this OPNsense firewall.
        </div>
        <div class="firewall-plugin-body">
            <p>
                Review installed and available OPNsense plugins. Install,
                reinstall, remove, lock and unlock operations remain protected
                by the global configuration lock.
            </p>
            <a
                class="button secondary"
                href="/plugins.php?firewall_id=<?= (int) $firewall['id'] ?>"
            >
                Manage plugins
            </a>
        </div>
    </section>

    <section class="firewall-opn-panel firewall-opn-wide">
        <div class="firewall-opn-titlebar">
            <div>
                <h2><?= h(t('details.site_vpn')) ?></h2>
            </div>
            <button type="button"
                    id="vpn-refresh-button"
                    class="secondary">
                Refresh VPN status
            </button>
        </div>
        <div id="vpn-state"
             class="firewall-opn-status loading">
            Loading WireGuard, IPsec and OpenVPN status…
        </div>

        <div class="vpn-grid">
            <div class="vpn-panel">
                <h3>WireGuard</h3>
                <div id="wireguard-summary"
                     class="vpn-summary"><?= h(t('common.loading')) ?></div>
                <div id="wireguard-list" class="vpn-list"></div>
                <details class="vpn-raw">
                    <summary><?= h(t('details.raw_api')) ?></summary>
                    <pre id="wireguard-raw"><?= h(t('common.loading')) ?></pre>
                </details>
            </div>

            <div class="vpn-panel">
                <h3>IPsec</h3>
                <div id="ipsec-summary"
                     class="vpn-summary"><?= h(t('common.loading')) ?></div>
                <div id="ipsec-list" class="vpn-list"></div>
                <details class="vpn-raw">
                    <summary><?= h(t('details.raw_api')) ?></summary>
                    <pre id="ipsec-raw"><?= h(t('common.loading')) ?></pre>
                </details>
            </div>

            <div class="vpn-panel">
                <h3>OpenVPN</h3>
                <div id="openvpn-summary"
                     class="vpn-summary"><?= h(t('common.loading')) ?></div>
                <div id="openvpn-list" class="vpn-list"></div>
                <details class="vpn-raw">
                    <summary><?= h(t('details.raw_api')) ?></summary>
                    <pre id="openvpn-raw"><?= h(t('common.loading')) ?></pre>
                </details>
            </div>
        </div>
    </section>
</div>

<form method="post" class="actions danger-zone">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">

    <button name="action" value="backup">
        Download configuration backup
    </button>

    <button
        class="warning"
        name="action"
        value="reboot"
        onclick="return confirm('Really reboot this firewall?')"
    >
        Reboot firewall
    </button>

    <button
        class="danger"
        name="action"
        value="delete"
        onclick="return confirm(
            'Delete this firewall from OpnCentral?'
        )"
    >
        Delete entry
    </button>
</form>

<script>
(function () {
    let managedWireGuardLinks = {};
    const tr = {"common.loading_short":<?= json_encode(t('common.loading_short'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.loading":<?= json_encode(t('common.loading'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.online":<?= json_encode(t('common.online'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.offline":<?= json_encode(t('common.offline'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.reachable":<?= json_encode(t('common.reachable'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.unavailable":<?= json_encode(t('common.unavailable'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.unknown":<?= json_encode(t('common.unknown'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.not_checked":<?= json_encode(t('common.not_checked'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.no_update":<?= json_encode(t('common.no_update'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.update_available":<?= json_encode(t('common.update_available'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.update_now":<?= json_encode(t('common.update_now'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.upgrade_now":<?= json_encode(t('common.upgrade_now'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.loading_firmware":<?= json_encode(t('dashboard.loading_firmware'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.start_update_confirm":<?= json_encode(t('dashboard.start_update_confirm'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.start_upgrade_confirm":<?= json_encode(t('dashboard.start_upgrade_confirm'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.starting_update":<?= json_encode(t('dashboard.starting_update'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.starting_upgrade":<?= json_encode(t('dashboard.starting_upgrade'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.action_started":<?= json_encode(t('dashboard.action_started'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"details.loading_system":<?= json_encode(t('details.loading_system'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"details.loading_firmware":<?= json_encode(t('details.loading_firmware'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"details.loading_vpn":<?= json_encode(t('details.loading_vpn'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>};
    const firewallId = <?= (int) $firewall['id'] ?>;
    const csrfToken = <?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>;
    const checkButton = document.getElementById('firmware-check-button');
    const installButton = document.getElementById('firmware-install-button');
    let firmwareAction = null;

    function setNotice(message, isError) {
        const good = document.getElementById('ajax-message');
        const bad = document.getElementById('ajax-error');

        good.classList.add('hidden');
        bad.classList.add('hidden');

        const target = isError ? bad : good;
        target.textContent = message;
        target.classList.remove('hidden');
    }

    function humanLabel(value) {
        return String(value || '')
            .replace(/[_-]+/g, ' ')
            .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
            .replace(/\b\w/g, char => char.toUpperCase());
    }

    function scalarDisplay(value) {
        if (value === null || value === undefined || value === '') {
            return '—';
        }

        if (value === true || value === 1 || value === '1') {
            return 'Enabled';
        }

        if (value === false || value === 0 || value === '0') {
            return 'Disabled';
        }

        if (Array.isArray(value)) {
            return value.length
                ? value.map(scalarDisplay).join(', ')
                : '—';
        }

        if (typeof value === 'object') {
            return JSON.stringify(value);
        }

        return String(value);
    }

    function collectDisplayRows(value, prefix = '', depth = 0) {
        const rows = [];

        if (
            value === null ||
            value === undefined ||
            depth > 2
        ) {
            return rows;
        }

        if (Array.isArray(value)) {
            if (
                value.every(item =>
                    item === null ||
                    ['string', 'number', 'boolean'].includes(typeof item)
                )
            ) {
                rows.push({
                    label: prefix || 'Value',
                    value: scalarDisplay(value)
                });
            }
            return rows;
        }

        if (typeof value !== 'object') {
            rows.push({
                label: prefix || 'Value',
                value: scalarDisplay(value)
            });
            return rows;
        }

        Object.entries(value).forEach(([key, item]) => {
            const lower = key.toLowerCase();

            if (
                ['metadata', 'translations'].includes(lower) ||
                lower === 'subsystems'
            ) {
                return;
            }

            const label = prefix
                ? prefix + ' · ' + humanLabel(key)
                : humanLabel(key);

            if (
                item !== null &&
                typeof item === 'object' &&
                !Array.isArray(item)
            ) {
                const nested = collectDisplayRows(
                    item,
                    label,
                    depth + 1
                );
                rows.push(...nested);
                return;
            }

            if (
                Array.isArray(item) &&
                item.some(entry =>
                    entry !== null &&
                    typeof entry === 'object'
                )
            ) {
                return;
            }

            rows.push({
                label,
                value: scalarDisplay(item)
            });
        });

        return rows;
    }

    function renderStructuredRows(container, rows, emptyText) {
        container.textContent = '';

        if (!rows.length) {
            const row = document.createElement('div');
            row.className = 'firewall-opn-row';
            row.innerHTML = `
                <div class="firewall-opn-label">
                    <span class="firewall-opn-info">i</span>
                    Status
                </div>
                <div class="firewall-opn-value">
                    <div class="firewall-opn-control">
                        ${escapeHtml(emptyText || 'No values returned.')}
                    </div>
                </div>
            `;
            container.appendChild(row);
            return;
        }

        rows.slice(0, 40).forEach(item => {
            const row = document.createElement('div');
            row.className = 'firewall-opn-row';

            const label = document.createElement('div');
            label.className = 'firewall-opn-label';

            const info = document.createElement('span');
            info.className = 'firewall-opn-info';
            info.textContent = 'i';

            const labelText = document.createElement('span');
            labelText.textContent = item.label;

            const value = document.createElement('div');
            value.className = 'firewall-opn-value';

            const control = document.createElement('div');
            control.className = 'firewall-opn-control';
            control.textContent = item.value;

            label.append(info, labelText);
            value.appendChild(control);
            row.append(label, value);
            container.appendChild(row);
        });
    }

    function showSystem(payload) {
        const state = document.getElementById('system-state');
        const output = document.getElementById('system-output');
        const fields = document.getElementById('system-fields');

        state.classList.remove('loading', 'good', 'bad');

        if (!payload || payload.ok !== true) {
            state.classList.add('bad');
            state.textContent = 'Could not load live status.';
            output.textContent = payload?.error || tr['common.unavailable'];
            renderStructuredRows(
                fields,
                [],
                payload?.error || tr['common.unavailable']
            );
            return;
        }

        state.classList.add('good');
        state.textContent = 'Live status loaded.';
        output.textContent = JSON.stringify(payload.value, null, 2);

        const rows = collectDisplayRows(payload.value)
            .filter(item =>
                !item.label.toLowerCase().includes('dialog') &&
                !item.label.toLowerCase().includes('title')
            );

        renderStructuredRows(
            fields,
            rows,
            'No displayable system values returned.'
        );
    }

    function showFirmware(payload) {
        const state = document.getElementById('firmware-state');
        const output = document.getElementById('firmware-output');
        const current = document.getElementById('current-version');
        const available = document.getElementById('available-version');
        const message = document.getElementById('firmware-message');
        const fields = document.getElementById('firmware-fields');

        state.classList.remove('loading', 'good', 'bad');
        installButton.classList.add('hidden');
        firmwareAction = null;

        if (!payload || payload.ok !== true) {
            state.classList.add('bad');
            state.textContent = 'Could not load firmware status.';
            output.textContent = payload?.error || tr['common.unavailable'];
            current.textContent = tr['common.unknown'];
            available.textContent = tr['common.unknown'];
            message.textContent = payload?.error || tr['common.unavailable'];
            renderStructuredRows(
                fields,
                [],
                payload?.error || tr['common.unavailable']
            );
            return;
        }

        const summary = payload.summary || {};

        state.classList.add('good');
        state.textContent = 'Firmware status loaded.';
        current.textContent =
            summary.current_version || tr['common.unknown'];
        available.textContent = summary.update_available
            ? (
                summary.available_version ||
                tr['common.update_available']
            )
            : (
                summary.checked
                    ? tr['common.no_update']
                    : tr['common.not_checked']
            );
        message.textContent = summary.message || '';
        output.textContent = JSON.stringify(payload.value, null, 2);

        const preferred = [
            ['Product', payload.value?.product?.product_name],
            ['Product version', payload.value?.product?.product_version],
            ['Architecture', payload.value?.product?.product_arch],
            ['Repository', payload.value?.product?.product_repo],
            ['Last checked', payload.value?.last_check],
            ['Needs reboot', payload.value?.needs_reboot],
            ['Download size', payload.value?.download_size],
            ['Connection', payload.value?.connection],
        ].filter(([, value]) =>
            value !== undefined &&
            value !== null &&
            value !== ''
        ).map(([label, value]) => ({
            label,
            value: scalarDisplay(value)
        }));

        renderStructuredRows(
            fields,
            preferred.length
                ? preferred
                : collectDisplayRows(payload.value),
            'No additional firmware values returned.'
        );

        if (summary.update_available && summary.action) {
            firmwareAction = summary.action;
            installButton.textContent =
                summary.action_label || tr['common.update_now'];
            installButton.classList.remove('hidden');
        }
    }

    async function fetchStatus(type) {
        const response = await fetch(
            '/firewall_status.php?id=' +
            encodeURIComponent(firewallId) +
            '&type=' +
            encodeURIComponent(type),
            {
                credentials: 'same-origin',
                cache: 'no-store'
            }
        );

        const responseText = await response.text();
        let result;

        try {
            result = JSON.parse(responseText);
        } catch (error) {
            throw new Error(
                'Server returned invalid JSON: ' +
                responseText.replace(/\s+/g, ' ').trim().slice(0, 500)
            );
        }

        if (!response.ok || result.ok !== true) {
            throw new Error(result.error || 'HTTP ' + response.status);
        }

        return result.data[type];
    }

    async function runAction(action) {
        const body = new URLSearchParams();
        body.set('csrf', csrfToken);
        body.set('id', String(firewallId));
        body.set('action', action);

        const response = await fetch('/firewall_action.php', {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
            },
            body
        });

        const responseText = await response.text();
        let result;

        try {
            result = JSON.parse(responseText);
        } catch (error) {
            throw new Error(
                'Server returned invalid JSON: ' +
                responseText.replace(/\s+/g, ' ').trim().slice(0, 500)
            );
        }

        if (!response.ok || result.ok !== true) {
            throw new Error(result.error || 'HTTP ' + response.status);
        }

        return result;
    }

    async function loadSystem() {
        try {
            showSystem(await fetchStatus('system'));
        } catch (error) {
            showSystem({ok: false, error: error.message});
        }
    }

    async function loadFirmware() {
        try {
            showFirmware(await fetchStatus('firmware'));
        } catch (error) {
            showFirmware({ok: false, error: error.message});
        }
    }

    checkButton.addEventListener('click', async function () {
        checkButton.disabled = true;
        checkButton.textContent = 'Checking…';
        document.getElementById('check-state').textContent =
            'OPNsense is checking its firmware mirror…';

        try {
            const result = await runAction('firmware_check');

            showFirmware({
                ok: true,
                value: result.value,
                summary: result.summary
            });

            document.getElementById('check-state').textContent =
                'Firmware check completed.';
            setNotice('Firmware check completed.', false);
        } catch (error) {
            document.getElementById('check-state').textContent =
                'Firmware check failed.';
            setNotice(error.message, true);
        } finally {
            checkButton.disabled = false;
            checkButton.textContent = 'Check for updates';
        }
    });

    installButton.addEventListener('click', async function () {
        if (!firmwareAction) {
            return;
        }

        const isUpgrade = firmwareAction === 'firmware_upgrade';
        const question = isUpgrade
            ? 'Start the major OPNsense upgrade now? The firewall will reboot and may be unavailable for an extended period.'
            : 'Install the available OPNsense update now? The firewall may reboot and temporarily become unavailable.';

        if (!confirm(question)) {
            return;
        }

        installButton.disabled = true;
        installButton.textContent = isUpgrade
            ? 'Starting upgrade…'
            : 'Starting update…';

        try {
            const result = await runAction(firmwareAction);
            setNotice(result.message || 'Firmware action started.', false);
            installButton.classList.add('hidden');
        } catch (error) {
            setNotice(error.message, true);
        } finally {
            installButton.disabled = false;
        }
    });


    function firstArray(value) {
        if (Array.isArray(value)) {
            return value;
        }

        if (!value || typeof value !== 'object') {
            return [];
        }

        for (const key of ['rows', 'items', 'data', 'sessions', 'tunnels', 'peers']) {
            if (Array.isArray(value[key])) {
                return value[key];
            }
        }

        return [];
    }

    function textValue(row, keys, fallback = '') {
        for (const key of keys) {
            if (
                row &&
                row[key] !== undefined &&
                row[key] !== null &&
                String(row[key]).trim() !== ''
            ) {
                return String(row[key]);
            }
        }

        return fallback;
    }

    function normalisedStatus(value) {
        return String(value ?? '').trim().toLowerCase();
    }

    function rowIsOnline(row) {
        const peerStatus = normalisedStatus(row?.['peer-status']);
        if (peerStatus) {
            return peerStatus === 'online';
        }

        const status = normalisedStatus(
            textValue(row, ['status', 'state', 'connected', 'active', 'running'])
        );

        return ['up', 'online', 'ok', 'established', 'connected', 'active', 'true', 'running']
            .includes(status);
    }

    function formatBytes(value) {
        const bytes = Number(value);
        if (!Number.isFinite(bytes) || bytes < 0) {
            return '';
        }

        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let amount = bytes;
        let unit = 0;
        while (amount >= 1024 && unit < units.length - 1) {
            amount /= 1024;
            unit += 1;
        }
        return (unit === 0 ? amount.toFixed(0) : amount.toFixed(1)) + ' ' + units[unit];
    }

    function appendVpnRow(container, options) {
        const box = document.createElement('div');
        box.className = 'vpn-row';

        const title = document.createElement('strong');
        title.textContent = options.name;

        const badge = document.createElement('span');
        badge.className = 'badge ' + (options.statusClass || (options.online ? 'good' : 'bad'));
        badge.textContent = options.status;

        box.appendChild(title);
        box.appendChild(badge);

        if (options.meta) {
            const meta = document.createElement('div');
            meta.className = 'vpn-meta';
            meta.textContent = options.meta;
            box.appendChild(meta);
        }
        if (options.actions instanceof Node) box.appendChild(options.actions);
        container.appendChild(box);
    }

    function managedWireGuardActions(peer) {
        const publicKey = String(peer?.['public-key'] || '');
        const link = managedWireGuardLinks[publicKey];
        if (!link?.managed) return null;
        const box = document.createElement('div'); box.className = 'vpn-actions';
        const label = document.createElement('span'); label.className = 'vpn-managed';
        label.textContent = 'Managed peer: ' + link.remote.firewall_name + (link.partial_state ? ' · partial state' : '');
        const button = document.createElement('button'); button.type = 'button';
        const enable = !link.paired_enabled; button.className = enable ? 'secondary' : 'warning';
        button.textContent = enable ? 'Enable both sides' : 'Disable both sides';
        button.addEventListener('click', async function () {
            const verb = enable ? 'enable' : 'disable';
            if (!confirm(`Really ${verb} only this WireGuard connection on both managed firewalls?

${link.local.firewall_name}: ${link.local.client_name || 'peer'}
${link.remote.firewall_name}: ${link.remote.client_name || 'peer'}

Other WireGuard peers and instances will remain unchanged.`)) return;
            button.disabled = true; button.textContent = enable ? 'Enabling…' : 'Disabling…';
            try {
                const body = new URLSearchParams();
                body.set('csrf', csrfToken); body.set('local_firewall_id', String(link.local.firewall_id));
                body.set('remote_firewall_id', String(link.remote.firewall_id)); body.set('local_client_uuid', link.local.client_uuid);
                body.set('remote_client_uuid', link.remote.client_uuid); body.set('local_expected_peer_key', link.local.expected_peer_key);
                body.set('remote_expected_peer_key', link.remote.expected_peer_key); body.set('enable', enable ? '1' : '0');
                const response = await fetch('/wireguard_link_action.php', {method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
                const result = await response.json(); if (!response.ok || result.ok !== true) throw new Error(result.error || 'Action failed.');
                setNotice(result.message, false); await loadVpn();
            } catch (error) { setNotice(error.message, true); button.disabled = false; button.textContent = enable ? 'Enable both sides' : 'Disable both sides'; }
        });
        box.appendChild(label); box.appendChild(button); return box;
    }

    function showVpnErrors(summary, errors) {
        if (!errors.length) {
            return;
        }

        const errorText = document.createElement('span');
        errorText.className = 'vpn-meta';
        errorText.textContent = errors.join(' | ');
        summary.appendChild(errorText);
    }

    function apiErrors(payload) {
        const errors = [];
        Object.entries(payload || {}).forEach(function ([key, result]) {
            if (!result || result.ok !== true) {
                errors.push(key + ': ' + (result?.error || 'Unavailable'));
            }
        });
        return errors;
    }

    function renderWireGuard(payload) {
        const summary = document.getElementById('wireguard-summary');
        const list = document.getElementById('wireguard-list');
        const raw = document.getElementById('wireguard-raw');
        raw.textContent = JSON.stringify(payload, null, 2);
        summary.textContent = '';
        list.textContent = '';

        const errors = apiErrors(payload);
        const rows = payload?.tunnels?.ok === true
            ? firstArray(payload.tunnels.value)
            : [];
        const interfaces = rows.filter(row => row?.type === 'interface');
        const peers = rows.filter(row => row?.type === 'peer');
        const runtimePeerKeys = new Set(peers.map(row => String(row?.['public-key'] || '')).filter(Boolean));
        const disabledManagedPeers = Object.entries(managedWireGuardLinks)
            .filter(([publicKey, link]) =>
                link?.managed === true &&
                link?.paired_enabled === false &&
                link?.partial_state !== true &&
                !runtimePeerKeys.has(publicKey)
            );
        const partialManagedPeers = Object.entries(managedWireGuardLinks)
            .filter(([publicKey, link]) =>
                link?.managed === true &&
                link?.partial_state === true &&
                !runtimePeerKeys.has(publicKey)
            );
        const onlinePeers = peers.filter(rowIsOnline).length;
        const interfaceUp = interfaces.some(row => normalisedStatus(row.status) === 'up');

        const badge = document.createElement('span');
        badge.className = 'badge ' + (interfaceUp || onlinePeers > 0 ? 'good' : 'bad');
        badge.textContent = peers.length
            ? onlinePeers + ' online / ' + peers.length + ' active peers'
            : (interfaceUp ? 'Interface up · no active peers returned' : 'No active peers returned');
        summary.appendChild(badge);

        const interfaceText = document.createElement('span');
        interfaceText.className = 'vpn-meta';
        interfaceText.textContent = interfaces.length
            ? 'Interface: ' + (interfaceUp ? 'Up' : textValue(interfaces[0], ['status'], 'Unknown'))
            : 'Interface status unavailable';
        summary.appendChild(interfaceText);

        if (disabledManagedPeers.length) {
            const disabledSummary = document.createElement('span');
            disabledSummary.className = 'vpn-meta';
            disabledSummary.textContent = disabledManagedPeers.length + ' managed peer' +
                (disabledManagedPeers.length === 1 ? '' : 's') + ' disabled on both sides';
            summary.appendChild(disabledSummary);
        }

        if (partialManagedPeers.length) {
            const partialSummary = document.createElement('span');
            partialSummary.className = 'vpn-meta';
            partialSummary.textContent = partialManagedPeers.length + ' managed peer' +
                (partialManagedPeers.length === 1 ? '' : 's') + ' in a partial state';
            summary.appendChild(partialSummary);
        }

        showVpnErrors(summary, errors);

        peers.forEach(function (row, index) {
            const online = rowIsOnline(row);
            const handshakeAge = row['latest-handshake-age'];
            const handshakeTime = row['latest-handshake-epoch'];
            const rx = formatBytes(row['transfer-rx']);
            const tx = formatBytes(row['transfer-tx']);
            const meta = [
                row.endpoint ? 'Endpoint: ' + row.endpoint : '',
                row['allowed-ips'] ? 'Networks: ' + row['allowed-ips'] : '',
                handshakeTime ? 'Last handshake: ' + handshakeTime : '',
                handshakeAge !== null && handshakeAge !== undefined ? 'Age: ' + handshakeAge + ' s' : '',
                rx ? 'RX: ' + rx : '',
                tx ? 'TX: ' + tx : ''
            ].filter(Boolean).join(' · ');

            appendVpnRow(list, {
                name: textValue(row, ['name', 'ifname'], 'WireGuard peer ' + (index + 1)),
                online: online,
                status: online ? 'Online' : 'Offline',
                meta: meta,
                actions: managedWireGuardActions(row)
            });
        });

        if (disabledManagedPeers.length) {
            const heading = document.createElement('h4');
            heading.className = 'vpn-section-title';
            heading.textContent = 'Disabled peers';
            list.appendChild(heading);

            disabledManagedPeers.forEach(function ([publicKey, link]) {
                appendVpnRow(list, {
                    name: link.local.client_name || ('Managed peer to ' + link.remote.firewall_name),
                    online: false,
                    statusClass: 'neutral',
                    status: 'Disabled on both sides',
                    meta: link.local.firewall_name + ' ↔ ' + link.remote.firewall_name,
                    actions: managedWireGuardActions({'public-key': publicKey})
                });
            });
        }

        if (partialManagedPeers.length) {
            const heading = document.createElement('h4');
            heading.className = 'vpn-section-title';
            heading.textContent = 'Needs attention';
            list.appendChild(heading);

            partialManagedPeers.forEach(function ([publicKey, link]) {
                appendVpnRow(list, {
                    name: link.local.client_name || ('Managed peer to ' + link.remote.firewall_name),
                    online: false,
                    statusClass: 'bad',
                    status: 'Partial state',
                    meta: link.local.firewall_name + ': ' + (link.local.enabled ? 'enabled' : 'disabled') +
                        ' · ' + link.remote.firewall_name + ': ' + (link.remote.enabled ? 'enabled' : 'disabled'),
                    actions: managedWireGuardActions({'public-key': publicKey})
                });
            });
        }

        if (!peers.length && !disabledManagedPeers.length && !partialManagedPeers.length) {
            list.textContent = 'No WireGuard peers returned.';
            list.className = 'vpn-list vpn-empty';
        } else {
            list.className = 'vpn-list';
        }
    }

    function renderIpsec(payload) {
        const summary = document.getElementById('ipsec-summary');
        const list = document.getElementById('ipsec-list');
        const raw = document.getElementById('ipsec-raw');
        raw.textContent = JSON.stringify(payload, null, 2);
        summary.textContent = '';
        list.textContent = '';
        list.className = 'vpn-list';

        const errors = apiErrors(payload);
        const serviceStatus = normalisedStatus(payload?.service?.value?.status);
        const phase1 = payload?.phase1?.ok === true ? firstArray(payload.phase1.value) : [];
        const phase2 = payload?.phase2?.ok === true ? firstArray(payload.phase2.value) : [];
        const disabled = serviceStatus === 'disabled';
        const establishedP1 = phase1.filter(rowIsOnline).length;
        const establishedP2 = phase2.filter(rowIsOnline).length;

        const badge = document.createElement('span');
        badge.className = 'badge ' + (disabled ? 'neutral' : (establishedP1 || establishedP2 ? 'good' : 'bad'));
        badge.textContent = disabled
            ? 'Disabled'
            : 'Phase 1: ' + establishedP1 + '/' + phase1.length +
              ' · Phase 2: ' + establishedP2 + '/' + phase2.length;
        summary.appendChild(badge);
        showVpnErrors(summary, errors);

        const rows = phase1.map(row => ({...row, _phase: 'Phase 1'}))
            .concat(phase2.map(row => ({...row, _phase: 'Phase 2'})));

        rows.forEach(function (row, index) {
            const online = rowIsOnline(row);
            appendVpnRow(list, {
                name: textValue(row, ['description', 'name', 'connection', 'id'], row._phase + ' ' + (index + 1)),
                online: online,
                status: online ? 'Established' : textValue(row, ['status', 'state'], 'Not established'),
                meta: [
                    row._phase,
                    textValue(row, ['remote', 'remote_host', 'remote_address', 'peer'])
                        ? 'Remote: ' + textValue(row, ['remote', 'remote_host', 'remote_address', 'peer'])
                        : ''
                ].filter(Boolean).join(' · ')
            });
        });

        if (!rows.length) {
            list.className = 'vpn-list vpn-empty';
            list.textContent = disabled
                ? 'IPsec is disabled and no Phase 1 or Phase 2 sessions are active.'
                : 'No active IPsec Phase 1 or Phase 2 sessions returned.';
        }
    }

    function isRoadwarriorSession(row) {
        const description = normalisedStatus(row?.description);
        const username = String(row?.username ?? '').trim();
        return description.includes('roadwarrior') ||
            description.includes('road warrior') ||
            username !== '' ||
            row?.is_client === true;
    }

    function openVpnRemoteHost(value) {
        let remote = String(value ?? '').trim()
            .replace(/^(udp|tcp)(4|6)?:/i, '');

        if (remote.startsWith('[')) {
            const closingBracket = remote.indexOf(']');
            return closingBracket > 0
                ? remote.substring(1, closingBracket)
                : remote;
        }

        const colonCount = (remote.match(/:/g) || []).length;
        if (colonCount === 1) {
            return remote.substring(0, remote.lastIndexOf(':'));
        }

        return remote;
    }

    function roadwarriorStatistics(rows) {
        const usernames = new Set();
        const publicAddresses = new Set();
        const virtualAddresses = new Set();

        rows.forEach(function (row) {
            const username = String(row?.username ?? '').trim();
            const publicAddress = openVpnRemoteHost(row?.real_address);
            const virtualAddress = String(row?.virtual_address ?? '').trim();

            if (username) usernames.add(username);
            if (publicAddress) publicAddresses.add(publicAddress);
            if (virtualAddress) virtualAddresses.add(virtualAddress);
        });

        return {
            records: rows.length,
            usernames: usernames.size,
            publicAddresses: publicAddresses.size,
            virtualAddresses: virtualAddresses.size
        };
    }

    function renderOpenVpn(payload) {
        const summary = document.getElementById('openvpn-summary');
        const list = document.getElementById('openvpn-list');
        const raw = document.getElementById('openvpn-raw');
        raw.textContent = JSON.stringify(payload, null, 2);
        summary.textContent = '';
        list.textContent = '';
        list.className = 'vpn-list';

        const errors = apiErrors(payload);
        const sessions = payload?.sessions?.ok === true
            ? firstArray(payload.sessions.value)
            : [];
        const roadwarriors = sessions.filter(isRoadwarriorSession);
        const roadwarriorStats = roadwarriorStatistics(roadwarriors);
        const siteToSite = sessions.filter(row => !isRoadwarriorSession(row));
        const onlineSiteToSite = siteToSite.filter(rowIsOnline).length;

        const badge = document.createElement('span');
        badge.className = 'badge ' + (onlineSiteToSite > 0 ? 'good' : 'neutral');
        badge.textContent = 'Site-to-site: ' + onlineSiteToSite + '/' + siteToSite.length +
            ' · Roadwarrior records: ' + roadwarriorStats.records;
        summary.appendChild(badge);
        showVpnErrors(summary, errors);

        siteToSite.forEach(function (row, index) {
            const online = rowIsOnline(row);
            appendVpnRow(list, {
                name: textValue(row, ['description', 'common_name', 'id'], 'OpenVPN tunnel ' + (index + 1)),
                online: online,
                status: online ? 'Connected' : textValue(row, ['status', 'state'], 'Status unknown'),
                meta: [
                    row.real_address ? 'Remote: ' + row.real_address : '',
                    row.virtual_address ? 'Tunnel address: ' + row.virtual_address : '',
                    row.connected_since ? 'Connected since: ' + row.connected_since : ''
                ].filter(Boolean).join(' · ')
            });
        });

        if (!siteToSite.length) {
            const empty = document.createElement('div');
            empty.className = 'vpn-empty';
            empty.textContent = 'No OpenVPN site-to-site sessions detected.';
            list.appendChild(empty);
        }

        if (roadwarriors.length) {
            const rw = document.createElement('div');
            rw.className = 'vpn-row';
            const title = document.createElement('strong');
            title.textContent = 'Roadwarrior sessions';
            const rwBadge = document.createElement('span');
            rwBadge.className = 'badge neutral';
            rwBadge.textContent = roadwarriorStats.records + ' session records';
            const meta = document.createElement('div');
            meta.className = 'vpn-meta';
            meta.textContent =
                roadwarriorStats.usernames + ' unique username' +
                (roadwarriorStats.usernames === 1 ? '' : 's') + ' · ' +
                roadwarriorStats.publicAddresses + ' unique public IP' +
                (roadwarriorStats.publicAddresses === 1 ? '' : 's') + ' · ' +
                roadwarriorStats.virtualAddresses + ' unique virtual IP' +
                (roadwarriorStats.virtualAddresses === 1 ? '' : 's') +
                '. Route records are excluded.';
            rw.appendChild(title);
            rw.appendChild(rwBadge);
            rw.appendChild(meta);
            list.appendChild(rw);
        }
    }

    function renderVpnType(type, payload) {
        if (type === 'wireguard') {
            renderWireGuard(payload);
        } else if (type === 'ipsec') {
            renderIpsec(payload);
        } else if (type === 'openvpn') {
            renderOpenVpn(payload);
        }
    }

    async function loadManagedWireGuardLinks() {
        try {
            const response = await fetch('/wireguard_links.php?id=' + encodeURIComponent(firewallId), {
                credentials: 'same-origin', cache: 'no-store'
            });
            const result = await response.json();
            managedWireGuardLinks = response.ok && result.ok === true ? (result.links || {}) : {};
        } catch (error) {
            managedWireGuardLinks = {};
        }
    }

    async function loadVpn() {
        const state = document.getElementById('vpn-state');
        const button = document.getElementById('vpn-refresh-button');

        state.className = 'live-status loading';
        state.textContent = 'Loading WireGuard, IPsec and OpenVPN status…';
        button.disabled = true;

        try {
            const linksPromise = loadManagedWireGuardLinks();
            const responsePromise = fetch(
                '/vpn_status.php?id=' + encodeURIComponent(firewallId) +
                '&type=all',
                {
                    credentials: 'same-origin',
                    cache: 'no-store'
                }
            );

            const [, response] = await Promise.all([
                linksPromise,
                responsePromise
            ]);

            const responseText = await response.text();
            let result;

            try {
                result = JSON.parse(responseText);
            } catch (error) {
                throw new Error(
                    'Server returned invalid JSON: ' +
                    responseText.replace(/\s+/g, ' ').trim().slice(0, 500)
                );
            }

            if (!response.ok || result.ok !== true) {
                throw new Error(result.error || 'HTTP ' + response.status);
            }

            renderVpnType('wireguard', result.data.wireguard || {});
            renderVpnType('ipsec', result.data.ipsec || {});
            renderVpnType('openvpn', result.data.openvpn || {});

            state.className = 'live-status good';
            state.textContent = 'VPN status loaded.';
        } catch (error) {
            state.className = 'live-status bad';
            state.textContent = error.message;

            ['wireguard', 'ipsec', 'openvpn'].forEach(function (type) {
                document.getElementById(type + '-summary').textContent =
                    tr['common.unavailable'];
                document.getElementById(type + '-list').textContent = '';
                document.getElementById(type + '-raw').textContent =
                    error.message;
            });
        } finally {
            button.disabled = false;
        }
    }

    document.getElementById('vpn-refresh-button')
        ?.addEventListener('click', loadVpn);


    loadSystem();
    loadFirmware();
    loadVpn();
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
