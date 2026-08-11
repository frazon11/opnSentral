<?php

require_once __DIR__ . '/inc/config.php';

require_login();

$firewalls = db()
    ->query('SELECT * FROM firewalls ORDER BY name')
    ->fetchAll();

require __DIR__ . '/inc/header.php';

?>

<style>
.view-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.view-switch{display:inline-flex;gap:4px;padding:4px;border:1px solid rgba(127,127,127,.25);border-radius:10px;background:rgba(127,127,127,.08)}
.view-switch button{border:0;border-radius:7px;padding:8px 12px;cursor:pointer;background:transparent;color:inherit}
.view-switch button.active{background:rgba(127,127,127,.2);font-weight:700}
.firewall-list{display:grid;gap:16px;align-items:stretch}
.view-cards .firewall-list{grid-template-columns:repeat(3,minmax(0,1fr))}
.view-compact .firewall-list{display:grid;grid-template-columns:1fr;gap:7px}
.view-compact .firewall-card{
    display:grid;
    grid-template-columns:minmax(260px,1.5fr) minmax(190px,.9fr) minmax(220px,1fr) auto;
    gap:14px;
    align-items:center;
    padding:10px 12px;
}
.view-compact .firewall-card .card-head{margin:0;align-items:center}
.view-compact .firewall-card .card-head h2{margin:0 0 2px;font-size:1.05rem}
.view-compact .firewall-card .card-head a{font-size:.82rem}
.view-compact .firewall-card .status-badge{margin-left:8px}
.view-compact .firewall-card dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:8px;align-items:center}
.view-compact .firewall-card dl dt{margin:0;font-size:.78rem;color:var(--muted)}
.view-compact .firewall-card dl dd{margin:0}
.view-compact .firewall-card .update-status-panel{margin:0;padding:7px 9px}
.view-compact .firewall-card .update-status-panel strong{font-size:.72rem;margin-bottom:2px;color:var(--muted)}
.view-compact .firewall-card .firmware-message{display:none}
.view-compact .firewall-card .actions{display:flex;margin:0;gap:5px;justify-content:flex-end;align-items:center}
.view-compact .firewall-card .actions button,
.view-compact .firewall-card .actions .button{width:auto;min-width:auto;padding:6px 8px;white-space:nowrap;font-size:.78rem}
.view-compact .firewall-card .refresh-one,
.view-compact .firewall-card .backup-one,
.view-compact .firewall-card .card-update-button,
.view-compact .firewall-card a[href^="/firewall_edit.php"]{display:none!important}
.firewall-card{display:flex;flex-direction:column;min-width:0}
.firewall-card .card-head{align-items:flex-start}
.firewall-card .card-head>div{min-width:0}
.firewall-card .card-head h2{overflow-wrap:anywhere}
.firewall-card .card-head a{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.firewall-card .actions{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:auto;align-items:stretch}
.firewall-card .actions button,.firewall-card .actions .button{width:100%;min-width:0;padding:8px 6px;text-align:center;white-space:normal;line-height:1.15}
.status-loading{opacity:.65}
.update-status-panel{padding:10px;border-radius:7px;background:rgba(127,127,127,.08);min-width:0;margin:10px 0}
.update-status-panel strong{display:block;font-size:.82rem;margin-bottom:4px}
.update-status-value{display:block}
.card-update-button.hidden{display:none}
.card-message{font-size:.9rem;opacity:.78;margin:8px 0 14px;min-height:3.4em}
@media(min-width:2100px){
    .view-cards .firewall-list{grid-template-columns:repeat(4,minmax(0,1fr))}
}
@media(max-width:1250px){
    .view-cards .firewall-list{grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media(max-width:1250px){
    .view-compact .firewall-card{grid-template-columns:minmax(220px,1fr) minmax(180px,1fr)}
    .view-compact .firewall-card .actions{justify-content:flex-start}
}
@media(max-width:760px){
    .view-cards .firewall-list{grid-template-columns:1fr}
    .firewall-card .actions{grid-template-columns:repeat(2,minmax(0,1fr))}
    .view-compact .firewall-card{display:flex;flex-direction:column;align-items:stretch}
    .view-compact .firewall-card .actions{display:flex;justify-content:flex-start}
}
</style>

<div class="page-title">
    <div>
        <h1><?= h(t('dashboard.title')) ?></h1>
        <p><?= h(t('dashboard.subtitle')) ?></p>
    </div>

    <div class="view-toolbar">
        <div class="view-switch">
            <button type="button" data-view="cards"><?= h(t('common.cards')) ?></button>
            <button type="button" data-view="compact"><?= h(t('common.compact')) ?></button>
        </div>

        <button type="button" class="button secondary" id="refresh-all">
            <?= h(t('common.refresh_status')) ?>
        </button>

        <a class="button" href="/firewall_edit.php">
            <?= h(t('menu.add_firewall')) ?>
        </a>
    </div>
</div>

<div id="firewall-dashboard" class="view-cards">
<?php if (!$firewalls): ?>
    <div class="empty"><?= h(t('dashboard.none')) ?></div>
<?php else: ?>
    <div class="firewall-list">
        <?php foreach ($firewalls as $firewall): ?>
            <article
                class="card firewall-card"
                data-firewall-id="<?= (int) $firewall['id'] ?>"
            >
                <div class="card-head">
                    <div>
                        <h2><?= h((string) $firewall['name']) ?></h2>
                        <a
                            class="muted"
                            target="_blank"
                            rel="noopener"
                            href="<?= h((string) $firewall['base_url']) ?>"
                        >
                            <?= h((string) $firewall['base_url']) ?>
                        </a>
                    </div>

                    <span class="badge status-badge">Loading</span>
                </div>

                <dl>
                    <dt><?= h(t('common.system')) ?></dt>
                    <dd class="system-value status-loading"><?= h(t('common.loading')) ?></dd>
                </dl>

                <div class="update-status-panel">
                    <strong>Update status</strong>
                    <span class="update-status-value status-loading"><?= h(t('common.loading')) ?></span>
                </div>

                <div class="card-message firmware-message">
                    Loading firmware status…
                </div>

                <div class="actions">
                    <button type="button" class="button secondary refresh-one">
                        Refresh
                    </button>

                    <button type="button" class="button secondary backup-one">
                        Backup now
                    </button>

                    <button
                        type="button"
                        class="warning card-update-button hidden"
                    >
                        Update now
                    </button>

                    <a
                        class="button secondary"
                        href="/firewall_view.php?id=<?= (int) $firewall['id'] ?>"
                    >
                        Details
                    </a>

                    <a
                        class="button secondary"
                        href="/plugins.php?firewall_id=<?= (int) $firewall['id'] ?>"
                    >
                        Plugins
                    </a>

                    <a
                        class="button secondary"
                        href="/firewall_edit.php?id=<?= (int) $firewall['id'] ?>"
                    >
                        Edit
                    </a>
                </div>
            </article>
        <?php endforeach; ?>
    </div>
<?php endif; ?>
</div>

<script>
(function () {
    const tr = {"common.loading_short":<?= json_encode(t('common.loading_short'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.loading":<?= json_encode(t('common.loading'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.online":<?= json_encode(t('common.online'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.offline":<?= json_encode(t('common.offline'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.reachable":<?= json_encode(t('common.reachable'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.unavailable":<?= json_encode(t('common.unavailable'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.unknown":<?= json_encode(t('common.unknown'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.not_checked":<?= json_encode(t('common.not_checked'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.no_update":<?= json_encode(t('common.no_update'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.update_available":<?= json_encode(t('common.update_available'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.update_now":<?= json_encode(t('common.update_now'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"common.upgrade_now":<?= json_encode(t('common.upgrade_now'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.loading_firmware":<?= json_encode(t('dashboard.loading_firmware'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.start_update_confirm":<?= json_encode(t('dashboard.start_update_confirm'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.start_upgrade_confirm":<?= json_encode(t('dashboard.start_upgrade_confirm'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.starting_update":<?= json_encode(t('dashboard.starting_update'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.starting_upgrade":<?= json_encode(t('dashboard.starting_upgrade'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"dashboard.action_started":<?= json_encode(t('dashboard.action_started'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"details.loading_system":<?= json_encode(t('details.loading_system'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"details.loading_firmware":<?= json_encode(t('details.loading_firmware'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>,"details.loading_vpn":<?= json_encode(t('details.loading_vpn'), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>};
    const csrfToken = <?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>;
    const dashboard = document.getElementById('firewall-dashboard');
    const cards = [...document.querySelectorAll('.firewall-card')];
    const viewButtons = document.querySelectorAll('[data-view]');
    const viewKey = 'opncentral-dashboard-view';

    function applyView(view) {
        if (!['cards', 'compact'].includes(view)) {
            view = 'cards';
        }

        dashboard.className = 'view-' + view;

        viewButtons.forEach(function (button) {
            button.classList.toggle('active', button.dataset.view === view);
        });

        localStorage.setItem(viewKey, view);
    }

    async function fetchType(id, type) {
        const response = await fetch(
            '/firewall_status.php?id=' +
            encodeURIComponent(id) +
            '&type=' +
            encodeURIComponent(type),
            {credentials: 'same-origin', cache: 'no-store'}
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

    async function runAction(id, action) {
        const body = new URLSearchParams();
        body.set('csrf', csrfToken);
        body.set('id', String(id));
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

    function setLoading(card) {
        card.querySelector('.status-badge').textContent = tr['common.loading_short'];
        card.querySelector('.status-badge').className = 'badge status-badge';
        card.querySelector('.system-value').textContent = tr['common.loading'];
        card.querySelector('.update-status-value').textContent = tr['common.loading'];
        card.querySelector('.firmware-message').textContent =
            tr['dashboard.loading_firmware'];
        card.querySelector('.card-update-button').classList.add('hidden');
        card.dataset.firmwareAction = '';
    }

    async function loadCard(card) {
        const id = card.dataset.firewallId;
        setLoading(card);

        const [systemResult, firmwareResult] = await Promise.allSettled([
            fetchType(id, 'system'),
            fetchType(id, 'firmware')
        ]);

        const badge = card.querySelector('.status-badge');
        const system = card.querySelector('.system-value');
        const updateStatus = card.querySelector('.update-status-value');
        const message = card.querySelector('.firmware-message');
        const updateButton = card.querySelector('.card-update-button');

        const systemOk =
            systemResult.status === 'fulfilled' &&
            systemResult.value?.ok === true;

        const firmwareOk =
            firmwareResult.status === 'fulfilled' &&
            firmwareResult.value?.ok === true;

        if (systemOk || firmwareOk) {
            badge.className = 'badge status-badge good';
            badge.textContent = tr['common.online'];
        } else {
            badge.className = 'badge status-badge bad';
            badge.textContent = tr['common.offline'];
        }

        if (firmwareOk) {
            const summary = firmwareResult.value.summary || {};
            const currentVersion =
                summary.current_version || tr['common.unknown'];

            system.textContent = currentVersion === tr['common.unknown']
                ? 'OPNsense'
                : 'OPNsense ' + currentVersion;

            updateStatus.textContent = summary.update_available
                ? (summary.available_version || tr['common.update_available'])
                : (summary.checked ? tr['common.no_update'] : tr['common.not_checked']);

            message.textContent = summary.message || '';

            if (summary.update_available && summary.action) {
                card.dataset.firmwareAction = summary.action;
                updateButton.textContent =
                    summary.action_label || tr['common.update_now'];
                updateButton.classList.remove('hidden');
            }
        } else {
            const firmwareError = firmwareResult.status === 'rejected'
                ? firmwareResult.reason.message
                : (firmwareResult.value?.error || tr['common.unavailable']);

            if (systemOk) {
                const value = systemResult.value.value || {};
                const rawVersion =
                    value.version ||
                    value.product_version ||
                    value.status ||
                    value.result ||
                    value.message ||
                    'OPNsense';

                system.textContent = String(rawVersion).startsWith('OPNsense')
                    ? String(rawVersion)
                    : 'OPNsense ' + rawVersion;

                updateStatus.textContent = tr['common.unavailable'];
                message.textContent = firmwareError;
            } else {
                const systemError = systemResult.status === 'rejected'
                    ? systemResult.reason.message
                    : (systemResult.value?.error || tr['common.unavailable']);

                system.textContent = systemError;
                updateStatus.textContent = tr['common.unavailable'];
                message.textContent = firmwareError;
            }
        }
    }

    async function backupFromCard(card) {
        const id = card.dataset.firewallId;
        const button = card.querySelector('.backup-one');

        if (!confirm('Create a configuration backup for this firewall now?')) {
            return;
        }

        const originalText = button.textContent;
        button.disabled = true;
        button.textContent = 'Backing up…';

        try {
            const body = new URLSearchParams();
            body.set('csrf', csrfToken);
            body.set('action', 'backup_one');
            body.set('firewall_id', String(id));

            const response = await fetch('/backups_action.php', {
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
                throw new Error(result.error || 'Backup failed.');
            }

            const download = confirm(
                result.message + '\n\nDownload this backup now?'
            );

            if (download && result.download_url) {
                window.location.href = result.download_url;
            }
        } catch (error) {
            alert(error.message);
        } finally {
            button.disabled = false;
            button.textContent = originalText;
        }
    }

    async function installFromCard(card) {
        const id = card.dataset.firewallId;
        const action = card.dataset.firmwareAction;

        if (!action) {
            return;
        }

        const major = action === 'firmware_upgrade';

        if (!confirm(
            major
                ? 'Start the major OPNsense upgrade now? The firewall will reboot and may be unavailable for an extended period.'
                : 'Install the available OPNsense update now? The firewall may reboot.'
        )) {
            return;
        }

        const button = card.querySelector('.card-update-button');
        button.disabled = true;
        button.textContent = major ? 'Starting upgrade…' : 'Starting update…';

        try {
            const result = await runAction(id, action);
            alert(result.message || 'Firmware action started.');
            button.classList.add('hidden');
        } catch (error) {
            alert(error.message);
        } finally {
            button.disabled = false;
        }
    }

    function loadAll() {
        cards.forEach(function (card, index) {
            setTimeout(function () {
                loadCard(card);
            }, index * 150);
        });
    }

    viewButtons.forEach(function (button) {
        button.addEventListener('click', function () {
            applyView(button.dataset.view);
        });
    });

    cards.forEach(function (card) {
        card.querySelector('.refresh-one')
            ?.addEventListener('click', function () {
                loadCard(card);
            });

        card.querySelector('.backup-one')
            ?.addEventListener('click', function () {
                backupFromCard(card);
            });

        card.querySelector('.card-update-button')
            ?.addEventListener('click', function () {
                installFromCard(card);
            });
    });

    document.getElementById('refresh-all')
        ?.addEventListener('click', loadAll);

    applyView(localStorage.getItem(viewKey) || 'cards');
    loadAll();
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
