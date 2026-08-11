<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();

$firewalls = db()
    ->query('SELECT id,name,base_url FROM firewalls ORDER BY name')
    ->fetchAll();

$firewallId = (int) ($_GET['firewall_id'] ?? 0);

$selectedFirewall = null;
foreach ($firewalls as $firewall) {
    if ((int) $firewall['id'] === $firewallId) {
        $selectedFirewall = $firewall;
        break;
    }
}

require __DIR__ . '/inc/header.php';
?>

<div class="page-title plugin-page-title">
    <div>
        <h1>
            <?= $selectedFirewall
                ? h((string) $selectedFirewall['name']) . ' · Plugins'
                : 'Plugins' ?>
        </h1>
        <p>
            <?= $selectedFirewall
                ? h((string) $selectedFirewall['base_url'])
                : 'No firewall configured.' ?>
        </p>
    </div>

    <div class="plugin-toolbar">
        <?php if ($selectedFirewall): ?>
            <a
                class="button secondary"
                href="/firewall_view.php?id=<?= (int) $selectedFirewall['id'] ?>"
            >
                Back to details
            </a>
        <?php endif; ?>

        <button type="button" class="button secondary" id="refresh">
            Check for plugins
        </button>
    </div>
</div>

<?php if (!$selectedFirewall): ?>
    <div class="empty">No firewall configured.</div>
<?php else: ?>

<div class="plugin-list-card card">
    <div class="plugin-list-toolbar">
        <div>
            <strong>Plugins</strong>
            <span id="plugin-summary" class="muted">Loading…</span>
        </div>

        <label class="plugin-search">
            <span>Search</span>
            <input
                type="search"
                id="plugin-search"
                placeholder="Filter plugins"
                autocomplete="off"
            >
        </label>
    </div>

    <div id="plugin-error" class="alert error hidden"></div>

    <div class="table-scroll">
        <table class="opnsense-plugin-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Version</th>
                    <th>Comment</th>
                    <th>Status</th>
                    <th class="plugin-action-column">Actions</th>
                </tr>
            </thead>
            <tbody id="plugin-body">
                <tr>
                    <td colspan="5">Loading plugin inventory…</td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<div class="alert warning plugin-safety">
    Install, reinstall and remove create a configuration backup first.
    Only packages beginning with <code>os-</code> can be managed.
</div>

<div class="card">
    <h2>Recent plugin jobs</h2>
    <div id="jobs">Loading…</div>
</div>

<script>
(function(){
    const firewallId = <?= (int) $firewallId ?>;
    const csrf = <?= json_encode(
        csrf_token(),
        JSON_UNESCAPED_SLASHES
    ) ?>;

    const body = document.getElementById('plugin-body');
    const summary = document.getElementById('plugin-summary');
    const errorBox = document.getElementById('plugin-error');
    const refresh = document.getElementById('refresh');
    const search = document.getElementById('plugin-search');
    const jobs = document.getElementById('jobs');

    let plugins = [];

    function escapeHtml(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
    }

    function statusMarkup(plugin){
        if(plugin.locked){
            return '<span class="badge warning">Locked</span>';
        }

        if(plugin.installed){
            return '<span class="badge good">Installed</span>';
        }

        return '<span class="badge neutral">Available</span>';
    }

    function actionMarkup(plugin){
        const pkg = escapeHtml(plugin.name);

        if(!plugin.installed){
            return `
                <button
                    class="plugin-icon-action install"
                    data-op="install"
                    data-pkg="${pkg}"
                    title="Install"
                    aria-label="Install ${pkg}"
                >＋</button>
            `;
        }

        return `
            <button
                class="plugin-icon-action"
                data-op="reinstall"
                data-pkg="${pkg}"
                title="Reinstall"
                aria-label="Reinstall ${pkg}"
            >↻</button>
            <button
                class="plugin-icon-action"
                data-op="${plugin.locked ? 'unlock' : 'lock'}"
                data-pkg="${pkg}"
                title="${plugin.locked ? 'Unlock' : 'Lock'}"
                aria-label="${plugin.locked ? 'Unlock' : 'Lock'} ${pkg}"
            >${plugin.locked ? '🔓' : '🔒'}</button>
            <button
                class="plugin-icon-action remove"
                data-op="remove"
                data-pkg="${pkg}"
                title="Remove"
                aria-label="Remove ${pkg}"
            >×</button>
        `;
    }

    function render(){
        const phrase = search.value.trim().toLowerCase();

        const filtered = plugins.filter(function(plugin){
            return (
                String(plugin.name || '').toLowerCase().includes(phrase) ||
                String(plugin.description || '').toLowerCase().includes(phrase)
            );
        });

        summary.textContent =
            filtered.length === plugins.length
                ? `${plugins.length} entries`
                : `${filtered.length} of ${plugins.length} entries`;

        body.innerHTML = filtered.length
            ? filtered.map(function(plugin){
                const installedVersion = plugin.installed
                    ? (plugin.version || 'installed')
                    : '—';

                const availableVersion =
                    plugin.available_version &&
                    plugin.available_version !== plugin.version
                        ? `<small>Available: ${
                            escapeHtml(plugin.available_version)
                        }</small>`
                        : '';

                return `
                    <tr>
                        <td class="plugin-name">
                            <strong>${escapeHtml(plugin.name)}</strong>
                        </td>
                        <td>
                            ${escapeHtml(installedVersion)}
                            ${availableVersion}
                        </td>
                        <td>${escapeHtml(plugin.description || '')}</td>
                        <td>${statusMarkup(plugin)}</td>
                        <td class="plugin-row-actions">
                            ${actionMarkup(plugin)}
                        </td>
                    </tr>
                `;
            }).join('')
            : '<tr><td colspan="5">No matching plugins.</td></tr>';

        body.querySelectorAll('[data-op]').forEach(function(button){
            button.addEventListener('click', function(){
                runAction(button);
            });
        });
    }

    async function readJson(response){
        const raw = await response.text();

        try{
            return JSON.parse(raw);
        }catch(parseError){
            throw new Error(
                'Server returned invalid JSON: ' +
                raw.replace(/\s+/g, ' ').trim().slice(0, 700)
            );
        }
    }

    async function load(force){
        refresh.disabled = true;

        try{
            const url = new URL(
                '/plugins_data.php',
                window.location.origin
            );
            url.searchParams.set('firewall_id', String(firewallId));

            if(force){
                url.searchParams.set('force', '1');
            }

            const response = await fetch(url, {
                credentials: 'same-origin',
                cache: 'no-store'
            });
            const data = await readJson(response);

            if(!response.ok || data.ok !== true){
                throw new Error(data.error || 'Plugin inventory failed.');
            }

            const firewall = data.firewalls?.[0];

            if(!firewall){
                throw new Error('No plugin inventory returned.');
            }

            if(firewall.ok !== true){
                throw new Error(firewall.error || 'Firewall unavailable.');
            }

            plugins = Array.isArray(firewall.plugins)
                ? firewall.plugins
                : [];

            render();
            errorBox.classList.add('hidden');
            errorBox.textContent = '';

            if(data.cache?.refresh_recommended){
                window.setTimeout(function(){
                    load(true);
                }, 200);
            }
        }catch(error){
            body.innerHTML =
                '<tr><td colspan="5">Could not load plugin inventory.</td></tr>';
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
        }finally{
            refresh.disabled = false;
        }
    }

    async function runAction(button){
        const operation = button.dataset.op;
        const packageName = button.dataset.pkg;
        const backupRequired = [
            'install',
            'reinstall',
            'remove'
        ].includes(operation);

        const prompt =
            operation.toUpperCase() + ' ' + packageName + '?' +
            (backupRequired
                ? '\n\nA configuration backup will be created first.'
                : '');

        if(!confirm(prompt)){
            return;
        }

        button.disabled = true;

        const form = new URLSearchParams({
            csrf,
            firewall_id: String(firewallId),
            package: packageName,
            operation
        });

        try{
            const response = await fetch('/plugin_action.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: {
                    'Content-Type':
                        'application/x-www-form-urlencoded;charset=UTF-8'
                },
                body: form
            });
            const data = await readJson(response);

            if(!response.ok || data.ok !== true){
                throw new Error(data.error || 'Plugin action failed.');
            }

            alert(data.message);
            await load(true);
            await loadJobs();
        }catch(error){
            alert(error.message);
        }finally{
            button.disabled = false;
        }
    }

    async function loadJobs(){
        try{
            const url = new URL(
                '/plugin_jobs_data.php',
                window.location.origin
            );
            url.searchParams.set('firewall_id', String(firewallId));

            const response = await fetch(url, {
                credentials: 'same-origin',
                cache: 'no-store'
            });
            const data = await readJson(response);

            if(!response.ok || data.ok !== true){
                throw new Error(data.error || 'Could not load jobs.');
            }

            jobs.innerHTML = data.jobs.length
                ? `
                    <div class="table-scroll">
                        <table>
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Operation</th>
                                    <th>Plugin</th>
                                    <th>Status</th>
                                    <th>Backup</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${data.jobs.map(function(job){
                                    return `
                                        <tr>
                                            <td>${escapeHtml(job.created_at)}</td>
                                            <td>${escapeHtml(job.operation)}</td>
                                            <td>
                                                <code>${
                                                    escapeHtml(job.package_name)
                                                }</code>
                                            </td>
                                            <td>${escapeHtml(job.status)}</td>
                                            <td>${
                                                job.backup_id
                                                    ? '#' + Number(job.backup_id)
                                                    : '—'
                                            }</td>
                                        </tr>
                                    `;
                                }).join('')}
                            </tbody>
                        </table>
                    </div>
                `
                : 'No plugin jobs for this firewall.';
        }catch(error){
            jobs.textContent = error.message;
        }
    }

    search.addEventListener('input', render);
    refresh.addEventListener('click', function(){
        load(true);
    });

    load(false);
    loadJobs();
    window.setInterval(loadJobs, 10000);
})();
</script>

<?php endif; ?>

<?php require __DIR__ . '/inc/footer.php'; ?>
