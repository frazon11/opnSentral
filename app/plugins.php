<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();

$firewalls = db()
    ->query('SELECT id,name,base_url FROM firewalls ORDER BY name')
    ->fetchAll();

require __DIR__ . '/inc/header.php';
?>

<style>
.plugin-fleet-toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:12px}
.plugin-fleet-toolbar .actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.plugin-fleet-search{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.plugin-fleet-search input[type=search]{min-width:260px;margin:0}
.plugin-fleet-table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.plugin-fleet-table{border-collapse:separate;border-spacing:0;min-width:max(1050px,100%);width:100%}
.plugin-fleet-table th,.plugin-fleet-table td{padding:10px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:middle;text-align:center}
.plugin-fleet-table th:last-child,.plugin-fleet-table td:last-child{border-right:0}
.plugin-fleet-table tr:last-child td{border-bottom:0}
.plugin-fleet-table thead th{position:sticky;top:0;z-index:3;background:var(--table-head)}
.plugin-fleet-table .plugin-col{position:sticky;left:0;z-index:2;text-align:left;min-width:310px;background:var(--card)}
.plugin-fleet-table thead .plugin-col{z-index:4;background:var(--table-head)}
.plugin-fleet-table .all-col{min-width:120px}
.plugin-fleet-firewall{min-width:150px}
.plugin-fleet-firewall strong{display:block}
.plugin-fleet-firewall small{display:block;margin-top:3px;color:var(--muted);font-weight:400}
.plugin-meta strong{display:block}.plugin-meta small{display:block;margin-top:4px;color:var(--muted);font-weight:400;line-height:1.3}
.plugin-cell{min-width:150px}
.plugin-cell .version{display:block;margin-top:4px;font-size:.76rem;color:var(--muted)}
.plugin-install{white-space:nowrap}
.plugin-result{margin-top:14px}.plugin-result-grid{display:grid;gap:7px;margin-top:8px}
.plugin-result-item{padding:9px 11px;border-radius:6px;background:rgba(127,127,127,.08)}
.plugin-result-item.good{border-left:4px solid #2aa84a}.plugin-result-item.bad{border-left:4px solid #d74747}
@media(max-width:850px){.plugin-fleet-toolbar{align-items:flex-start;flex-direction:column}.plugin-fleet-search input[type=search]{min-width:0;width:100%}}
</style>

<div class="page-title">
    <div>
        <h1>System → Firmware → Plugins</h1>
        <p>Compare installed OPNsense plugins across all managed firewalls and install a plugin on one or all compatible targets.</p>
    </div>
</div>

<div class="alert warningbox">
    <strong>Plugin installation creates a pre-change backup.</strong>
    Only OPNsense packages beginning with <code>os-</code> are managed. The <strong>Install on all</strong> action targets only firewalls where the plugin is available and not already installed.
</div>

<div class="plugin-fleet-toolbar">
    <div class="plugin-fleet-search">
        <input type="search" id="plugin-search" placeholder="Search plugins" autocomplete="off">
        <label><input type="checkbox" id="plugin-installed-only"> Installed somewhere only</label>
        <span id="plugin-summary" class="muted">Loading…</span>
    </div>
    <div class="actions">
        <button type="button" class="button secondary" id="plugin-refresh">Check for plugins</button>
    </div>
</div>

<div id="plugin-error" class="alert error hidden"></div>

<div class="plugin-fleet-table-wrap">
<table class="plugin-fleet-table">
    <thead>
        <tr>
            <th class="plugin-col">Plugin</th>
            <th class="all-col">All</th>
            <?php foreach ($firewalls as $firewall): ?>
                <th class="plugin-fleet-firewall">
                    <strong><?= h((string) $firewall['name']) ?></strong>
                    <small><?= h((string) $firewall['base_url']) ?></small>
                </th>
            <?php endforeach; ?>
        </tr>
    </thead>
    <tbody id="plugin-body">
        <tr><td colspan="<?= count($firewalls) + 2 ?>">Loading plugin inventory…</td></tr>
    </tbody>
</table>
</div>

<div id="plugin-result" class="plugin-result hidden">
    <div id="plugin-result-summary" class="alert"></div>
    <div id="plugin-result-grid" class="plugin-result-grid"></div>
</div>

<script>
(function(){
    const csrf = <?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>;
    const firewallOrder = <?= json_encode(array_map(
        static fn(array $fw): array => [
            'id' => (int) $fw['id'],
            'name' => (string) $fw['name'],
        ],
        $firewalls
    ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;

    const body = document.getElementById('plugin-body');
    const summary = document.getElementById('plugin-summary');
    const errorBox = document.getElementById('plugin-error');
    const refresh = document.getElementById('plugin-refresh');
    const search = document.getElementById('plugin-search');
    const installedOnly = document.getElementById('plugin-installed-only');
    const result = document.getElementById('plugin-result');
    const resultSummary = document.getElementById('plugin-result-summary');
    const resultGrid = document.getElementById('plugin-result-grid');

    let inventory = [];
    let catalog = [];

    function escapeHtml(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
    }

    function pluginFor(firewall, packageName){
        return (firewall.plugins || []).find(plugin => plugin.name === packageName) || null;
    }

    function cellMarkup(firewall, packageName){
        if(firewall.ok !== true){
            return '<span class="badge bad">Unavailable</span><span class="version">Inventory read failed</span>';
        }

        const plugin = pluginFor(firewall, packageName);
        if(!plugin){
            return '<span class="badge neutral">Not offered</span>';
        }

        if(plugin.installed){
            const version = plugin.version || 'installed';
            const update = plugin.available_version && plugin.available_version !== plugin.version
                ? '<span class="version">Available: '+escapeHtml(plugin.available_version)+'</span>'
                : '';
            return '<span class="badge good">Installed</span><span class="version">'+escapeHtml(version)+'</span>'+update;
        }

        return '<button type="button" class="button secondary plugin-install" data-package="'+escapeHtml(packageName)+'" data-firewall-ids="['+Number(firewall.id)+']">Install</button>' +
            (plugin.available_version ? '<span class="version">'+escapeHtml(plugin.available_version)+'</span>' : '');
    }

    function allMarkup(packageName){
        const targets = inventory
            .filter(fw => fw.ok === true)
            .filter(fw => {
                const plugin = pluginFor(fw, packageName);
                return plugin && !plugin.installed;
            })
            .map(fw => Number(fw.id));

        if(!targets.length){
            return '<span class="badge good">Installed / N/A</span>';
        }

        return '<button type="button" class="button plugin-install" data-package="'+escapeHtml(packageName)+'" data-firewall-ids="'+escapeHtml(JSON.stringify(targets))+'">Install on all ('+targets.length+')</button>';
    }

    function render(){
        const phrase = search.value.trim().toLowerCase();
        const onlyInstalled = installedOnly.checked;

        const filtered = catalog.filter(plugin => {
            const name = String(plugin.name || '').toLowerCase();
            const description = String(plugin.description || '').toLowerCase();
            if(phrase && !name.includes(phrase) && !description.includes(phrase)) return false;
            if(onlyInstalled){
                return inventory.some(fw => {
                    const item = pluginFor(fw, plugin.name);
                    return item && item.installed;
                });
            }
            return true;
        });

        const installedPackages = catalog.filter(plugin =>
            inventory.some(fw => {
                const item = pluginFor(fw, plugin.name);
                return item && item.installed;
            })
        ).length;

        summary.textContent = filtered.length+' shown · '+installedPackages+' installed plugin'+(installedPackages===1?'':'s')+' across fleet';

        if(!filtered.length){
            body.innerHTML = '<tr><td colspan="'+(firewallOrder.length+2)+'">No matching plugins.</td></tr>';
            return;
        }

        body.innerHTML = filtered.map(plugin => {
            const cells = firewallOrder.map(ref => {
                const fw = inventory.find(item => Number(item.id) === Number(ref.id));
                return '<td class="plugin-cell">'+(fw ? cellMarkup(fw, plugin.name) : '<span class="badge bad">No data</span>')+'</td>';
            }).join('');

            return '<tr>'+
                '<td class="plugin-col plugin-meta"><strong>'+escapeHtml(plugin.name)+'</strong><small>'+escapeHtml(plugin.description || '')+'</small></td>'+
                '<td class="all-col">'+allMarkup(plugin.name)+'</td>'+
                cells+
                '</tr>';
        }).join('');

        body.querySelectorAll('.plugin-install').forEach(button => {
            button.addEventListener('click', () => installPlugin(button));
        });
    }

    async function readJson(response){
        const raw = await response.text();
        try{return JSON.parse(raw);}catch(error){
            throw new Error('Server returned invalid JSON: '+raw.replace(/\s+/g,' ').trim().slice(0,700));
        }
    }

    async function load(force){
        refresh.disabled = true;
        errorBox.classList.add('hidden');
        try{
            const url = new URL('/plugins_data.php', window.location.origin);
            if(force) url.searchParams.set('force','1');
            const response = await fetch(url,{credentials:'same-origin',cache:'no-store'});
            const data = await readJson(response);
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'Plugin inventory failed.');
            inventory = Array.isArray(data.firewalls) ? data.firewalls : [];
            catalog = Array.isArray(data.catalog) ? data.catalog : [];
            render();
            if(data.cache?.refresh_recommended){
                window.setTimeout(()=>load(true),200);
            }
        }catch(error){
            body.innerHTML = '<tr><td colspan="'+(firewallOrder.length+2)+'">Could not load plugin inventory.</td></tr>';
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
        }finally{
            refresh.disabled = false;
        }
    }

    async function installPlugin(button){
        const packageName = button.dataset.package || '';
        let firewallIds = [];
        try{firewallIds = JSON.parse(button.dataset.firewallIds || '[]');}catch(error){}
        firewallIds = firewallIds.map(Number).filter(id => id > 0);
        if(!packageName || !firewallIds.length) return;

        const names = firewallIds.map(id => firewallOrder.find(fw => Number(fw.id)===id)?.name || ('#'+id));
        const targetText = firewallIds.length === 1 ? names[0] : firewallIds.length+' firewalls';
        if(!confirm('Install '+packageName+' on '+targetText+'?\n\nA configuration backup will be created on every target first.')) return;

        button.disabled = true;
        result.classList.remove('hidden');
        resultSummary.className = 'alert warningbox';
        resultSummary.textContent = 'Creating backups and starting plugin installation…';
        resultGrid.innerHTML = '';

        const form = new URLSearchParams();
        form.set('csrf', csrf);
        form.set('package', packageName);
        form.set('operation', 'install');
        form.set('firewall_ids', JSON.stringify(firewallIds));

        try{
            const response = await fetch('/plugin_action.php',{
                method:'POST',credentials:'same-origin',cache:'no-store',
                headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},
                body:form
            });
            const data = await readJson(response);
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'Plugin installation failed.');

            const rows = Array.isArray(data.results) ? data.results : [];
            rows.forEach(item => {
                const node = document.createElement('div');
                node.className = 'plugin-result-item '+(item.ok ? 'good' : 'bad');
                node.innerHTML = '<strong>'+escapeHtml(item.firewall_name || ('#'+item.firewall_id))+'</strong> '+
                    '<span class="badge '+(item.ok?'good':'bad')+'">'+(item.ok?'Started':'Failed')+'</span><br>'+
                    escapeHtml(item.ok ? (item.message || 'Installation started.') : (item.error || 'Installation failed.'));
                resultGrid.appendChild(node);
            });

            resultSummary.className = data.failure_count ? 'alert warningbox' : 'alert goodbox';
            resultSummary.textContent = data.message || 'Plugin installation submitted.';
            window.setTimeout(()=>load(true),2500);
        }catch(error){
            resultSummary.className = 'alert error';
            resultSummary.textContent = error.message;
        }finally{
            button.disabled = false;
        }
    }

    search.addEventListener('input',render);
    installedOnly.addEventListener('change',render);
    refresh.addEventListener('click',()=>load(true));
    load(false);
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
