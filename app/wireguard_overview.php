<?php
require_once __DIR__ . '/inc/config.php';
require_login();

$firewalls = db()
    ->query('SELECT id,name,base_url FROM firewalls ORDER BY name')
    ->fetchAll();

require __DIR__ . '/inc/header.php';
?>
<div class="page-title management-page-title">
    <div>
        <h1>Managed WireGuard</h1>
        <p>Managed WireGuard connections between OPNsense firewalls.</p>
    </div>
    <div class="management-toolbar">
        <a class="button" href="/wireguard_create.php">
            Create site-to-site tunnel
        </a>
        <button type="button" id="refresh-links" class="button secondary">
            Refresh
        </button>
    </div>
</div>

<div class="management-overview-bar">
    <div>
        <strong>WireGuard overview</strong>
        <div id="wg-overview-summary" class="management-summary">
            Loading managed connections…
        </div>
    </div>
</div>

<style>
.wg-link-list{display:grid;gap:10px}
.wg-link-card{padding:0}
.wg-link-main{display:grid;grid-template-columns:minmax(140px,1fr) minmax(70px,160px) minmax(140px,1fr) 100px auto;gap:14px;align-items:center;padding:14px 16px}
.wg-link-name{font-weight:700}
.wg-link-line{height:1px;background:var(--border);position:relative}
.wg-link-line::before,.wg-link-line::after{content:"";position:absolute;top:-2px;width:5px;height:5px;border-radius:50%;background:var(--muted)}
.wg-link-line::before{left:0}.wg-link-line::after{right:0}
.wg-link-status{text-transform:lowercase;font-weight:600}
.wg-link-details{padding:0 16px 14px}
@media(max-width:760px){.wg-link-main{grid-template-columns:1fr auto 1fr;gap:8px}.wg-link-status{grid-column:1 / span 2}.wg-link-main .button{grid-column:3;grid-row:2}.wg-link-line{min-width:50px}}
</style>

<div id="wg-overview-error" class="alert error hidden"></div>

<div id="wg-overview-list" class="wg-link-list">
    <section class="card vpn-summary-card">
        <p class="muted">Loading…</p>
    </section>
</div>

<script>
(function(){
    const configuredFirewalls = <?= json_encode(
        array_map(
            static fn(array $firewall): array => [
                'id' => (int) $firewall['id'],
                'name' => (string) $firewall['name'],
                'base_url' => (string) $firewall['base_url'],
            ],
            $firewalls
        ),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    ) ?>;

    const csrfToken = <?= json_encode(
        csrf_token(),
        JSON_UNESCAPED_SLASHES
    ) ?>;

    const list = document.getElementById('wg-overview-list');
    const summary = document.getElementById('wg-overview-summary');
    const errorBox = document.getElementById('wg-overview-error');
    const refresh = document.getElementById('refresh-links');

    function escapeHtml(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
    }

    function statusBadge(status){
        if(status === 'enabled'){
            return '<span class="badge good">Enabled</span>';
        }
        if(status === 'disabled'){
            return '<span class="badge neutral">Disabled</span>';
        }
        return '<span class="badge bad">Partial</span>';
    }

    function normalizedConnection(connection){
        const local = connection.local;
        const remote = connection.remote;
        const localName = String(local.firewall_name || '');
        const remoteName = String(remote.firewall_name || '');
        const localIsPrimary = localName.toLowerCase() === 'kryszon';
        const remoteIsPrimary = remoteName.toLowerCase() === 'kryszon';

        if(remoteIsPrimary && !localIsPrimary){
            return {connection, left: remote, right: local};
        }
        if(localIsPrimary && !remoteIsPrimary){
            return {connection, left: local, right: remote};
        }

        return localName.localeCompare(
            remoteName,
            undefined,
            {numeric:true,sensitivity:'base'}
        ) <= 0
            ? {connection, left: local, right: remote}
            : {connection, left: remote, right: local};
    }

    function sortedConnections(connections){
        return connections
            .map(normalizedConnection)
            .sort(function(a,b){
                const aPrimary = String(a.left.firewall_name || '').toLowerCase() === 'kryszon' ? 0 : 1;
                const bPrimary = String(b.left.firewall_name || '').toLowerCase() === 'kryszon' ? 0 : 1;
                if(aPrimary !== bPrimary) return aPrimary - bPrimary;

                const leftCompare = String(a.left.firewall_name || '').localeCompare(
                    String(b.left.firewall_name || ''),
                    undefined,
                    {numeric:true,sensitivity:'base'}
                );
                if(leftCompare !== 0) return leftCompare;
                return String(a.right.firewall_name || '').localeCompare(
                    String(b.right.firewall_name || ''),
                    undefined,
                    {numeric:true,sensitivity:'base'}
                );
            });
    }

    async function changeState(connection, enable, button){
        const verb = enable ? 'enable' : 'disable';

        if(!confirm(
            'Really ' + verb +
            ' this WireGuard connection on both managed firewalls?\n\n' +
            connection.local.firewall_name + ': ' +
            (connection.local.client_name || 'peer') + '\n' +
            connection.remote.firewall_name + ': ' +
            (connection.remote.client_name || 'peer') +
            '\n\nAutomatic backups will be created before the change.'
        )){
            return;
        }

        const original = button.textContent;
        button.disabled = true;
        button.textContent = enable ? 'Enabling…' : 'Disabling…';

        try{
            const params = new URLSearchParams({
                csrf: csrfToken,
                local_firewall_id: String(
                    connection.local.firewall_id
                ),
                remote_firewall_id: String(
                    connection.remote.firewall_id
                ),
                local_client_uuid:
                    connection.local.client_uuid,
                remote_client_uuid:
                    connection.remote.client_uuid,
                local_expected_peer_key:
                    connection.local.expected_peer_key,
                remote_expected_peer_key:
                    connection.remote.expected_peer_key,
                enable: enable ? '1' : '0'
            });

            const response = await fetch('/wireguard_link_action.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: {
                    'Content-Type':
                        'application/x-www-form-urlencoded;charset=UTF-8'
                },
                body: params
            });

            const raw = await response.text();
            let result;

            try{
                result = JSON.parse(raw);
            }catch(error){
                throw new Error(
                    'Invalid server response: ' +
                    raw.replace(/\s+/g, ' ').slice(0, 500)
                );
            }

            if(!response.ok || result.ok !== true){
                throw new Error(result.error || 'Action failed.');
            }

            await load();
        }catch(error){
            alert(error.message);
            button.disabled = false;
            button.textContent = original;
        }
    }

    function render(data){
        const connections = Array.isArray(data.connections)
            ? data.connections.filter(function(connection){
                return connection
                    && connection.local
                    && connection.remote
                    && Number(connection.local.firewall_id) > 0
                    && Number(connection.remote.firewall_id) > 0
                    && String(connection.local.client_uuid || '') !== ''
                    && String(connection.remote.client_uuid || '') !== '';
            })
            : [];
        const rows = sortedConnections(connections);

        summary.textContent =
            connections.length + ' existing managed tunnel' +
            (connections.length === 1 ? '' : 's');

        list.innerHTML = rows.length
            ? rows.map(function(item,index){
                const connection = item.connection;
                const left = item.left;
                const right = item.right;
                const enable = connection.status !== 'enabled';

                return `
                    <section class="card wg-link-card">
                        <div class="wg-link-main">
                            <div class="wg-link-name">${escapeHtml(left.firewall_name)}</div>
                            <div class="wg-link-line" aria-hidden="true"></div>
                            <div class="wg-link-name">${escapeHtml(right.firewall_name)}</div>
                            <div class="wg-link-status">${escapeHtml(connection.status)}</div>
                            <button
                                type="button"
                                class="button secondary wg-details-toggle"
                                data-connection="${index}"
                                aria-expanded="false"
                            >Details</button>
                        </div>

                        <div class="wg-link-details" hidden>
                            <div class="table-scroll management-table-wrap">
                                <table class="management-table">
                                    <thead>
                                        <tr>
                                            <th>Firewall</th>
                                            <th>Peer</th>
                                            <th>Configured</th>
                                            <th>Client UUID</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>${escapeHtml(left.firewall_name)}</td>
                                            <td>${escapeHtml(left.client_name || 'peer')}</td>
                                            <td>${left.enabled ? 'enabled' : 'disabled'}</td>
                                            <td><code>${escapeHtml(left.client_uuid || '—')}</code></td>
                                        </tr>
                                        <tr>
                                            <td>${escapeHtml(right.firewall_name)}</td>
                                            <td>${escapeHtml(right.client_name || 'peer')}</td>
                                            <td>${right.enabled ? 'enabled' : 'disabled'}</td>
                                            <td><code>${escapeHtml(right.client_uuid || '—')}</code></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                            <div style="margin-top:10px">
                                <button
                                    type="button"
                                    class="${enable ? 'button secondary' : 'button warning'} wg-state-action"
                                    data-connection="${index}"
                                >${enable ? 'Enable both sides' : 'Disable both sides'}</button>
                            </div>
                        </div>
                    </section>
                `;
            }).join('')
            : '<section class="card vpn-summary-card"><p class="muted">No existing managed WireGuard tunnels found.</p></section>';

        list.querySelectorAll('.wg-details-toggle').forEach(function(button){
            button.addEventListener('click',function(){
                const card = button.closest('.wg-link-card');
                const panel = card.querySelector('.wg-link-details');
                const expanded = button.getAttribute('aria-expanded') === 'true';
                button.setAttribute('aria-expanded', expanded ? 'false' : 'true');
                button.textContent = expanded ? 'Details' : 'Hide details';
                panel.hidden = expanded;
            });
        });

        list.querySelectorAll('.wg-state-action').forEach(function(button){
            button.addEventListener('click',function(){
                const item = rows[Number(button.dataset.connection)];
                if(!item) return;
                const connection = item.connection;
                changeState(
                    connection,
                    connection.status !== 'enabled',
                    button
                );
            });
        });
    }

    let hasRendered = false;
    let refreshing = false;

    function showErrors(data){
        if(Array.isArray(data.errors) && data.errors.length){
            errorBox.textContent = data.errors.join(' | ');
            errorBox.classList.remove('hidden');
        }else{
            errorBox.classList.add('hidden');
            errorBox.textContent = '';
        }
    }

    async function requestData(force){
        const response = await fetch(
            '/wireguard_overview_data.php' +
            (force ? '?force=1' : ''),
            {
                credentials: 'same-origin',
                cache: 'no-store'
            }
        );

        const raw = await response.text();
        let data;

        try{
            data = JSON.parse(raw);
        }catch(error){
            throw new Error(
                'Server returned invalid JSON: ' +
                raw.replace(/\s+/g, ' ').trim().slice(0, 500)
            );
        }

        if(!response.ok || data.ok !== true){
            throw new Error(data.error || 'Loading failed.');
        }

        return data;
    }

    async function load(force = false){
        if(refreshing){
            return;
        }

        refreshing = true;
        refresh.disabled = true;
        refresh.textContent = force ? 'Refreshing…' : 'Loading…';

        try{
            const data = await requestData(force);
            render(data);
            showErrors(data);
            hasRendered = true;

            if(
                !force &&
                data.cache?.refresh_recommended
            ){
                window.setTimeout(
                    () => load(true),
                    150
                );
            }
        }catch(error){
            if(!hasRendered){
                list.innerHTML =
                    '<section class="card vpn-summary-card">' +
                        '<p class="muted">' +
                            'Could not load WireGuard data.' +
                        '</p>' +
                    '</section>';
            }
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
        }finally{
            refreshing = false;
            refresh.disabled = false;
            refresh.textContent = 'Refresh';
        }
    }

    refresh.addEventListener('click', () => load(true));
    load(false);
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
