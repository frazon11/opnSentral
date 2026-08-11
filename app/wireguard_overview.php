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
        <p>WireGuard status grouped by managed OPNsense firewall.</p>
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

<div id="wg-overview-error" class="alert error hidden"></div>

<div id="wg-overview-list" class="vpn-summary-list">
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

    function firewallGroups(connections){
        const groups = new Map();

        configuredFirewalls.forEach(function(firewall){
            groups.set(Number(firewall.id), {
                firewall,
                connections: []
            });
        });

        connections.forEach(function(connection){
            [connection.local, connection.remote].forEach(function(side){
                const firewallId = Number(side.firewall_id);

                if(!groups.has(firewallId)){
                    groups.set(firewallId, {
                        firewall: {
                            id: firewallId,
                            name: side.firewall_name,
                            base_url: ''
                        },
                        connections: []
                    });
                }

                groups.get(firewallId).connections.push({
                    connection,
                    side:
                        Number(connection.local.firewall_id) === firewallId
                            ? 'local'
                            : 'remote'
                });
            });
        });

        return Array.from(groups.values()).sort(function(a, b){
            return String(a.firewall.name).localeCompare(
                String(b.firewall.name),
                undefined,
                {numeric: true, sensitivity: 'base'}
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

    function connectionRow(item, index){
        const connection = item.connection;
        const own = connection[item.side];
        const other = item.side === 'local'
            ? connection.remote
            : connection.local;
        const enable = connection.status !== 'enabled';

        return `
            <tr>
                <td>
                    <strong>${escapeHtml(
                        own.client_name || 'peer'
                    )}</strong>
                    <br>
                    <small>
                        to ${escapeHtml(other.firewall_name)}
                    </small>
                </td>
                <td>${escapeHtml(
                    other.client_name || 'peer'
                )}</td>
                <td>${statusBadge(connection.status)}</td>
                <td>
                    <code>${escapeHtml(
                        own.client_uuid || '—'
                    )}</code>
                </td>
                <td>
                    <button
                        type="button"
                        class="${
                            enable
                                ? 'button secondary'
                                : 'button warning'
                        } wg-state-action"
                        data-connection="${index}"
                    >
                        ${
                            enable
                                ? 'Enable both sides'
                                : 'Disable both sides'
                        }
                    </button>
                </td>
            </tr>
        `;
    }

    function render(data){
        const connections = Array.isArray(data.connections)
            ? data.connections
            : [];
        const groups = firewallGroups(connections);

        const enabled = connections.filter(
            connection => connection.status === 'enabled'
        ).length;
        const disabled = connections.filter(
            connection => connection.status === 'disabled'
        ).length;
        const partial = connections.filter(
            connection => connection.status === 'partial'
        ).length;

        summary.innerHTML =
            configuredFirewalls.length + ' firewalls · ' +
            '<span class="badge good">' +
                enabled + ' enabled connections</span> ' +
            '<span class="badge neutral">' +
                disabled + ' disabled</span> ' +
            '<span class="badge bad">' +
                partial + ' partial</span>';

        list.innerHTML = groups.length
            ? groups.map(function(group, groupIndex){
                const enabledCount = group.connections.filter(
                    item => item.connection.status === 'enabled'
                ).length;
                const partialCount = group.connections.filter(
                    item => item.connection.status === 'partial'
                ).length;

                return `
                    <section class="card vpn-summary-card">
                        <div class="vpn-summary-main">
                            <div class="vpn-summary-identity">
                                <h2>${escapeHtml(
                                    group.firewall.name
                                )}</h2>
                                ${
                                    group.firewall.base_url
                                        ? `<a
                                            class="muted"
                                            href="${escapeHtml(
                                                group.firewall.base_url
                                            )}"
                                            target="_blank"
                                            rel="noopener"
                                        >${escapeHtml(
                                            group.firewall.base_url
                                        )}</a>`
                                        : ''
                                }
                            </div>

                            <div class="vpn-summary-metric">
                                <span class="vpn-summary-label">
                                    Connections
                                </span>
                                <span class="badge neutral">
                                    ${group.connections.length}
                                </span>
                            </div>

                            <div class="vpn-summary-metric">
                                <span class="vpn-summary-label">
                                    Summary
                                </span>
                                <span class="muted">
                                    ${enabledCount} enabled
                                    ${
                                        partialCount
                                            ? ' · ' + partialCount + ' partial'
                                            : ''
                                    }
                                </span>
                            </div>

                            <div class="vpn-summary-actions">
                                <button
                                    type="button"
                                    class="button secondary vpn-details-toggle"
                                    aria-expanded="false"
                                >
                                    Details
                                </button>
                            </div>
                        </div>

                        <div class="vpn-details-panel" hidden>
                            <div class="vpn-details-header">
                                <div>
                                    <strong>WireGuard connections</strong>
                                    <div class="muted">
                                        ${escapeHtml(
                                            group.firewall.name
                                        )}
                                    </div>
                                </div>
                            </div>

                            <div class="table-scroll management-table-wrap">
                                <table class="management-table">
                                    <thead>
                                        <tr>
                                            <th>Local peer</th>
                                            <th>Remote peer</th>
                                            <th>Status</th>
                                            <th>Client UUID</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${
                                            group.connections.length
                                                ? group.connections.map(
                                                    function(item, itemIndex){
                                                        item.globalIndex =
                                                            groupIndex * 10000 +
                                                            itemIndex;
                                                        return connectionRow(
                                                            item,
                                                            item.globalIndex
                                                        );
                                                    }
                                                ).join('')
                                                : `<tr>
                                                    <td colspan="5">
                                                        No managed connections.
                                                    </td>
                                                </tr>`
                                        }
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </section>
                `;
            }).join('')
            : '<section class="card vpn-summary-card">' +
                '<p class="muted">No firewalls configured.</p>' +
              '</section>';

        const indexedConnections = new Map();
        groups.forEach(function(group, groupIndex){
            group.connections.forEach(function(item, itemIndex){
                indexedConnections.set(
                    groupIndex * 10000 + itemIndex,
                    item.connection
                );
            });
        });

        list.querySelectorAll('.vpn-details-toggle').forEach(
            function(button){
                button.addEventListener('click', function(){
                    const card = button.closest('.vpn-summary-card');
                    const panel = card.querySelector(
                        '.vpn-details-panel'
                    );
                    const expanded =
                        button.getAttribute('aria-expanded') === 'true';

                    button.setAttribute(
                        'aria-expanded',
                        expanded ? 'false' : 'true'
                    );
                    button.textContent = expanded
                        ? 'Details'
                        : 'Hide details';
                    panel.hidden = expanded;
                    card.classList.toggle(
                        'vpn-summary-expanded',
                        !expanded
                    );
                });
            }
        );

        list.querySelectorAll('.wg-state-action').forEach(
            function(button){
                button.addEventListener('click', function(){
                    const connection = indexedConnections.get(
                        Number(button.dataset.connection)
                    );
                    const enable =
                        connection.status !== 'enabled';
                    changeState(connection, enable, button);
                });
            }
        );
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
