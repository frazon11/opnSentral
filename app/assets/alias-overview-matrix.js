window.opnSentralAliasOverviewMatrix = function(options){
    'use strict';

    const list = document.getElementById(options.listId);
    const summary = document.getElementById(options.summaryId);
    const errorBox = document.getElementById(options.errorId);
    const refresh = document.getElementById(options.refreshId);
    const filter = document.getElementById(options.filterId);
    let inventoryData = null;

    function escapeHtml(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
    }

    function csrf(){
        return document.querySelector('input[name="csrf"]')?.value || '';
    }

    function statusBadge(item){
        if(!item.managed){
            return '<span class="badge unmanaged">Unmanaged</span>';
        }

        const status = String(item.last_status || 'unknown');
        const cssClass = status === 'synchronized'
            ? 'good'
            : ((status === 'unreachable' || status === 'error')
                ? 'bad'
                : 'warning-status');

        return '<span class="badge ' + cssClass + '">' +
            escapeHtml(status.charAt(0).toUpperCase() + status.slice(1)) +
        '</span>';
    }

    function matchingFirewallIds(name){
        if(!inventoryData || !Array.isArray(inventoryData.firewalls)) return [];
        const key = String(name).trim().toLowerCase();
        return inventoryData.firewalls
            .filter(function(result){
                const items = Array.isArray(result.aliases) ? result.aliases : [];
                return items.some(item => String(item.name || '').trim().toLowerCase() === key);
            })
            .map(result => Number(result.firewall.id));
    }

    async function renameEntry(button){
        const oldName = button.dataset.name || '';
        const firewallId = Number(button.dataset.firewallId || 0);
        const firewallName = button.dataset.firewallName || 'this firewall';
        const newName = window.prompt('Rename alias "' + oldName + '" to:', oldName);
        if(newName === null) return;

        const trimmed = newName.trim();
        if(!trimmed || trimmed === oldName) return;
        if(!/^[A-Za-z0-9_]+$/.test(trimmed)){
            window.alert('Alias name may contain only letters, numbers and underscores.');
            return;
        }

        const allIds = matchingFirewallIds(oldName);
        let targetIds = [firewallId];

        if(allIds.length > 1){
            const renameAll = window.confirm(
                'Rename alias "' + oldName + '" to "' + trimmed + '" on all ' +
                allIds.length + ' firewalls where it exists?\n\n' +
                'OK = all matching firewalls\nCancel = only ' + firewallName
            );
            targetIds = renameAll ? allIds : [firewallId];
        }else if(!window.confirm('Rename alias "' + oldName + '" to "' + trimmed + '" on ' + firewallName + '?')){
            return;
        }

        const syncCentral = allIds.length > 0
            && targetIds.length === allIds.length
            && allIds.every(id => targetIds.includes(id));

        button.disabled = true;
        const originalText = button.textContent;
        button.textContent = '…';

        try{
            const payload = new FormData();
            payload.set('csrf', csrf());
            payload.set('type', 'aliases');
            payload.set('old_name', oldName);
            payload.set('new_name', trimmed);
            payload.set('sync_central', syncCentral ? '1' : '0');
            targetIds.forEach(id => payload.append('firewall_ids[]', String(id)));

            const response = await fetch('/alias_category_inventory_action.php', {
                method: 'POST',
                credentials: 'same-origin',
                body: payload
            });
            const raw = await response.text();
            let data;
            try{ data = JSON.parse(raw); }
            catch(error){ throw new Error(raw.replace(/\s+/g, ' ').slice(0, 700)); }

            if(!response.ok || data.ok !== true){
                throw new Error(data.error || 'Rename failed.');
            }

            const failures = (data.results || []).filter(item => !item.ok);
            if(failures.length){
                throw new Error(failures.map(item => item.name + ': ' + item.message).join(' | '));
            }

            await load();
        }catch(error){
            window.alert(error.message);
        }finally{
            button.disabled = false;
            button.textContent = originalText;
        }
    }

    function applyFilter(){
        if(!filter || !list) return;
        const mode = filter.value;
        let visible = 0;

        list.querySelectorAll('tr.alias-matrix-row').forEach(function(row){
            const hasManaged = row.dataset.hasManaged === '1';
            const hasUnmanaged = row.dataset.hasUnmanaged === '1';
            const show = mode === 'all'
                || (mode === 'managed' && hasManaged)
                || (mode === 'unmanaged' && hasUnmanaged);
            row.hidden = !show;
            if(show) visible += 1;
        });

        const empty = document.getElementById('alias-matrix-filter-empty');
        if(empty){
            empty.hidden = visible !== 0;
        }
    }

    function render(data){
        inventoryData = data;
        const firewalls = Array.isArray(data.firewalls) ? data.firewalls : [];
        const aliasMap = new Map();
        let reachable = 0;
        let placements = 0;
        let managedPlacements = 0;
        let unmanagedPlacements = 0;

        firewalls.forEach(function(result){
            if(result.aliases_ok) reachable += 1;
            const items = Array.isArray(result.aliases) ? result.aliases : [];
            placements += items.length;

            items.forEach(function(item){
                if(item.managed) managedPlacements += 1;
                else unmanagedPlacements += 1;

                const key = String(item.name || '').trim().toLowerCase();
                if(!key) return;
                if(!aliasMap.has(key)){
                    aliasMap.set(key, {
                        name: String(item.name || ''),
                        description: String(item.description || ''),
                        type: String(item.type || ''),
                        byFirewall: new Map(),
                        hasManaged: false,
                        hasUnmanaged: false
                    });
                }
                const entry = aliasMap.get(key);
                if(!entry.description && item.description) entry.description = String(item.description);
                if(!entry.type && item.type) entry.type = String(item.type);
                entry.byFirewall.set(Number(result.firewall.id), item);
                if(item.managed) entry.hasManaged = true;
                else entry.hasUnmanaged = true;
            });
        });

        const aliases = Array.from(aliasMap.values()).sort(function(a, b){
            return a.name.localeCompare(b.name, undefined, {numeric:true, sensitivity:'base'});
        });

        summary.innerHTML =
            firewalls.length + ' firewalls · ' + reachable + ' reachable · ' + aliases.length + ' aliases · ' +
            placements + ' placements · ' +
            '<span class="badge good">' + managedPlacements + ' managed</span> ' +
            '<span class="badge unmanaged">' + unmanagedPlacements + ' unmanaged</span>';

        if(!firewalls.length){
            list.innerHTML = '<section class="card"><p class="muted">No firewalls configured.</p></section>';
            return;
        }

        const head = firewalls.map(function(result){
            const fw = result.firewall;
            return '<th class="alias-matrix-firewall">' +
                '<strong>' + escapeHtml(fw.name) + '</strong>' +
                '<a class="muted alias-matrix-firewall-url" href="' + escapeHtml(fw.base_url) + '" target="_blank" rel="noopener">' + escapeHtml(fw.base_url) + '</a>' +
            '</th>';
        }).join('');

        const rows = aliases.map(function(alias){
            const cells = firewalls.map(function(result){
                if(!result.aliases_ok){
                    return '<td class="alias-matrix-cell"><span class="badge bad">Unavailable</span></td>';
                }

                const item = alias.byFirewall.get(Number(result.firewall.id));
                if(!item){
                    return '<td class="alias-matrix-cell alias-matrix-missing"><span class="muted">—</span></td>';
                }

                return '<td class="alias-matrix-cell">' +
                    '<div class="alias-matrix-cell-status">' + statusBadge(item) + '</div>' +
                    '<div class="alias-matrix-cell-meta">' +
                        (item.enabled
                            ? '<span class="badge good">Enabled</span>'
                            : '<span class="badge neutral">Disabled</span>') +
                    '</div>' +
                    '<button type="button" class="button secondary inventory-rename alias-matrix-rename"' +
                        ' data-name="' + escapeHtml(item.name) + '"' +
                        ' data-firewall-id="' + Number(result.firewall.id) + '"' +
                        ' data-firewall-name="' + escapeHtml(result.firewall.name) + '">Rename</button>' +
                '</td>';
            }).join('');

            return '<tr class="alias-matrix-row" data-has-managed="' + (alias.hasManaged ? '1' : '0') + '" data-has-unmanaged="' + (alias.hasUnmanaged ? '1' : '0') + '">' +
                '<th scope="row" class="alias-matrix-name">' +
                    '<strong>' + escapeHtml(alias.name) + '</strong>' +
                    (alias.type ? '<span class="alias-matrix-type">' + escapeHtml(alias.type) + '</span>' : '') +
                    (alias.description ? '<small>' + escapeHtml(alias.description) + '</small>' : '') +
                '</th>' + cells +
            '</tr>';
        }).join('');

        list.innerHTML =
            '<div class="card alias-matrix-card">' +
                '<div class="table-scroll alias-matrix-scroll">' +
                    '<table class="management-table alias-matrix-table">' +
                        '<thead><tr><th class="alias-matrix-corner">Alias</th>' + head + '</tr></thead>' +
                        '<tbody>' + rows +
                            '<tr id="alias-matrix-filter-empty" hidden><td colspan="' + (firewalls.length + 1) + '" class="alias-filter-empty">No aliases match this filter.</td></tr>' +
                        '</tbody>' +
                    '</table>' +
                '</div>' +
            '</div>';

        list.querySelectorAll('.inventory-rename').forEach(function(button){
            button.addEventListener('click', function(){ renameEntry(button); });
        });

        const failures = firewalls.filter(result => !result.aliases_ok);
        if(failures.length){
            errorBox.textContent = failures.map(result => result.firewall.name + ': ' + result.aliases_error).join(' | ');
            errorBox.classList.remove('hidden');
        }else{
            errorBox.textContent = '';
            errorBox.classList.add('hidden');
        }

        applyFilter();
    }

    async function load(){
        refresh.disabled = true;
        refresh.textContent = 'Loading…';
        errorBox.classList.add('hidden');

        try{
            const response = await fetch('/alias_category_inventory_data.php', {
                credentials: 'same-origin',
                cache: 'no-store'
            });
            const raw = await response.text();
            let data;
            try{ data = JSON.parse(raw); }
            catch(error){ throw new Error('Invalid server response: ' + raw.replace(/\s+/g, ' ').slice(0, 700)); }
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'Inventory load failed.');
            render(data);
        }catch(error){
            summary.textContent = 'Inventory unavailable';
            list.innerHTML = '<section class="card"><p class="muted">Could not load the remote inventory.</p></section>';
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
        }finally{
            refresh.disabled = false;
            refresh.textContent = 'Refresh';
        }
    }

    if(filter) filter.addEventListener('change', applyFilter);
    refresh.addEventListener('click', load);
    load();
};
