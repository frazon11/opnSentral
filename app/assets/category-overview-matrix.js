window.opnSentralCategoryOverviewMatrix = function(options){
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
        const cssClass = status === 'synchronized' ? 'good' : ((status === 'unreachable' || status === 'error') ? 'bad' : 'warning-status');
        return '<span class="badge ' + cssClass + '">' + escapeHtml(status.charAt(0).toUpperCase() + status.slice(1)) + '</span>';
    }

    function matchingFirewallIds(name){
        if(!inventoryData || !Array.isArray(inventoryData.firewalls)) return [];
        const key = String(name).trim().toLowerCase();
        return inventoryData.firewalls.filter(function(result){
            const items = Array.isArray(result.categories) ? result.categories : [];
            return items.some(item => String(item.name || '').trim().toLowerCase() === key);
        }).map(result => Number(result.firewall.id));
    }

    async function renameEntry(button){
        const oldName = button.dataset.name || '';
        const firewallId = Number(button.dataset.firewallId || 0);
        const firewallName = button.dataset.firewallName || 'this firewall';
        const newName = window.prompt('Rename category "' + oldName + '" to:', oldName);
        if(newName === null) return;
        const trimmed = newName.trim();
        if(!trimmed || trimmed === oldName) return;
        if(trimmed.length > 255){ window.alert('Category name may contain at most 255 characters.'); return; }

        const allIds = matchingFirewallIds(oldName);
        let targetIds = [firewallId];
        if(allIds.length > 1){
            const renameAll = window.confirm(
                'Rename category "' + oldName + '" to "' + trimmed + '" on all ' + allIds.length + ' firewalls where it exists?\n\n' +
                'OK = all matching firewalls\nCancel = only ' + firewallName
            );
            targetIds = renameAll ? allIds : [firewallId];
        }else if(!window.confirm('Rename category "' + oldName + '" to "' + trimmed + '" on ' + firewallName + '?')) return;

        const syncCentral = allIds.length > 0 && targetIds.length === allIds.length && allIds.every(id => targetIds.includes(id));
        button.disabled = true;
        const originalText = button.textContent;
        button.textContent = '…';
        try{
            const payload = new FormData();
            payload.set('csrf', csrf());
            payload.set('type', 'categories');
            payload.set('old_name', oldName);
            payload.set('new_name', trimmed);
            payload.set('sync_central', syncCentral ? '1' : '0');
            targetIds.forEach(id => payload.append('firewall_ids[]', String(id)));
            const response = await fetch('/alias_category_inventory_action.php', {method:'POST', credentials:'same-origin', body:payload});
            const raw = await response.text();
            let data; try{ data = JSON.parse(raw); } catch(error){ throw new Error(raw.replace(/\s+/g,' ').slice(0,700)); }
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'Rename failed.');
            const failures = (data.results || []).filter(item => !item.ok);
            if(failures.length) throw new Error(failures.map(item => item.name + ': ' + item.message).join(' | '));
            await load();
        }catch(error){ window.alert(error.message); }
        finally{ button.disabled = false; button.textContent = originalText; }
    }

    async function deployMissing(button){
        const name = button.dataset.name || '';
        const sourceId = Number(button.dataset.sourceFirewallId || 0);
        const sourceName = button.dataset.sourceFirewallName || 'source firewall';
        const targetIds = String(button.dataset.targetFirewallIds || '').split(',').map(value => Number(value)).filter(id => id > 0);
        if(!name || !sourceId || !targetIds.length) return;
        if(!window.confirm(
            'Apply category "' + name + '" from ' + sourceName + ' to the ' + targetIds.length +
            ' remaining reachable OPNsense' + (targetIds.length === 1 ? '' : 's') + '?\n\n' +
            'Only firewalls where the category is missing will be changed. Existing categories are left untouched.'
        )) return;

        button.disabled = true;
        const originalText = button.textContent;
        button.textContent = 'Applying…';
        try{
            const payload = new FormData();
            payload.set('csrf', csrf());
            payload.set('name', name);
            payload.set('source_firewall_id', String(sourceId));
            targetIds.forEach(id => payload.append('target_firewall_ids[]', String(id)));
            const response = await fetch('/category_deploy_missing.php', {method:'POST', credentials:'same-origin', body:payload});
            const raw = await response.text();
            let data; try{ data = JSON.parse(raw); } catch(error){ throw new Error(raw.replace(/\s+/g,' ').slice(0,700)); }
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'Category deployment failed.');
            const failures = (data.results || []).filter(item => !item.ok);
            if(failures.length){ window.alert('Some firewalls failed:\n' + failures.map(item => item.name + ': ' + item.message).join('\n')); }
            await load();
        }catch(error){ window.alert(error.message); }
        finally{ button.disabled = false; button.textContent = originalText; }
    }

    function applyFilter(){
        if(!filter || !list) return;
        const mode = filter.value;
        let visible = 0;
        list.querySelectorAll('tr.category-matrix-row').forEach(function(row){
            const hasManaged = row.dataset.hasManaged === '1';
            const hasUnmanaged = row.dataset.hasUnmanaged === '1';
            const show = mode === 'all' || (mode === 'managed' && hasManaged) || (mode === 'unmanaged' && hasUnmanaged);
            row.hidden = !show;
            if(show) visible += 1;
        });
        const empty = document.getElementById('category-matrix-filter-empty');
        if(empty) empty.hidden = visible !== 0;
    }

    function render(data){
        inventoryData = data;
        const firewalls = Array.isArray(data.firewalls) ? data.firewalls : [];
        const categoryMap = new Map();
        let reachable = 0, placements = 0, managedPlacements = 0, unmanagedPlacements = 0;

        firewalls.forEach(function(result){
            if(result.categories_ok) reachable += 1;
            const items = Array.isArray(result.categories) ? result.categories : [];
            placements += items.length;
            items.forEach(function(item){
                if(item.managed) managedPlacements += 1; else unmanagedPlacements += 1;
                const key = String(item.name || '').trim().toLowerCase();
                if(!key) return;
                if(!categoryMap.has(key)){
                    categoryMap.set(key, {name:String(item.name || ''), color:String(item.color || ''), automatic:!!item.automatic, byFirewall:new Map(), hasManaged:false, hasUnmanaged:false});
                }
                const entry = categoryMap.get(key);
                if(!entry.color && item.color) entry.color = String(item.color);
                entry.automatic = !!item.automatic;
                entry.byFirewall.set(Number(result.firewall.id), item);
                if(item.managed) entry.hasManaged = true; else entry.hasUnmanaged = true;
            });
        });

        const categories = Array.from(categoryMap.values()).sort((a,b) => a.name.localeCompare(b.name, undefined, {numeric:true,sensitivity:'base'}));
        summary.innerHTML = firewalls.length + ' firewalls · ' + reachable + ' reachable · ' + categories.length + ' categories · ' + placements + ' placements · ' +
            '<span class="badge good">' + managedPlacements + ' managed</span> <span class="badge unmanaged">' + unmanagedPlacements + ' unmanaged</span>';

        if(!firewalls.length){ list.innerHTML = '<section class="card"><p class="muted">No firewalls configured.</p></section>'; return; }

        const head = firewalls.map(function(result){
            const fw = result.firewall;
            return '<th class="category-matrix-firewall"><strong>' + escapeHtml(fw.name) + '</strong>' +
                '<a class="muted category-matrix-firewall-url" href="' + escapeHtml(fw.base_url) + '" target="_blank" rel="noopener">' + escapeHtml(fw.base_url) + '</a></th>';
        }).join('');

        const rows = categories.map(function(category){
            const sources = firewalls.filter(result => result.categories_ok && category.byFirewall.has(Number(result.firewall.id))).map(result => ({result:result,item:category.byFirewall.get(Number(result.firewall.id))}));
            const source = sources.find(entry => entry.item && entry.item.managed) || sources[0] || null;
            const missingTargets = firewalls.filter(result => result.categories_ok && !category.byFirewall.has(Number(result.firewall.id))).map(result => Number(result.firewall.id));
            const deployButton = source && missingTargets.length
                ? '<button type="button" class="button category-deploy-missing" data-name="' + escapeHtml(category.name) + '" data-source-firewall-id="' + Number(source.result.firewall.id) + '" data-source-firewall-name="' + escapeHtml(source.result.firewall.name) + '" data-target-firewall-ids="' + missingTargets.join(',') + '">Apply to missing (' + missingTargets.length + ')</button>'
                : '';

            const cells = firewalls.map(function(result){
                if(!result.categories_ok) return '<td class="category-matrix-cell"><span class="badge bad">Unavailable</span></td>';
                const item = category.byFirewall.get(Number(result.firewall.id));
                if(!item) return '<td class="category-matrix-cell category-matrix-missing"><span class="muted">—</span></td>';
                return '<td class="category-matrix-cell">' +
                    '<div class="category-matrix-cell-status">' + statusBadge(item) + '</div>' +
                    '<div class="category-matrix-cell-meta"><span class="badge neutral">' + escapeHtml(item.color || 'Default') + '</span></div>' +
                    '<div class="category-matrix-cell-meta">' + (item.automatic ? '<span class="badge neutral">Automatic</span>' : '<span class="badge good">Persistent</span>') + '</div>' +
                    '<button type="button" class="button secondary inventory-rename category-matrix-rename" data-name="' + escapeHtml(item.name) + '" data-firewall-id="' + Number(result.firewall.id) + '" data-firewall-name="' + escapeHtml(result.firewall.name) + '">Rename</button></td>';
            }).join('');

            return '<tr class="category-matrix-row" data-has-managed="' + (category.hasManaged ? '1' : '0') + '" data-has-unmanaged="' + (category.hasUnmanaged ? '1' : '0') + '">' +
                '<th scope="row" class="category-matrix-name"><strong>' + escapeHtml(category.name) + '</strong>' +
                (category.color ? '<span class="category-matrix-type">' + escapeHtml(category.color) + '</span>' : '') +
                (deployButton ? '<div class="category-matrix-row-action">' + deployButton + '</div>' : '') + '</th>' + cells + '</tr>';
        }).join('');

        list.innerHTML = '<div class="card category-matrix-card"><div class="table-scroll category-matrix-scroll"><table class="management-table category-matrix-table">' +
            '<thead><tr><th class="category-matrix-corner">Category</th>' + head + '</tr></thead><tbody>' + rows +
            '<tr id="category-matrix-filter-empty" hidden><td colspan="' + (firewalls.length + 1) + '" class="category-filter-empty">No categories match this filter.</td></tr>' +
            '</tbody></table></div></div>';

        list.querySelectorAll('.inventory-rename').forEach(button => button.addEventListener('click', () => renameEntry(button)));
        list.querySelectorAll('.category-deploy-missing').forEach(button => button.addEventListener('click', () => deployMissing(button)));

        const failures = firewalls.filter(result => !result.categories_ok);
        if(failures.length){ errorBox.textContent = failures.map(result => result.firewall.name + ': ' + result.categories_error).join(' | '); errorBox.classList.remove('hidden'); }
        else{ errorBox.textContent = ''; errorBox.classList.add('hidden'); }
        applyFilter();
    }

    async function load(){
        refresh.disabled = true; refresh.textContent = 'Loading…'; errorBox.classList.add('hidden');
        try{
            const response = await fetch('/alias_category_inventory_data.php', {credentials:'same-origin', cache:'no-store'});
            const raw = await response.text();
            let data; try{ data = JSON.parse(raw); } catch(error){ throw new Error('Invalid server response: ' + raw.replace(/\s+/g,' ').slice(0,700)); }
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'Inventory load failed.');
            render(data);
        }catch(error){ summary.textContent = 'Inventory unavailable'; list.innerHTML = '<section class="card"><p class="muted">Could not load the remote inventory.</p></section>'; errorBox.textContent = error.message; errorBox.classList.remove('hidden'); }
        finally{ refresh.disabled = false; refresh.textContent = 'Refresh'; }
    }

    if(filter) filter.addEventListener('change', applyFilter);
    refresh.addEventListener('click', load);
    load();
};
