window.opnSentralSharedInventory = function(options){
    'use strict';

    const mount = document.getElementById(options.mountId);
    if(!mount) return;

    function esc(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
    }

    function csrf(){
        return document.querySelector('input[name="csrf"]')?.value || '';
    }

    function aggregate(data){
        const map = new Map();
        const firewalls = Array.isArray(data.firewalls) ? data.firewalls : [];
        firewalls.forEach(function(result){
            const items = Array.isArray(result[options.type]) ? result[options.type] : [];
            items.forEach(function(item){
                const key = String(item.name || '').trim().toLowerCase();
                if(!key) return;
                if(!map.has(key)) map.set(key,{name:item.name,firewalls:[],items:[]});
                const entry = map.get(key);
                entry.firewalls.push(result.firewall);
                entry.items.push(item);
            });
        });
        return Array.from(map.values()).map(function(entry){
            entry.everywhere = firewalls.length > 0 && entry.firewalls.length === firewalls.length;
            entry.managed = entry.items.some(function(item){ return item && item.managed === true; });
            return entry;
        }).sort(function(a,b){
            if(a.everywhere !== b.everywhere) return a.everywhere ? -1 : 1;
            return a.name.localeCompare(b.name);
        });
    }

    function render(data){
        const entries = aggregate(data);
        const firewallCount = Array.isArray(data.firewalls) ? data.firewalls.length : 0;
        const everywhereCount = entries.filter(item=>item.everywhere).length;
        const managedFilterOption = options.type === 'aliases'
            ? '<option value="managed">Managed by opnSentral</option>'
            : '';

        mount.innerHTML = `
            <section class="card management-card">
                <div class="card-head">
                    <div>
                        <h2>Shared ${esc(options.label)}</h2>
                        <p class="muted">${everywhereCount} of ${entries.length} unique entries exist on all ${firewallCount} firewall(s).</p>
                    </div>
                    <label style="max-width:240px">Show
                        <select id="shared-inventory-filter">
                            <option value="everywhere">Present on all</option>
                            <option value="all">All unique entries</option>
                            ${managedFilterOption}
                        </select>
                    </label>
                </div>
                <div id="shared-inventory-result"></div>
                <div class="table-wrap">
                    <table class="management-table">
                        <thead><tr><th>Name</th><th>Presence</th><th>Firewalls</th><th>Actions</th></tr></thead>
                        <tbody id="shared-inventory-body"></tbody>
                    </table>
                </div>
            </section>`;

        const body = mount.querySelector('#shared-inventory-body');
        const filter = mount.querySelector('#shared-inventory-filter');
        const result = mount.querySelector('#shared-inventory-result');

        function draw(){
            const visible = entries.filter(function(item){
                if(filter.value === 'all') return true;
                if(filter.value === 'managed') return item.managed === true;
                return item.everywhere;
            });
            body.innerHTML = visible.length ? visible.map(function(entry,index){
                const names = entry.firewalls.map(fw=>fw.name).join(', ');
                const managedIndex = entry.items.findIndex(item=>item && item.managed === true);
                const sourceIndex = managedIndex >= 0 ? managedIndex : 0;
                const sourceFirewall = entry.firewalls[sourceIndex];
                const definitionEdit = options.type === 'aliases' && sourceFirewall
                    ? '<a class="button secondary" href="/alias_edit.php?name=' + encodeURIComponent(entry.name) + '&source_firewall_id=' + Number(sourceFirewall.id) + '">Edit definition</a>'
                    : '';
                return `
                    <tr data-index="${index}" data-name="${esc(entry.name)}">
                        <td><strong>${esc(entry.name)}</strong></td>
                        <td>${entry.everywhere
                            ? '<span class="badge good">All firewalls</span>'
                            : '<span class="badge warning-status">' + entry.firewalls.length + ' / ' + firewallCount + '</span>'}</td>
                        <td>${esc(names)}</td>
                        <td>
                            <div class="management-row-actions">
                                ${definitionEdit}
                                <button type="button" class="button secondary shared-rename">Rename</button>
                            </div>
                            <div class="management-row-actions shared-editor" hidden style="margin-top:8px">
                                <input class="shared-new-name" type="text" value="${esc(entry.name)}" style="min-width:180px" aria-label="New name">
                                <select class="shared-scope" aria-label="Apply to">
                                    <option value="all-matching">All matching firewalls</option>
                                    ${entry.firewalls.map(fw=>'<option value="'+Number(fw.id)+'">Only '+esc(fw.name)+'</option>').join('')}
                                </select>
                                <button type="button" class="button shared-save">Save rename</button>
                                <button type="button" class="button secondary shared-cancel">Cancel</button>
                            </div>
                        </td>
                    </tr>`;
            }).join('') : '<tr><td colspan="4">No matching entries.</td></tr>';

            body.querySelectorAll('.shared-rename').forEach(function(button){
                button.addEventListener('click', function(){
                    const row = button.closest('tr');
                    row.querySelector('.shared-editor').hidden = false;
                    button.hidden = true;
                    row.querySelector('.shared-new-name').focus();
                });
            });

            body.querySelectorAll('.shared-cancel').forEach(function(button){
                button.addEventListener('click', function(){
                    const row = button.closest('tr');
                    row.querySelector('.shared-new-name').value = row.dataset.name;
                    row.querySelector('.shared-editor').hidden = true;
                    const renameButton = row.querySelector('.shared-rename');
                    if(renameButton) renameButton.hidden = false;
                });
            });

            body.querySelectorAll('.shared-save').forEach(function(button){
                button.addEventListener('click', async function(){
                    const row = button.closest('tr');
                    const oldName = row.dataset.name;
                    const newName = row.querySelector('.shared-new-name').value.trim();
                    const scope = row.querySelector('.shared-scope').value;
                    const entry = entries.find(item=>item.name===oldName);
                    const ids = scope === 'all-matching'
                        ? entry.firewalls.map(fw=>fw.id)
                        : [Number(scope)];
                    if(!newName){
                        result.innerHTML = '<div class="alert error">The new name must not be empty.</div>';
                        return;
                    }
                    if(newName===oldName){
                        result.innerHTML = '<div class="alert">The name has not changed.</div>';
                        return;
                    }
                    if(!window.confirm('Rename "'+oldName+'" to "'+newName+'" on '+ids.length+' firewall(s)?')) return;

                    button.disabled = true;
                    result.innerHTML = '<div class="alert">Renaming…</div>';
                    try{
                        const payload = new FormData();
                        payload.set('csrf',csrf());
                        payload.set('type',options.type);
                        payload.set('old_name',oldName);
                        payload.set('new_name',newName);
                        ids.forEach(id=>payload.append('firewall_ids[]',String(id)));
                        const response = await fetch('/alias_category_inventory_action.php',{method:'POST',credentials:'same-origin',body:payload});
                        const raw = await response.text();
                        let json;
                        try{json=JSON.parse(raw);}catch(e){throw new Error(raw.slice(0,500));}
                        if(!response.ok||json.ok!==true) throw new Error(json.error||'Rename failed.');
                        const failures = json.results.filter(item=>!item.ok);
                        result.innerHTML = failures.length
                            ? '<div class="alert error">'+esc(failures.map(item=>item.name+': '+item.message).join(' | '))+'</div>'
                            : '<div class="alert goodbox">Rename completed on '+json.results.length+' firewall(s).</div>';
                        if(!failures.length) setTimeout(()=>location.reload(),700);
                    }catch(error){
                        result.innerHTML = '<div class="alert error">'+esc(error.message)+'</div>';
                    }finally{
                        button.disabled = false;
                    }
                });
            });
        }

        filter.addEventListener('change',draw);
        draw();
    }

    fetch('/alias_category_inventory_data.php',{credentials:'same-origin',cache:'no-store'})
        .then(response=>response.text().then(raw=>({response,raw})))
        .then(function(pack){
            let data;
            try{data=JSON.parse(pack.raw);}catch(e){throw new Error('Invalid inventory response.');}
            if(!pack.response.ok||data.ok!==true) throw new Error(data.error||'Inventory load failed.');
            render(data);
        })
        .catch(function(error){
            mount.innerHTML='<div class="alert error">'+esc(error.message)+'</div>';
        });
};
