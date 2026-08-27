window.opnSentralSharedInventory = function(options){
    'use strict';

    const mount = document.getElementById(options.mountId);
    if(!mount) return;

    function esc(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
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
                            <option value="managed">Managed by opnSentral</option>
                        </select>
                    </label>
                </div>
                <div class="table-wrap">
                    <table class="management-table">
                        <thead><tr><th>Name</th><th>Presence</th><th>Firewalls</th><th>Actions</th></tr></thead>
                        <tbody id="shared-inventory-body"></tbody>
                    </table>
                </div>
            </section>`;

        const body = mount.querySelector('#shared-inventory-body');
        const filter = mount.querySelector('#shared-inventory-filter');

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
                let editLink = '';
                if(sourceFirewall){
                    const path = options.type === 'aliases' ? '/alias_edit.php' : '/category_edit.php';
                    editLink = '<a class="button secondary" href="'+path+'?name=' + encodeURIComponent(entry.name) + '&source_firewall_id=' + Number(sourceFirewall.id) + '">Edit</a>';
                }
                return `
                    <tr data-index="${index}" data-name="${esc(entry.name)}">
                        <td><strong>${esc(entry.name)}</strong></td>
                        <td>${entry.everywhere
                            ? '<span class="badge good">All firewalls</span>'
                            : '<span class="badge warning-status">' + entry.firewalls.length + ' / ' + firewallCount + '</span>'}</td>
                        <td>${esc(names)}</td>
                        <td><div class="management-row-actions">${editLink}</div></td>
                    </tr>`;
            }).join('') : '<tr><td colspan="4">No matching entries.</td></tr>';
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
