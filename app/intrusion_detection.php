<?php

declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_login();
require __DIR__ . '/inc/header.php';

$allowed = [
    'administration'=>'Administration',
    'download'=>'Download',
    'policies'=>'Policies',
    'rules'=>'Rules',
    'user-defined'=>'User defined',
    'alerts'=>'Alerts',
    'schedule'=>'Schedule',
    'log-file'=>'Log File',
];
$view = (string) ($_GET['view'] ?? 'administration');
if (!isset($allowed[$view])) $view = 'administration';
$title = $allowed[$view];
?>

<div class="page-title management-page-title">
    <div>
        <h1>Intrusion Detection · <?= h($title) ?></h1>
        <p>Central IDS/IPS status and administration across all managed OPNsense firewalls.</p>
    </div>
    <div class="management-toolbar">
        <input id="ids-search" type="search" placeholder="Filter table…" style="width:240px;margin:0">
        <button type="button" class="button secondary" id="ids-refresh">Refresh</button>
    </div>
</div>

<div id="ids-error" class="alert error hidden"></div>
<div id="ids-summary" class="management-overview-bar"><strong>Loading <?= h($title) ?>…</strong></div>
<div id="ids-content" class="card management-card"><p class="muted" style="padding:16px">Loading…</p></div>

<script>
(function(){
    const view=<?= json_encode($view) ?>;
    const content=document.getElementById('ids-content');
    const summary=document.getElementById('ids-summary');
    const errorBox=document.getElementById('ids-error');
    const refresh=document.getElementById('ids-refresh');
    const search=document.getElementById('ids-search');
    const columnFilters={};
    let lastData=null;
    let renderedRows=[];
    let renderedColumns=[];

    function esc(value){
        const node=document.createElement('div');
        node.textContent=String(value??'');
        return node.innerHTML;
    }

    function display(value){
        if(value===null||value===undefined||value==='') return '—';
        if(typeof value==='boolean') return value?'Yes':'No';
        if(typeof value==='object') return JSON.stringify(value);
        return String(value);
    }

    function flatten(row,prefix='',target={}){
        if(!row||typeof row!=='object'){
            target[prefix||'Value']=row;
            return target;
        }
        Object.entries(row).forEach(function(entry){
            const key=prefix?prefix+' · '+entry[0]:entry[0];
            const value=entry[1];
            if(value&&typeof value==='object'&&!Array.isArray(value)) flatten(value,key,target);
            else target[key]=value;
        });
        return target;
    }

    function finalColumnName(column){
        return String(column).split('·').pop().trim().toLowerCase();
    }

    function isEnabledColumn(column){
        return finalColumnName(column)==='enabled';
    }

    function isDocumentationColumn(column){
        return finalColumnName(column)==='documentation';
    }

    function isDocumentationUrlColumn(column){
        return finalColumnName(column)==='documentation_url';
    }

    function columnLabel(column){
        return isDocumentationUrlColumn(column)?'Documentation':column;
    }

    function safeHttpUrl(value){
        const raw=String(value??'').trim();
        if(raw==='') return null;
        try{
            const parsed=new URL(raw,window.location.href);
            return (parsed.protocol==='http:'||parsed.protocol==='https:')?parsed.href:null;
        }catch(error){
            return null;
        }
    }

    function renderCell(column,value){
        if(isDocumentationUrlColumn(column)){
            const url=safeHttpUrl(value);
            if(url){
                return '<a href="'+esc(url)+'" target="_blank" rel="noopener noreferrer">Open documentation</a>';
            }
        }
        return esc(display(value));
    }

    function enabledState(value){
        if(value===true||value===1) return 'enabled';
        const normalized=String(value??'').trim().toLowerCase();
        if(['1','true','yes','enabled','on'].includes(normalized)) return 'enabled';
        if(['0','false','no','disabled','off'].includes(normalized)) return 'disabled';
        return 'unknown';
    }

    function buildHeaderFilter(column){
        const value=columnFilters[column]??'';
        if(isEnabledColumn(column)){
            return '<select class="ids-column-filter" data-column="'+esc(column)+'" style="min-width:125px;margin:6px 0 0">'+
                '<option value="all"'+(value==='all'?' selected':'')+'>All</option>'+
                '<option value="enabled"'+(value==='enabled'?' selected':'')+'>Enabled only</option>'+
                '<option value="disabled"'+(value==='disabled'?' selected':'')+'>Disabled only</option>'+
            '</select>';
        }
        return '<input class="ids-column-filter" data-column="'+esc(column)+'" type="search" value="'+esc(value)+'" placeholder="Filter…" style="min-width:110px;width:100%;margin:6px 0 0">';
    }

    function applyFilters(){
        const globalFilter=search.value.trim().toLowerCase();
        let visibleCount=0;

        renderedRows.forEach(function(row,index){
            const globalMatch=!globalFilter||JSON.stringify(row).toLowerCase().includes(globalFilter);
            const columnMatch=renderedColumns.every(function(column){
                const filter=columnFilters[column]??'';
                if(isEnabledColumn(column)){
                    if(filter===''||filter==='all') return true;
                    return enabledState(row[column])===filter;
                }
                if(filter==='') return true;
                return display(row[column]).toLowerCase().includes(String(filter).toLowerCase());
            });

            const tableRow=content.querySelector('tbody tr[data-row-index="'+index+'"]');
            const visible=globalMatch&&columnMatch;
            if(tableRow) tableRow.hidden=!visible;
            if(visible) visibleCount++;
        });

        const count=content.querySelector('[data-ids-visible-count]');
        if(count) count.textContent=visibleCount+' of '+renderedRows.length+' rows shown';
    }

    function bindHeaderFilters(){
        content.querySelectorAll('.ids-column-filter').forEach(function(control){
            const eventName=control.tagName==='SELECT'?'change':'input';
            control.addEventListener(eventName,function(){
                columnFilters[control.dataset.column]=control.value;
                applyFilters();
            });
        });
    }

    function renderAdministration(data,firewalls){
        const reachable=firewalls.filter(item=>item.ok).length;
        const enabled=firewalls.filter(item=>item.ok&&item.ids_enabled===true).length;
        summary.innerHTML='<div><strong>Administration</strong><div class="management-summary">'+reachable+' of '+firewalls.length+' firewalls returned IDS data · '+enabled+' enabled</div></div>';

        renderedRows=[];
        renderedColumns=[];
        content.innerHTML=
            '<div class="table-wrap"><table class="management-table"><thead><tr>'+
            '<th>Firewall</th><th>IDS/IPS</th><th>Mode</th><th>Interfaces</th><th>Promisc</th><th>Detection profile</th><th>Action</th>'+
            '</tr></thead><tbody>'+
            firewalls.map(function(fw){
                const status=!fw.ok
                    ? '<span class="badge bad">Unavailable</span>'
                    : (fw.ids_enabled===true?'<span class="badge good">Enabled</span>':'<span class="badge neutral">Disabled</span>');
                const actionButton=!fw.ok
                    ? '—'
                    : '<div style="display:flex;gap:8px;flex-wrap:wrap">'+
                      '<button type="button" class="button secondary ids-edit-action" data-firewall-id="'+esc(fw.id)+'">Edit</button>'+
                      '<button type="button" class="button secondary ids-state-action" data-firewall-id="'+esc(fw.id)+'" data-enable="'+(fw.ids_enabled===true?'0':'1')+'">'+(fw.ids_enabled===true?'Disable':'Enable')+'</button>'+
                      '</div>';
                const promisc=fw.ids_promisc===true?'Yes':'No';
                const profile=String(fw.ids_detection_profile||'').trim()||'Default';
                return '<tr><td><strong>'+esc(fw.name)+'</strong></td><td>'+status+'</td><td>'+esc(display(fw.ids_mode))+'</td><td>'+esc(display(fw.ids_interfaces))+'</td><td>'+esc(promisc)+'</td><td>'+esc(profile)+'</td><td>'+actionButton+'</td></tr>'+
                    (!fw.ok?'':'<tr class="ids-edit-row hidden" data-edit-firewall-id="'+esc(fw.id)+'"><td colspan="7">'+
                    '<div class="card" style="padding:14px;margin:4px 0">'+
                    '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px">'+
                    '<label>Mode<select class="ids-edit-mode">'+
                    ['pcap','netmap','divert'].map(v=>'<option value="'+v+'"'+(fw.ids_mode===v?' selected':'')+'>'+v+'</option>').join('')+
                    '</select></label>'+
                    '<label>Interfaces<select class="ids-edit-interfaces" multiple size="4">'+
                    (Array.isArray(fw.interface_options)?fw.interface_options:[]).map(opt=>'<option value="'+esc(opt.value)+'"'+(String(fw.ids_interfaces||'').split(',').map(x=>x.trim()).includes(opt.value)?' selected':'')+'>'+esc(opt.label)+' ('+esc(opt.value)+')</option>').join('')+
                    '</select></label>'+
                    '<label>Promiscuous mode<select class="ids-edit-promisc"><option value="0"'+(fw.ids_promisc===true?'':' selected')+'>Disabled</option><option value="1"'+(fw.ids_promisc===true?' selected':'')+'>Enabled</option></select></label>'+
                    '<label>Detection profile<select class="ids-edit-profile">'+
                    [['','Default'],['low','Low'],['medium','Medium'],['high','High'],['custom','Custom']].map(opt=>'<option value="'+opt[0]+'"'+((fw.ids_detection_profile||'')===opt[0]?' selected':'')+'>'+opt[1]+'</option>').join('')+
                    '</select></label>'+
                    '</div>'+
                    '<label style="display:block;margin-top:12px">Home networks<input class="ids-edit-homenet" type="text" value="'+esc(fw.ids_homenet||'')+'" placeholder="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"></label>'+
                    '<div style="display:flex;gap:8px;margin-top:12px"><button type="button" class="button ids-save-settings">Save settings</button><button type="button" class="button secondary ids-cancel-edit">Cancel</button></div>'+
                    '</div></td></tr>');
            }).join('')+
            '</tbody></table></div>';

        content.querySelectorAll('.ids-edit-action').forEach(function(button){
            button.addEventListener('click',function(){
                const row=content.querySelector('[data-edit-firewall-id="'+button.dataset.firewallId+'"]');
                if(row) row.classList.toggle('hidden');
            });
        });

        content.querySelectorAll('.ids-cancel-edit').forEach(function(button){
            button.addEventListener('click',function(){
                const row=button.closest('.ids-edit-row');
                if(row) row.classList.add('hidden');
            });
        });

        content.querySelectorAll('.ids-save-settings').forEach(function(button){
            button.addEventListener('click',async function(){
                const row=button.closest('.ids-edit-row');
                if(!row) return;
                const firewallId=row.dataset.editFirewallId||'';
                const interfaces=Array.from(row.querySelector('.ids-edit-interfaces').selectedOptions).map(opt=>opt.value);
                if(!interfaces.length){errorBox.textContent='Select at least one IDS interface.';errorBox.classList.remove('hidden');return;}
                const original=button.textContent;
                button.disabled=true;
                button.textContent='Saving…';
                try{
                    const form=new URLSearchParams();
                    form.set('csrf',<?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>);
                    form.set('firewall_id',firewallId);
                    form.set('action','set_settings');
                    form.set('mode',row.querySelector('.ids-edit-mode').value);
                    interfaces.forEach(value=>form.append('interfaces[]',value));
                    form.set('promisc',row.querySelector('.ids-edit-promisc').value);
                    form.set('detection_profile',row.querySelector('.ids-edit-profile').value);
                    form.set('homenet',row.querySelector('.ids-edit-homenet').value.trim());
                    const response=await fetch('/intrusion_detection_action.php',{
                        method:'POST',credentials:'same-origin',cache:'no-store',
                        headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body:form
                    });
                    const raw=await response.text();
                    let result;
                    try{result=JSON.parse(raw);}catch(e){throw new Error('Invalid server response: '+raw.slice(0,400));}
                    if(!response.ok||result.ok!==true) throw new Error(result.error||'IDS/IPS settings update failed.');
                    await load();
                }catch(error){
                    errorBox.textContent=error.message;
                    errorBox.classList.remove('hidden');
                    button.disabled=false;
                    button.textContent=original;
                }
            });
        });

        content.querySelectorAll('.ids-state-action').forEach(function(button){
            button.addEventListener('click',async function(){
                const enable=button.dataset.enable==='1';
                const verb=enable?'enable':'disable';
                if(!confirm('Really '+verb+' IDS/IPS on this firewall?')) return;
                const original=button.textContent;
                button.disabled=true;
                button.textContent=enable?'Enabling…':'Disabling…';
                try{
                    const form=new URLSearchParams({
                        csrf:<?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>,
                        firewall_id:button.dataset.firewallId||'',
                        action:'set_enabled',
                        enabled:enable?'1':'0'
                    });
                    const response=await fetch('/intrusion_detection_action.php',{
                        method:'POST',
                        credentials:'same-origin',
                        cache:'no-store',
                        headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},
                        body:form
                    });
                    const raw=await response.text();
                    let result;
                    try{result=JSON.parse(raw);}catch(e){throw new Error('Invalid server response: '+raw.slice(0,400));}
                    if(!response.ok||result.ok!==true) throw new Error(result.error||'IDS/IPS change failed.');
                    await load();
                }catch(error){
                    errorBox.textContent=error.message;
                    errorBox.classList.remove('hidden');
                    button.disabled=false;
                    button.textContent=original;
                }
            });
        });
    }

    function render(data){
        lastData=data;
        const firewalls=Array.isArray(data.firewalls)?data.firewalls:[];
        if(view==='administration'){
            renderAdministration(data,firewalls);
            return;
        }
        const reachable=firewalls.filter(item=>item.ok).length;
        summary.innerHTML='<div><strong>'+esc(data.title)+'</strong><div class="management-summary">'+reachable+' of '+firewalls.length+' firewalls returned IDS data</div></div>';

        const flattened=[];
        firewalls.forEach(function(firewall){
            if(!firewall.ok){
                flattened.push({Firewall:firewall.name,Status:'Unavailable',Error:firewall.error||'Unavailable'});
                return;
            }
            const rows=Array.isArray(firewall.rows)?firewall.rows:[];
            if(!rows.length){
                flattened.push({Firewall:firewall.name,Status:'No rows returned',Endpoint:firewall.endpoint||'—'});
                return;
            }
            rows.forEach(function(row){
                flattened.push(Object.assign({Firewall:firewall.name},flatten(row)));
            });
        });

        const hasDocumentationUrl=flattened.some(row=>Object.keys(row).some(column=>isDocumentationUrlColumn(column)&&safeHttpUrl(row[column])));
        const columns=[];
        flattened.forEach(row=>Object.keys(row).forEach(key=>{
            if(hasDocumentationUrl&&isDocumentationColumn(key)) return;
            if(!columns.includes(key)) columns.push(key);
        }));
        const preferred=['Firewall','Status','Error','Endpoint'];
        columns.sort((a,b)=>{
            const ai=preferred.indexOf(a),bi=preferred.indexOf(b);
            if(ai>=0||bi>=0) return (ai<0?999:ai)-(bi<0?999:bi);
            return a.localeCompare(b);
        });

        if(!flattened.length){
            renderedRows=[];
            renderedColumns=[];
            content.innerHTML='<p class="muted" style="padding:16px">No rows returned.</p>';
            return;
        }

        renderedRows=flattened;
        renderedColumns=columns;

        content.innerHTML=
            '<div style="padding:10px 14px;border-bottom:1px solid var(--border-color, #3d4852)" class="muted" data-ids-visible-count></div>'+
            '<div class="table-wrap"><table class="management-table"><thead>'+
                '<tr>'+columns.map(c=>'<th>'+esc(columnLabel(c))+'</th>').join('')+'</tr>'+
                '<tr class="ids-column-filter-row">'+columns.map(c=>'<th>'+buildHeaderFilter(c)+'</th>').join('')+'</tr>'+
            '</thead><tbody>'+
                flattened.map((row,index)=>'<tr data-row-index="'+index+'">'+columns.map(c=>'<td>'+renderCell(c,row[c])+'</td>').join('')+'</tr>').join('')+
            '</tbody></table></div>';

        bindHeaderFilters();
        applyFilters();
    }

    async function load(){
        refresh.disabled=true;
        refresh.textContent='Refreshing…';
        try{
            const response=await fetch('/intrusion_detection_data.php?view='+encodeURIComponent(view),{credentials:'same-origin',cache:'no-store'});
            const raw=await response.text();
            let data;
            try{data=JSON.parse(raw);}catch(e){throw new Error('Invalid server response: '+raw.replace(/\s+/g,' ').slice(0,400));}
            if(!response.ok||data.ok!==true) throw new Error(data.error||'Could not load IDS data.');
            errorBox.classList.add('hidden');
            errorBox.textContent='';
            render(data);
        }catch(error){
            errorBox.textContent=error.message;
            errorBox.classList.remove('hidden');
            content.innerHTML='<p class="muted" style="padding:16px">Could not load Intrusion Detection data.</p>';
        }finally{
            refresh.disabled=false;
            refresh.textContent='Refresh';
        }
    }

    refresh.addEventListener('click',load);
    search.addEventListener('input',applyFilters);
    load();
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
