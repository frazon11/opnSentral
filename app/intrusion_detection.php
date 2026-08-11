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
        <p>Read-only IDS/IPS information across all managed OPNsense firewalls.</p>
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
    let enabledDefaultApplied=false;

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

    function isEnabledColumn(column){
        const finalPart=String(column).split('·').pop().trim().toLowerCase();
        return finalPart==='enabled';
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

    function render(data){
        lastData=data;
        const firewalls=Array.isArray(data.firewalls)?data.firewalls:[];
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

        const columns=[];
        flattened.forEach(row=>Object.keys(row).forEach(key=>{if(!columns.includes(key)) columns.push(key);}));
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

        if(!enabledDefaultApplied){
            const enabledColumn=columns.find(isEnabledColumn);
            if(enabledColumn&&columnFilters[enabledColumn]===undefined){
                columnFilters[enabledColumn]='enabled';
            }
            enabledDefaultApplied=true;
        }

        renderedRows=flattened;
        renderedColumns=columns;

        content.innerHTML=
            '<div style="padding:10px 14px;border-bottom:1px solid var(--border-color, #3d4852)" class="muted" data-ids-visible-count></div>'+
            '<div class="table-wrap"><table class="management-table"><thead>'+
                '<tr>'+columns.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr>'+
                '<tr class="ids-column-filter-row">'+columns.map(c=>'<th>'+buildHeaderFilter(c)+'</th>').join('')+'</tr>'+
            '</thead><tbody>'+
                flattened.map((row,index)=>'<tr data-row-index="'+index+'">'+columns.map(c=>'<td>'+esc(display(row[c]))+'</td>').join('')+'</tr>').join('')+
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
