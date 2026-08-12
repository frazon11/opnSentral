<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/system_administration_matrix.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$settings = administration_matrix_settings();
$matrix = [];

$downloadRequests = [];
foreach ($firewalls as $firewall) {
    $downloadRequests[(int) $firewall['id']] = [
        'firewall' => $firewall,
        'path' => 'core/backup/download/this',
        'timeout' => 60,
    ];
}
$downloads = opn_downloads_parallel($downloadRequests);

$agentRows = db()->query(
    'SELECT * FROM agents WHERE firewall_id IS NOT NULL ORDER BY id DESC'
)->fetchAll();
$agentsByFirewall = [];
foreach ($agentRows as $agent) {
    $fid = (int) ($agent['firewall_id'] ?? 0);
    if ($fid > 0 && !isset($agentsByFirewall[$fid])) {
        $agentsByFirewall[$fid] = $agent;
    }
}

foreach ($firewalls as $firewall) {
    $fid = (int) $firewall['id'];
    $entry = [
        'firewall' => $firewall,
        'ok' => false,
        'values' => [],
        'error' => '',
        'agent' => $agentsByFirewall[$fid] ?? null,
    ];

    $download = $downloads[$fid] ?? ['ok' => false, 'error' => 'No response.'];
    if (($download['ok'] ?? false) === true) {
        try {
            $xml = simplexml_load_string(
                (string) ($download['value'] ?? ''),
                SimpleXMLElement::class,
                LIBXML_NONET | LIBXML_NOCDATA
            );
            if (!$xml instanceof SimpleXMLElement) {
                throw new RuntimeException('Could not parse configuration XML.');
            }
            foreach ($settings as $key => $definition) {
                $entry['values'][$key] = administration_matrix_xml_bool(
                    $xml,
                    (string) $definition['path']
                );
            }
            $entry['ok'] = true;
        } catch (Throwable $exception) {
            $entry['error'] = $exception->getMessage();
        }
    } else {
        $entry['error'] = (string) ($download['error'] ?? 'Could not read configuration.');
    }

    $matrix[$fid] = $entry;
}

function administration_agent_writable(?array $agent): bool
{
    if (!is_array($agent) || (int) ($agent['enabled'] ?? 0) !== 1) {
        return false;
    }
    $version = trim((string) ($agent['last_agent_version'] ?? ''));
    return $version !== '' && version_compare($version, '0.1.1', '>=');
}

require __DIR__ . '/inc/header.php';
?>
<style>
.admin-fleet-toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:12px}
.admin-fleet-toolbar .actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.admin-fleet-table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.admin-fleet-table{border-collapse:separate;border-spacing:0;min-width:max(980px,100%);width:100%}
.admin-fleet-table th,.admin-fleet-table td{padding:10px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:middle;text-align:center}
.admin-fleet-table th:last-child,.admin-fleet-table td:last-child{border-right:0}
.admin-fleet-table tr:last-child td{border-bottom:0}
.admin-fleet-table thead th{position:sticky;top:0;z-index:3;background:var(--table-head)}
.admin-fleet-table .setting-col{position:sticky;left:0;z-index:2;text-align:left;min-width:280px;background:var(--card)}
.admin-fleet-table thead .setting-col{z-index:4;background:var(--table-head)}
.admin-fleet-table .all-col{min-width:100px}
.admin-fleet-setting strong{display:block}.admin-fleet-setting small{display:block;margin-top:4px;color:var(--muted);font-weight:400;line-height:1.3}
.admin-fleet-firewall{min-width:150px}.admin-fleet-firewall a{display:block;font-weight:700}.admin-fleet-firewall small{display:block;margin-top:3px;color:var(--muted);font-weight:400}
.admin-fleet-cell{min-width:150px}.admin-fleet-cell input[type=checkbox],.admin-fleet-row-all{width:20px;height:20px}
.admin-fleet-cell.dirty{background:rgba(240,173,78,.12)}
.admin-fleet-cell .cell-note{display:block;margin-top:5px;font-size:.72rem;color:var(--muted)}
.admin-fleet-result{margin-top:14px}.admin-fleet-result-grid{display:grid;gap:7px;margin-top:8px}.admin-fleet-result-item{padding:9px 11px;border-radius:6px;background:rgba(127,127,127,.08)}
.admin-fleet-result-item.good{border-left:4px solid #2aa84a}.admin-fleet-result-item.bad{border-left:4px solid #d74747}.admin-fleet-result-item.pending{border-left:4px solid #d6a52f}
@media(max-width:850px){.admin-fleet-toolbar{align-items:flex-start;flex-direction:column}}
</style>

<div class="page-title">
    <div>
        <h1>System → Settings → Administration</h1>
        <p>Compare and deploy selected Web GUI administration settings across managed OPNsense firewalls.</p>
    </div>
    <a class="button secondary" href="/agents.php">Agents</a>
</div>

<div class="alert warningbox">
    <strong>Fleet writes use the opnSentral agent.</strong>
    Current values are read through the normal OPNsense API. A firewall needs an enabled agent version 0.1.1 or newer for changes. Every target receives an opnSentral pre-change backup before a job is queued.
</div>

<div class="admin-fleet-toolbar">
    <div>
        <strong><?= count($firewalls) ?> managed firewall<?= count($firewalls) === 1 ? '' : 's' ?></strong>
        <span class="muted"> · Change one cell, or use the checkbox in the All column to set the whole row.</span>
    </div>
    <div class="actions">
        <button type="button" class="button secondary" id="admin-fleet-reset" disabled>Reset changes</button>
        <button type="button" class="button" id="admin-fleet-apply" disabled>Apply changes</button>
    </div>
</div>

<div class="admin-fleet-table-wrap">
<table class="admin-fleet-table">
    <thead>
        <tr>
            <th class="setting-col">Setting</th>
            <th class="all-col">All</th>
            <?php foreach ($matrix as $fid => $entry):
                $firewall = $entry['firewall'];
                $agent = $entry['agent'];
                $writable = administration_agent_writable($agent);
            ?>
                <th class="admin-fleet-firewall">
                    <a href="/system_administration.php?firewall_id=<?= $fid ?>"><?= h((string) $firewall['name']) ?></a>
                    <?php if (!$entry['ok']): ?>
                        <small><span class="badge bad">Read failed</span></small>
                    <?php elseif ($writable): ?>
                        <small><span class="badge good">Agent ready</span></small>
                    <?php elseif (is_array($agent)): ?>
                        <small><span class="badge warning">Update agent</span></small>
                    <?php else: ?>
                        <small><span class="badge neutral">Read-only</span></small>
                    <?php endif; ?>
                </th>
            <?php endforeach; ?>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($settings as $key => $definition): ?>
            <tr data-setting="<?= h($key) ?>">
                <td class="setting-col admin-fleet-setting">
                    <strong><?= h((string) $definition['label']) ?></strong>
                    <small><?= h((string) $definition['help']) ?></small>
                </td>
                <td class="all-col">
                    <input type="checkbox" class="admin-fleet-row-all" aria-label="Set <?= h((string) $definition['label']) ?> on all writable firewalls">
                </td>
                <?php foreach ($matrix as $fid => $entry):
                    $agent = $entry['agent'];
                    $writable = $entry['ok'] && administration_agent_writable($agent);
                    $value = (bool) ($entry['values'][$key] ?? false);
                ?>
                    <td class="admin-fleet-cell" data-firewall-id="<?= $fid ?>" data-firewall-name="<?= h((string) $entry['firewall']['name']) ?>">
                        <?php if ($entry['ok']): ?>
                            <input
                                type="checkbox"
                                class="admin-fleet-checkbox"
                                data-setting="<?= h($key) ?>"
                                data-firewall-id="<?= $fid ?>"
                                data-initial="<?= $value ? '1' : '0' ?>"
                                <?= $value ? 'checked' : '' ?>
                                <?= $writable ? '' : 'disabled' ?>
                            >
                            <?php if (!$writable): ?>
                                <span class="cell-note"><?= is_array($agent) ? 'Agent 0.1.1+ required' : 'Agent required for write' ?></span>
                            <?php endif; ?>
                        <?php else: ?>
                            <span class="badge bad">Unavailable</span>
                            <span class="cell-note" title="<?= h((string) $entry['error']) ?>">Could not read</span>
                        <?php endif; ?>
                    </td>
                <?php endforeach; ?>
            </tr>
        <?php endforeach; ?>
    </tbody>
</table>
</div>

<div id="admin-fleet-result" class="admin-fleet-result hidden">
    <div id="admin-fleet-result-summary" class="alert"></div>
    <div id="admin-fleet-result-grid" class="admin-fleet-result-grid"></div>
</div>

<script>
(function(){
    const csrf=<?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>;
    const apply=document.getElementById('admin-fleet-apply');
    const reset=document.getElementById('admin-fleet-reset');
    const result=document.getElementById('admin-fleet-result');
    const summary=document.getElementById('admin-fleet-result-summary');
    const resultGrid=document.getElementById('admin-fleet-result-grid');
    const boxes=Array.from(document.querySelectorAll('.admin-fleet-checkbox'));

    function dirtyBoxes(){
        return boxes.filter(box => !box.disabled && (box.checked ? '1':'0') !== box.dataset.initial);
    }
    function refreshDirty(){
        boxes.forEach(box => box.closest('.admin-fleet-cell')?.classList.toggle('dirty', !box.disabled && (box.checked?'1':'0') !== box.dataset.initial));
        const dirty=dirtyBoxes().length>0;
        apply.disabled=!dirty;
        reset.disabled=!dirty;
    }
    boxes.forEach(box=>box.addEventListener('change',refreshDirty));

    document.querySelectorAll('.admin-fleet-row-all').forEach(all=>{
        const row=all.closest('tr');
        const rowBoxes=()=>Array.from(row.querySelectorAll('.admin-fleet-checkbox:not(:disabled)'));
        function syncAll(){
            const writable=rowBoxes();
            if(!writable.length){all.disabled=true;all.indeterminate=false;return;}
            const checked=writable.filter(box=>box.checked).length;
            all.checked=checked===writable.length;
            all.indeterminate=checked>0&&checked<writable.length;
        }
        all.addEventListener('change',()=>{
            rowBoxes().forEach(box=>{box.checked=all.checked;});
            syncAll();refreshDirty();
        });
        row.querySelectorAll('.admin-fleet-checkbox').forEach(box=>box.addEventListener('change',syncAll));
        syncAll();
    });

    reset.addEventListener('click',()=>{
        boxes.forEach(box=>{if(!box.disabled)box.checked=box.dataset.initial==='1';});
        document.querySelectorAll('.admin-fleet-row-all').forEach(all=>all.dispatchEvent(new Event('change',{bubbles:false})));
        refreshDirty();
    });

    async function pollJobs(jobs){
        const ids=jobs.map(job=>job.job_id).filter(Boolean);
        if(!ids.length)return;
        const deadline=Date.now()+120000;
        while(Date.now()<deadline){
            await new Promise(resolve=>setTimeout(resolve,1500));
            const response=await fetch('/system_administration_matrix_status.php?ids='+encodeURIComponent(ids.join(',')),{credentials:'same-origin',cache:'no-store'});
            const data=await response.json();
            if(!response.ok||data.ok!==true)throw new Error(data.error||'Could not read deployment status.');
            const byId=new Map((data.jobs||[]).map(job=>[Number(job.id),job]));
            let done=true;
            jobs.forEach(item=>{
                const job=byId.get(Number(item.job_id));
                const node=document.getElementById('admin-job-'+item.job_id);
                if(!job||!node)return;
                const status=String(job.status||'queued');
                if(status==='completed'){
                    node.className='admin-fleet-result-item good';
                    node.innerHTML='<strong>'+escapeHtml(item.firewall_name)+'</strong> <span class="badge good">Successfully deployed</span><br>'+escapeHtml(job.message||'Applied by agent.');
                }else if(status==='failed'){
                    node.className='admin-fleet-result-item bad';
                    node.innerHTML='<strong>'+escapeHtml(item.firewall_name)+'</strong> <span class="badge bad">Deployment failed</span><br>'+escapeHtml(job.error||'Agent job failed.');
                }else{
                    done=false;
                    node.className='admin-fleet-result-item pending';
                    node.innerHTML='<strong>'+escapeHtml(item.firewall_name)+'</strong> <span class="badge neutral">'+escapeHtml(status)+'</span>';
                }
            });
            if(done){
                summary.className='alert goodbox';
                summary.textContent='Deployment finished. Refreshing current values…';
                window.setTimeout(()=>window.location.reload(),900);
                return;
            }
        }
        summary.className='alert warningbox';
        summary.textContent='Jobs are still queued or running. The agent will continue processing them; refresh this page to see the current values.';
    }

    apply.addEventListener('click',async()=>{
        const changed=dirtyBoxes();
        if(!changed.length)return;
        const changes=changed.map(box=>({
            firewall_id:Number(box.dataset.firewallId),
            setting:String(box.dataset.setting),
            enabled:box.checked
        }));
        const firewallCount=new Set(changes.map(item=>item.firewall_id)).size;
        if(!confirm('Apply '+changes.length+' Administration setting change'+(changes.length===1?'':'s')+' to '+firewallCount+' firewall'+(firewallCount===1?'':'s')+'?\n\nA pre-change configuration backup will be created for every target before its agent job is queued.'))return;

        apply.disabled=true;reset.disabled=true;result.classList.remove('hidden');
        summary.className='alert warningbox';summary.textContent='Creating pre-change backups and queueing deployment…';resultGrid.innerHTML='';
        try{
            const body=new URLSearchParams();body.set('csrf',csrf);body.set('changes',JSON.stringify(changes));
            const response=await fetch('/system_administration_matrix_action.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
            const data=await response.json();
            if(!response.ok||data.ok!==true)throw new Error(data.error||'Could not queue Administration deployment.');
            const jobs=Array.isArray(data.jobs)?data.jobs:[];
            const failures=Array.isArray(data.failures)?data.failures:[];
            jobs.forEach(job=>{
                const node=document.createElement('div');node.id='admin-job-'+job.job_id;node.className='admin-fleet-result-item pending';node.innerHTML='<strong>'+escapeHtml(job.firewall_name)+'</strong> <span class="badge neutral">Queued</span>';resultGrid.appendChild(node);
            });
            failures.forEach(item=>{
                const node=document.createElement('div');node.className='admin-fleet-result-item bad';node.innerHTML='<strong>'+escapeHtml(item.firewall_name)+'</strong> <span class="badge bad">Not queued</span><br>'+escapeHtml(item.error);resultGrid.appendChild(node);
            });
            summary.className=failures.length?'alert warningbox':'alert goodbox';
            summary.textContent=jobs.length+' firewall job'+(jobs.length===1?'':'s')+' queued'+(failures.length?' · '+failures.length+' target'+(failures.length===1?'':'s')+' failed before queueing.':'.');
            await pollJobs(jobs);
        }catch(error){
            summary.className='alert error';summary.textContent=error.message;
            refreshDirty();
        }
    });

    function escapeHtml(value){const node=document.createElement('div');node.textContent=String(value??'');return node.innerHTML;}
    refreshDirty();
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
