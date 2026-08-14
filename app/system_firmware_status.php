<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_login();
$firewalls = db()->query('SELECT id,name,base_url FROM firewalls ORDER BY name')->fetchAll();
require __DIR__ . '/inc/header.php';
?>
<style>
.audit-result{margin-top:12px;border-top:1px solid rgba(127,127,127,.25);padding-top:12px}
.audit-result summary{cursor:pointer;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:6px 0}
.audit-result summary::-webkit-details-marker{display:none}
.audit-result summary::before{content:'▸';display:inline-block;margin-right:7px;transition:transform .15s ease}
.audit-result[open] summary::before{transform:rotate(90deg)}
.audit-result-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex:1;flex-wrap:wrap}
.audit-result pre{max-height:360px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:rgba(127,127,127,.08);padding:12px;border-radius:8px;margin:8px 0 0}
.audit-dialog[hidden]{display:none}
.audit-dialog{position:fixed;inset:0;z-index:1000;display:grid;place-items:center;padding:20px}
.audit-dialog-backdrop{position:absolute;inset:0;background:rgba(0,0,0,.55)}
.audit-dialog-card{position:relative;width:min(620px,100%);max-height:90vh;overflow:auto;background:var(--panel,#fff);color:inherit;border-radius:12px;padding:20px;box-shadow:0 18px 60px rgba(0,0,0,.35)}
.audit-options{display:grid;gap:10px;margin:16px 0}
.audit-option{display:flex;gap:10px;align-items:flex-start;padding:12px;border:1px solid rgba(127,127,127,.25);border-radius:9px;cursor:pointer}
.audit-option input{margin-top:3px}
.audit-option strong,.audit-option small{display:block}
.audit-option small{margin-top:3px;color:var(--muted)}
.firmware-meta{margin-top:14px;padding-top:12px;border-top:1px solid rgba(127,127,127,.18)}
.firmware-meta[hidden]{display:none}
.firmware-meta-grid{display:grid;grid-template-columns:minmax(120px,180px) minmax(0,1fr);gap:7px 18px;margin:0}
.firmware-meta-grid dt{font-weight:700;color:var(--muted)}
.firmware-meta-grid dd{margin:0;min-width:0;overflow-wrap:anywhere}
@media (max-width:720px){
  .firmware-meta-grid{grid-template-columns:1fr;gap:3px}
  .firmware-meta-grid dd{margin-bottom:8px}
}
</style>
<div class="page-title management-page-title">
  <div><h1>System → Firmware → Status</h1><p>Check for updates, start supported firmware updates and run firmware audits across managed OPNsense firewalls.</p></div>
  <button type="button" class="button secondary" id="firmware-refresh-all">Check all</button>
</div>
<div id="firmware-status-message" class="alert hidden"></div>
<div id="firmware-status-list" class="vpn-summary-list">
<?php foreach ($firewalls as $firewall): ?>
<section class="card vpn-summary-card" data-firewall-id="<?= (int)$firewall['id'] ?>" data-firewall-name="<?= h((string)$firewall['name']) ?>">
  <div class="vpn-summary-main">
    <div class="vpn-summary-identity"><h2><?= h((string)$firewall['name']) ?></h2><a class="muted" href="<?= h((string)$firewall['base_url']) ?>" target="_blank" rel="noopener"><?= h((string)$firewall['base_url']) ?></a></div>
    <div class="vpn-summary-metric"><span class="vpn-summary-label">Firmware</span><span class="firmware-state badge neutral">Not checked</span></div>
    <div class="vpn-summary-actions">
      <button type="button" class="button secondary firmware-check">Check for updates</button>
      <button type="button" class="button secondary firmware-audit">Run audit</button>
      <button type="button" class="warning firmware-update hidden">Update now</button>
    </div>
  </div>
  <div class="firmware-details muted">No firmware information loaded.</div>
  <div class="firmware-meta" hidden>
    <dl class="firmware-meta-grid"></dl>
  </div>
  <details class="audit-result" hidden>
    <summary>
      <span class="audit-result-head">
        <strong class="audit-result-title">Audit result</strong>
        <span class="audit-result-time muted"></span>
      </span>
    </summary>
    <pre class="audit-result-log"></pre>
  </details>
</section>
<?php endforeach; ?>
<?php if (!$firewalls): ?><section class="card"><p class="muted">No firewalls configured.</p></section><?php endif; ?>
</div>

<div id="firmware-audit-dialog" class="audit-dialog" hidden>
  <div class="audit-dialog-backdrop"></div>
  <section class="audit-dialog-card" role="dialog" aria-modal="true" aria-labelledby="firmware-audit-title">
    <h2 id="firmware-audit-title">Select firmware audit</h2>
    <p id="firmware-audit-target" class="muted"></p>
    <div class="audit-options">
      <label class="audit-option"><input type="radio" name="audit_type" value="security" checked><span><strong>Security audit</strong><small>Check installed packages against known vulnerability information.</small></span></label>
      <label class="audit-option"><input type="radio" name="audit_type" value="health"><span><strong>Health audit</strong><small>Check installation integrity, package database, disk and filesystem health.</small></span></label>
      <label class="audit-option"><input type="radio" name="audit_type" value="connectivity"><span><strong>Connectivity audit</strong><small>Test firmware mirror, DNS and network connectivity used for updates.</small></span></label>
      <label class="audit-option"><input type="radio" name="audit_type" value="cleanup"><span><strong>Cleanup audit</strong><small>Remove temporary update files that may interfere with later updates.</small></span></label>
      <label class="audit-option"><input type="radio" name="audit_type" value="upgrade_log"><span><strong>Upgrade log</strong><small>Show the stored package upgrade log from the last major upgrade.</small></span></label>
    </div>
    <div class="actions">
      <button type="button" class="button secondary" id="firmware-audit-cancel">Cancel</button>
      <button type="button" class="button" id="firmware-audit-run">Run selected audit</button>
    </div>
  </section>
</div>

<script>
(function(){
 const csrf=<?= json_encode(csrf_token(),JSON_UNESCAPED_SLASHES) ?>;
 const message=document.getElementById('firmware-status-message');
 const dialog=document.getElementById('firmware-audit-dialog');
 const dialogTarget=document.getElementById('firmware-audit-target');
 const runButton=document.getElementById('firmware-audit-run');
 let auditCard=null;
 const auditLabels={security:'Security audit',health:'Health audit',connectivity:'Connectivity audit',cleanup:'Cleanup audit',upgrade_log:'Upgrade log'};
 function firstValue(source,paths){
   for(const path of paths){
     let value=source;
     for(const part of path.split('.')){
       if(value===null||typeof value!=='object'||!(part in value)){value=undefined;break;}
       value=value[part];
     }
     if(value!==undefined&&value!==null&&String(value).trim()!=='') return value;
   }
   return '';
 }
 function repositoriesText(value){
   if(!value) return '';
   if(typeof value==='string') return value;
   if(Array.isArray(value)){
     return value.map(repo=>{
       if(typeof repo==='string') return repo;
       if(!repo||typeof repo!=='object') return '';
       const name=repo.name??repo.repository??repo.id??repo.repo??'';
       const priority=repo.priority??repo.prio??'';
       return name ? String(name)+(priority!==''?' (Priority: '+priority+')':'') : '';
     }).filter(Boolean).join(', ');
   }
   if(typeof value==='object'){
     return Object.entries(value).map(([name,repo])=>{
       if(repo&&typeof repo==='object'){
         const label=repo.name??name;
         const priority=repo.priority??repo.prio??'';
         return String(label)+(priority!==''?' (Priority: '+priority+')':'');
       }
       return String(name);
     }).join(', ');
   }
   return String(value);
 }
 function renderFirmwareMeta(card,value){
   const panel=card.querySelector('.firmware-meta');
   const grid=card.querySelector('.firmware-meta-grid');
   if(!panel||!grid) return;
   const rows=[
     ['Type',firstValue(value,['product.product_name','product.product_type','product_name','product_type','type'])],
     ['Version',firstValue(value,['product.product_version','product_version','version'])],
     ['Architecture',firstValue(value,['product.product_arch','product.product_architecture','product_arch','product_architecture','architecture'])],
     ['Commit',firstValue(value,['product.product_hash','product.product_commit','product_hash','product_commit','commit','hash'])],
     ['Mirror',firstValue(value,['product.product_mirror','product_mirror','mirror','repository_url'])],
     ['Repositories',repositoriesText(firstValue(value,['product.product_repositories','product.repositories','product_repositories','repositories','repos']))],
     ['Updated on',firstValue(value,['product.product_updated','product.product_updated_on','product_updated','product_updated_on','updated','updated_on','last_update'])],
     ['Checked on',firstValue(value,['product.product_checked','product.product_checked_on','product_checked','product_checked_on','checked','checked_on','last_check'])]
   ].filter(([,val])=>String(val??'').trim()!=='');
   grid.replaceChildren();
   for(const [label,val] of rows){
     const dt=document.createElement('dt');
     const dd=document.createElement('dd');
     dt.textContent=label;
     dd.textContent=String(val);
     grid.append(dt,dd);
   }
   panel.hidden=rows.length===0;
 }
 function show(text,bad=false){message.textContent=text;message.className='alert '+(bad?'error':'goodbox');}
 function storageKey(id){return 'opnsentral-firmware-audit-'+id;}
 function renderAudit(card,record){
   const panel=card.querySelector('.audit-result');
   panel.hidden=false;
   card.querySelector('.audit-result-title').textContent=(auditLabels[record.type]||'Firmware audit')+' result';
   card.querySelector('.audit-result-time').textContent=record.time?new Date(record.time).toLocaleString():'';
   card.querySelector('.audit-result-log').textContent=record.log||'No output returned.';
 }
 function saveAudit(card,type,log){
   const record={type,log,time:new Date().toISOString()};
   localStorage.setItem(storageKey(card.dataset.firewallId),JSON.stringify(record));
   renderAudit(card,record);
 }
 document.querySelectorAll('[data-firewall-id]').forEach(card=>{
   try{const saved=JSON.parse(localStorage.getItem(storageKey(card.dataset.firewallId))||'null');if(saved)renderAudit(card,saved);}catch(e){}
 });
 async function action(card,action,extra={}){
   const id=card.dataset.firewallId; const body=new URLSearchParams({csrf,id,action,...extra});
   const response=await fetch('/firewall_action.php',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
   const raw=await response.text(); let data; try{data=JSON.parse(raw);}catch(e){throw new Error(raw.slice(0,700));}
   if(!response.ok||data.ok!==true) throw new Error(data.error||'Action failed.'); return data;
 }
 async function check(card){
   const state=card.querySelector('.firmware-state'), details=card.querySelector('.firmware-details'), update=card.querySelector('.firmware-update');
   state.textContent='Checking…'; state.className='firmware-state badge neutral'; update.classList.add('hidden');
   card.querySelector('.firmware-meta')?.setAttribute('hidden','');
   try{
     const data=await action(card,'firmware_check');
     const s=data.summary||{};
     state.textContent=s.update_available?'Update available':'Up to date';
     state.className='firmware-state badge '+(s.update_available?'warning':'good');
     details.textContent=s.message||s.status||'Firmware status loaded.';
     renderFirmwareMeta(card,data.value||{});
     if(s.update_available&&s.action){
       update.dataset.action=s.action;
       update.textContent=s.action==='firmware_upgrade'?'Upgrade now':'Update now';
       update.classList.remove('hidden');
     }
   }
   catch(e){state.textContent='Failed';state.className='firmware-state badge bad';details.textContent=e.message;}
 }
 async function pollAudit(card,type){
   const started=Date.now();
   while(Date.now()-started<240000){
     await new Promise(resolve=>setTimeout(resolve,3000));
     const data=await action(card,'firmware_audit_status');
     const status=data.status||'running';
     const log=data.log||'';
     if(status==='done'||status==='error'||status==='reboot'||log.includes('***DONE***')){
       saveAudit(card,type,log||('Audit finished with status: '+status));
       return;
     }
     if(log) renderAudit(card,{type,log,time:new Date().toISOString()});
   }
   throw new Error('Audit is still running after four minutes. The latest output remains visible.');
 }
 async function runAudit(card,type){
   const button=card.querySelector('.firmware-audit');
   button.disabled=true; button.textContent='Auditing…';
   try{
     const data=await action(card,'firmware_audit',{audit_type:type});
     if(data.status==='done') saveAudit(card,type,data.log||JSON.stringify(data.value,null,2));
     else await pollAudit(card,type);
     show((auditLabels[type]||'Firmware audit')+' completed on '+card.dataset.firewallName+'.');
   }catch(e){show(e.message,true);}
   finally{button.disabled=false;button.textContent='Run audit';}
 }
 document.querySelectorAll('.firmware-check').forEach(b=>b.addEventListener('click',()=>check(b.closest('[data-firewall-id]'))));
 document.querySelectorAll('.firmware-audit').forEach(b=>b.addEventListener('click',()=>{auditCard=b.closest('[data-firewall-id]');dialogTarget.textContent='Target: '+auditCard.dataset.firewallName;dialog.hidden=false;}));
 document.getElementById('firmware-audit-cancel')?.addEventListener('click',()=>{dialog.hidden=true;auditCard=null;});
 dialog.querySelector('.audit-dialog-backdrop')?.addEventListener('click',()=>{dialog.hidden=true;auditCard=null;});
 runButton?.addEventListener('click',()=>{if(!auditCard)return;const selected=dialog.querySelector('input[name="audit_type"]:checked');const type=selected?.value||'security';const card=auditCard;dialog.hidden=true;auditCard=null;runAudit(card,type);});
 document.querySelectorAll('.firmware-update').forEach(b=>b.addEventListener('click',async()=>{if(!confirm('Start the offered firmware action on this OPNsense?'))return;try{const d=await action(b.closest('[data-firewall-id]'),b.dataset.action);show(d.message||'Firmware action started.');}catch(e){show(e.message,true);}}));
 document.getElementById('firmware-refresh-all')?.addEventListener('click',()=>document.querySelectorAll('[data-firewall-id]').forEach(check));
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
