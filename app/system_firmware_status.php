<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_login();
$firewalls = db()->query('SELECT id,name,base_url FROM firewalls ORDER BY name')->fetchAll();
require __DIR__ . '/inc/header.php';
?>
<div class="page-title management-page-title">
  <div><h1>System → Firmware → Status</h1><p>Check for updates, start supported firmware updates and run firmware audits across managed OPNsense firewalls.</p></div>
  <button type="button" class="button secondary" id="firmware-refresh-all">Check all</button>
</div>
<div id="firmware-status-message" class="alert hidden"></div>
<div id="firmware-status-list" class="vpn-summary-list">
<?php foreach ($firewalls as $firewall): ?>
<section class="card vpn-summary-card" data-firewall-id="<?= (int)$firewall['id'] ?>">
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
</section>
<?php endforeach; ?>
<?php if (!$firewalls): ?><section class="card"><p class="muted">No firewalls configured.</p></section><?php endif; ?>
</div>
<script>
(function(){
 const csrf=<?= json_encode(csrf_token(),JSON_UNESCAPED_SLASHES) ?>;
 const message=document.getElementById('firmware-status-message');
 function show(text,bad=false){message.textContent=text;message.className='alert '+(bad?'error':'goodbox');}
 async function action(card,action){
   const id=card.dataset.firewallId; const body=new URLSearchParams({csrf,id,action});
   const response=await fetch('/firewall_action.php',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
   const raw=await response.text(); let data; try{data=JSON.parse(raw);}catch(e){throw new Error(raw.slice(0,700));}
   if(!response.ok||data.ok!==true) throw new Error(data.error||'Action failed.'); return data;
 }
 async function check(card){
   const state=card.querySelector('.firmware-state'), details=card.querySelector('.firmware-details'), update=card.querySelector('.firmware-update');
   state.textContent='Checking…'; state.className='firmware-state badge neutral'; update.classList.add('hidden');
   try{const data=await action(card,'firmware_check'); const s=data.summary||{}; state.textContent=s.update_available?'Update available':'Up to date'; state.className='firmware-state badge '+(s.update_available?'warning':'good'); details.textContent=s.message||s.status||'Firmware status loaded.'; if(s.update_available&&s.action){update.dataset.action=s.action; update.textContent=s.action==='firmware_upgrade'?'Upgrade now':'Update now'; update.classList.remove('hidden');}}
   catch(e){state.textContent='Failed';state.className='firmware-state badge bad';details.textContent=e.message;}
 }
 document.querySelectorAll('.firmware-check').forEach(b=>b.addEventListener('click',()=>check(b.closest('[data-firewall-id]'))));
 document.querySelectorAll('.firmware-audit').forEach(b=>b.addEventListener('click',async()=>{const c=b.closest('[data-firewall-id]');b.disabled=true;b.textContent='Auditing…';try{const d=await action(c,'firmware_audit');c.querySelector('.firmware-details').textContent=d.message||JSON.stringify(d.value);show('Firmware audit completed.');}catch(e){show(e.message,true);}finally{b.disabled=false;b.textContent='Run audit';}}));
 document.querySelectorAll('.firmware-update').forEach(b=>b.addEventListener('click',async()=>{if(!confirm('Start the offered firmware action on this OPNsense?'))return;try{const d=await action(b.closest('[data-firewall-id]'),b.dataset.action);show(d.message||'Firmware action started.');}catch(e){show(e.message,true);}}));
 document.getElementById('firmware-refresh-all')?.addEventListener('click',()=>document.querySelectorAll('[data-firewall-id]').forEach(check));
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
