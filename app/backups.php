<?php
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/backups.php';
require_login();
$rows = backup_rows();
require __DIR__ . '/inc/header.php';
?>
<div class="page-title">
    <div>
        <h1>Backups</h1>
        <p>Persistent OPNsense configuration backups and automatic pre-change protection.</p>
    </div>
    <button id="backup-all" type="button">Backup all firewalls</button>
</div>

<div id="backup-message" class="alert goodbox hidden"></div>
<div id="backup-error" class="alert error hidden"></div>
<div id="backup-results" class="card hidden"></div>

<section class="card">
    <div class="card-head">
        <h2>Backup history</h2>
        <span class="muted">Pre-change retention: <?= h(envv('PRECHANGE_BACKUP_RETENTION','20')) ?> per firewall</span>
    </div>
    <?php if (!$rows): ?>
        <div class="empty">No backups recorded yet.</div>
    <?php else: ?>
        <div class="table-wrap">
            <table class="opn-table">
                <thead><tr><th>Date</th><th>Firewall</th><th>Type</th><th>Reason</th><th>Status</th><th>Size</th><th>Download</th></tr></thead>
                <tbody>
                <?php foreach ($rows as $row): ?>
                    <tr>
                        <td><?= h((string)$row['created_at']) ?></td>
                        <td><?= h((string)$row['firewall_name']) ?></td>
                        <td><?= h((string)$row['backup_type']) ?></td>
                        <td><?= h((string)$row['reason']) ?></td>
                        <td><span class="badge <?= $row['status']==='ok'?'good':'bad' ?>"><?= h((string)$row['status']) ?></span></td>
                        <td><?= $row['status']==='ok' ? h(number_format(((int)$row['byte_size'])/1024,1).' KB') : h((string)$row['error']) ?></td>
                        <td><?php if ($row['status']==='ok'): ?><a
    class="button secondary remote-change-control backup-download-control"
    href="/backup_download.php?id=<?= (int)$row['id'] ?>"
>Download</a><?php endif; ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</section>
<script>
(function(){
 const button=document.getElementById('backup-all');
 const message=document.getElementById('backup-message');
 const error=document.getElementById('backup-error');
 const results=document.getElementById('backup-results');
 button.addEventListener('click',async function(){
   if(!confirm('Back up all managed OPNsense firewalls now?')) return;
   button.disabled=true; button.textContent='Backing up…';
   message.classList.add('hidden'); error.classList.add('hidden'); results.classList.add('hidden');
   try{
     const body=new URLSearchParams(); body.set('csrf',<?= json_encode(csrf_token()) ?>); body.set('action','backup_all');
     const response=await fetch('/backups_action.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
     const data=await response.json();
     if(!response.ok||data.ok!==true) throw new Error(data.error||'Backup failed.');
     results.innerHTML='<h3>'+data.successful+' of '+data.total+' backups completed</h3>'+
       data.results.map(r=>'<div class="backup-result '+(r.ok?'ok':'bad')+'"><strong>'+escapeHtml(r.firewall)+'</strong> '+(r.ok?'Completed':'Failed: '+escapeHtml(r.error))+'</div>').join('')+
       (data.batch?'<p><a class="button remote-change-control backup-download-control" href="/backup_zip_download.php?batch='+encodeURIComponent(data.batch)+'">Download all as ZIP</a></p>':'');
     results.classList.remove('hidden');
     message.textContent='Backup all completed.'; message.classList.remove('hidden');
   }catch(e){error.textContent=e.message;error.classList.remove('hidden');}
   finally{button.disabled=false;button.textContent='Backup all firewalls';}
 });
 function escapeHtml(v){const d=document.createElement('div');d.textContent=String(v);return d.innerHTML;}
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
