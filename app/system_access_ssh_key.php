<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();

$firewallId = (int)($_GET['firewall_id'] ?? 0);
$userName = trim((string)($_GET['user'] ?? ''));
if ($firewallId <= 0 || $userName === '') {
    header('Location: /system_access_users.php');
    exit;
}

$firewallStmt = db()->prepare('SELECT id,name FROM firewalls WHERE id = ?');
$firewallStmt->execute([$firewallId]);
$firewall = $firewallStmt->fetch();
if (!is_array($firewall)) {
    http_response_code(404);
    exit('Firewall not found.');
}

$agentStmt = db()->prepare('SELECT * FROM agents WHERE firewall_id = ? ORDER BY id DESC LIMIT 1');
$agentStmt->execute([$firewallId]);
$agent = $agentStmt->fetch();
$version = is_array($agent) ? trim((string)($agent['last_version'] ?? '')) : '';
$lastSeen = is_array($agent) && !empty($agent['last_seen_at']) ? (strtotime((string)$agent['last_seen_at']) ?: 0) : 0;
$online = is_array($agent) && (int)($agent['enabled'] ?? 0) === 1 && $lastSeen > 0 && (time() - $lastSeen) < 300;
$capable = $online && $version !== '' && version_compare($version, '0.1.12', '>=');

$result = $_SESSION['ssh_key_deploy_result'] ?? null;
unset($_SESSION['ssh_key_deploy_result']);

require __DIR__ . '/inc/header.php';
?>
<style>
.ssh-key-card{max-width:900px}.ssh-key-card label{display:block;margin-bottom:12px}.ssh-key-text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;min-height:130px;width:100%}.ssh-key-result{padding:10px 12px;border-radius:6px;margin-top:8px;background:rgba(127,127,127,.08)}.ssh-key-result.good{border-left:4px solid #2aa84a}.ssh-key-result.bad{border-left:4px solid #d74747}.ssh-key-result.pending{border-left:4px solid #d6a52f}.fixed-target{padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:14px}
</style>
<div class="page-title">
    <div><h1>System → Access → Add SSH Key</h1><p>One SSH public key → one existing user → one OPNsense.</p></div>
    <a class="button secondary" href="/system_access_users.php">Back to Users</a>
</div>
<div class="alert warningbox"><strong>Only Authorized Keys is changed.</strong> Disabled state, password, OTP, groups, privileges, shell and API keys are not part of this job. Existing SSH keys are preserved.</div>
<div class="card ssh-key-card">
    <h2>Target</h2>
    <div class="fixed-target"><strong><?= h((string)$firewall['name']) ?></strong><br>User: <strong><?= h($userName) ?></strong><br><small><?= $version !== '' ? 'Agent '.h($version) : 'No agent' ?><?= !$online ? ' · offline/stale' : '' ?></small></div>
    <?php if (!$capable): ?>
        <div class="alert warningbox"><strong>Cannot deploy yet.</strong> This firewall needs an online agent 0.1.12.</div>
    <?php else: ?>
    <form method="post" action="/system_access_ssh_key_action.php">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="firewall_id" value="<?= $firewallId ?>">
        <input type="hidden" name="user" value="<?= h($userName) ?>">
        <label>OpenSSH public key
            <textarea class="ssh-key-text" name="authorized_key" rows="5" spellcheck="false" required placeholder="ssh-ed25519 AAAA... comment"></textarea>
            <small>Exactly one public key. If the same key already exists, the agent makes no change.</small>
        </label>
        <button class="button" type="submit">Add SSH key to <?= h($userName) ?> on <?= h((string)$firewall['name']) ?></button>
    </form>
    <?php endif; ?>
</div>
<?php if (is_array($result)): ?>
<div class="card" style="margin-top:14px;max-width:900px">
    <h2>Deployment result</h2>
    <?php if (!empty($result['error'])): ?>
        <div class="ssh-key-result bad"><strong>Not queued</strong><br><?= h((string)$result['error']) ?></div>
    <?php elseif (!empty($result['job_id'])): ?>
        <div class="ssh-key-result pending" id="ssh-key-job"><strong><?= h((string)($result['firewall_name'] ?? 'Firewall')) ?></strong> <span class="badge neutral">Queued</span><br>User <?= h((string)($result['user'] ?? '')) ?></div>
    <?php endif; ?>
</div>
<?php if (!empty($result['job_id'])): ?>
<script>
(async function(){
 const id=<?= (int)$result['job_id'] ?>; const node=document.getElementById('ssh-key-job'); const deadline=Date.now()+120000;
 while(Date.now()<deadline){
   await new Promise(r=>setTimeout(r,1500));
   const response=await fetch('/system_administration_matrix_status.php?ids='+id,{credentials:'same-origin',cache:'no-store'});
   const data=await response.json(); if(!response.ok||data.ok!==true)break;
   const job=(data.jobs||[]).find(j=>Number(j.id)===id); if(!job)continue;
   const status=String(job.status||'queued');
   if(status==='completed'){node.className='ssh-key-result good';node.innerHTML='<strong>Successfully applied</strong><br>'+escapeHtml(job.message||'SSH key added.');return;}
   if(status==='failed'){node.className='ssh-key-result bad';node.innerHTML='<strong>Deployment failed</strong><br>'+escapeHtml(job.error||'Agent job failed.');return;}
 }
 function escapeHtml(v){const n=document.createElement('div');n.textContent=String(v??'');return n.innerHTML;}
})();
</script>
<?php endif; ?>
<?php endif; ?>
<?php require __DIR__ . '/inc/footer.php'; ?>
