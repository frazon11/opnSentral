<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();

$prefillFirewallId = (int)($_GET['firewall_id'] ?? 0);
$prefillUser = trim((string)($_GET['user'] ?? ''));
$firewalls = db()->query('SELECT id,name FROM firewalls ORDER BY name')->fetchAll();
$agents = db()->query('SELECT * FROM agents WHERE firewall_id IS NOT NULL ORDER BY id DESC')->fetchAll();
$agentsByFirewall = [];
foreach ($agents as $agent) {
    $fid = (int)($agent['firewall_id'] ?? 0);
    if ($fid > 0 && !isset($agentsByFirewall[$fid])) $agentsByFirewall[$fid] = $agent;
}

$result = $_SESSION['ssh_key_deploy_result'] ?? null;
unset($_SESSION['ssh_key_deploy_result']);

require __DIR__ . '/inc/header.php';
?>
<style>
.ssh-key-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(300px,.7fr);gap:14px}.ssh-key-card label{display:block;margin-bottom:12px}.ssh-key-text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;min-height:130px;width:100%}.ssh-key-result{padding:10px 12px;border-radius:6px;margin-top:8px;background:rgba(127,127,127,.08)}.ssh-key-result.good{border-left:4px solid #2aa84a}.ssh-key-result.bad{border-left:4px solid #d74747}.ssh-key-result.pending{border-left:4px solid #d6a52f}@media(max-width:900px){.ssh-key-grid{grid-template-columns:1fr}}
</style>
<div class="page-title">
    <div><h1>System → Access → Add SSH Key</h1><p>Add one SSH public key to one existing OPNsense user on one firewall.</p></div>
    <a class="button secondary" href="/system_access_users.php">Back to Users</a>
</div>
<div class="alert warningbox"><strong>Single-target safety mode.</strong> This action changes only Authorized Keys. It does not change Disabled, password, OTP, groups, privileges, shell, or API keys. The agent verifies the user locally and creates a local safety copy of <code>/conf/config.xml</code> before writing.</div>
<form method="post" action="/system_access_ssh_key_action.php">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<div class="ssh-key-grid">
    <div class="card ssh-key-card">
        <h2>Target</h2>
        <label>OPNsense
            <select name="firewall_id" required>
                <option value="">Select firewall…</option>
                <?php foreach ($firewalls as $firewall):
                    $fid = (int)$firewall['id'];
                    $agent = $agentsByFirewall[$fid] ?? null;
                    $version = is_array($agent) ? trim((string)($agent['last_version'] ?? '')) : '';
                    $lastSeen = is_array($agent) && !empty($agent['last_seen_at']) ? (strtotime((string)$agent['last_seen_at']) ?: 0) : 0;
                    $online = is_array($agent) && (int)($agent['enabled'] ?? 0) === 1 && $lastSeen > 0 && (time() - $lastSeen) < 300;
                    $capable = $online && $version !== '' && version_compare($version, '0.1.11', '>=');
                ?>
                <option value="<?= $fid ?>" <?= $fid === $prefillFirewallId ? 'selected' : '' ?> <?= $capable ? '' : 'disabled' ?>><?= h((string)$firewall['name']) ?><?= $version !== '' ? ' — agent '.h($version) : ' — no agent' ?><?= !$online ? ' — offline/stale' : (!$capable ? ' — update agent' : '') ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <label>User name
            <input type="text" name="user" maxlength="128" autocomplete="off" required value="<?= h($prefillUser) ?>" placeholder="e.g. admin">
        </label>
        <label>OpenSSH public key
            <textarea class="ssh-key-text" name="authorized_key" rows="5" spellcheck="false" required placeholder="ssh-ed25519 AAAA... comment"></textarea>
            <small>Exactly one public key. Existing Authorized Keys are preserved; this key is added only if it is not already present.</small>
        </label>
        <button class="button" type="submit">Add SSH key</button>
    </div>
    <div class="card ssh-key-card">
        <h2>Safety</h2>
        <p>The selected firewall must have an online agent 0.1.11+.</p>
        <p>The agent confirms the user exists in the local OPNsense configuration before changing anything.</p>
        <p>A local safety copy of <code>/conf/config.xml</code> is created first.</p>
        <p>The job appends one key to <code>authorizedkeys</code>; existing keys are preserved. No other user field is sent by this action.</p>
    </div>
</div>
</form>
<?php if (is_array($result)): ?>
<div class="card" style="margin-top:14px">
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
