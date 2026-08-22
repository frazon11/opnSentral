<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/system_access_inventory.php';
require_login();

$firewallId = (int) ($_GET['firewall_id'] ?? 0);
$userName = trim((string) ($_GET['user'] ?? ''));
if ($firewallId <= 0 || $userName === '') {
    http_response_code(400);
    exit('Firewall and user are required.');
}

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$fleet = access_load_fleet_inventory($firewalls);
$sourceEntry = $fleet[$firewallId] ?? null;
$sourceUser = is_array($sourceEntry) ? ($sourceEntry['users'][$userName] ?? null) : null;
if (!is_array($sourceEntry) || ($sourceEntry['ok'] ?? false) !== true || !is_array($sourceUser)) {
    http_response_code(404);
    exit('User was not found on the selected firewall.');
}

$groups = array_keys($sourceEntry['groups'] ?? []);
natcasesort($groups);
$groups = array_values($groups);

$privilegeSet = ['page-all' => true, 'user-shell-access' => true];
foreach ($fleet as $entry) {
    foreach (($entry['users'] ?? []) as $user) {
        foreach (($user['privileges'] ?? []) as $priv) $privilegeSet[(string) $priv] = true;
    }
    foreach (($entry['groups'] ?? []) as $group) {
        foreach (($group['privileges'] ?? []) as $priv) $privilegeSet[(string) $priv] = true;
    }
}
$privileges = array_keys($privilegeSet);
natcasesort($privileges);
$privileges = array_values($privileges);

$agents = db()->query('SELECT * FROM agents WHERE firewall_id IS NOT NULL ORDER BY id DESC')->fetchAll();
$agentsByFirewall = [];
foreach ($agents as $agent) {
    $fid = (int) ($agent['firewall_id'] ?? 0);
    if ($fid > 0 && !isset($agentsByFirewall[$fid])) $agentsByFirewall[$fid] = $agent;
}

$result = $_SESSION['access_user_edit_result'] ?? null;
unset($_SESSION['access_user_edit_result']);

$shellOptions = array_values(array_unique(array_filter([
    (string) ($sourceUser['shell'] ?? ''),
    '/bin/csh',
    '/bin/tcsh',
    '/bin/sh',
    '/sbin/nologin',
    '/usr/local/bin/scponly',
    '/usr/local/sbin/scponlyc',
    '/usr/local/sbin/ssh_tunnel_shell',
])));

require __DIR__ . '/inc/header.php';
?>
<style>
.access-edit-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,.8fr);gap:14px}.access-edit-card label{display:block;margin-bottom:12px}.access-edit-card select[multiple]{min-height:180px}.access-targets{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}.access-target{padding:10px;border:1px solid var(--border);border-radius:6px}.access-target small{display:block;color:var(--muted);margin-top:3px}.access-edit-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.access-result-item{padding:9px 11px;border-radius:6px;margin-top:7px;background:rgba(127,127,127,.08)}.access-result-item.good{border-left:4px solid #2aa84a}.access-result-item.bad{border-left:4px solid #d74747}.access-result-item.pending{border-left:4px solid #d6a52f}.authorized-keys{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;min-height:150px;width:100%}@media(max-width:900px){.access-edit-grid{grid-template-columns:1fr}}
</style>
<div class="page-title">
    <div><h1>System → Access → Users → Edit</h1><p><?= h($userName) ?> · source <?= h((string) $sourceEntry['firewall']['name']) ?></p></div>
    <a class="button secondary" href="/system_access_users.php">Back to Users</a>
</div>
<div class="alert warningbox"><strong>Authentication-critical change.</strong> Disabled, Login shell, Group membership, direct Privileges and Authorized Keys can be modified. Passwords, OTP seeds and API keys are preserved. A pre-change backup is created for every target before the job is queued.</div>

<form method="post" action="/system_access_user_action.php">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<input type="hidden" name="source_firewall_id" value="<?= $firewallId ?>">
<input type="hidden" name="user" value="<?= h($userName) ?>">
<div class="access-edit-grid">
    <div class="card access-edit-card">
        <h2>User details</h2>
        <label><input type="checkbox" name="disabled" value="1" <?= !empty($sourceUser['disabled']) ? 'checked' : '' ?> <?= (string)($sourceUser['uid'] ?? '') === '0' ? 'disabled' : '' ?>> Disable user</label>
        <?php if ((string)($sourceUser['uid'] ?? '') === '0'): ?><p class="muted">UID 0 cannot be disabled through opnSentral.</p><?php endif; ?>
        <label>Login shell
            <select name="shell">
                <option value="">Default / none</option>
                <?php foreach ($shellOptions as $shell): ?><option value="<?= h($shell) ?>" <?= (string)($sourceUser['shell'] ?? '') === $shell ? 'selected' : '' ?>><?= h($shell) ?></option><?php endforeach; ?>
            </select>
        </label>
        <label>Authorized Keys
            <textarea class="authorized-keys" name="authorized_keys" rows="7" spellcheck="false" placeholder="ssh-ed25519 AAAA... comment&#10;ssh-rsa AAAA... comment"><?= h((string)($sourceUser['authorized_keys'] ?? '')) ?></textarea>
            <small>One OpenSSH public key per line. Leave empty to remove all authorized keys for this user.</small>
        </label>
        <label>Group membership
            <select name="groups[]" multiple>
                <?php foreach ($groups as $group): ?><option value="<?= h($group) ?>" <?= in_array($group, $sourceUser['groups'] ?? [], true) ? 'selected' : '' ?>><?= h($group) ?></option><?php endforeach; ?>
            </select>
        </label>
        <label>Privileges
            <select name="privileges[]" multiple>
                <?php foreach ($privileges as $priv): ?><option value="<?= h($priv) ?>" <?= in_array($priv, $sourceUser['privileges'] ?? [], true) ? 'selected' : '' ?>><?= h($priv) ?></option><?php endforeach; ?>
            </select>
        </label>
        <label>Additional privilege IDs
            <textarea name="additional_privileges" rows="4" placeholder="One privilege ID per line"></textarea>
            <small>Use this for an installed plug-in privilege that is not currently assigned anywhere in the fleet.</small>
        </label>
    </div>

    <div class="card access-edit-card">
        <h2>Deploy to</h2>
        <div class="access-targets">
        <?php foreach ($fleet as $fid => $entry):
            $user = $entry['users'][$userName] ?? null;
            if (!is_array($user)) continue;
            $agent = $agentsByFirewall[$fid] ?? null;
            $agentVersion = is_array($agent) ? trim((string)($agent['last_version'] ?? '')) : '';
            $writable = is_array($agent) && (int)($agent['enabled'] ?? 0) === 1 && $agentVersion !== '' && version_compare($agentVersion, '0.1.10', '>=');
        ?>
            <label class="access-target">
                <input type="checkbox" name="targets[]" value="<?= (int)$fid ?>" <?= $fid === $firewallId && $writable ? 'checked' : '' ?> <?= $writable ? '' : 'disabled' ?>>
                <strong><?= h((string)$entry['firewall']['name']) ?></strong>
                <small>UID <?= h((string)($user['uid'] ?? '—')) ?> · <?= $agentVersion !== '' ? 'agent '.$agentVersion : 'no agent' ?></small>
                <?php if (!$writable): ?><small><span class="badge warning">Agent 0.1.10+ required</span></small><?php endif; ?>
            </label>
        <?php endforeach; ?>
        </div>
        <div class="access-edit-actions">
            <button class="button" type="submit">Apply selected user settings</button>
            <button class="button secondary" type="button" id="select-all-targets">Select all writable</button>
        </div>
    </div>
</div>
</form>

<?php if (is_array($result)): ?>
<div class="card" style="margin-top:14px" id="access-edit-result">
    <h2>Deployment result</h2>
    <div id="access-edit-summary" class="alert <?= !empty($result['failures']) ? 'warningbox' : 'goodbox' ?>"><?= h((string)($result['message'] ?? 'Deployment queued.')) ?></div>
    <div id="access-edit-result-grid">
        <?php foreach (($result['jobs'] ?? []) as $job): ?><div class="access-result-item pending" id="access-job-<?= (int)$job['job_id'] ?>"><strong><?= h((string)$job['firewall_name']) ?></strong> <span class="badge neutral">Queued</span></div><?php endforeach; ?>
        <?php foreach (($result['failures'] ?? []) as $failure): ?><div class="access-result-item bad"><strong><?= h((string)$failure['firewall_name']) ?></strong> <span class="badge bad">Not queued</span><br><?= h((string)$failure['error']) ?></div><?php endforeach; ?>
    </div>
</div>
<?php endif; ?>
<script>
document.getElementById('select-all-targets')?.addEventListener('click',()=>document.querySelectorAll('input[name="targets[]"]:not(:disabled)').forEach(box=>box.checked=true));
<?php if (is_array($result) && !empty($result['jobs'])): ?>
(async function(){
 const jobs=<?= json_encode(array_values($result['jobs']), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE) ?>;
 const ids=jobs.map(j=>j.job_id); const summary=document.getElementById('access-edit-summary'); const deadline=Date.now()+120000;
 while(Date.now()<deadline){
   await new Promise(r=>setTimeout(r,1500));
   const response=await fetch('/system_administration_matrix_status.php?ids='+encodeURIComponent(ids.join(',')),{credentials:'same-origin',cache:'no-store'});
   const data=await response.json(); if(!response.ok||data.ok!==true)break;
   const map=new Map((data.jobs||[]).map(j=>[Number(j.id),j])); let done=true; let failed=0;
   jobs.forEach(item=>{ const job=map.get(Number(item.job_id)); const node=document.getElementById('access-job-'+item.job_id); if(!job||!node){done=false;return;} const status=String(job.status||'queued');
     if(status==='completed'){node.className='access-result-item good';node.innerHTML='<strong>'+escapeHtml(item.firewall_name)+'</strong> <span class="badge good">Successfully deployed</span><br>'+escapeHtml(job.message||'User settings applied.');}
     else if(status==='failed'){failed++;node.className='access-result-item bad';node.innerHTML='<strong>'+escapeHtml(item.firewall_name)+'</strong> <span class="badge bad">Deployment failed</span><br>'+escapeHtml(job.error||'Agent job failed.');}
     else {done=false;node.className='access-result-item pending';node.innerHTML='<strong>'+escapeHtml(item.firewall_name)+'</strong> <span class="badge neutral">'+escapeHtml(status)+'</span>';}
   });
   if(done){summary.className=failed?'alert warningbox':'alert goodbox';summary.textContent=failed?'Deployment finished with '+failed+' failure'+(failed===1?'':'s')+'.':'User settings successfully deployed to all queued firewalls.';return;}
 }
 summary.className='alert warningbox';summary.textContent='Some jobs are still queued or running. Refresh this page to check the current state.';
 function escapeHtml(v){const n=document.createElement('div');n.textContent=String(v??'');return n.innerHTML;}
})();
<?php endif; ?>
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
