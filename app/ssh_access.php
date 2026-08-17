<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/ssh_access.php';
require_login();

$firewalls = db()->query('SELECT id,name,base_url FROM firewalls ORDER BY name')->fetchAll();
$source = '';
$sourceError = '';
try {
    $source = ssh_access_public_source();
} catch (Throwable $exception) {
    $sourceError = $exception->getMessage();
}

$rows = [];
foreach ($firewalls as $firewall) {
    $fid = (int) $firewall['id'];
    $agent = ssh_access_agent($fid);
    $latestJob = $agent !== null ? ssh_access_latest_job((int) $agent['id']) : null;
    $jobResult = null;
    if (is_array($latestJob) && trim((string) ($latestJob['result_json'] ?? '')) !== '') {
        $decoded = json_decode((string) $latestJob['result_json'], true);
        if (is_array($decoded)) $jobResult = $decoded;
    }
    $rows[] = [
        'firewall' => $firewall,
        'agent' => $agent,
        'agent_ready' => ssh_access_agent_ready($agent),
        'latest_job' => $latestJob,
        'job_result' => $jobResult,
    ];
}

$flash = $_SESSION['ssh_access_result'] ?? null;
unset($_SESSION['ssh_access_result']);

function ssh_status_badge(?array $job, ?array $result): string
{
    if (!is_array($job)) return '<span class="badge neutral">Not checked</span>';
    $status = (string) ($job['status'] ?? '');
    if (in_array($status, ['queued', 'running'], true)) return '<span class="badge warning">' . h($status) . '</span>';
    if ($status === 'failed') return '<span class="badge bad">Failed</span>';
    if (($result['ok'] ?? false) === true) return '<span class="badge good">Ready</span>';
    return '<span class="badge warning">Needs repair</span>';
}

require __DIR__ . '/inc/header.php';
?>
<style>
.ssh-fleet-toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.ssh-fleet-actions{display:flex;gap:8px;flex-wrap:wrap}
.ssh-fleet-table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.ssh-fleet-table{width:100%;border-collapse:separate;border-spacing:0;min-width:980px}
.ssh-fleet-table th,.ssh-fleet-table td{padding:11px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:middle}
.ssh-fleet-table th:last-child,.ssh-fleet-table td:last-child{border-right:0}.ssh-fleet-table tr:last-child td{border-bottom:0}
.ssh-fleet-table thead th{background:var(--table-head);text-align:left}.ssh-fleet-check{width:20px;height:20px}
.ssh-fleet-row-actions{display:flex;gap:7px;flex-wrap:wrap}.ssh-fleet-result-grid{display:grid;gap:7px;margin-top:8px}
.ssh-fleet-result{padding:9px 11px;border-radius:6px;background:rgba(127,127,127,.08)}.ssh-fleet-result.good{border-left:4px solid #2aa84a}.ssh-fleet-result.bad{border-left:4px solid #d74747}
.ssh-requirements{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}.ssh-requirements .card{margin:0}
@media(max-width:900px){.ssh-requirements{grid-template-columns:1fr 1fr}}@media(max-width:620px){.ssh-requirements{grid-template-columns:1fr}}
</style>

<div class="page-title">
    <div>
        <h1>System → Settings → Managed SSH Access</h1>
        <p>Enable or repair secure SSH management access on one, selected, or all managed OPNsense firewalls.</p>
    </div>
    <a class="button secondary" href="/agents.php">Manage Agents</a>
</div>

<?php if ($sourceError !== ''): ?><div class="alert error"><?= h($sourceError) ?></div><?php endif; ?>

<?php if (is_array($flash)): ?>
<div class="alert <?= !empty($flash['ok']) ? 'goodbox' : 'warningbox' ?>">
    <strong>SSH deployment</strong><div><?= h((string) ($flash['message'] ?? '')) ?></div>
    <?php if (!empty($flash['results']) && is_array($flash['results'])): ?>
    <div class="ssh-fleet-result-grid">
        <?php foreach ($flash['results'] as $item): ?>
        <div class="ssh-fleet-result <?= !empty($item['ok']) ? 'good' : 'bad' ?>">
            <strong><?= h((string) ($item['firewall'] ?? 'Firewall')) ?></strong> — <?= h((string) ($item['message'] ?? '')) ?>
        </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
</div>
<?php endif; ?>

<div class="ssh-requirements">
    <div class="card"><strong>SSH service</strong><div>Enabled on TCP/22</div></div>
    <div class="card"><strong>Access group</strong><div>SSH group: admins · sudo: admins</div></div>
    <div class="card"><strong>Firewall access</strong><div>Source alias <code>opnSentral</code> → This Firewall TCP/22</div></div>
    <div class="card"><strong>Source</strong><div><?= h($source !== '' ? $source : 'Unavailable') ?></div></div>
</div>

<div class="alert warningbox">
    <strong>What “Enable / Repair” does:</strong> creates a pre-change backup, creates/repairs the “Managed by opnSentral” category, maintains the <code>opnSentral</code> source alias, creates/repairs the inbound TCP/22 management rule, configures OPNsense SSH for the <code>admins</code> group with sudo access, restarts OpenSSH, and verifies the resulting SSH state. The remote agent performs the local OPNsense system changes; it is not the SSH connection itself.
</div>

<form method="post" action="/ssh_access_action.php" id="ssh-fleet-form">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<input type="hidden" name="action" value="ensure">
<div class="ssh-fleet-toolbar">
    <div><strong><?= count($rows) ?> managed firewall<?= count($rows) === 1 ? '' : 's' ?></strong><span class="muted"> · Select any combination of targets.</span></div>
    <div class="ssh-fleet-actions">
        <button type="button" class="button secondary" id="ssh-select-all">Select all ready</button>
        <button type="submit" class="button" id="ssh-enable-selected" disabled>Enable / Repair selected</button>
    </div>
</div>

<div class="ssh-fleet-table-wrap">
<table class="ssh-fleet-table">
<thead><tr><th style="width:56px">Select</th><th>OPNsense</th><th>Agent</th><th>SSH status</th><th>Last result</th><th>Actions</th></tr></thead>
<tbody>
<?php foreach ($rows as $entry):
    $firewall = $entry['firewall'];
    $fid = (int) $firewall['id'];
    $agent = $entry['agent'];
    $agentReady = (bool) $entry['agent_ready'];
    $agentVersion = is_array($agent) ? trim((string) ($agent['last_version'] ?? '')) : '';
    $job = $entry['latest_job'];
    $result = $entry['job_result'];
?>
<tr>
    <td><input class="ssh-fleet-check" type="checkbox" name="firewall_ids[]" value="<?= $fid ?>" <?= $agentReady && $sourceError === '' ? '' : 'disabled' ?>></td>
    <td><strong><?= h((string) $firewall['name']) ?></strong><div class="muted"><?= h((string) $firewall['base_url']) ?></div></td>
    <td>
        <?php if ($agentReady): ?><span class="badge good">Ready</span> <?= h($agentVersion !== '' ? 'v' . $agentVersion : '') ?>
        <?php elseif (is_array($agent)): ?><span class="badge warning">Update required</span> <?= h($agentVersion !== '' ? 'v' . $agentVersion : '') ?>
        <?php else: ?><span class="badge bad">Missing</span><?php endif; ?>
    </td>
    <td><?= ssh_status_badge($job, $result) ?></td>
    <td>
        <?php if (is_array($job)): ?>Job #<?= (int) $job['id'] ?> · <?= h((string) ($job['status'] ?? '')) ?>
        <?php else: ?><span class="muted">No status job yet</span><?php endif; ?>
    </td>
    <td class="ssh-fleet-row-actions">
        <button type="button" class="button secondary ssh-check-one" data-id="<?= $fid ?>" <?= !$agentReady ? 'disabled' : '' ?>>Check</button>
        <button type="button" class="button ssh-enable-one" data-id="<?= $fid ?>" data-name="<?= h((string) $firewall['name']) ?>" <?= !$agentReady || $sourceError !== '' ? 'disabled' : '' ?>>Enable / Repair</button>
    </td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>
</form>

<script>
(function(){
    const checks=Array.from(document.querySelectorAll('.ssh-fleet-check'));
    const selectedButton=document.getElementById('ssh-enable-selected');
    const selectAll=document.getElementById('ssh-select-all');
    const csrf=<?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>;

    function refresh(){selectedButton.disabled=!checks.some(c=>!c.disabled&&c.checked);}
    checks.forEach(c=>c.addEventListener('change',refresh));
    selectAll.addEventListener('click',()=>{checks.forEach(c=>{if(!c.disabled)c.checked=true;});refresh();});
    document.getElementById('ssh-fleet-form').addEventListener('submit',function(event){
        const count=checks.filter(c=>!c.disabled&&c.checked).length;
        if(!count||!confirm('Enable / repair managed SSH access on '+count+' firewall'+(count===1?'':'s')+'?\n\nA pre-change backup will be created for every target.')) event.preventDefault();
    });

    function submitOne(id,action){
        const form=document.createElement('form');form.method='post';form.action='/ssh_access_action.php';form.style.display='none';
        [["csrf",csrf],["firewall_id",String(id)],["action",action]].forEach(([name,value])=>{const input=document.createElement('input');input.name=name;input.value=value;form.appendChild(input);});
        document.body.appendChild(form);form.submit();
    }
    document.querySelectorAll('.ssh-enable-one').forEach(btn=>btn.addEventListener('click',()=>{
        if(confirm('Enable / repair managed SSH access on '+btn.dataset.name+'?\n\nA pre-change backup will be created first.')) submitOne(btn.dataset.id,'ensure');
    }));
    document.querySelectorAll('.ssh-check-one').forEach(btn=>btn.addEventListener('click',()=>submitOne(btn.dataset.id,'check')));
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
