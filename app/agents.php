<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/agent_deployment.php';
require_login();

$pdo = db();
$firewalls = $pdo->query('SELECT id, name, base_url FROM firewalls ORDER BY name')->fetchAll();
$agents = $pdo->query(
    'SELECT a.*, f.name AS firewall_name
     FROM agents a
     LEFT JOIN firewalls f ON f.id = a.firewall_id
     ORDER BY COALESCE(f.name, a.name, a.agent_id)'
)->fetchAll();
$jobs = $pdo->query(
    'SELECT j.*, a.name AS agent_name, a.last_hostname, a.agent_id AS external_agent_id
     FROM agent_jobs j
     JOIN agents a ON a.id = j.agent_id
     ORDER BY j.id DESC
     LIMIT 30'
)->fetchAll();

$agentsByFirewall = [];
foreach ($agents as $agentRow) {
    $fid = (int) ($agentRow['firewall_id'] ?? 0);
    if ($fid > 0 && !isset($agentsByFirewall[$fid])) $agentsByFirewall[$fid] = $agentRow;
}

$targetAgentVersion = agent_current_version();
$registration = $_SESSION['new_agent_registration'] ?? null;
unset($_SESSION['new_agent_registration']);
$legacyCredentials = $_SESSION['new_agent_credentials'] ?? null;
unset($_SESSION['new_agent_credentials']);
$updateResult = $_SESSION['agent_update_result'] ?? null;
unset($_SESSION['agent_update_result']);

$forwardedProto = trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))[0] ?? '');
$scheme = $forwardedProto !== ''
    ? strtolower($forwardedProto)
    : (((string) ($_SERVER['HTTPS'] ?? '')) !== '' && ($_SERVER['HTTPS'] ?? 'off') !== 'off' ? 'https' : 'http');
$host = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
$publicBase = $host !== '' ? $scheme . '://' . $host : '';

require __DIR__ . '/inc/header.php';
?>
<div class="page-title management-page-title">
    <div>
        <h1>Agents</h1>
        <p>Outbound management agents. Native OPNsense plugin deployment is the target path; legacy standalone deployment is retained only for migration and recovery.</p>
    </div>
    <div class="management-toolbar">
        <button type="button" class="button secondary" onclick="window.location.reload()">Refresh</button>
    </div>
</div>

<?php if (is_string($updateResult) && $updateResult !== ''): ?>
    <div class="alert goodbox"><strong>Agent update</strong><div><?= h($updateResult) ?></div></div>
<?php endif; ?>

<?php if (is_array($registration)): ?>
    <?php
        $token = (string) ($registration['token'] ?? '');
        $installUrl = $publicBase . '/agent/install.sh';
        $command = 'fetch -o - ' . escapeshellarg($installUrl)
            . ' | sh -s -- ' . escapeshellarg($publicBase)
            . ' ' . escapeshellarg($token);
    ?>
    <div class="alert warningbox" data-presentation-exempt="true">
        <strong>Legacy standalone registration command</strong>
        <p>
            This command installs/registers the standalone agent worker; it does <strong>not</strong> install the native <code>os-opnsentral-agent</code> plugin.
            Run it as <strong>root</strong> on the remote OPNsense system before
            <?= h((string) ($registration['expires_at'] ?? 'the token expires')) ?>.
            The token cannot be displayed again after leaving this page.
        </p>
        <?php if ($publicBase === '' || $scheme !== 'https'): ?>
            <p><strong>HTTPS is required.</strong> Open opnSentral through its public HTTPS URL, generate a new token, and use that command.</p>
        <?php else: ?>
            <pre id="agent-registration-command"><?= h($command) ?></pre>
            <button type="button" class="button secondary" id="copy-agent-registration">Copy command</button>
        <?php endif; ?>
    </div>
<?php endif; ?>

<?php if (is_array($legacyCredentials)): ?>
<div class="alert warningbox" data-presentation-exempt="true">
    <strong>Legacy agent credentials — save now.</strong>
    <pre>AGENT_ID=<?= h((string) $legacyCredentials['agent_id']) . "\n" ?>AGENT_SECRET=<?= h((string) $legacyCredentials['secret']) ?></pre>
</div>
<?php endif; ?>

<div class="management-overview-bar">
    <div>
        <strong>Agent overview</strong>
        <div class="management-summary">
            <?= count($agents) ?> registered agent<?= count($agents) === 1 ? '' : 's' ?> · current worker <?= h($targetAgentVersion) ?>
        </div>
    </div>
</div>

<div class="card management-card">
    <div class="management-card-header">
        <div>
            <h2>Legacy standalone deployment / recovery</h2>
            <div class="management-summary">Existing SSH bootstrap for the standalone worker only. These controls do not install the native <code>os-opnsentral-agent</code> plugin.</div>
        </div>
    </div>
    <div class="table-scroll management-table-wrap">
        <table class="management-table">
            <thead><tr><th>Firewall</th><th>Installed</th><th>Target</th><th>Connection</th><th>Action</th></tr></thead>
            <tbody>
            <?php if (!$firewalls): ?><tr><td colspan="5">No managed firewalls configured.</td></tr><?php endif; ?>
            <?php foreach ($firewalls as $firewall):
                $fid = (int) $firewall['id'];
                $agent = $agentsByFirewall[$fid] ?? null;
                $installed = is_array($agent) ? trim((string) ($agent['last_agent_version'] ?? '')) : '';
                $enabled = is_array($agent) && (int) ($agent['enabled'] ?? 0) === 1;
                $last = is_array($agent) && $agent['last_seen_at'] ? (strtotime((string) $agent['last_seen_at']) ?: 0) : 0;
                $fresh = $enabled && $last > 0 && time() - $last < 150;
                $current = $installed !== '' && $targetAgentVersion !== 'unknown' && version_compare($installed, $targetAgentVersion, '>=');
                $selfUpdateCapable = $installed !== '' && version_compare($installed, '0.1.2', '>=');
            ?>
                <tr>
                    <td><strong><?= h((string) $firewall['name']) ?></strong><br><small><?= h((string) $firewall['base_url']) ?></small></td>
                    <td>
                        <?php if (!is_array($agent)): ?>
                            <span class="badge neutral">Missing</span>
                        <?php elseif ($installed === ''): ?>
                            <span class="badge warning">Unknown</span>
                        <?php elseif ($current): ?>
                            <span class="badge good"><?= h($installed) ?> · Current</span>
                        <?php else: ?>
                            <span class="badge warning"><?= h($installed) ?> · Update available</span>
                        <?php endif; ?>
                    </td>
                    <td><?= h($targetAgentVersion) ?></td>
                    <td>
                        <?php if (!is_array($agent)): ?>—
                        <?php elseif (!$enabled): ?><span class="badge bad">Disabled</span>
                        <?php elseif ($fresh): ?><span class="badge good">Online</span>
                        <?php else: ?><span class="badge warning">Stale</span><?php endif; ?>
                    </td>
                    <td>
                        <?php if (!is_array($agent)): ?>
                            <a class="button" href="/agent_bootstrap.php?firewall_id=<?= $fid ?>">Legacy SSH install</a>
                        <?php elseif ($current): ?>
                            <span class="badge good">Current</span>
                            <a class="button secondary" href="/agent_bootstrap.php?firewall_id=<?= $fid ?>">SSH Recovery</a>
                        <?php elseif ($selfUpdateCapable && $enabled): ?>
                            <form method="post" action="/agents_action.php" class="management-row-actions">
                                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                                <input type="hidden" name="action" value="self_update">
                                <input type="hidden" name="id" value="<?= (int) $agent['id'] ?>">
                                <button class="button" type="submit" onclick="return confirm('Queue agent update for <?= h(addslashes((string) $firewall['name'])) ?>?')">Update Worker</button>
                                <a class="button secondary" href="/agent_bootstrap.php?firewall_id=<?= $fid ?>">SSH Recovery</a>
                            </form>
                        <?php else: ?>
                            <a class="button" href="/agent_bootstrap.php?firewall_id=<?= $fid ?>"><?= $installed === '' ? 'Legacy Install / Recover' : 'Update via SSH' ?></a>
                            <?php if (!$enabled): ?><small>Enable agent 0.1.2+ for future outbound updates.</small><?php elseif ($installed !== '' && version_compare($installed, '0.1.2', '<')): ?><small>One SSH update is required to reach self-update capable 0.1.2.</small><?php endif; ?>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <p class="muted">Legacy/recovery path only. SSH passwords/private keys entered in the bootstrap form are never stored. From agent 0.1.2 onward, worker updates verify the SHA-256 of the replacement before activation.</p>
</div>

<div class="management-secondary-grid">
    <div class="card management-card">
        <div class="management-card-header">
            <div>
                <h2>Legacy manual registration</h2>
                <div class="management-summary">Standalone-worker fallback for sites where SSH from opnSentral is not reachable.</div>
            </div>
        </div>
        <form method="post" action="/agents_action.php" class="management-form-grid">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <input type="hidden" name="action" value="create_registration">
            <label>Existing firewall association
                <select name="firewall_id">
                    <option value="0">Unassigned — register first, associate later</option>
                    <?php foreach ($firewalls as $firewall): ?>
                        <option value="<?= (int) $firewall['id'] ?>"><?= h((string) $firewall['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label>Label<input name="name" maxlength="255" placeholder="Optional customer/site label"></label>
            <label>Token validity
                <select name="ttl_minutes">
                    <option value="5">5 minutes</option><option value="10">10 minutes</option><option value="15" selected>15 minutes</option><option value="30">30 minutes</option><option value="60">60 minutes</option>
                </select>
            </label>
            <div class="management-form-action"><button class="button" type="submit">Generate legacy registration command</button></div>
        </form>
        <p class="muted">The registration token is stored only as a hash and becomes unusable after the first successful standalone-agent registration.</p>
    </div>

    <div class="card management-card">
        <div class="management-card-header"><div><h2>Legacy connection model</h2><div class="management-summary">Current standalone worker uses SSH only for bootstrap/recovery; normal communication is outbound HTTPS.</div></div></div>
        <pre>Legacy install: opnSentral ── SSH ──► OPNsense
Normal use:     OPNsense ── HTTPS/443 outbound ──► opnSentral</pre>
        <p class="muted">Agent requests use an individual secret, HMAC-SHA256 signatures, a timestamp window and one-time nonces. SSH is not used for routine agent communication.</p>
    </div>
</div>

<div class="card management-card">
    <div class="management-card-header"><div><h2>Registered agents</h2><div class="management-summary">Agents report status and poll opnSentral for allow-listed jobs.</div></div></div>
    <div class="table-scroll management-table-wrap">
        <table class="management-table">
            <thead><tr><th>Firewall / site</th><th>Agent</th><th>Last seen</th><th>OPNsense</th><th>Status</th><th>Remote jobs</th><th>Actions</th></tr></thead>
            <tbody>
            <?php if (!$agents): ?><tr><td colspan="7">No agents registered.</td></tr><?php endif; ?>
            <?php foreach ($agents as $agent):
                $last = $agent['last_seen_at'] ? (strtotime((string) $agent['last_seen_at']) ?: 0) : 0;
                $fresh = $last > 0 && time() - $last < 150;
            ?>
                <tr>
                    <td><?= h((string) ($agent['firewall_name'] ?? $agent['name'] ?? 'Unassigned')) ?><?php if (empty($agent['firewall_id'])): ?><br><small>Not associated with a managed firewall</small><?php endif; ?></td>
                    <td><code><?= h(substr((string) $agent['agent_id'], 0, 12)) ?>…</code><br><small><?= h((string) $agent['last_hostname']) ?> · v<?= h((string) ($agent['last_agent_version'] ?: 'unknown')) ?></small></td>
                    <td><?= h((string) ($agent['last_seen_at'] ?: 'Never')) ?></td>
                    <td><?= h((string) ($agent['last_opnsense_version'] ?: '—')) ?></td>
                    <td><span class="badge <?= $fresh && $agent['enabled'] ? 'good' : 'bad' ?>"><?= $agent['enabled'] ? ($fresh ? 'Online' : 'Stale') : 'Disabled' ?></span></td>
                    <td>
                        <form method="post" action="/agents_action.php" class="management-row-actions">
                            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="queue_job"><input type="hidden" name="id" value="<?= (int) $agent['id'] ?>">
                            <button class="button secondary" name="job_type" value="inventory" <?= !$agent['enabled'] ? 'disabled' : '' ?>>Inventory</button>
                            <button class="button secondary" name="job_type" value="system_status" <?= !$agent['enabled'] ? 'disabled' : '' ?>>System status</button>
                        </form>
                    </td>
                    <td>
                        <form method="post" action="/agents_action.php" class="management-row-actions">
                            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) $agent['id'] ?>">
                            <button class="button secondary" name="action" value="toggle"><?= $agent['enabled'] ? 'Disable' : 'Enable' ?></button>
                            <button class="button danger" name="action" value="delete" onclick="return confirm('Delete this agent and its queued job history?')">Delete</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="card management-card">
    <div class="management-card-header"><div><h2>Recent remote jobs</h2><div class="management-summary">Remote jobs are strictly allow-listed, including signed agent self-updates and supported Administration writes.</div></div></div>
    <div class="table-scroll management-table-wrap">
        <table class="management-table">
            <thead><tr><th>ID</th><th>Agent</th><th>Job</th><th>Status</th><th>Created</th><th>Finished</th><th>Result</th></tr></thead>
            <tbody>
            <?php if (!$jobs): ?><tr><td colspan="7">No remote jobs yet.</td></tr><?php endif; ?>
            <?php foreach ($jobs as $job):
                $status = (string) $job['status'];
                $badge = $status === 'completed' ? 'good' : ($status === 'failed' ? 'bad' : 'neutral');
                $result = trim((string) $job['result_json']);
                $error = trim((string) $job['error']);
            ?>
                <tr>
                    <td>#<?= (int) $job['id'] ?></td>
                    <td><?= h((string) ($job['agent_name'] ?: $job['last_hostname'] ?: substr((string) $job['external_agent_id'], 0, 12))) ?></td>
                    <td><?= h((string) $job['job_type']) ?></td>
                    <td><span class="badge <?= $badge ?>"><?= h(ucfirst($status)) ?></span></td>
                    <td><?= h((string) $job['created_at']) ?></td><td><?= h((string) ($job['finished_at'] ?: '—')) ?></td>
                    <td><?php if ($error !== ''): ?><small><?= h($error) ?></small><?php elseif ($result !== '' && $result !== 'null'): ?><details><summary>View</summary><pre><?= h($result) ?></pre></details><?php else: ?>—<?php endif; ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<script>
document.getElementById('copy-agent-registration')?.addEventListener('click', async function(){
    const command = document.getElementById('agent-registration-command')?.textContent || '';
    if(!command) return;
    try{
        await navigator.clipboard.writeText(command);
        const previous=this.textContent;this.textContent='Copied';window.setTimeout(()=>{this.textContent=previous;},1200);
    }catch(error){window.prompt('Copy this command:',command);}
});
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>