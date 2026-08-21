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

$registration = $_SESSION['new_agent_registration'] ?? null;
unset($_SESSION['new_agent_registration']);
$updateResult = $_SESSION['agent_update_result'] ?? null;
unset($_SESSION['agent_update_result']);
$associationResult = $_SESSION['agent_association_result'] ?? null;
unset($_SESSION['agent_association_result']);
$targetAgentVersion = agent_current_version();
$agentStaleAfterSeconds = 300;

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
        <p>Native OPNsense plugin-managed agents using outbound HTTPS to opnSentral.</p>
    </div>
    <div class="management-toolbar">
        <form method="post" action="/agents_action.php" style="display:inline">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <input type="hidden" name="action" value="self_update_all">
            <button type="submit" class="button" onclick="return confirm('Queue an update to agent v<?= h($targetAgentVersion) ?> for every enabled agent that is older and supports self-update?')">Update all agents</button>
        </form>
        <span class="badge neutral">Target v<?= h($targetAgentVersion) ?></span>
        <button type="button" class="button secondary" onclick="window.location.reload()">Refresh</button>
    </div>
</div>

<?php if (is_string($updateResult) && $updateResult !== ''): ?>
    <div class="alert goodbox"><strong>Agent update</strong><div><?= h($updateResult) ?></div></div>
<?php endif; ?>

<?php if (is_array($associationResult)): ?>
    <div class="alert <?= !empty($associationResult['ok']) ? 'goodbox' : 'error' ?>">
        <strong>Firewall association</strong>
        <div><?= h((string) ($associationResult['message'] ?? '')) ?></div>
    </div>
<?php endif; ?>

<?php if (is_array($registration)): ?>
    <?php
        $token = (string) ($registration['token'] ?? '');
        $installUrl = $publicBase . '/agent/install-plugin.sh';
        $command = 'fetch -o - ' . escapeshellarg($installUrl)
            . ' | sh -s -- ' . escapeshellarg($publicBase)
            . ' ' . escapeshellarg($token);
    ?>
    <div class="alert warningbox" data-presentation-exempt="true">
        <strong>One-command plugin installation</strong>
        <p>
            Run this command as <strong>root</strong> on the target OPNsense firewall before
            <?= h((string) ($registration['expires_at'] ?? 'the token expires')) ?>.
            It installs the opnSentral plugin files, registers the firewall, downloads and verifies the worker, starts the service and checks that it is online.
            The token is single-use and cannot be displayed again after leaving this page.
        </p>
        <?php if ($publicBase === '' || $scheme !== 'https'): ?>
            <p><strong>HTTPS is required.</strong> Open opnSentral through its public HTTPS URL and generate a new installation command.</p>
        <?php else: ?>
            <pre id="agent-registration-command"><?= h($command) ?></pre>
            <button type="button" class="button secondary" id="copy-agent-registration">Copy command</button>
        <?php endif; ?>
    </div>
<?php endif; ?>

<div class="management-overview-bar">
    <div>
        <strong>Agent overview</strong>
        <div class="management-summary">
            <?= count($agents) ?> registered agent<?= count($agents) === 1 ? '' : 's' ?> · current package target v<?= h($targetAgentVersion) ?>
        </div>
    </div>
</div>

<div class="management-secondary-grid">
    <div class="card management-card">
        <div class="management-card-header">
            <div>
                <h2>Install agent</h2>
                <div class="management-summary">Generate a short-lived token and one command for the target OPNsense firewall.</div>
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
            <div class="management-form-action"><button class="button" type="submit">Generate install command</button></div>
        </form>
        <p class="muted">The token is stored only as a hash and becomes unusable after the first successful registration.</p>
    </div>

    <div class="card management-card">
        <div class="management-card-header"><div><h2>Connection model</h2><div class="management-summary">Installation, registration and normal operation require only outbound HTTPS from OPNsense.</div></div></div>
        <pre>Install/register: OPNsense ── HTTPS/443 outbound ──► opnSentral
Normal use:       OPNsense ── HTTPS/443 outbound ──► opnSentral</pre>
        <p class="muted">The installer deploys the native plugin integration. The worker reports status and polls opnSentral for strictly allow-listed jobs.</p>
    </div>
</div>

<div class="card management-card">
    <div class="management-card-header"><div><h2>Registered agents</h2><div class="management-summary">Update agent replaces only the SHA-256-verified opnSentral worker and keeps registration, firewall association and OPNsense configuration.</div></div></div>
    <div class="table-scroll management-table-wrap">
        <table class="management-table">
            <thead><tr><th>Firewall / site</th><th>Agent</th><th>Last seen</th><th>OPNsense</th><th>Status</th><th>Remote jobs</th><th>Actions</th></tr></thead>
            <tbody>
            <?php if (!$agents): ?><tr><td colspan="7">No agents registered.</td></tr><?php endif; ?>
            <?php foreach ($agents as $agent):
                $last = !empty($agent['last_seen_at']) ? (strtotime((string) $agent['last_seen_at']) ?: 0) : 0;
                $age = $last > 0 ? max(0, time() - $last) : null;
                $fresh = $last > 0 && $age < $agentStaleAfterSeconds;
                $currentFirewallId = (int) ($agent['firewall_id'] ?? 0);
                $agentVersion = trim((string) ($agent['last_version'] ?? ''));
                $updateCapable = !empty($agent['enabled']) && $agentVersion !== '' && version_compare($agentVersion, '0.1.2', '>=');
                $needsUpdate = $updateCapable && $targetAgentVersion !== 'unknown' && version_compare($agentVersion, $targetAgentVersion, '<');
            ?>
                <tr>
                    <td>
                        <?= h((string) ($agent['firewall_name'] ?? $agent['name'] ?? 'Unassigned')) ?>
                        <?php if (empty($agent['firewall_id'])): ?><br><small>Not associated with a managed firewall</small><?php endif; ?>
                    </td>
                    <td><code><?= h(substr((string) ($agent['agent_id'] ?? ''), 0, 12)) ?>…</code><br><small><?= h((string) ($agent['last_hostname'] ?? '')) ?> · v<?= h($agentVersion !== '' ? $agentVersion : 'unknown') ?></small></td>
                    <td><?= h((string) (($agent['last_seen_at'] ?? '') !== '' ? $agent['last_seen_at'] : 'Never')) ?><?php if ($age !== null): ?><br><small><?= h((string)$age) ?>s ago</small><?php endif; ?></td>
                    <td><?= h((string) (($agent['last_opnsense_version'] ?? '') !== '' ? $agent['last_opnsense_version'] : '—')) ?></td>
                    <td><span class="badge <?= $fresh && !empty($agent['enabled']) ? 'good' : 'bad' ?>"><?= !empty($agent['enabled']) ? ($fresh ? 'Online' : 'Stale') : 'Disabled' ?></span></td>
                    <td>
                        <form method="post" action="/agents_action.php" class="management-row-actions">
                            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="queue_job"><input type="hidden" name="id" value="<?= (int) ($agent['id'] ?? 0) ?>">
                            <button class="button secondary" name="job_type" value="inventory" <?= empty($agent['enabled']) ? 'disabled' : '' ?>>Inventory</button>
                            <button class="button secondary" name="job_type" value="system_status" <?= empty($agent['enabled']) ? 'disabled' : '' ?>>System status</button>
                        </form>
                    </td>
                    <td>
                        <div class="management-row-actions" style="align-items:center;flex-wrap:wrap">
                            <?php if ($currentFirewallId === 0): ?>
                                <form method="post" action="/agents_action.php" class="management-row-actions">
                                    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                                    <input type="hidden" name="action" value="associate">
                                    <input type="hidden" name="id" value="<?= (int) ($agent['id'] ?? 0) ?>">
                                    <select name="firewall_id" aria-label="Managed firewall association" required>
                                        <option value="" selected disabled>Select firewall…</option>
                                        <?php foreach ($firewalls as $firewall): ?>
                                            <option value="<?= (int) $firewall['id'] ?>"><?= h((string) $firewall['name']) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                    <button class="button secondary" type="submit">Associate</button>
                                </form>
                            <?php else: ?>
                                <span class="badge neutral">Associated: <?= h((string) ($agent['firewall_name'] ?? ('Firewall #' . $currentFirewallId))) ?></span>
                                <form method="post" action="/agents_action.php" class="management-row-actions">
                                    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                                    <input type="hidden" name="action" value="associate">
                                    <input type="hidden" name="id" value="<?= (int) ($agent['id'] ?? 0) ?>">
                                    <input type="hidden" name="firewall_id" value="0">
                                    <button class="button secondary" type="submit" onclick="return confirm('De-associate this agent from <?= h((string) ($agent['firewall_name'] ?? 'the managed firewall')) ?>? The agent remains registered but firewall-specific jobs cannot be sent until it is associated again.')">De-associate</button>
                                </form>
                            <?php endif; ?>
                            <?php if (!empty($agent['firewall_id'])): ?><a class="button secondary" href="/ssh_access.php?firewall_id=<?= (int) $agent['firewall_id'] ?>">SSH access</a><?php endif; ?>
                            <form method="post" action="/agents_action.php" class="management-row-actions">
                                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="id" value="<?= (int) ($agent['id'] ?? 0) ?>">
                                <button class="button secondary" name="action" value="self_update" <?= !$updateCapable ? 'disabled' : '' ?>><?= $needsUpdate ? 'Update agent' : 'Reinstall agent worker' ?></button>
                                <button class="button secondary" name="action" value="toggle"><?= !empty($agent['enabled']) ? 'Disable' : 'Enable' ?></button>
                                <button class="button danger" name="action" value="delete" onclick="return confirm('Delete this agent and its queued job history?')">Delete</button>
                            </form>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="card management-card">
    <div class="management-card-header"><div><h2>Recent remote jobs</h2><div class="management-summary">Remote jobs are strictly allow-listed, including SHA-256-verified worker self-updates and emergency restore jobs.</div></div></div>
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
