<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/ssh_access.php';
require_login();

$firewalls = db()->query('SELECT id,name,base_url FROM firewalls ORDER BY name')->fetchAll();
$firewallId = (int) ($_GET['firewall_id'] ?? 0);
$firewall = $firewallId > 0 ? firewall_by_id($firewallId) : null;
$agent = $firewallId > 0 ? ssh_access_agent($firewallId) : null;
$source = '';
$objects = null;
$error = '';
$latestJob = $agent !== null ? ssh_access_latest_job((int) $agent['id']) : null;
$flash = $_SESSION['ssh_access_result'] ?? null;
unset($_SESSION['ssh_access_result']);

if ($firewall !== null) {
    try {
        $source = ssh_access_public_source();
        $objects = ssh_access_objects_status($firewall, $source);
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

$agentVersion = trim((string) ($agent['last_version'] ?? ''));
$agentReady = ssh_access_agent_ready($agent);
$jobResult = null;
if (is_array($latestJob) && trim((string) ($latestJob['result_json'] ?? '')) !== '') {
    $decoded = json_decode((string) $latestJob['result_json'], true);
    if (is_array($decoded)) $jobResult = $decoded;
}

function ssh_badge(bool $ok, string $yes = 'OK', string $no = 'Missing / wrong'): string
{
    return '<span class="badge ' . ($ok ? 'good' : 'bad') . '">' . h($ok ? $yes : $no) . '</span>';
}

require __DIR__ . '/inc/header.php';
?>
<style>
.ssh-grid{display:grid;grid-template-columns:minmax(260px,.8fr) minmax(0,1.2fr);gap:16px}.ssh-status{display:grid;gap:8px}.ssh-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border:1px solid var(--border);border-radius:6px}.ssh-row strong{min-width:170px}.ssh-actions{display:flex;gap:9px;flex-wrap:wrap}.ssh-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:14px}@media(max-width:900px){.ssh-grid,.ssh-summary{grid-template-columns:1fr}}
</style>
<div class="page-title management-page-title">
    <div><h1>Managed SSH Access</h1><p>Check and enforce restricted SSH management access from opnSentral to one OPNsense firewall.</p></div>
    <a class="button secondary" href="/agents.php">Agents</a>
</div>

<?php if (is_array($flash)): ?>
<div class="alert <?= !empty($flash['ok']) ? 'goodbox' : 'error' ?>"><strong>SSH access</strong><div><?= h((string) ($flash['message'] ?? '')) ?></div></div>
<?php endif; ?>
<?php if ($error !== ''): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<div class="card management-card">
    <div class="management-card-header"><div><h2>Target</h2><div class="management-summary">Port 22, source alias opnSentral, category Managed by opnSentral.</div></div></div>
    <form method="get" class="management-form-grid">
        <label>OPNsense
            <select name="firewall_id" onchange="this.form.submit()">
                <option value="">Select firewall</option>
                <?php foreach ($firewalls as $item): ?>
                <option value="<?= (int) $item['id'] ?>" <?= $firewallId === (int) $item['id'] ? 'selected' : '' ?>><?= h((string) $item['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
    </form>
</div>

<?php if ($firewall !== null): ?>
<div class="ssh-summary">
    <div class="card"><strong>Source</strong><div><?= h($source !== '' ? $source : 'Unknown') ?></div></div>
    <div class="card"><strong>Agent</strong><div><?= h($agentVersion !== '' ? 'v' . $agentVersion : 'Not available') ?> <?= $agentReady ? '<span class="badge good">Ready</span>' : '<span class="badge bad">Update required</span>' ?></div></div>
    <div class="card"><strong>Target</strong><div>TCP/22 · This Firewall</div></div>
</div>

<div class="ssh-grid">
    <div class="card management-card">
        <div class="management-card-header"><div><h2>Actions</h2><div class="management-summary">Both actions use the registered outbound agent; SSH itself is not required for the check.</div></div></div>
        <?php if ($agent === null): ?>
            <div class="alert error">No enabled agent is associated with this firewall.</div>
        <?php elseif (!$agentReady): ?>
            <div class="alert warningbox">Agent <?= h(SSH_ACCESS_AGENT_MIN_VERSION) ?> or newer is required. Current: <?= h($agentVersion !== '' ? $agentVersion : 'unknown') ?>.</div>
        <?php endif; ?>
        <div class="ssh-actions">
            <form method="post" action="/ssh_access_action.php">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="firewall_id" value="<?= $firewallId ?>"><input type="hidden" name="action" value="check">
                <button class="button secondary" <?= !$agentReady ? 'disabled' : '' ?>>Check status</button>
            </form>
            <form method="post" action="/ssh_access_action.php" onsubmit="return confirm('Enable/repair restricted SSH management access on this OPNsense firewall?')">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="firewall_id" value="<?= $firewallId ?>"><input type="hidden" name="action" value="ensure">
                <button class="button" <?= !$agentReady ? 'disabled' : '' ?>>Enable / Repair SSH Access</button>
            </form>
        </div>
        <p class="muted">Enable / Repair creates a pre-change backup, repairs the managed category/alias/rule, enables SSH on port 22, selects admins for sudo, restarts OpenSSH and verifies the resulting state. Root login and password authentication are not enabled.</p>
    </div>

    <div class="card management-card">
        <div class="management-card-header"><div><h2>Managed objects</h2><div class="management-summary">Current API-visible state on the selected firewall.</div></div></div>
        <div class="ssh-status">
            <div class="ssh-row"><strong>Category</strong><?= ssh_badge((bool) ($objects['category']['present'] ?? false), 'Managed by opnSentral', 'Missing') ?></div>
            <div class="ssh-row"><strong>Alias opnSentral</strong><?= ssh_badge((bool) ($objects['alias']['ok'] ?? false)) ?></div>
            <div class="ssh-row"><strong>Alias source</strong><span><?= h($source !== '' ? $source : 'Unknown') ?></span></div>
            <div class="ssh-row"><strong>Firewall rule</strong><?= ssh_badge((bool) ($objects['rule']['ok'] ?? false)) ?></div>
            <div class="ssh-row"><strong>Rule source</strong><span>opnSentral</span></div>
            <div class="ssh-row"><strong>Rule destination</strong><span>This Firewall · TCP/22</span></div>
        </div>
    </div>
</div>

<div class="card management-card">
    <div class="management-card-header"><div><h2>Remote SSH status</h2><div class="management-summary">Latest result reported by the OPNsense agent.</div></div></div>
    <?php if ($latestJob === null): ?>
        <div class="empty">No SSH status job has run yet.</div>
    <?php else: ?>
        <p>Job #<?= (int) $latestJob['id'] ?> · <span class="badge <?= (string) $latestJob['status'] === 'completed' ? 'good' : ((string) $latestJob['status'] === 'failed' ? 'bad' : 'neutral') ?>"><?= h((string) $latestJob['status']) ?></span></p>
        <?php if ((string) ($latestJob['error'] ?? '') !== ''): ?><div class="alert error"><?= h((string) $latestJob['error']) ?></div><?php endif; ?>
        <?php if (is_array($jobResult)): ?>
        <div class="ssh-status">
            <div class="ssh-row"><strong>SSH configured</strong><?= ssh_badge((bool) ($jobResult['ssh_enabled'] ?? false)) ?></div>
            <div class="ssh-row"><strong>SSH daemon</strong><?= ssh_badge((bool) ($jobResult['daemon_running'] ?? false), 'Running', 'Stopped') ?></div>
            <div class="ssh-row"><strong>Port</strong><?= ssh_badge((string) ($jobResult['port'] ?? '') === '22', '22', (string) ($jobResult['port'] ?? 'Unknown')) ?></div>
            <div class="ssh-row"><strong>SSH group</strong><?= ssh_badge((string) ($jobResult['ssh_group'] ?? '') === 'admins', 'admins', (string) ($jobResult['ssh_group'] ?? 'Unknown')) ?></div>
            <div class="ssh-row"><strong>Sudo</strong><?= ssh_badge((bool) ($jobResult['sudo_enabled'] ?? false), 'Enabled', 'Disabled') ?></div>
            <div class="ssh-row"><strong>Sudo group</strong><?= ssh_badge((string) ($jobResult['sudo_group'] ?? '') === 'admins', 'admins', (string) ($jobResult['sudo_group'] ?? 'Unknown')) ?></div>
            <div class="ssh-row"><strong>Overall</strong><?= ssh_badge((bool) ($jobResult['ok'] ?? false), 'READY', 'Needs repair') ?></div>
        </div>
        <?php endif; ?>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php require __DIR__ . '/inc/footer.php'; ?>
