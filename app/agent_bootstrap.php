<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/agent_deployment.php';
require_login();

$id = (int) ($_GET['firewall_id'] ?? 0);
$firewall = $id > 0 ? firewall_by_id($id) : null;
if ($firewall === null) {
    http_response_code(404);
    exit('Firewall not found.');
}

$host = (string) (parse_url((string) $firewall['base_url'], PHP_URL_HOST) ?: '');
$publicBase = agent_public_base_url();
$agentVersion = agent_current_version();

$existing = db()->prepare(
    'SELECT * FROM agents WHERE firewall_id = ? ORDER BY id DESC LIMIT 1'
);
$existing->execute([$id]);
$agent = $existing->fetch() ?: null;

$result = $_SESSION['agent_bootstrap_result'] ?? null;
unset($_SESSION['agent_bootstrap_result']);

require __DIR__ . '/inc/header.php';
?>
<div class="page-title management-page-title">
    <div>
        <h1>Deploy opnSentral Agent</h1>
        <p><?= h((string) $firewall['name']) ?> · target agent <?= h($agentVersion) ?></p>
    </div>
    <a class="button secondary" href="/agents.php">Back to Agents</a>
</div>

<?php if (is_array($result)): ?>
    <div class="alert <?= ($result['ok'] ?? false) ? 'goodbox' : 'error' ?>">
        <strong><?= ($result['ok'] ?? false) ? 'Agent bootstrap completed' : 'Agent bootstrap failed' ?></strong>
        <div><?= h((string) ($result['message'] ?? '')) ?></div>
        <?php if (!empty($result['output'])): ?><pre><?= h((string) $result['output']) ?></pre><?php endif; ?>
    </div>
<?php endif; ?>

<?php if (is_array($agent)): ?>
    <div class="alert warningbox">
        This firewall already has an associated agent reporting version
        <strong><?= h((string) ($agent['last_agent_version'] ?: 'unknown')) ?></strong>.
        Use <strong>Update Agent</strong> on the Agents page for normal upgrades; SSH bootstrap is intended for first installation or recovery.
    </div>
<?php endif; ?>

<div class="card management-card">
    <div class="management-card-header">
        <div>
            <h2>One-time SSH bootstrap</h2>
            <div class="management-summary">The SSH credential is used only for this request and is not stored by opnSentral.</div>
        </div>
    </div>

    <form method="post" action="/agent_bootstrap_action.php" class="management-form-grid" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="firewall_id" value="<?= $id ?>">

        <label>
            OPNsense SSH host
            <input name="ssh_host" required value="<?= h($host) ?>" placeholder="192.168.1.1">
        </label>

        <label>
            SSH port
            <input name="ssh_port" type="number" min="1" max="65535" value="22" required>
        </label>

        <label>
            SSH user
            <input name="ssh_user" value="root" required>
            <small class="muted">The bootstrap currently requires a root-capable OPNsense SSH account.</small>
        </label>

        <label>
            Authentication
            <select name="auth_type" id="bootstrap-auth-type">
                <option value="password">Password</option>
                <option value="key">Private key</option>
            </select>
        </label>

        <label id="bootstrap-password-row">
            Password
            <input name="ssh_password" type="password" autocomplete="new-password">
        </label>

        <label id="bootstrap-key-row" class="hidden">
            Private key
            <textarea name="ssh_private_key" rows="9" spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
            <small class="muted">The key is written to a temporary 0600 file for the SSH process and deleted immediately afterward.</small>
        </label>

        <label>
            Public opnSentral URL
            <input name="server_url" required value="<?= h($publicBase) ?>" placeholder="https://opnsentral.example.com">
            <small class="muted">The OPNsense agent must be able to reach this HTTPS URL outbound.</small>
        </label>

        <label>
            Host-key handling
            <select name="host_key_mode">
                <option value="accept-new" selected>Accept new host key for this bootstrap</option>
                <option value="strict">Require an already known host key</option>
            </select>
            <small class="muted">Accept-new protects against changed host keys but trusts the first connection. Strict mode uses the container's known_hosts.</small>
        </label>

        <div class="management-form-action">
            <button class="button" type="submit" onclick="return confirm('Install and register the opnSentral agent on <?= h(addslashes((string) $firewall['name'])) ?> via SSH?')">Install Agent</button>
        </div>
    </form>
</div>

<script>
(function(){
    const type=document.getElementById('bootstrap-auth-type');
    const password=document.getElementById('bootstrap-password-row');
    const key=document.getElementById('bootstrap-key-row');
    function sync(){
        const keyMode=type.value==='key';
        key.classList.toggle('hidden',!keyMode);
        password.classList.toggle('hidden',keyMode);
    }
    type.addEventListener('change',sync);sync();
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
