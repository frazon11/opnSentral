<?php
require_once __DIR__ . '/inc/config.php';
require_login();

$id = (int) ($_GET['id'] ?? 0);
$firewall = [
    'name' => '', 'base_url' => '', 'verify_tls' => 1, 'notes' => '',
    'ssh_username' => '', 'ssh_auth_method' => 'password', 'ssh_port' => 22,
    'ssh_password_enc' => '', 'ssh_private_key_enc' => '',
];
$error = '';

if ($id) {
    $statement = db()->prepare('SELECT * FROM firewalls WHERE id = ?');
    $statement->execute([$id]);
    $firewall = $statement->fetch() ?: $firewall;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    try {
        $name = trim((string) ($_POST['name'] ?? ''));
        $url = normalize_url((string) ($_POST['base_url'] ?? ''));
        $verifyTls = isset($_POST['verify_tls']) ? 1 : 0;
        $notes = trim((string) ($_POST['notes'] ?? ''));
        $apiKey = trim((string) ($_POST['api_key'] ?? ''));
        $apiSecret = trim((string) ($_POST['api_secret'] ?? ''));
        $sshUsername = trim((string) ($_POST['ssh_username'] ?? ''));
        $sshAuthMethod = (string) ($_POST['ssh_auth_method'] ?? 'password');
        $sshPort = filter_var($_POST['ssh_port'] ?? 22, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
        $sshPassword = (string) ($_POST['ssh_password'] ?? '');
        $sshPrivateKey = trim((string) ($_POST['ssh_private_key'] ?? ''));
        $clearSshCredentials = isset($_POST['clear_ssh_credentials']);

        if (!in_array($sshAuthMethod, ['password', 'key'], true)) {
            throw new InvalidArgumentException('Invalid SSH authentication method.');
        }
        if ($sshPort === false) {
            throw new InvalidArgumentException('SSH port must be between 1 and 65535.');
        }

        if ($name === '') {
            throw new InvalidArgumentException(t('firewall.name_required'));
        }

        $now = gmdate('c');

        if ($id) {
            $existingStatement = db()->prepare('SELECT * FROM firewalls WHERE id = ?');
            $existingStatement->execute([$id]);
            $existing = $existingStatement->fetch();
            if (!is_array($existing)) {
                throw new RuntimeException('Firewall not found.');
            }

            $apiKeyEnc = (string) $existing['api_key_enc'];
            $apiSecretEnc = (string) $existing['api_secret_enc'];
            if ($apiKey !== '' || $apiSecret !== '') {
                if ($apiKey === '' || $apiSecret === '') {
                    throw new InvalidArgumentException(t('firewall.enter_key_secret'));
                }
                $apiKeyEnc = encrypt_value($apiKey);
                $apiSecretEnc = encrypt_value($apiSecret);
            }

            $sshPasswordEnc = (string) ($existing['ssh_password_enc'] ?? '');
            $sshPrivateKeyEnc = (string) ($existing['ssh_private_key_enc'] ?? '');
            if ($clearSshCredentials || $sshUsername === '') {
                $sshUsername = '';
                $sshPasswordEnc = '';
                $sshPrivateKeyEnc = '';
            } elseif ($sshAuthMethod === 'password') {
                if ($sshPassword !== '') {
                    $sshPasswordEnc = encrypt_value($sshPassword);
                }
                $sshPrivateKeyEnc = '';
                if ($sshPasswordEnc === '') {
                    throw new InvalidArgumentException('Enter an SSH password or keep the existing stored password.');
                }
            } else {
                if ($sshPrivateKey !== '') {
                    $sshPrivateKeyEnc = encrypt_value($sshPrivateKey);
                }
                $sshPasswordEnc = '';
                if ($sshPrivateKeyEnc === '') {
                    throw new InvalidArgumentException('Enter an SSH private key or keep the existing stored key.');
                }
            }

            $statement = db()->prepare(
                'UPDATE firewalls SET name=?,base_url=?,api_key_enc=?,api_secret_enc=?,verify_tls=?,ssh_username=?,ssh_auth_method=?,ssh_password_enc=?,ssh_private_key_enc=?,ssh_port=?,notes=?,updated_at=? WHERE id=?'
            );
            $statement->execute([
                $name, $url, $apiKeyEnc, $apiSecretEnc, $verifyTls,
                $sshUsername, $sshAuthMethod, $sshPasswordEnc, $sshPrivateKeyEnc, (int) $sshPort,
                $notes, $now, $id,
            ]);
        } else {
            if ($apiKey === '' || $apiSecret === '') {
                throw new InvalidArgumentException(t('firewall.key_secret_required'));
            }

            $sshPasswordEnc = '';
            $sshPrivateKeyEnc = '';
            if ($sshUsername !== '') {
                if ($sshAuthMethod === 'password') {
                    if ($sshPassword === '') {
                        throw new InvalidArgumentException('Enter the SSH password for automatic WebSSH login.');
                    }
                    $sshPasswordEnc = encrypt_value($sshPassword);
                } else {
                    if ($sshPrivateKey === '') {
                        throw new InvalidArgumentException('Enter the SSH private key for automatic WebSSH login.');
                    }
                    $sshPrivateKeyEnc = encrypt_value($sshPrivateKey);
                }
            }

            $statement = db()->prepare(
                'INSERT INTO firewalls(name,base_url,api_key_enc,api_secret_enc,verify_tls,ssh_username,ssh_auth_method,ssh_password_enc,ssh_private_key_enc,ssh_port,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)'
            );
            $statement->execute([
                $name, $url, encrypt_value($apiKey), encrypt_value($apiSecret), $verifyTls,
                $sshUsername, $sshAuthMethod, $sshPasswordEnc, $sshPrivateKeyEnc, (int) $sshPort,
                $notes, $now, $now,
            ]);
        }

        header('Location: /');
        exit;
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.firewall-edit-layout{display:grid;grid-template-columns:minmax(520px,820px) minmax(360px,1fr);gap:22px;align-items:start}
.firewall-edit-layout .form-card{margin:0;max-width:none}
.onboarding-guide{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:18px 20px;position:sticky;top:16px}
.onboarding-guide h2{margin:0 0 8px;font-size:1.2rem}.onboarding-guide h3{margin:18px 0 7px;font-size:1rem}.onboarding-guide p{margin:6px 0;line-height:1.45}.onboarding-guide ol,.onboarding-guide ul{margin:8px 0 0 20px;padding:0}.onboarding-guide li{margin:7px 0;line-height:1.4}.onboarding-guide code{overflow-wrap:anywhere}.guide-example{background:rgba(127,127,127,.09);border-radius:6px;padding:9px 11px;margin:8px 0}.guide-note{margin-top:14px;padding:10px 12px;border-left:4px solid #d39b22;background:rgba(211,155,34,.08)}.guide-good{margin-top:10px;padding:10px 12px;border-left:4px solid #2aa84a;background:rgba(42,168,74,.08)}
@media(max-width:1100px){.firewall-edit-layout{grid-template-columns:1fr}.onboarding-guide{position:static}}
</style>

<div class="page-title">
    <h1><?= h($id ? t('firewall.edit_title') : t('firewall.add_title')) ?></h1>
</div>

<?php if ($error): ?>
    <div class="alert error"><?= h($error) ?></div>
<?php endif; ?>

<div class="firewall-edit-layout">
<form class="form-card" method="post">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">

    <label>
        <?= h(t('firewall.name')) ?>
        <input name="name" value="<?= h((string) $firewall['name']) ?>" required>
    </label>

    <label>
        <?= h(t('firewall.url')) ?>
        <input name="base_url" value="<?= h((string) $firewall['base_url']) ?>" placeholder="https://firewall.example.net:444" required>
    </label>

    <label>
        <?= h(t('firewall.api_key')) ?>
        <input name="api_key" <?= $id ? 'placeholder="' . h(t('firewall.keep_current')) . '"' : 'required' ?>>
    </label>

    <label>
        <?= h(t('firewall.api_secret')) ?>
        <input type="password" name="api_secret" <?= $id ? 'placeholder="' . h(t('firewall.keep_current')) . '"' : 'required' ?>>
    </label>

    <fieldset style="margin:18px 0;padding:14px 16px;border:1px solid var(--border);border-radius:8px">
        <legend><strong>WebSSH automatic login</strong></legend>
        <p class="muted" style="margin-top:0">Optional. Stored SSH credentials are encrypted with APP_KEY and are never sent to the browser in plaintext.</p>

        <label>
            SSH username
            <input name="ssh_username" value="<?= h((string) ($firewall['ssh_username'] ?? '')) ?>" placeholder="adminfk">
        </label>

        <label>
            Authentication
            <select name="ssh_auth_method" id="ssh-auth-method">
                <option value="password" <?= (($firewall['ssh_auth_method'] ?? 'password') === 'password') ? 'selected' : '' ?>>Password</option>
                <option value="key" <?= (($firewall['ssh_auth_method'] ?? '') === 'key') ? 'selected' : '' ?>>Private key</option>
            </select>
        </label>

        <label>
            SSH port
            <input type="number" name="ssh_port" min="1" max="65535" value="<?= (int) ($firewall['ssh_port'] ?? 22) ?>">
        </label>

        <label id="ssh-password-field">
            SSH password
            <input type="password" name="ssh_password" autocomplete="new-password" <?= $id && !empty($firewall['ssh_password_enc']) ? 'placeholder="Keep current stored password"' : '' ?>>
        </label>

        <label id="ssh-key-field" style="display:none">
            SSH private key
            <textarea name="ssh_private_key" autocomplete="off" spellcheck="false" placeholder="<?= $id && !empty($firewall['ssh_private_key_enc']) ? 'Keep current stored private key' : '-----BEGIN OPENSSH PRIVATE KEY-----' ?>"></textarea>
        </label>

        <?php if ($id && (!empty($firewall['ssh_password_enc']) || !empty($firewall['ssh_private_key_enc']))): ?>
        <label class="checkbox">
            <input type="checkbox" name="clear_ssh_credentials">
            Remove stored WebSSH credentials
        </label>
        <?php endif; ?>
    </fieldset>

    <label class="checkbox">
        <input type="checkbox" name="verify_tls" <?= !empty($firewall['verify_tls']) ? 'checked' : '' ?>>
        <?= h(t('firewall.verify_tls')) ?>
    </label>

    <label>
        <?= h(t('firewall.notes')) ?>
        <textarea name="notes"><?= h((string) $firewall['notes']) ?></textarea>
    </label>

    <div class="actions">
        <button><?= h(t('common.save')) ?></button>
        <a class="button secondary" href="/"><?= h(t('common.cancel')) ?></a>
    </div>
</form>

<aside class="onboarding-guide">
    <h2>Quick setup on OPNsense</h2>
    <p>Create a dedicated OPNsense account for opnSentral, then copy its API key and secret into the form.</p>

    <h3>1. Web/API URL</h3>
    <p>Use the same base address you use to open the OPNsense Web GUI, including <strong>HTTPS</strong> and a non-default port if configured.</p>
    <div class="guide-example"><code>https://opnsense.example.net:444</code></div>
    <p>Do not append <code>/api</code>, <code>/ui</code>, or another path. opnSentral adds the required API paths itself.</p>

    <h3>2. Create the opnSentral service account</h3>
    <ol>
        <li>In OPNsense open <strong>System → Access → Users</strong>.</li>
        <li>Click <strong>+</strong> to create a new user.</li>
        <li>Use a dedicated username such as <code>opnsentral</code>.</li>
        <li><strong>Do not disable the user.</strong> A disabled user cannot authenticate with the API key.</li>
        <li>Use <strong>Scrambled Password</strong> so the account is not usable for normal password login.</li>
        <li>Do not configure SSH authorized keys for this account.</li>
        <li>Save the user.</li>
    </ol>

    <div class="guide-good">
        <strong>Recommended lockdown</strong>
        <ul>
            <li>Dedicated <code>opnsentral</code> user</li>
            <li>Scrambled Password enabled</li>
            <li>No SSH keys</li>
            <li>Dedicated API key/secret used only by opnSentral</li>
            <li>Grant only the OPNsense privileges required by the opnSentral features you use</li>
        </ul>
    </div>

    <p><strong>Compatibility fallback:</strong> adding the service account to the <strong>admins</strong> group gives all current opnSentral features access without maintaining individual privileges, but is less restrictive.</p>

    <h3>3. Create API credentials</h3>
    <ol>
        <li>Edit the new <code>opnsentral</code> user.</li>
        <li>In the <strong>API keys</strong> section, create a new API key.</li>
        <li>OPNsense downloads/displays the new <strong>Key</strong> and <strong>Secret</strong>.</li>
        <li>Copy the key into <strong>API key</strong> and the secret into <strong>API secret</strong> here.</li>
    </ol>

    <div class="guide-note">
        <strong>Keep the API secret safe.</strong> OPNsense only provides the secret when the key is created. If it is lost, create a new API key rather than trying to recover the old secret.
    </div>

    <h3>4. TLS verification</h3>
    <p>Leave <strong>Verify TLS certificate</strong> enabled when OPNsense uses a certificate trusted by the opnSentral host. Disable it only when the firewall deliberately uses an untrusted/self-signed certificate.</p>
</aside>
</div>
<script>
(function(){
    const method=document.getElementById('ssh-auth-method');
    const passwordField=document.getElementById('ssh-password-field');
    const keyField=document.getElementById('ssh-key-field');
    function update(){
        const useKey=method && method.value==='key';
        if(passwordField) passwordField.style.display=useKey?'none':'block';
        if(keyField) keyField.style.display=useKey?'block':'none';
    }
    method?.addEventListener('change',update);
    update();
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
