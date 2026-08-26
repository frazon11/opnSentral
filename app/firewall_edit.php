<?php
require_once __DIR__ . '/inc/config.php';
require_login();

$id = (int) ($_GET['id'] ?? 0);
$firewall = ['name' => '', 'base_url' => '', 'verify_tls' => 1, 'notes' => ''];
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

        if ($name === '') {
            throw new InvalidArgumentException(t('firewall.name_required'));
        }

        $now = gmdate('c');

        if ($id) {
            if ($apiKey !== '' || $apiSecret !== '') {
                if ($apiKey === '' || $apiSecret === '') {
                    throw new InvalidArgumentException(t('firewall.enter_key_secret'));
                }

                $statement = db()->prepare(
                    'UPDATE firewalls SET name=?,base_url=?,api_key_enc=?,api_secret_enc=?,verify_tls=?,notes=?,updated_at=? WHERE id=?'
                );
                $statement->execute([
                    $name,
                    $url,
                    encrypt_value($apiKey),
                    encrypt_value($apiSecret),
                    $verifyTls,
                    $notes,
                    $now,
                    $id,
                ]);
            } else {
                $statement = db()->prepare(
                    'UPDATE firewalls SET name=?,base_url=?,verify_tls=?,notes=?,updated_at=? WHERE id=?'
                );
                $statement->execute([$name, $url, $verifyTls, $notes, $now, $id]);
            }
        } else {
            if ($apiKey === '' || $apiSecret === '') {
                throw new InvalidArgumentException(t('firewall.key_secret_required'));
            }

            $statement = db()->prepare(
                'INSERT INTO firewalls(name,base_url,api_key_enc,api_secret_enc,verify_tls,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)'
            );
            $statement->execute([
                $name,
                $url,
                encrypt_value($apiKey),
                encrypt_value($apiSecret),
                $verifyTls,
                $notes,
                $now,
                $now,
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
<?php require __DIR__ . '/inc/footer.php'; ?>
