<?php
declare(strict_types=1);
require_once __DIR__.'/inc/config.php';
require_once __DIR__.'/inc/mfa.php';
require_login();
header('Cache-Control: no-store, no-cache, must-revalidate');
start_session_secure();

$message = '';
$error = '';
$enabled = mfa_enabled();

// Enrollment expires and is never committed until the first TOTP code verifies.
if (isset($_SESSION['mfa_enroll_created']) &&
    (time() - (int)$_SESSION['mfa_enroll_created'] > 600)) {
    unset($_SESSION['mfa_enroll_secret'], $_SESSION['mfa_enroll_created']);
}
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    require_csrf();
    $action = (string)($_POST['action'] ?? '');
    try {
        if ($action === 'begin' && !$enabled) {
            $password = (string)($_POST['password'] ?? '');
            if ($password === '' || !hash_equals(envv('ADMIN_PASSWORD'), $password)) {
                throw new RuntimeException('Administrator password incorrect.');
            }
            $_SESSION['mfa_enroll_secret'] = mfa_base32_encode(random_bytes(20));
            $_SESSION['mfa_enroll_created'] = time();
            $_SESSION['mfa_enroll_failures'] = 0;
            $message = 'Scan the QR code or enter the setup key manually, then verify a code.';
        } elseif ($action === 'enable' && !$enabled) {
            $secret = (string)($_SESSION['mfa_enroll_secret'] ?? '');
            $created = (int)($_SESSION['mfa_enroll_created'] ?? 0);
            if ($secret === '' || $created < time()-600 || $created > time()) {
                throw new RuntimeException('Enrollment expired. Start again.');
            }
            if ((int)($_SESSION['mfa_enroll_failures'] ?? 0) >= 8) {
                unset($_SESSION['mfa_enroll_secret'], $_SESSION['mfa_enroll_created']);
                throw new RuntimeException('Too many verification attempts. Start again.');
            }
            $result = mfa_enable_with_code($secret,trim((string)($_POST['code'] ?? '')),
                (string)($_POST['password'] ?? ''));
            unset($_SESSION['mfa_enroll_secret'], $_SESSION['mfa_enroll_created'], $_SESSION['mfa_enroll_failures']);
            session_regenerate_id(true);
            $_SESSION['mfa_verified'] = true;
            $_SESSION['mfa_generation'] = $result['generation'];
            $_SESSION['mfa_new_recovery_codes'] = $result['codes'];
            $enabled = true;
            $message = 'MFA enabled. Save the one-time recovery codes below now.';
        } elseif ($action === 'disable' && $enabled) {
            if (!mfa_disable((string)($_POST['password'] ?? ''), trim((string)($_POST['code'] ?? '')))) {
                throw new RuntimeException('Invalid password, TOTP or recovery code.');
            }
            unset($_SESSION['mfa_new_recovery_codes']);
            $_SESSION['mfa_verified'] = false;
            $_SESSION['mfa_generation'] = '';
            $enabled = false;
            $message = 'MFA disabled.';
        } elseif ($action === 'cancel') {
            unset($_SESSION['mfa_enroll_secret'], $_SESSION['mfa_enroll_created'], $_SESSION['mfa_enroll_failures']);
            $message = 'Enrollment cancelled.';
        } else {
            throw new RuntimeException('Invalid MFA operation.');
        }
    } catch (Throwable $exception) {
        if ($action === 'enable') $_SESSION['mfa_enroll_failures'] = (int)($_SESSION['mfa_enroll_failures'] ?? 0) + 1;
        $error = $exception->getMessage();
    }
}

$enrolling = !$enabled && isset($_SESSION['mfa_enroll_secret'], $_SESSION['mfa_enroll_created'])
    && (time()-(int)$_SESSION['mfa_enroll_created']) <= 600;
$secret = $enrolling ? (string)$_SESSION['mfa_enroll_secret'] : '';
$codes = $_SESSION['mfa_new_recovery_codes'] ?? [];
unset($_SESSION['mfa_new_recovery_codes']);

require __DIR__.'/inc/header.php';
?>
<div class="page-title"><div><h1>Multi-factor authentication</h1>
<p>Protect your opnSentral administrator login with TOTP.</p></div></div>
<section class="card" style="max-width:780px">
<?php if ($message): ?><div class="alert goodbox"><?= h($message) ?></div><?php endif; ?>
<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<?php if (is_array($codes) && count($codes)): ?>
    <h2>Save recovery codes</h2>
    <p>These codes appear only once. Each code can be used once instead of TOTP. Store them offline.</p>
    <pre><?= h(implode("\n", $codes)) ?></pre>
<?php endif; ?>

<?php if ($enabled): ?>
    <p><strong>Status: Enabled.</strong> Interactive API-key login is disabled.</p>
    <p>Disabling MFA requires both your administrator password and a current TOTP code or unused recovery code.</p>
    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="action" value="disable">
        <label>Administrator password<input type="password" name="password" autocomplete="current-password" required></label>
        <label>Authenticator or recovery code<input type="text" name="code" autocomplete="one-time-code" required maxlength="32"></label>
        <button type="submit">Disable MFA</button>
    </form>
<?php elseif ($enrolling): ?>
    <p><strong>Step 2:</strong> Add opnSentral to your authenticator.</p>
    <img src="/mfa_qr.php" alt="TOTP setup QR code" width="220" height="220" style="background:white;padding:10px">
    <p>Manual setup key: <code><?= h($secret) ?></code></p>
    <p>Type: TOTP · SHA-1 · 6 digits · 30 seconds.</p>
    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="action" value="enable">
        <label>Administrator password<input type="password" name="password" autocomplete="current-password" required></label>
        <label>First six-digit code<input type="text" name="code" required inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"></label>
        <button type="submit">Verify and enable MFA</button>
    </form>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="action" value="cancel">
        <button type="submit" class="secondary">Cancel enrollment</button>
    </form>
<?php else: ?>
    <p><strong>Status: Disabled.</strong> Enabling MFA will require TOTP for interactive administrator login and disable browser API-key login.</p>
    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="action" value="begin">
        <label>Confirm administrator password<input type="password" name="password" required autocomplete="current-password"></label>
        <button type="submit">Set up TOTP</button>
    </form>
<?php endif; ?>
</section>
<?php require __DIR__.'/inc/footer.php'; ?>
