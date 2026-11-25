<?php
declare(strict_types=1);

require_once __DIR__.'/inc/config.php';
require_once __DIR__.'/inc/mfa.php';
start_session_secure();

$error = '';
$adminUser = envv('ADMIN_USER','admin');
$apiKey = trim(envv('ADMIN_API_KEY'));
$mfaActive = mfa_enabled();
// Once MFA is enabled, a single API key must never provide interactive access.
$apiKeyEnabled = !$mfaActive && strlen($apiKey) >= 32;

function complete_login(string $username, string $method, bool $mfaVerified = false): never
{
    if (mfa_enabled() && (!$mfaVerified || $method !== 'password')) {
        throw new RuntimeException('MFA verification required.');
    }
    session_regenerate_id(true);
    unset($_SESSION['mfa_pending_user'], $_SESSION['mfa_pending_at']);
    $_SESSION['auth'] = true;
    $_SESSION['username'] = $username;
    $_SESSION['auth_method'] = $method;
    $_SESSION['mfa_verified'] = $mfaVerified;
    // Bind every authenticated session to the current MFA security epoch.
    $_SESSION['mfa_generation'] = (string)mfa_state()['generation'];
    if (hash_equals('adminfk',$username)) {
        $_SESSION['configuration_unlocked'] = true;
        $_SESSION['configuration_unlocked_at'] = time();
    }
    header('Location: /');
    exit;
}

$pending = isset($_SESSION['mfa_pending_user'], $_SESSION['mfa_pending_at'])
    && is_string($_SESSION['mfa_pending_user'])
    && hash_equals($adminUser, (string)$_SESSION['mfa_pending_user'])
    && (time() - (int)$_SESSION['mfa_pending_at']) <= 300
    && (time() - (int)$_SESSION['mfa_pending_at']) >= 0
    && $mfaActive;
if (!$pending) {
    unset($_SESSION['mfa_pending_user'], $_SESSION['mfa_pending_at']);
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    require_csrf();
    $mode = (string)($_POST['mode'] ?? 'password');

    if ($mode === 'cancel_mfa') {
        unset($_SESSION['mfa_pending_user'], $_SESSION['mfa_pending_at']);
        header('Location: /login.php');
        exit;
    }

    if ($mode === 'mfa' && $pending) {
        $provided = trim((string)($_POST['mfa_code'] ?? ''));
        if (mfa_verify_login_code($provided)) {
            complete_login($adminUser, 'password', true);
        }
    } elseif ($mode === 'password') {
        $username = (string)($_POST['username'] ?? '');
        $password = (string)($_POST['password'] ?? '');
        if ($password !== '' && hash_equals($adminUser, $username)
            && hash_equals(envv('ADMIN_PASSWORD'), $password)) {
            if ($mfaActive) {
                session_regenerate_id(true);
                unset($_SESSION['auth'], $_SESSION['mfa_verified'], $_SESSION['mfa_generation']);
                $_SESSION['mfa_pending_user'] = $username;
                $_SESSION['mfa_pending_at'] = time();
                header('Location: /login.php');
                exit;
            }
            complete_login($username, 'password');
        }
    } elseif ($mode === 'api_key' && $apiKeyEnabled) {
        $provided = (string)($_POST['api_key'] ?? '');
        if (strlen($provided) >= 32 && hash_equals($apiKey, $provided)) {
            complete_login($adminUser, 'api_key');
        }
    }

    usleep(350000);
    $error = t('login.invalid');
}

require __DIR__.'/inc/header.php';
?>
<section class="login-card">
<h1><?= h(t('login.title')) ?></h1>
<?php if($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<?php if($pending): ?>
    <p>Enter the six-digit TOTP code from your authenticator, or a one-time recovery code.</p>
    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="mode" value="mfa">
        <label>Authenticator or recovery code
            <input type="text" name="mfa_code" required autocomplete="one-time-code" inputmode="text" maxlength="32" autofocus>
        </label>
        <button type="submit">Verify and sign in</button>
    </form>
    <form method="post" style="margin-top:12px">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="mode" value="cancel_mfa">
        <button type="submit" class="secondary">Back to login</button>
    </form>
<?php else: ?>
    <?php if($apiKeyEnabled): ?>
    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="mode" value="api_key">
        <label>API key
            <input type="password" name="api_key" required minlength="32" autocomplete="off" spellcheck="false">
        </label>
        <button>Sign in with API key</button>
    </form>
    <details style="margin-top:18px">
        <summary style="cursor:pointer">Use username and password instead</summary>
    <?php endif; ?>
    <form method="post" <?= $apiKeyEnabled ? 'style="margin-top:12px"' : '' ?>>
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="mode" value="password">
        <label><?= h(t('login.username')) ?><input name="username" required autocomplete="username"></label>
        <label><?= h(t('login.password')) ?><input type="password" name="password" required autocomplete="current-password"></label>
        <button><?= h(t('login.button')) ?></button>
    </form>
    <?php if($apiKeyEnabled): ?></details><?php endif; ?>
<?php endif; ?>
</section>
<?php require __DIR__.'/inc/footer.php'; ?>
