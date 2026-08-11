<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/notification_settings.php';
require_once __DIR__ . '/inc/mailer.php';
require_once __DIR__ . '/inc/alerts.php';
require_login();

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    $action = (string) ($_POST['action'] ?? 'save');
    try {
        if ($action === 'save') {
            notification_save_settings($_POST);
            $message = t('notifications.save_success');
        } elseif ($action === 'test') {
            smtp_send(
                '[opnCentral] Test email',
                "This is a test email from opnCentral.\n\nTime: " . date(DATE_RFC2822) . "\nHost: " . (gethostname() ?: 'opncentral')
            );
            $message = t('notifications.test_success');
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

alerts_prepare_database();
$recent = db()->query('SELECT * FROM alert_log ORDER BY id DESC LIMIT 20')->fetchAll();
$settings = notification_settings();
$config = smtp_config();
require __DIR__ . '/inc/header.php';
?>
<div class="page-title">
    <div>
        <h1><?= h(t('notifications.title')) ?></h1>
        <p><?= h(t('notifications.subtitle')) ?></p>
    </div>
</div>

<?php if ($message): ?><div class="alert goodbox"><?= h($message) ?></div><?php endif; ?>
<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<form method="post" class="detail-grid">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">

    <section class="card">
        <h2><?= h(t('notifications.alert_settings')) ?></h2>

        <label class="checkbox">
            <input type="checkbox" name="alerts_enabled" value="1" <?= $settings['alerts_enabled'] ? 'checked' : '' ?>>
            <span><?= h(t('notifications.enabled')) ?></span>
        </label>

        <label class="checkbox">
            <input type="checkbox" name="alert_vpn" value="1" <?= $settings['alert_vpn'] ? 'checked' : '' ?>>
            <span><?= h(t('notifications.enable_vpn')) ?></span>
        </label>

        <label><?= h(t('notifications.interval')) ?>
            <input type="number" name="check_interval" min="60" max="86400" step="1" required value="<?= h((string) $settings['check_interval']) ?>">
            <span class="muted"><?= h(t('notifications.interval_help')) ?></span>
        </label>

        <label><?= h(t('notifications.threshold')) ?>
            <input type="number" name="failure_threshold" min="1" max="100" step="1" required value="<?= h((string) $settings['failure_threshold']) ?>">
            <span class="muted"><?= h(t('notifications.threshold_help')) ?></span>
        </label>
    </section>

    <section class="card">
        <h2><?= h(t('notifications.smtp_settings')) ?></h2>

        <label><?= h(t('notifications.smtp_host')) ?>
            <input type="text" name="smtp_host" value="<?= h((string) $settings['smtp_host']) ?>" autocomplete="off">
        </label>

        <label><?= h(t('notifications.smtp_port')) ?>
            <input type="number" name="smtp_port" min="1" max="65535" required value="<?= h((string) $settings['smtp_port']) ?>">
        </label>

        <label><?= h(t('notifications.smtp_security')) ?>
            <select name="smtp_security">
                <?php foreach (['tls' => 'STARTTLS', 'ssl' => 'SSL/TLS', 'none' => t('notifications.security_none')] as $value => $label): ?>
                    <option value="<?= h($value) ?>" <?= $settings['smtp_security'] === $value ? 'selected' : '' ?>><?= h((string) $label) ?></option>
                <?php endforeach; ?>
            </select>
        </label>

        <label><?= h(t('notifications.smtp_username')) ?>
            <input type="text" name="smtp_username" value="<?= h((string) $settings['smtp_username']) ?>" autocomplete="username">
        </label>

        <label><?= h(t('notifications.smtp_password')) ?>
            <input type="password" name="smtp_password" value="" autocomplete="new-password" placeholder="<?= h(t('notifications.password_unchanged')) ?>">
        </label>

        <label><?= h(t('notifications.from')) ?>
            <input type="email" name="smtp_from" value="<?= h((string) $settings['smtp_from']) ?>">
        </label>

        <label><?= h(t('notifications.from_name')) ?>
            <input type="text" name="smtp_from_name" value="<?= h((string) $settings['smtp_from_name']) ?>">
        </label>

        <label><?= h(t('notifications.recipients')) ?>
            <input type="text" name="notify_to" value="<?= h((string) $settings['notify_to']) ?>" placeholder="admin@example.com, second@example.com">
            <span class="muted"><?= h(t('notifications.recipients_help')) ?></span>
        </label>
    </section>

    <section class="card wide">
        <div class="actions">
            <button type="submit" name="action" value="save"><?= h(t('common.save')) ?></button>
            <button type="submit" name="action" value="test" class="secondary"><?= h(t('notifications.send_test')) ?></button>
        </div>
        <p class="muted"><?= h(t('notifications.settings_source')) ?>: <?= h((string) $settings['source']) ?></p>
    </section>
</form>

<section class="card" style="margin-top:18px">
    <h2><?= h(t('notifications.recent')) ?></h2>
    <?php if (!$recent): ?>
        <p class="muted"><?= h(t('notifications.none')) ?></p>
    <?php else: ?>
        <div style="overflow:auto">
            <table style="width:100%;border-collapse:collapse">
                <thead><tr><th style="text-align:left;padding:8px">Time</th><th style="text-align:left;padding:8px">Event</th><th style="text-align:left;padding:8px">Subject</th><th style="text-align:left;padding:8px">Result</th></tr></thead>
                <tbody>
                <?php foreach ($recent as $row): ?>
                    <tr>
                        <td style="padding:8px"><?= h((string)$row['created_at']) ?></td>
                        <td style="padding:8px"><?= h((string)$row['event_type']) ?></td>
                        <td style="padding:8px"><?= h((string)$row['subject']) ?></td>
                        <td style="padding:8px"><span class="badge <?= (int)$row['sent_ok'] === 1 ? 'good' : 'bad' ?>"><?= (int)$row['sent_ok'] === 1 ? h(t('notifications.sent')) : h((string)$row['error']) ?></span></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</section>
<?php require __DIR__ . '/inc/footer.php'; ?>
