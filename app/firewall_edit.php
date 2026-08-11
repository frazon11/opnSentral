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
<div class="page-title">
    <h1><?= h($id ? t('firewall.edit_title') : t('firewall.add_title')) ?></h1>
</div>

<?php if ($error): ?>
    <div class="alert error"><?= h($error) ?></div>
<?php endif; ?>

<form class="form-card" method="post">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">

    <label>
        <?= h(t('firewall.name')) ?>
        <input name="name" value="<?= h((string) $firewall['name']) ?>" required>
    </label>

    <label>
        <?= h(t('firewall.url')) ?>
        <input name="base_url" value="<?= h((string) $firewall['base_url']) ?>" placeholder="https://firewall.example.net" required>
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
<?php require __DIR__ . '/inc/footer.php'; ?>
