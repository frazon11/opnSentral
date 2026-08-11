<?php
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/category_central.php';
require_once __DIR__ . '/inc/managed_category.php';
require_once __DIR__ . '/inc/distribution_targets.php';
require_login();
central_category_init();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$results = [];
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    try {
        require_configuration_unlocked(false);
        $name = trim((string) ($_POST['name'] ?? ''));
        $color = central_category_normalize_color((string) ($_POST['color'] ?? ''));
        $automatic = isset($_POST['automatic']) ? 1 : 0;
        $mode = (string) ($_POST['mode'] ?? 'create');
        $targetIds = distribution_target_ids($firewalls);

        if ($name === '' || mb_strlen($name) > 255) {
            throw new RuntimeException('Enter a category name with at most 255 characters.');
        }

        if (!in_array($mode, ['create', 'replace'], true)) {
            throw new RuntimeException('Invalid distribution mode.');
        }

        if (!$targetIds) {
            throw new RuntimeException('Select at least one firewall.');
        }

        $categoryId = central_category_save_definition($name, $color, $automatic);
        $placeholders = implode(',', array_fill(0, count($targetIds), '?'));
        $statement = db()->prepare(
            'SELECT * FROM firewalls WHERE id IN (' . $placeholders . ') ORDER BY name'
        );
        $statement->execute($targetIds);

        foreach ($statement->fetchAll() as $firewall) {
            try {
                backup_before_change($firewall, 'category-distribution');
                $existing = central_category_search($firewall, $name);

                if ($existing === null) {
                    $response = opn_request(
                        $firewall,
                        'firewall/category/add_item',
                        'POST',
                        central_category_payload($name, $color, $automatic),
                        20
                    );
                    $message = 'Created.';
                } else {
                    if ($mode === 'create') {
                        throw new RuntimeException(
                            'Category already exists; create-only mode made no change.'
                        );
                    }

                    $uuid = (string) ($existing['uuid'] ?? '');
                    if ($uuid === '') {
                        throw new RuntimeException('Existing category has no UUID.');
                    }

                    $response = opn_request(
                        $firewall,
                        'firewall/category/set_item/' . rawurlencode($uuid),
                        'POST',
                        central_category_payload($name, $color, $automatic, $existing),
                        20
                    );
                    $message = 'Replaced.';
                }

                if (
                    isset($response['result'])
                    && !in_array((string) $response['result'], ['saved', 'ok'], true)
                    && !isset($response['uuid'])
                ) {
                    throw new RuntimeException(
                        'OPNsense rejected the category: ' . json_encode($response)
                    );
                }

                central_category_target_status(
                    $categoryId,
                    (int) $firewall['id'],
                    'synchronized',
                    $message
                );

                $results[] = [
                    'name' => (string) $firewall['name'],
                    'ok' => true,
                    'message' => $message,
                ];
            } catch (Throwable $exception) {
                central_category_target_status(
                    $categoryId,
                    (int) $firewall['id'],
                    'error',
                    $exception->getMessage()
                );

                $results[] = [
                    'name' => (string) $firewall['name'],
                    'ok' => false,
                    'message' => $exception->getMessage(),
                ];
            }
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.category-layout{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(280px,.85fr);gap:20px}.category-form label{display:block;font-weight:700;margin:14px 0 6px}.category-form input[type=text],.category-form select{width:100%;box-sizing:border-box}.target-list,.result-list{display:grid;gap:8px;margin-top:8px}.target-item,.result-item{display:flex;gap:8px;align-items:center;padding:10px;border-radius:8px;background:rgba(127,127,127,.08)}.result-item{display:block}.result-item.ok{border-left:4px solid #2aa84a}.result-item.bad{border-left:4px solid #d74747}.result-item strong{display:block;margin-bottom:4px}.help{font-size:.9rem;opacity:.75;margin-top:5px}@media(max-width:850px){.category-layout{grid-template-columns:1fr}}
</style>

<div class="page-title">
    <div>
        <h1><?= h(t('categories.title')) ?></h1>
        <p><?= h(t('categories.subtitle')) ?></p>
    </div>
    <a class="button secondary" href="/category_overview.php"><?= h(t('categories.overview')) ?></a>
</div>

<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<div class="category-layout">
<section class="card">
<h2><?= h(t('categories.definition')) ?></h2>
<form method="post" class="category-form">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">

<label for="name"><?= h(t('categories.name')) ?></label>
<input id="name" name="name" type="text" required maxlength="255" value="<?= h((string)($_POST['name'] ?? managed_category_name())) ?>">

<label for="color"><?= h(t('categories.color')) ?></label>
<input id="color" name="color" type="text" value="<?= h((string)($_POST['color'] ?? managed_category_color())) ?>" placeholder="#f0ad4e">
<div class="help"><?= h(t('categories.color_help')) ?></div>

<label for="mode"><?= h(t('categories.exists')) ?></label>
<?php $selectedMode = (string)($_POST['mode'] ?? 'create'); ?>
<select id="mode" name="mode">
<option value="create" <?= $selectedMode === 'create' ? 'selected' : '' ?>><?= h(t('aliases.create_only')) ?></option>
<option value="replace" <?= $selectedMode === 'replace' ? 'selected' : '' ?>><?= h(t('categories.replace')) ?></option>
</select>

<label><input type="checkbox" name="automatic" value="1" <?= isset($_POST['automatic']) ? 'checked' : '' ?>> <?= h(t('categories.automatic')) ?></label>
<div class="help">Automatic categories may be removed by OPNsense when no longer used. Leave this disabled for centrally managed categories.</div>

<fieldset class="distribution-targets">
<legend><?= h(t('categories.targets')) ?></legend>

<?php $targetScope = (string)($_POST['target_scope'] ?? ($_GET['scope'] ?? 'one'));
$requestedFirewallId = (int)($_POST['target_firewall_id'] ?? $_GET['firewall_id'] ?? 0); ?>
<label class="distribution-scope-option">
<input type="radio" name="target_scope" value="one" <?= $targetScope === 'one' ? 'checked' : '' ?>>
<span><strong>One OPNsense</strong><small>Distribute only to the selected firewall.</small></span>
</label>

<label class="distribution-firewall-select">
OPNsense
<select name="target_firewall_id" id="category-target-firewall">
<option value="">Select firewall</option>
<?php foreach ($firewalls as $firewall): ?>
<option value="<?= (int)$firewall['id'] ?>" <?= $requestedFirewallId === (int)$firewall['id'] ? 'selected' : '' ?>><?= h((string)$firewall['name']) ?></option>
<?php endforeach; ?>
</select>
</label>

<label class="distribution-scope-option">
<input type="radio" name="target_scope" value="all" <?= $targetScope === 'all' ? 'checked' : '' ?>>
<span><strong>All OPNsense firewalls</strong><small>Distribute to every currently managed firewall.</small></span>
</label>
</fieldset>

<div class="actions">
<button type="submit" onclick="return confirm('Distribute this category using the selected target scope?')"><?= h(t('categories.distribute')) ?></button>
</div>
</form>
</section>

<section class="card">
<h2><?= h(t('aliases.results')) ?></h2>
<?php if (!$results): ?><div class="empty"><?= h(t('aliases.results_empty')) ?></div><?php else: ?>
<div class="result-list">
<?php foreach ($results as $result): ?>
<div class="result-item <?= $result['ok'] ? 'ok' : 'bad' ?>"><strong><?= h($result['name']) ?></strong><?= h($result['message']) ?></div>
<?php endforeach; ?>
</div>
<?php endif; ?>
</section>
</div>

<script>
document.querySelectorAll('input[name="target_scope"]').forEach(function(radio){
radio.addEventListener('change',function(){
const select=document.getElementById('category-target-firewall');
select.disabled=document.querySelector('input[name="target_scope"]:checked')?.value==='all';
});
});
document.querySelector('input[name="target_scope"]:checked')?.dispatchEvent(new Event('change'));
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
