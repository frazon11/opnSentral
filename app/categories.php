<?php
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/category_central.php';
require_once __DIR__ . '/inc/managed_category.php';
require_once __DIR__ . '/inc/distribution_targets.php';
require_login();
central_category_init();

function category_distribution_scalar(mixed $value): string
{
    if(!is_array($value)) return trim((string)$value);
    foreach($value as $key=>$item){if(is_array($item)&&!empty($item['selected'])) return is_string($key)?trim($key):trim((string)($item['value']??$item['name']??''));}
    foreach($value as $key=>$item){if(is_string($key)&&!is_array($item)&&in_array(strtolower(trim((string)$item)),['1','true','yes','on','selected'],true)) return trim($key);}
    foreach($value as $item){if(!is_array($item)&&trim((string)$item)!=='') return trim((string)$item);}
    return '';
}
function category_distribution_bool(mixed $value): int
{
    return in_array(strtolower(category_distribution_scalar($value)),['1','true','yes','on','enabled'],true)?1:0;
}
function category_distribution_success(array $response): bool
{
    if(($response['error']??'')!=='') return false;
    $validations=$response['validations']??null;if(is_array($validations)&&$validations!==[]) return false;
    foreach(['result','status'] as $field){if(!array_key_exists($field,$response)) continue;$value=$response[$field];if($value===false||$value===0||$value==='0') return false;if(is_string($value)&&in_array(strtolower(trim($value)),['failed','failure','error','invalid','rejected'],true)) return false;}
    return true;
}

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

        if ($name === '' || mb_strlen($name) > 255) throw new RuntimeException('Enter a category name with at most 255 characters.');
        if (!in_array($mode, ['create', 'replace'], true)) throw new RuntimeException('Invalid distribution mode.');
        if (!$targetIds) throw new RuntimeException('Select at least one firewall.');

        $categoryId = central_category_save_definition($name, $color, $automatic);
        $placeholders = implode(',', array_fill(0, count($targetIds), '?'));
        $statement = db()->prepare('SELECT * FROM firewalls WHERE id IN (' . $placeholders . ') ORDER BY name');
        $statement->execute($targetIds);

        foreach ($statement->fetchAll() as $firewall) {
            try {
                $existing = central_category_search($firewall, $name);
                if ($existing !== null && $mode === 'create') {
                    throw new RuntimeException('Category already exists; create-only mode made no change.');
                }

                backup_before_change($firewall, 'category-distribution');
                if ($existing === null) {
                    $response = opn_raw_request($firewall,'firewall/category/add_item','POST',central_category_payload($name,$color,$automatic),30);
                    $message = 'Created.';
                } else {
                    $uuid = trim((string)($existing['uuid'] ?? ''));
                    if ($uuid === '') throw new RuntimeException('Existing category has no UUID.');
                    $response = opn_raw_request($firewall,'firewall/category/set_item/' . rawurlencode($uuid),'POST',['category'=>[
                        'name'=>$name,
                        'color'=>$color,
                        'auto'=>(string)$automatic,
                    ]],30);
                    $message = 'Replaced.';
                }
                if(!category_distribution_success($response)) throw new RuntimeException('OPNsense rejected the category: '.json_encode($response,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));

                $reconfigure=opn_raw_request($firewall,'firewall/category/reconfigure','POST',[],45);
                if(!category_distribution_success($reconfigure)) throw new RuntimeException('OPNsense rejected category reconfigure: '.json_encode($reconfigure,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));

                $verify=central_category_search($firewall,$name);
                if($verify===null) throw new RuntimeException('Verification failed: category was not found after saving.');
                $verifyColor=central_category_normalize_color(category_distribution_scalar($verify['color']??''));
                $verifyAutomatic=category_distribution_bool($verify['auto']??$verify['automatic']??0);
                if(strcasecmp($verifyColor,$color)!==0) throw new RuntimeException('Verification failed: category color does not match.');
                if($verifyAutomatic!==$automatic) throw new RuntimeException('Verification failed: automatic state does not match.');

                central_category_target_status($categoryId,(int)$firewall['id'],'synchronized',$message.' Verified.');
                $results[]=['name'=>(string)$firewall['name'],'ok'=>true,'message'=>$message.' Verified.'];
            } catch (Throwable $exception) {
                central_category_target_status($categoryId,(int)$firewall['id'],'error',$exception->getMessage());
                $results[]=['name'=>(string)$firewall['name'],'ok'=>false,'message'=>$exception->getMessage()];
            }
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.category-layout{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(280px,.85fr);gap:20px}.category-form label{display:block;font-weight:700;margin:14px 0 6px}.category-form input[type=text],.category-form select{width:100%;box-sizing:border-box}.result-list{display:grid;gap:8px;margin-top:8px}.result-item{padding:10px;border-radius:8px;background:rgba(127,127,127,.08)}.result-item.ok{border-left:4px solid #2aa84a}.result-item.bad{border-left:4px solid #d74747}.result-item strong{display:block;margin-bottom:4px}.help{font-size:.9rem;opacity:.75;margin-top:5px}.category-auto{display:flex!important;align-items:center;gap:9px}.category-auto input{width:auto}.category-targets{margin-top:18px;padding:12px;border:1px solid rgba(127,127,127,.35);border-radius:7px}.category-targets legend{padding:0 7px;font-weight:700}.category-target-option{display:grid!important;grid-template-columns:20px minmax(0,1fr);gap:10px;align-items:start;margin:0!important;padding:11px 12px;border:1px solid transparent;border-radius:6px;cursor:pointer}.category-target-option:has(input:checked){background:rgba(55,139,220,.10);border-color:rgba(55,139,220,.45)}.category-target-option input{margin-top:3px}.category-target-option strong{display:block}.category-target-option small{display:block;margin-top:3px}.category-target-select{margin:5px 12px 10px 42px}.category-target-select select{width:100%}.category-target-select select:disabled{opacity:.5}@media(max-width:850px){.category-layout{grid-template-columns:1fr}.category-target-select{margin-left:12px}}
</style>

<div class="page-title"><div><h1><?= h(t('categories.title')) ?></h1><p><?= h(t('categories.subtitle')) ?></p></div><a class="button secondary" href="/category_overview.php"><?= h(t('categories.overview')) ?></a></div>
<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<div class="category-layout">
<section class="card">
<h2><?= h(t('categories.definition')) ?></h2>
<form method="post" class="category-form" id="category-distribute-form">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<label for="name"><?= h(t('categories.name')) ?></label>
<input id="name" name="name" type="text" required maxlength="255" value="<?= h((string)($_POST['name'] ?? managed_category_name())) ?>">
<label for="color"><?= h(t('categories.color')) ?></label>
<input id="color" name="color" type="text" value="<?= h((string)($_POST['color'] ?? managed_category_color())) ?>" placeholder="F0AD4E">
<div class="help"><?= h(t('categories.color_help')) ?></div>
<label for="mode"><?= h(t('categories.exists')) ?></label>
<?php $selectedMode = (string)($_POST['mode'] ?? 'create'); ?>
<select id="mode" name="mode">
<option value="create" <?= $selectedMode === 'create' ? 'selected' : '' ?>>Create only</option>
<option value="replace" <?= $selectedMode === 'replace' ? 'selected' : '' ?>>Replace</option>
</select>
<div class="help" id="category-mode-help"></div>
<label class="category-auto"><input type="checkbox" name="automatic" value="1" <?= isset($_POST['automatic']) ? 'checked' : '' ?>><span><?= h(t('categories.automatic')) ?></span></label>
<div class="help">Automatic categories may be removed by OPNsense when no longer used. Leave this disabled for centrally managed categories.</div>

<fieldset class="category-targets"><legend><?= h(t('categories.targets')) ?></legend>
<?php $targetScope=(string)($_POST['target_scope']??($_GET['scope']??'one'));$requestedFirewallId=(int)($_POST['target_firewall_id']??$_GET['firewall_id']??0); ?>
<label class="category-target-option"><input type="radio" name="target_scope" value="one" <?= $targetScope==='one'?'checked':'' ?>><span><strong>One OPNsense</strong><small class="muted">Distribute only to the selected firewall.</small></span></label>
<div class="category-target-select"><select name="target_firewall_id" id="category-target-firewall"><option value="">Select firewall</option><?php foreach($firewalls as $firewall): ?><option value="<?= (int)$firewall['id'] ?>" <?= $requestedFirewallId===(int)$firewall['id']?'selected':'' ?>><?= h((string)$firewall['name']) ?></option><?php endforeach; ?></select></div>
<label class="category-target-option"><input type="radio" name="target_scope" value="all" <?= $targetScope==='all'?'checked':'' ?>><span><strong>All OPNsense firewalls</strong><small class="muted">Distribute to every currently managed firewall.</small></span></label>
</fieldset>
<div class="actions"><button type="submit"><?= h(t('categories.distribute')) ?></button></div>
</form>
</section>

<section class="card"><h2><?= h(t('aliases.results')) ?></h2><?php if (!$results): ?><div class="empty"><?= h(t('aliases.results_empty')) ?></div><?php else: ?><div class="result-list"><?php foreach ($results as $result): ?><div class="result-item <?= $result['ok'] ? 'ok' : 'bad' ?>"><strong><?= h($result['name']) ?></strong><?= h($result['message']) ?></div><?php endforeach; ?></div><?php endif; ?></section>
</div>

<script>
(function(){
const form=document.getElementById('category-distribute-form');const select=document.getElementById('category-target-firewall');const mode=document.getElementById('mode');const help=document.getElementById('category-mode-help');
function syncTarget(){const all=document.querySelector('input[name="target_scope"]:checked')?.value==='all';select.disabled=all;}
function syncMode(){help.textContent=mode.value==='replace'?'If the category exists, replace its color and automatic state. If it does not exist, create it.':'Create the category only when it does not already exist. Existing categories are left unchanged.';}
document.querySelectorAll('input[name="target_scope"]').forEach(r=>r.addEventListener('change',syncTarget));mode.addEventListener('change',syncMode);syncTarget();syncMode();
form.addEventListener('submit',function(event){if(!form.checkValidity())return;const scope=document.querySelector('input[name="target_scope"]:checked')?.value;const message=scope==='all'?'Distribute this category to all managed OPNsense firewalls?':'Distribute this category to the selected OPNsense?';if(!confirm(message))event.preventDefault();});
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
