<?php
declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/alias_central.php';

require_login();
central_alias_init();

function alias_edit_assert_success(array $response, string $operation): void
{
    $validations = $response['validations'] ?? null;
    if (is_array($validations) && $validations !== []) {
        throw new RuntimeException('OPNsense rejected alias ' . $operation . ': ' . json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
    foreach (['result', 'status'] as $field) {
        if (!array_key_exists($field, $response)) continue;
        $value = $response[$field];
        if ($value === false || $value === 0 || $value === '0') {
            throw new RuntimeException('OPNsense rejected alias ' . $operation . '.');
        }
        if (is_string($value) && in_array(strtolower(trim($value)), ['failed','failure','error','invalid','rejected'], true)) {
            throw new RuntimeException('OPNsense rejected alias ' . $operation . ': ' . $value);
        }
    }
}

function alias_edit_enabled(mixed $value): int
{
    $value = strtolower(trim(central_alias_scalar($value)));
    return in_array($value, ['1','true','yes','on','enabled'], true) ? 1 : 0;
}

function alias_edit_verify(array $firewall, string $name, string $type, array $lines, string $description, int $enabled): void
{
    $remote = central_alias_find($firewall, $name);
    if ($remote === null) {
        throw new RuntimeException('Alias "' . $name . '" was not found after saving.');
    }
    if (strcasecmp((string)($remote['type'] ?? ''), $type) !== 0) {
        throw new RuntimeException('Verification failed: type is "' . (string)($remote['type'] ?? '') . '", expected "' . $type . '".');
    }
    if (central_alias_lines((string)($remote['content'] ?? '')) !== central_alias_lines(implode("\n", $lines))) {
        throw new RuntimeException('Verification failed: content does not match.');
    }
    if (trim((string)($remote['description'] ?? '')) !== $description) {
        throw new RuntimeException('Verification failed: description does not match.');
    }
    if (alias_edit_enabled($remote['enabled'] ?? 0) !== $enabled) {
        throw new RuntimeException('Verification failed: enabled state does not match.');
    }
}

function alias_edit_raw_model(array $firewall, string $uuid): array
{
    $current = opn_raw_request(
        $firewall,
        'firewall/alias/get_item/' . rawurlencode($uuid),
        'GET',
        null,
        20
    );
    $model = isset($current['alias']) && is_array($current['alias']) ? $current['alias'] : $current;
    if (!is_array($model) || $model === []) {
        throw new RuntimeException('OPNsense did not return the alias definition before editing.');
    }
    return $model;
}

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$firewallById = [];
foreach ($firewalls as $fw) $firewallById[(int)$fw['id']] = $fw;

$name = trim((string)($_POST['name'] ?? $_GET['name'] ?? ''));
$sourceFirewallId = (int)($_POST['source_firewall_id'] ?? $_GET['source_firewall_id'] ?? 0);
if ($name === '' || $sourceFirewallId <= 0 || !isset($firewallById[$sourceFirewallId])) {
    http_response_code(400);
    exit('Alias name and source firewall are required.');
}

$sourceFirewall = $firewallById[$sourceFirewallId];
$sourceAlias = central_alias_find($sourceFirewall, $name);
if ($sourceAlias === null) {
    http_response_code(404);
    exit('Alias not found on the selected source firewall.');
}

$error = '';
$results = [];
$types = ['host'=>'Host(s)','network'=>'Network(s)','port'=>'Port(s)','url'=>'URL','urltable'=>'URL table','geoip'=>'GeoIP','networkgroup'=>'Network group','mac'=>'MAC','asn'=>'ASN'];

$typeValue = (string)($sourceAlias['type'] ?? 'host');
$contentValue = (string)($sourceAlias['content'] ?? '');
$descriptionValue = (string)($sourceAlias['description'] ?? '');
$enabledValue = alias_edit_enabled($sourceAlias['enabled'] ?? 1);
$scopeValue = 'one';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    try {
        require_configuration_unlocked(false);
        $typeValue = trim((string)($_POST['type'] ?? 'host'));
        $contentValue = (string)($_POST['content'] ?? '');
        $descriptionValue = trim((string)($_POST['description'] ?? ''));
        $enabledValue = isset($_POST['enabled']) ? 1 : 0;
        $scopeValue = (string)($_POST['target_scope'] ?? 'one');
        $targetFirewallId = (int)($_POST['target_firewall_id'] ?? $sourceFirewallId);
        $lines = central_alias_lines($contentValue);

        if (!isset($types[$typeValue])) throw new RuntimeException('Invalid alias type.');
        if ($lines === []) throw new RuntimeException('Enter at least one alias value.');
        if (mb_strlen($descriptionValue) > 255) throw new RuntimeException('Description may contain at most 255 characters.');
        if (!in_array($scopeValue, ['one','all-existing'], true)) throw new RuntimeException('Invalid target scope.');
        if ($scopeValue === 'one' && !isset($firewallById[$targetFirewallId])) throw new RuntimeException('Select a valid firewall.');

        $targets = $scopeValue === 'one' ? [$firewallById[$targetFirewallId]] : $firewalls;
        foreach ($targets as $firewall) {
            try {
                $existing = central_alias_find($firewall, $name);
                if ($existing === null) {
                    if ($scopeValue === 'all-existing') {
                        $results[] = ['ok'=>true,'skipped'=>true,'name'=>$firewall['name'],'message'=>'Skipped: alias does not exist on this firewall.'];
                        continue;
                    }
                    throw new RuntimeException('Alias does not exist on this firewall.');
                }

                $uuid = trim((string)($existing['uuid'] ?? ''));
                if ($uuid === '') throw new RuntimeException('OPNsense did not return the alias UUID.');

                backup_before_change($firewall, 'alias-edit');

                // Preserve the exact raw MVC model returned by OPNsense. Normalized
                // inventory values are safe for display/comparison, but posting them
                // back can corrupt OptionField/RelationField shapes and cause HTTP 500.
                $payload = alias_edit_raw_model($firewall, $uuid);
                $payload['name'] = $name;
                $payload['type'] = $typeValue;
                $payload['content'] = implode("\n", $lines);
                $payload['description'] = $descriptionValue;
                $payload['enabled'] = (string)$enabledValue;

                $write = opn_raw_request(
                    $firewall,
                    'firewall/alias/set_item/' . rawurlencode($uuid),
                    'POST',
                    ['alias'=>$payload],
                    30
                );
                alias_edit_assert_success($write, 'update');

                $reconfigure = opn_raw_request($firewall, 'firewall/alias/reconfigure', 'POST', [], 45);
                alias_edit_assert_success($reconfigure, 'reconfigure');
                alias_edit_verify($firewall, $name, $typeValue, $lines, $descriptionValue, $enabledValue);
                $results[] = ['ok'=>true,'skipped'=>false,'name'=>$firewall['name'],'message'=>'Updated and verified.'];
            } catch (Throwable $exception) {
                $results[] = ['ok'=>false,'skipped'=>false,'name'=>$firewall['name'],'message'=>$exception->getMessage()];
            }
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.alias-edit-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(300px,.8fr);gap:20px}.alias-edit-form label{display:block;font-weight:700;margin:14px 0 6px}.alias-edit-form input[type=text],.alias-edit-form select,.alias-edit-form textarea{width:100%;box-sizing:border-box}.alias-edit-form textarea{min-height:220px;font-family:monospace}.alias-edit-enabled{display:flex!important;align-items:center;gap:9px}.alias-edit-enabled input{width:auto}.alias-edit-source{padding:10px;border-radius:6px;background:rgba(127,127,127,.08)}.alias-edit-results{display:grid;gap:8px}.alias-edit-result{padding:10px;border-radius:6px;background:rgba(127,127,127,.08)}.alias-edit-result.good{border-left:4px solid #2aa84a}.alias-edit-result.bad{border-left:4px solid #d74747}@media(max-width:850px){.alias-edit-grid{grid-template-columns:1fr}}
</style>
<div class="page-title"><div><h1>Edit alias definition</h1><p>Edit type, content, description and enabled state. Renaming is a separate action.</p></div><a class="button secondary" href="/alias_overview.php">Back to aliases</a></div>
<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>
<div class="alias-edit-grid">
<section class="card">
    <h2><?= h($name) ?></h2>
    <div class="alias-edit-source"><strong>Source:</strong> <?= h((string)$sourceFirewall['name']) ?><br><span class="muted">The name is intentionally fixed here. Use Rename in the overview if you want to change it.</span></div>
    <form method="post" class="alias-edit-form" id="alias-edit-form">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="name" value="<?= h($name) ?>">
        <input type="hidden" name="source_firewall_id" value="<?= (int)$sourceFirewallId ?>">
        <label>Type</label><select name="type"><?php foreach ($types as $value=>$label): ?><option value="<?= h($value) ?>" <?= $typeValue===$value?'selected':'' ?>><?= h($label) ?></option><?php endforeach; ?></select>
        <label>Content</label><textarea name="content" required><?= h($contentValue) ?></textarea>
        <label>Description</label><input type="text" name="description" maxlength="255" value="<?= h($descriptionValue) ?>"><small class="muted">Optional. Maximum 255 characters.</small>
        <label class="alias-edit-enabled"><input type="checkbox" name="enabled" value="1" <?= $enabledValue ? 'checked' : '' ?>><span>Enabled</span></label>
        <fieldset><legend>Apply changes to</legend>
            <label><input type="radio" name="target_scope" value="one" <?= $scopeValue==='one'?'checked':'' ?>> One OPNsense</label>
            <select name="target_firewall_id" id="alias-edit-target"><?php foreach ($firewalls as $fw): ?><option value="<?= (int)$fw['id'] ?>" <?= (int)$fw['id']===$sourceFirewallId?'selected':'' ?>><?= h((string)$fw['name']) ?></option><?php endforeach; ?></select>
            <label><input type="radio" name="target_scope" value="all-existing" <?= $scopeValue==='all-existing'?'checked':'' ?>> All OPNsense where this alias already exists</label>
            <small class="muted">All-existing never creates a missing alias. Existing categories are preserved.</small>
        </fieldset>
        <div class="actions"><button type="submit">Save definition</button></div>
    </form>
</section>
<section class="card"><h2>Results</h2><?php if (!$results): ?><div class="empty">No changes saved yet.</div><?php else: ?><div class="alias-edit-results"><?php foreach ($results as $result): ?><div class="alias-edit-result <?= $result['ok']?'good':'bad' ?>"><strong><?= h((string)$result['name']) ?></strong><br><?= h((string)$result['message']) ?></div><?php endforeach; ?></div><?php endif; ?></section>
</div>
<script>
(function(){
    const form=document.getElementById('alias-edit-form');
    const target=document.getElementById('alias-edit-target');
    function sync(){const all=document.querySelector('input[name="target_scope"]:checked')?.value==='all-existing';if(target)target.disabled=all;}
    document.querySelectorAll('input[name="target_scope"]').forEach(r=>r.addEventListener('change',sync));sync();
    form?.addEventListener('submit',function(event){if(!form.checkValidity())return;const scope=document.querySelector('input[name="target_scope"]:checked')?.value;const message=scope==='all-existing'?'Save this definition to every OPNsense where the alias already exists?':'Save this definition to the selected OPNsense?';if(!confirm(message))event.preventDefault();});
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>