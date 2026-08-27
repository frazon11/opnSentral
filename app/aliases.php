<?php
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/alias_central.php';
require_once __DIR__ . '/inc/distribution_targets.php';
require_login();
central_alias_init();

function alias_assert_api_success(array $response, string $operation): void
{
    $validations = $response['validations'] ?? null;
    if (is_array($validations) && $validations !== []) {
        throw new RuntimeException(
            'OPNsense rejected alias ' . $operation . ': ' .
            json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
        );
    }

    foreach (['result', 'status'] as $field) {
        if (!array_key_exists($field, $response)) {
            continue;
        }
        $value = $response[$field];
        if ($value === false || $value === 0 || $value === '0') {
            throw new RuntimeException(
                'OPNsense rejected alias ' . $operation . ': ' .
                json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            );
        }
        if (is_string($value)) {
            $normalized = strtolower(trim($value));
            if (in_array($normalized, ['failed', 'failure', 'error', 'invalid', 'rejected'], true)) {
                throw new RuntimeException(
                    'OPNsense rejected alias ' . $operation . ': ' .
                    json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                );
            }
        }
    }
}

function alias_verify_remote_state(
    array $firewall,
    string $name,
    string $type,
    array $expectedLines,
    string $categoryUuid
): void {
    $verified = central_alias_find($firewall, $name);
    if ($verified === null) {
        throw new RuntimeException('OPNsense returned success, but alias "' . $name . '" was not found after deployment.');
    }
    if (strcasecmp((string) ($verified['name'] ?? ''), $name) !== 0) {
        throw new RuntimeException('Alias verification failed: remote alias name does not match "' . $name . '".');
    }
    if (strcasecmp((string) ($verified['type'] ?? ''), $type) !== 0) {
        throw new RuntimeException(
            'Alias verification failed for "' . $name . '": remote type is "' .
            (string) ($verified['type'] ?? '') . '", expected "' . $type . '".'
        );
    }
    $remoteLines = central_alias_lines((string) ($verified['content'] ?? ''));
    $expected = array_values($expectedLines);
    sort($expected, SORT_NATURAL | SORT_FLAG_CASE);
    if ($remoteLines !== $expected) {
        throw new RuntimeException('Alias verification failed for "' . $name . '": remote content does not match the deployed content.');
    }
    if (!central_alias_has_category($verified, $categoryUuid)) {
        throw new RuntimeException('Alias verification failed for "' . $name . '": managed category is missing on the remote alias.');
    }
}

function alias_normalize_port_token(string $value): ?string
{
    $value = trim($value);
    if (!preg_match('/^(\d{1,5})(?::(\d{1,5}))?$/', $value, $matches)) {
        return null;
    }
    $first = (int) $matches[1];
    $last = isset($matches[2]) && $matches[2] !== '' ? (int) $matches[2] : null;
    if ($first < 1 || $first > 65535) {
        return null;
    }
    if ($last !== null && ($last < 1 || $last > 65535 || $last < $first)) {
        return null;
    }
    return $last === null ? (string) $first : $first . ':' . $last;
}

function alias_port_sources(): array
{
    $rows = db()->query("SELECT name, content, description FROM central_aliases WHERE type = 'port' ORDER BY name")->fetchAll();
    $result = [];
    foreach ($rows as $row) {
        $values = [];
        $valid = true;
        foreach (central_alias_lines((string) ($row['content'] ?? '')) as $line) {
            $normalized = alias_normalize_port_token($line);
            if ($normalized === null) {
                $valid = false;
                break;
            }
            $values[] = $normalized;
        }
        $name = trim((string) ($row['name'] ?? ''));
        if ($valid && $name !== '' && $values !== []) {
            $result[$name] = [
                'name' => $name,
                'values' => array_values(array_unique($values)),
                'description' => (string) ($row['description'] ?? ''),
            ];
        }
    }
    return $result;
}

function alias_resolve_port_lines(array $inputLines, array $selectedAliases, array $portSources, string $currentName): array
{
    $resolved = [];
    foreach ($inputLines as $line) {
        $normalized = alias_normalize_port_token($line);
        if ($normalized !== null) {
            $resolved[] = $normalized;
            continue;
        }
        if (isset($portSources[$line]) && strcasecmp($line, $currentName) !== 0) {
            array_push($resolved, ...$portSources[$line]['values']);
            continue;
        }
        throw new RuntimeException(
            'Invalid Port(s) content "' . $line . '". Enter a port (for example 443), a range (for example 8000:8100), or select an existing Port alias.'
        );
    }

    foreach ($selectedAliases as $aliasName) {
        $aliasName = trim((string) $aliasName);
        if ($aliasName === '' || strcasecmp($aliasName, $currentName) === 0) {
            continue;
        }
        if (!isset($portSources[$aliasName])) {
            throw new RuntimeException('Selected Port alias "' . $aliasName . '" is no longer available or contains invalid port values.');
        }
        array_push($resolved, ...$portSources[$aliasName]['values']);
    }

    $resolved = array_values(array_unique($resolved));
    sort($resolved, SORT_NATURAL | SORT_FLAG_CASE);
    return $resolved;
}

$managedCategoryName = managed_category_name();
$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$portSources = alias_port_sources();
$results = [];
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    try {
        require_configuration_unlocked(false);
        $name = trim((string) ($_POST['name'] ?? ''));
        $type = trim((string) ($_POST['type'] ?? 'host'));
        $lines = central_alias_lines((string) ($_POST['content'] ?? ''));
        $selectedPortAliases = is_array($_POST['port_aliases'] ?? null) ? $_POST['port_aliases'] : [];
        $description = trim((string) ($_POST['description'] ?? ''));
        $mode = (string) ($_POST['mode'] ?? 'create');
        $takeOverExisting = isset($_POST['take_over_existing']);
        $enabled = isset($_POST['enabled']) ? 1 : 0;
        $targetIds = distribution_target_ids($firewalls);

        if (!preg_match('/^[A-Za-z0-9_]+$/', $name)) {
            throw new RuntimeException('Alias name may contain only letters, numbers and underscores.');
        }
        if (mb_strlen($description) > 255) {
            throw new RuntimeException('Description may contain at most 255 characters.');
        }
        if ($type === 'port') {
            $lines = alias_resolve_port_lines($lines, $selectedPortAliases, $portSources, $name);
        }
        if (!$lines) {
            throw new RuntimeException('Enter at least one alias value.');
        }
        if (!$targetIds) {
            throw new RuntimeException('Select at least one firewall.');
        }
        if (!in_array($mode, ['create', 'replace', 'merge'], true)) {
            throw new RuntimeException('Invalid distribution mode.');
        }

        $content = implode("\n", $lines);
        $aliasId = central_alias_save_definition($name, $type, $content, $description, $enabled);

        $placeholders = implode(',', array_fill(0, count($targetIds), '?'));
        $statement = db()->prepare('SELECT * FROM firewalls WHERE id IN (' . $placeholders . ') ORDER BY name');
        $statement->execute($targetIds);

        foreach ($statement->fetchAll() as $firewall) {
            try {
                backup_before_change($firewall, 'alias-distribution');
                $categoryUuid = central_alias_category_uuid($firewall);
                if ($categoryUuid === null) {
                    throw new RuntimeException('Category ' . $managedCategoryName . ' is missing on this firewall. Create it under Firewall > Categories.');
                }

                $existing = central_alias_find($firewall, $name);
                $finalLines = $lines;
                $action = 'Created';

                if ($existing !== null) {
                    if ($mode === 'create') {
                        throw new RuntimeException('Alias already exists; create-only mode made no change.');
                    }
                    $alreadyManaged = central_alias_has_category($existing, $categoryUuid);
                    if (!$alreadyManaged && !$takeOverExisting) {
                        throw new RuntimeException(
                            'Existing alias is not in category ' . $managedCategoryName . ' and was protected. ' .
                            'Enable “Take over existing alias” to preserve its current categories and add ' . $managedCategoryName . '.'
                        );
                    }
                    if ($mode === 'merge') {
                        $finalLines = array_values(array_unique(array_merge(
                            central_alias_lines((string) ($existing['content'] ?? '')),
                            $lines
                        )));
                        sort($finalLines, SORT_NATURAL | SORT_FLAG_CASE);
                        $action = 'Merged';
                    } else {
                        $action = 'Replaced';
                    }

                    $payload = $existing;
                    unset($payload['uuid']);
                    $payload['enabled'] = (string) $enabled;
                    $payload['name'] = $name;
                    $payload['type'] = $type;
                    $payload['content'] = implode("\n", $finalLines);
                    $payload['description'] = $description;
                    $payload['categories'] = central_alias_merge_category($existing['categories'] ?? '', $categoryUuid);
                    if (!$alreadyManaged) {
                        $action .= ' and taken over';
                    }
                    $writeResponse = opn_request(
                        $firewall,
                        'firewall/alias/set_item/' . rawurlencode((string) $existing['uuid']),
                        'POST',
                        ['alias' => $payload],
                        25
                    );
                    alias_assert_api_success($writeResponse, 'update');
                } else {
                    $writeResponse = opn_request(
                        $firewall,
                        'firewall/alias/add_item',
                        'POST',
                        ['alias' => [
                            'enabled' => (string) $enabled,
                            'name' => $name,
                            'type' => $type,
                            'content' => implode("\n", $finalLines),
                            'description' => $description,
                            'categories' => $categoryUuid,
                        ]],
                        25
                    );
                    alias_assert_api_success($writeResponse, 'creation');
                }

                $reconfigureResponse = opn_request($firewall, 'firewall/alias/reconfigure', 'POST', [], 30);
                alias_assert_api_success($reconfigureResponse, 'reconfigure');
                alias_verify_remote_state($firewall, $name, $type, $finalLines, $categoryUuid);

                central_alias_target_status($aliasId, (int) $firewall['id'], 'synchronized', $action . ' and verified.');
                $results[] = ['ok' => true, 'name' => $firewall['name'], 'message' => $action . ' and verified.'];
            } catch (Throwable $exception) {
                central_alias_target_status($aliasId, (int) $firewall['id'], 'error', $exception->getMessage());
                $results[] = ['ok' => false, 'name' => $firewall['name'], 'message' => $exception->getMessage()];
            }
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.alias-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(280px,.8fr);gap:20px}.alias-form label{display:block;font-weight:700;margin:14px 0 6px}.alias-form input[type=text],.alias-form select,.alias-form textarea{width:100%;box-sizing:border-box}.alias-form textarea{min-height:180px;font-family:monospace}.targets,.results{display:grid;gap:8px}.target,.result{padding:10px;border-radius:8px;background:rgba(127,127,127,.08)}.result.good{border-left:4px solid #2aa84a}.result.bad{border-left:4px solid #d74747}.takeover-option{display:flex!important;align-items:flex-start;gap:9px;padding:10px;border:1px solid #d6b56a;background:#fff8e7;border-radius:3px}.takeover-option input{width:auto;margin:3px 0 0}.enabled-option{display:flex!important;align-items:center;gap:9px;margin:14px 0 6px!important}.enabled-option input{width:auto;margin:0}.mode-help{margin-top:6px;padding:8px 10px;border-radius:5px;background:rgba(127,127,127,.08)}.field-help{display:flex;justify-content:space-between;gap:12px;margin-top:5px}.deploy-status{display:none;align-items:center;gap:10px;margin-top:12px;padding:10px 12px;border-radius:6px;background:rgba(127,127,127,.08);font-weight:700}.deploy-status.active{display:flex}.deploy-spinner{width:16px;height:16px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:alias-spin .7s linear infinite}.port-alias-picker{display:none;margin-top:12px;padding:12px;border:1px solid rgba(127,127,127,.25);border-radius:7px;background:rgba(127,127,127,.04)}.port-alias-picker.active{display:block}.port-alias-picker select{min-height:150px}.port-alias-picker .picker-actions{display:flex;gap:8px;align-items:center;margin-top:8px}.port-alias-picker .picker-actions button{width:auto}.resolved-preview{margin-top:8px;padding:8px 10px;border-radius:5px;background:rgba(127,127,127,.08);font-family:monospace;white-space:pre-wrap}.resolved-preview:empty{display:none}@keyframes alias-spin{to{transform:rotate(360deg)}}@media(max-width:850px){.alias-grid{grid-template-columns:1fr}}
</style>
<div class="page-title"><div><h1><?= h(t('aliases.distribute')) ?></h1><p>Category <?= h($managedCategoryName) ?> protects centrally managed aliases.</p></div><a class="button secondary" href="/alias_overview.php">Overview</a></div>
<?php if ($error): ?><div class="alert error" id="alias-top-error"><?= h($error) ?></div><?php endif; ?>
<div class="alias-grid">
<section class="card"><h2>Alias</h2><form method="post" class="alias-form" id="alias-distribution-form"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<label>Name</label><input type="text" name="name" required pattern="[A-Za-z0-9_]+" value="<?= h((string)($_POST['name'] ?? '')) ?>" placeholder="Trusted_Admins">
<label><?= h(t('aliases.type')) ?></label><select name="type" id="alias-type"><?php foreach (['host'=>'Host(s)','network'=>'Network(s)','port'=>'Port(s)','url'=>'URL','urltable'=>'URL table','geoip'=>'GeoIP','networkgroup'=>'Network group','mac'=>'MAC','asn'=>'ASN'] as $value=>$label): ?><option value="<?= h($value) ?>" <?= (($_POST['type'] ?? 'host') === $value) ? 'selected' : '' ?>><?= h($label) ?></option><?php endforeach; ?></select>
<label><?= h(t('aliases.content')) ?></label><textarea name="content" id="alias-content" required placeholder="One value per line"><?= h((string)($_POST['content'] ?? '')) ?></textarea>
<div class="port-alias-picker" id="port-alias-picker">
    <strong>Add values from existing Port aliases</strong>
    <div class="field-help"><small class="muted">Select one or more aliases. opnSentral expands them to numeric ports/ranges before deployment.</small></div>
    <label for="port-alias-filter">Filter aliases</label><input type="text" id="port-alias-filter" placeholder="Search Port aliases…">
    <label for="port-alias-select">Available Port aliases</label>
    <select name="port_aliases[]" id="port-alias-select" multiple size="8">
        <?php foreach ($portSources as $source): ?>
            <?php if (strcasecmp((string)($_POST['name'] ?? ''), $source['name']) === 0) continue; ?>
            <option value="<?= h($source['name']) ?>" data-values="<?= h(implode("\n", $source['values'])) ?>"><?= h($source['name']) ?> → <?= h(implode(', ', $source['values'])) ?></option>
        <?php endforeach; ?>
    </select>
    <div class="picker-actions"><button type="button" class="secondary" id="add-port-alias-values">Add selected values to Content</button><small class="muted"><?= count($portSources) ?> compatible Port alias(es)</small></div>
    <div class="resolved-preview" id="port-resolved-preview"></div>
</div>
<label><?= h(t('aliases.description')) ?></label><input type="text" name="description" id="alias-description" maxlength="255" value="<?= h((string)($_POST['description'] ?? '')) ?>"><div class="field-help"><small class="muted">Optional. Maximum 255 characters.</small><small class="muted"><span id="alias-description-count">0</span>/255</small></div>
<label>Existing alias</label>
<select name="mode" id="alias-existing-mode"><option value="create" <?= (($_POST['mode'] ?? 'create') === 'create') ? 'selected' : '' ?>><?= h(t('aliases.create_only')) ?></option><option value="replace" <?= (($_POST['mode'] ?? '') === 'replace') ? 'selected' : '' ?>>Replace</option><option value="merge" <?= (($_POST['mode'] ?? '') === 'merge') ? 'selected' : '' ?>>Merge</option></select>
<div class="mode-help muted" id="alias-mode-help"></div>
<label class="takeover-option"><input type="checkbox" name="take_over_existing" value="1" <?= isset($_POST['take_over_existing']) ? 'checked' : '' ?>><span><strong>Take over existing alias</strong><br><span class="muted">Only applies when an alias with this name already exists but is not yet managed by opnSentral. Existing categories are preserved and <?= h($managedCategoryName) ?> is added before replace/merge is applied.</span></span></label>
<label class="enabled-option"><input type="checkbox" name="enabled" value="1" <?= !isset($_POST['enabled']) && $_SERVER['REQUEST_METHOD'] !== 'POST' || isset($_POST['enabled']) ? 'checked' : '' ?>><span>Enabled</span></label>
<fieldset class="distribution-targets"><legend><?= h(t('categories.targets')) ?></legend>
<?php $targetScope = (string)($_POST['target_scope'] ?? ($_GET['scope'] ?? 'one')); $requestedFirewallId = (int)($_POST['target_firewall_id'] ?? $_GET['firewall_id'] ?? 0); ?>
<label class="distribution-scope-option"><input type="radio" name="target_scope" value="one" <?= $targetScope === 'one' ? 'checked' : '' ?>><span><strong>One OPNsense</strong><small>Distribute only to the selected firewall.</small></span></label>
<label class="distribution-firewall-select">OPNsense<select name="target_firewall_id" id="alias-target-firewall"><option value="">Select firewall</option><?php foreach ($firewalls as $firewall): ?><option value="<?= (int)$firewall['id'] ?>" <?= $requestedFirewallId === (int)$firewall['id'] ? 'selected' : '' ?>><?= h((string)$firewall['name']) ?></option><?php endforeach; ?></select></label>
<label class="distribution-scope-option"><input type="radio" name="target_scope" value="all" <?= $targetScope === 'all' ? 'checked' : '' ?>><span><strong>All OPNsense firewalls</strong><small>Distribute to every currently managed firewall.</small></span></label>
</fieldset>
<div class="actions"><button type="submit" id="alias-distribute-button">Distribute</button><div class="deploy-status" id="alias-deploy-status" role="status" aria-live="polite"><span class="deploy-spinner" aria-hidden="true"></span><span id="alias-deploy-status-text">Deploying alias to OPNsense…</span></div></div>
</form></section>
<section class="card" id="alias-results"><h2>Results</h2><?php if (!$results): ?><div class="empty">No distribution performed yet.</div><?php else: ?><div class="results"><?php foreach ($results as $result): ?><div class="result <?= $result['ok'] ? 'good' : 'bad' ?>"><strong><?= h($result['name']) ?></strong><br><?= h($result['message']) ?></div><?php endforeach; ?></div><?php endif; ?></section>
</div>
<script>
const managedCategoryName = <?= json_encode($managedCategoryName, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;
document.querySelectorAll('input[name="target_scope"]').forEach(function(radio){radio.addEventListener('change',function(){const select=document.getElementById('alias-target-firewall');select.disabled=document.querySelector('input[name="target_scope"]:checked')?.value==='all';});});
document.querySelector('input[name="target_scope"]:checked')?.dispatchEvent(new Event('change'));

const descriptionInput=document.getElementById('alias-description');
const descriptionCount=document.getElementById('alias-description-count');
function updateDescriptionCount(){if(descriptionInput&&descriptionCount){descriptionCount.textContent=String(descriptionInput.value.length);}}
descriptionInput?.addEventListener('input',updateDescriptionCount);updateDescriptionCount();

const modeSelect=document.getElementById('alias-existing-mode');
const modeHelp=document.getElementById('alias-mode-help');
function updateModeHelp(){
    if(!modeSelect||!modeHelp)return;
    const mode=modeSelect.value;
    if(mode==='create') modeHelp.textContent='Create only: if the alias does not exist, it is created. If it already exists, no change is made.';
    else if(mode==='replace') modeHelp.textContent='Replace: if the alias exists, its content/type/description/enabled state are replaced with these values. If it does not exist, a new alias is created.';
    else modeHelp.textContent='Merge: if the alias exists, the submitted content is added to its existing content without duplicates. If it does not exist, a new alias is created from the submitted content.';
}
modeSelect?.addEventListener('change',updateModeHelp);updateModeHelp();

const aliasType=document.getElementById('alias-type');
const aliasContent=document.getElementById('alias-content');
const portPicker=document.getElementById('port-alias-picker');
const portSelect=document.getElementById('port-alias-select');
const portFilter=document.getElementById('port-alias-filter');
const portPreview=document.getElementById('port-resolved-preview');
function updatePortPicker(){portPicker?.classList.toggle('active',aliasType?.value==='port');}
aliasType?.addEventListener('change',updatePortPicker);updatePortPicker();
portFilter?.addEventListener('input',function(){const query=portFilter.value.trim().toLowerCase();Array.from(portSelect?.options||[]).forEach(function(option){option.hidden=query!==''&&!option.textContent.toLowerCase().includes(query);});});
function selectedPortValues(){const values=[];Array.from(portSelect?.selectedOptions||[]).forEach(function(option){String(option.dataset.values||'').split(/\r?\n/).forEach(function(value){value=value.trim();if(value&&!values.includes(value)){values.push(value);}});});return values;}
function updatePortPreview(){if(!portPreview)return;const values=selectedPortValues();portPreview.textContent=values.length?'Resolved selection: '+values.join(', '):'';}
portSelect?.addEventListener('change',updatePortPreview);updatePortPreview();
document.getElementById('add-port-alias-values')?.addEventListener('click',function(){const existing=String(aliasContent?.value||'').split(/\r?\n/).map(v=>v.trim()).filter(Boolean);selectedPortValues().forEach(function(value){if(!existing.includes(value)){existing.push(value);}});existing.sort(function(a,b){return a.localeCompare(b,undefined,{numeric:true,sensitivity:'base'});});if(aliasContent){aliasContent.value=existing.join('\n');aliasContent.dispatchEvent(new Event('input'));}});

function confirmAliasDistribution(){const mode=document.querySelector('select[name="mode"]')?.value||'create';const takeover=document.querySelector('input[name="take_over_existing"]')?.checked===true;let message='Distribute this alias using '+mode+' mode?';if(takeover){message+='\n\nExisting aliases not yet managed by '+managedCategoryName+' will keep their current categories, receive the '+managedCategoryName+' category, and then be '+(mode==='merge'?'merged':'replaced')+'.';}return confirm(message);}
const aliasForm=document.getElementById('alias-distribution-form');
const distributeButton=document.getElementById('alias-distribute-button');
const deployStatus=document.getElementById('alias-deploy-status');
const deployStatusText=document.getElementById('alias-deploy-status-text');
aliasForm?.addEventListener('submit',function(event){if(!aliasForm.checkValidity()){return;}if(!confirmAliasDistribution()){event.preventDefault();return;}if(distributeButton){distributeButton.disabled=true;distributeButton.textContent='Deploying…';}deployStatus?.classList.add('active');const scope=document.querySelector('input[name="target_scope"]:checked')?.value;const selected=document.querySelector('#alias-target-firewall option:checked')?.textContent?.trim();if(deployStatusText){deployStatusText.textContent=scope==='all'?'Deploying alias to all OPNsense firewalls…':'Deploying alias to '+(selected||'OPNsense')+'…';}});
<?php if ($_SERVER['REQUEST_METHOD'] === 'POST'): ?>
window.addEventListener('load',function(){const target=document.getElementById(<?= $error ? "'alias-top-error'" : "'alias-results'" ?>);target?.scrollIntoView({behavior:'smooth',block:'start'});});
<?php endif; ?>
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>