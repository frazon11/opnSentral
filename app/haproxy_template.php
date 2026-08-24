<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/haproxy_reverse_proxy.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$error = '';
$pluginStatus = null;
$preview = null;
$preflight = null;
$deployment = null;

$defaults = [
    'template' => 'guacamole',
    'firewall_id' => '',
    'public_hostname' => '',
    'wan_interface' => 'wan',
    'bind_address' => '*',
    'frontend_port' => '443',
    'backend_ip' => '',
    'backend_port' => '8348',
    'backend_protocol' => 'http',
    'certificate' => '',
    'healthcheck' => '1',
    'backend_verify_tls' => '1',
];
$form = array_merge($defaults, array_map(static fn($v) => is_string($v) ? trim($v) : $v, $_POST));

function rp_page_validate(array $form): void
{
    if (!in_array((string) $form['template'], ['generic','guacamole','synology'], true)) {
        throw new RuntimeException('Unknown reverse proxy template.');
    }
    $hostname = (string) $form['public_hostname'];
    if ($hostname === '' || strlen($hostname) > 253 || filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        throw new RuntimeException('Enter a valid public hostname.');
    }
    if (filter_var((string) $form['backend_ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        throw new RuntimeException('Backend IP must be a valid IPv4 address.');
    }
    foreach (['frontend_port','backend_port'] as $field) {
        if (filter_var($form[$field] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1,'max_range'=>65535]]) === false) {
            throw new RuntimeException($field . ' must be between 1 and 65535.');
        }
    }
    if (!in_array((string) $form['backend_protocol'], ['http','https'], true)) {
        throw new RuntimeException('Backend protocol must be HTTP or HTTPS.');
    }
    if (!preg_match('/^[A-Za-z0-9_.:-]+$/', (string) $form['wan_interface'])) {
        throw new RuntimeException('WAN interface contains unsupported characters.');
    }
    if (!preg_match('/^(\*|[A-Za-z0-9_.:-]+)$/', (string) $form['bind_address'])) {
        throw new RuntimeException('Bind address is invalid. Use *, an IP address, or a resolvable name.');
    }
}

function rp_page_preview(array $form): array
{
    $slug = strtolower(trim((string) preg_replace('/[^a-z0-9]+/i', '_', (string) $form['public_hostname']), '_'));
    $bindSlug = strtolower(trim((string) preg_replace('/[^a-z0-9]+/i', '_', (string) $form['bind_address']), '_')) ?: 'any';
    $prefix = 'opnsentral_' . $slug;
    return [
        'required_plugin' => 'os-haproxy',
        'target' => [
            'hostname' => $form['public_hostname'],
            'frontend_bind' => $form['bind_address'] . ':' . (int) $form['frontend_port'],
            'wan_interface' => $form['wan_interface'],
            'backend' => $form['backend_protocol'] . '://' . $form['backend_ip'] . ':' . (int) $form['backend_port'],
        ],
        'managed_objects' => [
            'server' => $prefix . '_server',
            'backend' => $prefix . '_backend',
            'acl' => $prefix . '_host',
            'action' => $prefix . '_use_backend',
            'shared_frontend' => 'opnsentral_https_' . $bindSlug . '_' . (int) $form['frontend_port'],
        ],
        'safety' => [
            'pre_change_backup' => true,
            'plugin_required' => true,
            'bind_conflict_check' => true,
            'idempotent_upsert' => true,
            'configtest_before_reconfigure' => true,
            'firewall_rule_automation' => false,
        ],
        'notes' => [
            'The HTTPS frontend is shared per bind address/port, so multiple hostnames can use the same TCP 443 listener.',
            'No DNAT rule is created; HAProxy itself listens on the firewall.',
            'WAN firewall rule creation is not automated in this testing build.',
        ],
    ];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    try {
        rp_page_validate($form);
        $firewallId = filter_var($form['firewall_id'] ?? null, FILTER_VALIDATE_INT);
        if ($firewallId === false) throw new RuntimeException('Select a target firewall.');
        $selectedFirewall = firewall_by_id((int) $firewallId);
        $pluginStatus = rp_require_plugin($selectedFirewall);
        $preview = rp_page_preview($form);

        $operation = (string) ($_POST['operation'] ?? 'preview');
        if ($operation === 'preflight') {
            rp_validate_certificate($selectedFirewall, (string) $form['certificate']);
            $frontendName = (string) $preview['managed_objects']['shared_frontend'];
            $bind = (string) $preview['target']['frontend_bind'];
            rp_assert_bind_available($selectedFirewall, $frontendName, $bind);
            $preflight = [
                'firewall' => (string) $selectedFirewall['name'],
                'plugin' => $pluginStatus,
                'service_status' => opn_request($selectedFirewall, 'haproxy/service/status', 'GET', [], 15),
                'existing_server' => rp_find_exact($selectedFirewall, 'server', (string) $preview['managed_objects']['server']),
                'existing_backend' => rp_find_exact($selectedFirewall, 'backend', (string) $preview['managed_objects']['backend']),
                'existing_acl' => rp_find_exact($selectedFirewall, 'acl', (string) $preview['managed_objects']['acl']),
                'existing_action' => rp_find_exact($selectedFirewall, 'action', (string) $preview['managed_objects']['action']),
                'existing_frontend' => rp_find_exact($selectedFirewall, 'frontend', $frontendName),
            ];
        } elseif ($operation === 'deploy') {
            require_configuration_unlocked(false);
            if (($_POST['confirm_deploy'] ?? '') !== '1') throw new RuntimeException('Deployment confirmation is required.');
            $deployment = rp_deploy($selectedFirewall, $form);
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.rp-grid{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(320px,.95fr);gap:20px}.rp-form label{display:block;font-weight:700;margin:13px 0 6px}.rp-form input,.rp-form select{width:100%;box-sizing:border-box}.rp-two{display:grid;grid-template-columns:1fr 1fr;gap:12px}.rp-options{display:flex;gap:16px;flex-wrap:wrap;margin-top:14px}.rp-option{display:flex!important;align-items:center;gap:8px;margin:0!important}.rp-option input{width:auto}.rp-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.rp-actions button{width:auto}.rp-raw{max-height:430px;overflow:auto;background:rgba(127,127,127,.08);padding:10px;border-radius:7px;font-family:monospace;font-size:.9em;white-space:pre-wrap}.rp-note{padding:10px 12px;border-radius:7px;background:rgba(127,127,127,.08);margin:10px 0}.rp-danger{border-left:4px solid #d74747}.rp-good{border-left:4px solid #2aa84a}@media(max-width:900px){.rp-grid,.rp-two{grid-template-columns:1fr}}
</style>
<div class="page-title"><div><h1>HAProxy Reverse Proxy Template (testing)</h1><p>Preview, preflight and deploy an opnSentral-managed HTTPS reverse proxy.</p></div></div>

<div class="alert warningbox"><strong>Requirement:</strong> <code>os-haproxy</code> must be installed on the selected firewall. Deployment also requires Configuration unlocked.</div>
<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>
<?php if ($pluginStatus): ?><div class="alert goodbox"><strong>HAProxy plugin detected.</strong> <code>os-haproxy</code><?= !empty($pluginStatus['version']) ? ' ' . h((string)$pluginStatus['version']) : '' ?>.</div><?php endif; ?>
<?php if ($deployment): ?><div class="alert goodbox"><strong>Deployment completed.</strong> HAProxy passed configtest and was reconfigured. Backup: <code><?= h((string)$deployment['backup']) ?></code>.</div><?php endif; ?>

<div class="rp-grid">
<section class="card">
<h2>Template parameters</h2>
<form method="post" class="rp-form" id="rp-form">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<input type="hidden" name="confirm_deploy" id="confirm_deploy" value="0">

<label for="template">Template</label>
<select id="template" name="template">
<option value="guacamole" <?= $form['template']==='guacamole'?'selected':'' ?>>Guacamole</option>
<option value="synology" <?= $form['template']==='synology'?'selected':'' ?>>Synology DSM</option>
<option value="generic" <?= $form['template']==='generic'?'selected':'' ?>>Generic HTTPS reverse proxy</option>
</select>

<label for="firewall_id">Target firewall</label>
<select id="firewall_id" name="firewall_id" required><option value="">Select firewall…</option><?php foreach($firewalls as $fw): ?><option value="<?= (int)$fw['id'] ?>" <?= (string)$form['firewall_id']===(string)$fw['id']?'selected':'' ?>><?= h((string)$fw['name']) ?></option><?php endforeach; ?></select>

<label for="public_hostname">Public hostname</label>
<input id="public_hostname" name="public_hostname" required value="<?= h((string)$form['public_hostname']) ?>" placeholder="guac.example.com">

<div class="rp-two">
<div><label for="wan_interface">WAN interface</label><input id="wan_interface" name="wan_interface" required value="<?= h((string)$form['wan_interface']) ?>" placeholder="wan"></div>
<div><label for="bind_address">HAProxy bind address</label><input id="bind_address" name="bind_address" required value="<?= h((string)$form['bind_address']) ?>" placeholder="*"></div>
</div>

<div class="rp-two">
<div><label for="frontend_port">Frontend HTTPS port</label><input id="frontend_port" type="number" min="1" max="65535" name="frontend_port" required value="<?= h((string)$form['frontend_port']) ?>"></div>
<div><label for="certificate">Certificate reference (refid)</label><input id="certificate" name="certificate" required value="<?= h((string)$form['certificate']) ?>" placeholder="OPNsense certificate refid"></div>
</div>

<div class="rp-two">
<div><label for="backend_ip">Backend IPv4</label><input id="backend_ip" name="backend_ip" required value="<?= h((string)$form['backend_ip']) ?>" placeholder="192.168.1.150"></div>
<div><label for="backend_port">Backend port</label><input id="backend_port" type="number" min="1" max="65535" name="backend_port" required value="<?= h((string)$form['backend_port']) ?>"></div>
</div>

<label for="backend_protocol">Backend protocol</label>
<select id="backend_protocol" name="backend_protocol"><option value="http" <?= $form['backend_protocol']==='http'?'selected':'' ?>>HTTP</option><option value="https" <?= $form['backend_protocol']==='https'?'selected':'' ?>>HTTPS</option></select>

<div class="rp-options">
<input type="hidden" name="healthcheck" value="0"><label class="rp-option"><input type="checkbox" name="healthcheck" value="1" <?= !empty($form['healthcheck'])?'checked':'' ?>> Health check</label>
<input type="hidden" name="backend_verify_tls" value="0"><label class="rp-option"><input type="checkbox" name="backend_verify_tls" value="1" <?= !empty($form['backend_verify_tls'])?'checked':'' ?>> Verify backend TLS certificate</label>
</div>

<div class="rp-actions">
<button type="submit" name="operation" value="preview">Preview</button>
<button type="submit" name="operation" value="preflight" class="secondary">Preflight</button>
<button type="submit" name="operation" value="deploy" id="deploy-button">Deploy (testing)</button>
</div>
</form>
<div class="rp-note">Deployment sequence: plugin check → certificate check → pre-change backup → bind conflict check → idempotent HAProxy upsert → enable HAProxy → configtest → reconfigure.</div>
</section>

<section class="card">
<h2>Result</h2>
<?php if ($deployment): ?>
<div class="rp-note rp-good"><strong>Applied to <?= h((string)($deployment['bind'] ?? '')) ?></strong></div>
<div class="rp-raw"><?= h(json_encode($deployment, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)) ?></div>
<?php elseif ($preflight): ?>
<div class="rp-note rp-good"><strong>Preflight passed.</strong> Plugin, certificate and bind checks succeeded.</div>
<div class="rp-raw"><?= h(json_encode($preflight, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)) ?></div>
<?php elseif ($preview): ?>
<div class="rp-raw"><?= h(json_encode($preview, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)) ?></div>
<?php else: ?><p>Enter the parameters and run Preview or Preflight.</p><?php endif; ?>

<div class="rp-note rp-danger"><strong>Still manual in this testing build:</strong> the WAN firewall pass rule for TCP/<?= h((string)$form['frontend_port']) ?>. No DNAT is required.</div>
</section>
</div>
<script>
(function(){
 const form=document.getElementById('rp-form'), deploy=document.getElementById('deploy-button'), confirmField=document.getElementById('confirm_deploy');
 const template=document.getElementById('template'), port=document.getElementById('backend_port'), protocol=document.getElementById('backend_protocol');
 let portTouched=false;
 port.addEventListener('input',()=>portTouched=true);
 template.addEventListener('change',()=>{
   if(!portTouched){ if(template.value==='guacamole'){port.value='8348';protocol.value='http';} if(template.value==='synology'){port.value='5001';protocol.value='https';} }
 });
 deploy.addEventListener('click',function(event){
   if(!confirm('Deploy this HAProxy reverse proxy to the selected firewall?\n\nA pre-change configuration backup will be created first.')){event.preventDefault();return;}
   confirmField.value='1';
 });
 form.addEventListener('submit',function(event){if(event.submitter!==deploy)confirmField.value='0';});
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
