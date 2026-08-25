<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_login();

function dyn_bool(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    return in_array(strtolower(trim((string)$value)), ['1','true','yes','on','installed','running'], true);
}

function dyn_api_ok(array $response, string $operation): void
{
    if (isset($response['validations']) && is_array($response['validations']) && $response['validations'] !== []) {
        throw new RuntimeException($operation . ' failed validation: ' . json_encode($response['validations'], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
    }
    foreach (['result','status'] as $field) {
        if (!array_key_exists($field, $response)) continue;
        $value = strtolower(trim((string)$response[$field]));
        if (in_array($value, ['failed','failure','error','invalid','rejected','0','false'], true)) {
            throw new RuntimeException($operation . ' failed: ' . json_encode($response, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        }
    }
}

$firewallId = (int)($_GET['firewall_id'] ?? $_POST['firewall_id'] ?? 0);
$mode = (string)($_GET['mode'] ?? $_POST['mode'] ?? 'general');
$uuid = trim((string)($_GET['uuid'] ?? $_POST['uuid'] ?? ''));
if ($firewallId <= 0 || !in_array($mode, ['general','account'], true)) {
    throw new RuntimeException('Invalid Dynamic DNS edit target.');
}
$firewall = firewall_by_id($firewallId);
$error = '';
$success = '';
$form = [];

function dyn_load_general(array $firewall): array
{
    $settings = opn_request($firewall, 'dyndns/settings/get', 'GET', [], 25);
    $general = $settings['ddclient']['general'] ?? null;
    if (!is_array($general)) throw new RuntimeException('Unexpected Dynamic DNS settings response.');
    return $general;
}

function dyn_load_account(array $firewall, string $uuid): array
{
    if ($uuid === '') throw new RuntimeException('Dynamic DNS account UUID is missing.');
    $response = opn_request($firewall, 'dyndns/accounts/get_item/' . rawurlencode($uuid), 'GET', [], 25);
    $account = $response['account'] ?? null;
    if (!is_array($account)) throw new RuntimeException('Unexpected Dynamic DNS account response.');
    return $account;
}

try {
    $form = $mode === 'general' ? dyn_load_general($firewall) : dyn_load_account($firewall, $uuid);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        require_csrf();
        require_configuration_unlocked(false);
        $backup = backup_before_change($firewall, 'dyndns-' . $mode);

        if ($mode === 'general') {
            $payload = $form;
            $payload['enabled'] = isset($_POST['enabled']) ? '1' : '0';
            $payload['verbose'] = isset($_POST['verbose']) ? '1' : '0';
            $payload['allowipv6'] = isset($_POST['allowipv6']) ? '1' : '0';
            $payload['backend'] = in_array((string)($_POST['backend'] ?? ''), ['ddclient','opnsense'], true) ? (string)$_POST['backend'] : 'opnsense';
            $delay = filter_var($_POST['daemon_delay'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1,'max_range'=>86400]]);
            if ($delay === false) throw new RuntimeException('Daemon delay must be between 1 and 86400 seconds.');
            $payload['daemon_delay'] = (string)$delay;

            $response = opn_request($firewall, 'dyndns/settings/set', 'POST', ['ddclient'=>['general'=>$payload]], 30);
            dyn_api_ok($response, 'Dynamic DNS settings update');
            $verify = dyn_load_general($firewall);
            foreach (['enabled','verbose','allowipv6','backend','daemon_delay'] as $field) {
                if ((string)($verify[$field] ?? '') !== (string)($payload[$field] ?? '')) {
                    throw new RuntimeException('Dynamic DNS settings verification failed for ' . $field . '.');
                }
            }
            $form = $verify;
        } else {
            $payload = $form;
            unset($payload['current_ip'], $payload['current_mtime']);
            $payload['enabled'] = isset($_POST['enabled']) ? '1' : '0';
            $payload['description'] = trim((string)($_POST['description'] ?? ''));
            $payload['service'] = trim((string)($_POST['service'] ?? ''));
            $payload['username'] = trim((string)($_POST['username'] ?? ''));
            $payload['hostnames'] = trim((string)($_POST['hostnames'] ?? ''));
            $payload['resourceId'] = trim((string)($_POST['resourceId'] ?? ''));
            $payload['zone'] = trim((string)($_POST['zone'] ?? ''));
            $payload['checkip'] = trim((string)($_POST['checkip'] ?? 'web_dyndns'));
            $payload['interface'] = trim((string)($_POST['interface'] ?? ''));
            $payload['protocol'] = trim((string)($_POST['protocol'] ?? ''));
            $payload['server'] = trim((string)($_POST['server'] ?? ''));
            $payload['wildcard'] = isset($_POST['wildcard']) ? '1' : '0';
            $payload['force_ssl'] = isset($_POST['force_ssl']) ? '1' : '0';
            $timeout = filter_var($_POST['checkip_timeout'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>10,'max_range'=>60]]);
            if ($timeout === false) throw new RuntimeException('Check IP timeout must be between 10 and 60 seconds.');
            $ttl = filter_var($_POST['ttl'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1,'max_range'=>604800]]);
            if ($ttl === false) throw new RuntimeException('TTL must be between 1 and 604800 seconds.');
            $payload['checkip_timeout'] = (string)$timeout;
            $payload['ttl'] = (string)$ttl;
            $password = (string)($_POST['password'] ?? '');
            if ($password !== '') $payload['password'] = $password; else unset($payload['password']);

            if ($payload['service'] === '' || $payload['hostnames'] === '') throw new RuntimeException('Service and hostname(s) are required.');

            $response = opn_request($firewall, 'dyndns/accounts/set_item/' . rawurlencode($uuid), 'POST', ['account'=>$payload], 30);
            dyn_api_ok($response, 'Dynamic DNS account update');
            $verify = dyn_load_account($firewall, $uuid);
            foreach (['enabled','description','service','username','hostnames','resourceId','zone','checkip','interface','protocol','server','wildcard','force_ssl','checkip_timeout','ttl'] as $field) {
                if ((string)($verify[$field] ?? '') !== (string)($payload[$field] ?? '')) {
                    throw new RuntimeException('Dynamic DNS account verification failed for ' . $field . '.');
                }
            }
            $form = $verify;
        }

        $reconfigure = opn_request($firewall, 'dyndns/service/reconfigure', 'POST', [], 45);
        dyn_api_ok($reconfigure, 'Dynamic DNS reconfigure');
        $success = 'Saved, verified and reconfigured. Backup: ' . (string)($backup['filename'] ?? 'created') . '.';
    }
} catch (Throwable $exception) {
    $error = $exception->getMessage();
}

require __DIR__ . '/inc/header.php';
?>
<style>
.dyn-edit{max-width:900px}.dyn-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.dyn-edit label{display:block;font-weight:700;margin:12px 0 6px}.dyn-edit input,.dyn-edit select{width:100%;box-sizing:border-box}.dyn-checks{display:flex;gap:18px;flex-wrap:wrap;margin:16px 0}.dyn-checks label{display:flex;align-items:center;gap:7px;margin:0}.dyn-checks input{width:auto}.dyn-actions{display:flex;gap:10px;margin-top:18px}@media(max-width:760px){.dyn-grid{grid-template-columns:1fr}}
</style>
<div class="page-title"><div><h1>Services → DynDNS → Edit</h1><p><?= h((string)$firewall['name']) ?></p></div></div>
<?php if($error!==''): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>
<?php if($success!==''): ?><div class="alert goodbox"><?= h($success) ?></div><?php endif; ?>
<div class="card dyn-edit">
<form method="post">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="firewall_id" value="<?= $firewallId ?>"><input type="hidden" name="mode" value="<?= h($mode) ?>"><input type="hidden" name="uuid" value="<?= h($uuid) ?>">
<?php if($mode==='general'): ?>
<div class="dyn-grid"><div><label>Backend</label><select name="backend"><option value="opnsense" <?= (($form['backend']??'')==='opnsense')?'selected':'' ?>>native</option><option value="ddclient" <?= (($form['backend']??'')==='ddclient')?'selected':'' ?>>ddclient</option></select></div><div><label>Daemon delay (seconds)</label><input type="number" min="1" max="86400" name="daemon_delay" value="<?= h((string)($form['daemon_delay']??'300')) ?>"></div></div>
<div class="dyn-checks"><label><input type="checkbox" name="enabled" <?= dyn_bool($form['enabled']??false)?'checked':'' ?>> Enabled</label><label><input type="checkbox" name="verbose" <?= dyn_bool($form['verbose']??false)?'checked':'' ?>> Verbose</label><label><input type="checkbox" name="allowipv6" <?= dyn_bool($form['allowipv6']??false)?'checked':'' ?>> Allow IPv6</label></div>
<?php else: ?>
<div class="dyn-grid"><div><label>Description</label><input name="description" value="<?= h((string)($form['description']??'')) ?>"></div><div><label>Service</label><input name="service" required value="<?= h((string)($form['service']??'')) ?>"></div><div><label>Hostname(s)</label><input name="hostnames" required value="<?= h((string)($form['hostnames']??'')) ?>"></div><div><label>Username</label><input name="username" value="<?= h((string)($form['username']??'')) ?>"></div><div><label>New password</label><input type="password" name="password" autocomplete="new-password" placeholder="Leave blank to keep current"></div><div><label>Interface</label><input name="interface" value="<?= h((string)($form['interface']??'')) ?>"></div><div><label>Check IP method</label><input name="checkip" value="<?= h((string)($form['checkip']??'web_dyndns')) ?>"></div><div><label>Check IP timeout</label><input type="number" min="10" max="60" name="checkip_timeout" value="<?= h((string)($form['checkip_timeout']??'10')) ?>"></div><div><label>TTL</label><input type="number" min="1" max="604800" name="ttl" value="<?= h((string)($form['ttl']??'300')) ?>"></div><div><label>Resource ID</label><input name="resourceId" value="<?= h((string)($form['resourceId']??'')) ?>"></div><div><label>Zone</label><input name="zone" value="<?= h((string)($form['zone']??'')) ?>"></div><div><label>Custom protocol</label><input name="protocol" value="<?= h((string)($form['protocol']??'')) ?>"></div><div><label>Custom server</label><input name="server" value="<?= h((string)($form['server']??'')) ?>"></div></div>
<div class="dyn-checks"><label><input type="checkbox" name="enabled" <?= dyn_bool($form['enabled']??false)?'checked':'' ?>> Enabled</label><label><input type="checkbox" name="wildcard" <?= dyn_bool($form['wildcard']??false)?'checked':'' ?>> Wildcard</label><label><input type="checkbox" name="force_ssl" <?= dyn_bool($form['force_ssl']??true)?'checked':'' ?>> Force SSL</label></div>
<?php endif; ?>
<div class="alert warningbox"><strong>Safe write:</strong> opnSentral creates a pre-change backup, writes only this firewall, reads the settings back for verification, and only then reconfigures Dynamic DNS.</div>
<div class="dyn-actions"><button type="submit">Save and apply</button><a class="button secondary" href="/dyndns.php">Back to overview</a></div>
</form></div>
<?php require __DIR__ . '/inc/footer.php'; ?>
