<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/ssh_access.php';
require_login();

const API_PROTECTION_ALIAS = 'opnSentral_API';
const API_PROTECTION_DESC = 'Managed by opnSentral - API Access Protection';

function ap_request(array $fw, string $path, string $method = 'GET', ?array $data = null): array {
    return opn_request($fw, $path, $method, $data, 15);
}
function ap_find(array $fw): array {
    $alias = central_alias_find($fw, API_PROTECTION_ALIAS);
    $res = ap_request($fw, 'firewall/filter/search_rule?current=1&rowCount=500&searchPhrase=' . rawurlencode(API_PROTECTION_DESC));
    if (!isset($res['rows']) || !is_array($res['rows'])) throw new RuntimeException('Rule inventory unavailable');
    $rules = array_values(array_filter($res['rows'], static fn($r) => ($r['description'] ?? '') === API_PROTECTION_DESC));
    if (count($rules) > 1) throw new RuntimeException('Duplicate managed rules');
    $rule = null;
    if ($rules) {
        $uuid = (string)$rules[0]['uuid'];
        $r = ap_request($fw, 'firewall/filter/get_rule/' . rawurlencode($uuid));
        $rule = $r['rule'] ?? throw new RuntimeException('Rule details unavailable');
        $rule['uuid'] = $uuid;
    }
    return [$alias, $rule];
}
function ap_value(array $r, string $key): string {
    return ssh_access_single_value($r[$key] ?? '');
}
function ap_port(array $fw): int {
    return (int)(parse_url($fw['base_url'], PHP_URL_PORT) ?: 443);
}
function ap_assert_rule(array $r, array $fw): void {
    foreach (['description'=>API_PROTECTION_DESC,'action'=>'block','quick'=>'1','direction'=>'in','protocol'=>'tcp','source_net'=>API_PROTECTION_ALIAS,'source_not'=>'1','destination_net'=>'(self)','destination_not'=>'0','destination_port'=>(string)ap_port($fw),'ipprotocol'=>'inet46'] as $k=>$v) {
        if (ap_value($r,$k) !== $v) throw new RuntimeException('Managed rule differs: '.$k);
    }
    if (ssh_access_selected_values($r['interface'] ?? '') !== ['wan']) throw new RuntimeException('Managed rule is not WAN-only');
}
function ap_saved(array $response): void {
    if (($response['result'] ?? '') !== 'saved') throw new RuntimeException('OPNsense did not confirm save');
}
function ap_ok(array $response): void {
    if (!in_array(strtolower((string)($response['status'] ?? '')), ['ok','done'], true)) throw new RuntimeException('OPNsense did not confirm operation');
}
function ap_prepare(array $fw, string $fqdn): void {
    if (!filter_var($fqdn,FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME) || !str_contains($fqdn,'.') || filter_var($fqdn,FILTER_VALIDATE_IP)) throw new RuntimeException('Enter a valid source FQDN');
    if (parse_url($fw['base_url'],PHP_URL_SCHEME) !== 'https') throw new RuntimeException('HTTPS required');
    [$alias,$rule] = ap_find($fw);
    if ($rule !== null) throw new RuntimeException('Rule already prepared; no overwrite');
    if ($alias !== null) throw new RuntimeException('Alias already exists; no overwrite');
    $category = ssh_access_category_uuid($fw,true);
    ap_saved(ap_request($fw,'firewall/alias/add_item','POST',['alias'=>['name'=>API_PROTECTION_ALIAS,'enabled'=>'1','type'=>'host','content'=>$fqdn,'description'=>API_PROTECTION_DESC,'categories'=>$category]]));
    ap_ok(ap_request($fw,'firewall/alias/reconfigure','POST',[]));
    ap_saved(ap_request($fw,'firewall/filter/add_rule','POST',['rule'=>[
        'enabled'=>'0','action'=>'block','quick'=>'1','interface'=>'wan','direction'=>'in','ipprotocol'=>'inet46','protocol'=>'tcp','source_net'=>API_PROTECTION_ALIAS,'source_not'=>'1','destination_net'=>'(self)','destination_not'=>'0','destination_port'=>(string)ap_port($fw),'log'=>'1','description'=>API_PROTECTION_DESC,'categories'=>$category
    ]]));
    // Disabled rule is staged only; never reload filter rules during preparation.
    [$a,$r]=ap_find($fw);
    if (!$a || !$r || ap_value($r,'enabled') !== '0') throw new RuntimeException('Preparation read-back failed');
    ap_assert_rule($r,$fw);
}
function ap_toggle(array $fw,bool $enable): void {
    [$alias,$rule]=ap_find($fw);
    if (!$alias || !$rule) throw new RuntimeException('Prepare first');
    ap_assert_rule($rule,$fw);
    if (ap_value($alias,'description') !== API_PROTECTION_DESC || ap_value($alias,'enabled') !== '1' || ap_value($alias,'type') !== 'host') throw new RuntimeException('Alias differs from managed configuration');
    // No safe automatic activation until rule order and on-firewall rollback can
    // be verified for this firmware. Never fall back to an unprotected apply.
    if ($enable) throw new RuntimeException('Activation blocked: rule priority and firmware-specific rollback have not yet been validated.');
    if (ap_value($rule,'enabled') === '0') return;
    // Disabling a block rule relaxes access; still require an explicit savepoint.
    $sp=ap_request($fw,'firewall/filter/savepoint','POST',[]);
    ap_ok($sp);
    $revision=(string)($sp['revision'] ?? '');
    if (!preg_match('/^\d+(?:\.\d+)?$/D',$revision)) throw new RuntimeException('No valid rollback revision');
    ap_saved(ap_request($fw,'firewall/filter/set_rule/'.rawurlencode($rule['uuid']),'POST',['rule'=>['enabled'=>'0']]));
    ap_ok(ap_request($fw,'firewall/filter/apply/'.rawurlencode($revision),'POST',[]));
    [, $after]=ap_find($fw);
    if (!$after || ap_value($after,'enabled') !== '0') throw new RuntimeException('Read-back failed; rollback not cancelled');
    ap_ok(ap_request($fw,'firewall/filter/cancelRollback/'.rawurlencode($revision),'POST',[]));
}
$error='';$message='';
if ($_SERVER['REQUEST_METHOD']==='POST') {
    require_csrf();
    try {
        if (!configuration_unlocked()) throw new RuntimeException('Configuration locked');
        $fw=firewall_by_id((int)($_POST['id']??0));
        $action=(string)($_POST['action']??'');
        if ($action==='prepare') ap_prepare($fw,trim((string)($_POST['fqdn']??'')));
        elseif ($action==='activate'||$action==='deactivate') ap_toggle($fw,$action==='activate');
        else throw new RuntimeException('Invalid action');
        $message='Configuration read-back succeeded';
    } catch(Throwable $e) {$error=$e->getMessage();}
}
$firewalls=db()->query('SELECT id,name,base_url FROM firewalls ORDER BY name')->fetchAll();
require __DIR__.'/inc/header.php';
?>
<div class="page-title"><h1>API Access Protection (preview)</h1><p>WAN HTTPS management source restriction. Configuration state is not proof of effective traffic filtering.</p></div>
<?php if($error!==''):?><div class="alert error"><?=h($error)?></div><?php endif;?>
<?php if($message!==''):?><div class="alert goodbox"><?=h($message)?></div><?php endif;?>
<div class="alert warningbox">Preview: activation is deliberately blocked pending verification of rule priority and firmware-specific rollback. Preparing creates a disabled WAN block rule and a source alias; it does not apply the filter rules.</div>
<table><thead><tr><th>Firewall</th><th>Alias / FQDN</th><th>Rule configuration</th><th>Actions</th></tr></thead><tbody>
<?php foreach($firewalls as $row): $alias=$rule=null;$status='Unknown';$detail='';
try {[$alias,$rule]=ap_find(firewall_by_id((int)$row['id']));$status=$alias||$rule?'Incomplete':'Not configured';if($alias&&$rule){ap_assert_rule($rule,$row);$status=ap_value($rule,'enabled')==='1'?'Enabled (effectiveness unverified)':'Prepared / disabled';}}catch(Throwable $e){$status='Unknown / conflict';$detail=$e->getMessage();}
?>
<tr><td><?=h($row['name'])?></td><td><?=h($alias?implode(', ',ssh_access_selected_values($alias['content']??'')):'—')?></td><td><?=h($status)?> <?=h($detail)?></td><td>
<form method="post"><input type="hidden" name="csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="id" value="<?=(int)$row['id']?>">
<?php if($status==='Not configured'):?><input name="fqdn" required placeholder="Source FQDN"><button name="action" value="prepare" <?=configuration_unlocked()?'':'disabled'?>>Prepare</button><?php endif;?>
<?php if($status==='Prepared / disabled'):?><button type="button" disabled title="Pending rollback and priority validation">Activate</button><?php endif;?>
<?php if($status==='Enabled (effectiveness unverified)'):?><button name="action" value="deactivate" <?=configuration_unlocked()?'':'disabled'?>>Deactivate</button><?php endif;?>
</form></td></tr>
<?php endforeach;?>
</tbody></table>
<?php require __DIR__.'/inc/footer.php'; ?>
