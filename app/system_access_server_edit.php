<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/system_access_management.php';
require_login();

$firewall=firewall_by_id((int)($_GET['firewall_id']??0));
$state=access_management_state($firewall);
if(!$state['writable']) throw new RuntimeException('System Access write API is unavailable on this firewall.');
$index=isset($_GET['index'])?(int)$_GET['index']:null;
$server=null;
if($index!==null){
    foreach($state['servers'] as $candidate){
        if(is_array($candidate) && empty($candidate['builtin']) && (int)($candidate['index']??-999)===$index){$server=$candidate;break;}
    }
    if(!is_array($server)) throw new RuntimeException('Authentication server not found.');
}
$s=$server??[];
$type=(string)($s['type']??'totp');

require __DIR__ . '/inc/header.php';
?>
<style>
.server-form{display:grid;grid-template-columns:repeat(2,minmax(260px,1fr));gap:12px}.server-form label{display:grid;gap:5px}.server-form .wide{grid-column:1/-1}.server-type-section{display:contents}.hidden-section{display:none}
</style>
<div class="page-title"><div><h1><?= $server?'Edit':'Add' ?> authentication server</h1><p><?= h((string)$firewall['name']) ?></p></div><a class="button secondary" href="/system_access_servers.php">Back</a></div>
<div class="card management-card">
<form method="post" action="/system_access_server_action.php" class="server-form" id="server-form">
  <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
  <input type="hidden" name="action" value="save">
  <input type="hidden" name="firewall_id" value="<?= (int)$firewall['id'] ?>">
  <input type="hidden" name="index" value="<?= $server!==null?(int)$s['index']:'' ?>">
  <label>Name<input name="name" required maxlength="128" value="<?= h((string)($s['name']??'')) ?>"></label>
  <label>Type<select name="type" id="server-type">
    <?php foreach(['totp'=>'Local + TOTP','ldap'=>'LDAP','ldap-totp'=>'LDAP + TOTP','radius'=>'RADIUS'] as $value=>$label): ?>
      <option value="<?= h($value) ?>" <?= $type===$value?'selected':'' ?>><?= h($label) ?></option>
    <?php endforeach; ?>
  </select></label>

  <div class="server-type-section type-totp type-ldap-totp">
    <label>Token length<select name="otpLength"><option value="">Default (6)</option><option value="6" <?= (string)($s['otpLength']??'')==='6'?'selected':'' ?>>6</option><option value="8" <?= (string)($s['otpLength']??'')==='8'?'selected':'' ?>>8</option></select></label>
    <label>Time window (seconds)<input type="number" min="1" name="timeWindow" value="<?= h((string)($s['timeWindow']??'')) ?>" placeholder="30"></label>
    <label>Grace period (seconds)<input type="number" min="0" name="graceperiod" value="<?= h((string)($s['graceperiod']??'')) ?>" placeholder="10"></label>
    <label><span>Reverse token order</span><select name="passwordFirst"><option value="0">No</option><option value="1" <?= !empty($s['passwordFirst'])?'selected':'' ?>>Yes — token after password</option></select></label>
  </div>

  <div class="server-type-section type-ldap type-ldap-totp">
    <label>LDAP host<input name="host" value="<?= h((string)($s['host']??'')) ?>"></label>
    <label>LDAP port<input type="number" min="1" max="65535" name="ldap_port" value="<?= h((string)($s['ldap_port']??'')) ?>"></label>
    <label>Transport<select name="ldap_urltype"><?php foreach(['TCP - Standard'=>'Standard','SSL - Encrypted'=>'SSL/TLS','STARTTLS'=>'STARTTLS'] as $v=>$l): ?><option value="<?= h($v) ?>" <?= (string)($s['ldap_urltype']??'')===$v?'selected':'' ?>><?= h($l) ?></option><?php endforeach; ?></select></label>
    <label>Protocol version<input name="ldap_protver" value="<?= h((string)($s['ldap_protver']??'3')) ?>"></label>
    <label class="wide">Base DN<input name="ldap_basedn" value="<?= h((string)($s['ldap_basedn']??'')) ?>"></label>
    <label>Authentication containers<input name="ldap_authcn" value="<?= h((string)($s['ldap_authcn']??'')) ?>"></label>
    <label>User naming attribute<input name="ldap_attr_user" value="<?= h((string)($s['ldap_attr_user']??'')) ?>"></label>
    <label>Bind DN<input name="ldap_binddn" value="<?= h((string)($s['ldap_binddn']??'')) ?>"></label>
    <label>Bind password<input type="password" name="ldap_bindpw" value="" placeholder="<?= !empty($s['ldap_bindpw_set'])?'Stored — leave blank to keep':'Optional' ?>"></label>
    <label class="wide">Extended query<input name="ldap_extended_query" value="<?= h((string)($s['ldap_extended_query']??'')) ?>"></label>
    <label>Scope<select name="ldap_scope"><option value="one" <?= (string)($s['ldap_scope']??'')==='one'?'selected':'' ?>>One level</option><option value="subtree" <?= (string)($s['ldap_scope']??'')==='subtree'?'selected':'' ?>>Entire subtree</option></select></label>
    <label>Read properties<select name="ldap_read_properties"><option value="0">No</option><option value="1" <?= !empty($s['ldap_read_properties'])?'selected':'' ?>>Yes</option></select></label>
  </div>

  <div class="server-type-section type-radius">
    <label>RADIUS host<input name="host" value="<?= h((string)($s['host']??'')) ?>"></label>
    <label>Authentication port<input type="number" min="1" max="65535" name="radius_auth_port" value="<?= h((string)($s['radius_auth_port']??'1812')) ?>"></label>
    <label>Accounting port<input type="number" min="1" max="65535" name="radius_acct_port" value="<?= h((string)($s['radius_acct_port']??'1813')) ?>"></label>
    <label>Shared secret<input type="password" name="radius_secret" value="" placeholder="<?= !empty($s['radius_secret_set'])?'Stored — leave blank to keep':'Required by server' ?>"></label>
    <label>Timeout<input type="number" min="1" name="radius_timeout" value="<?= h((string)($s['radius_timeout']??'')) ?>"></label>
    <label>NAS identifier<input name="radius_stationid" value="<?= h((string)($s['radius_stationid']??'')) ?>"></label>
  </div>

  <div class="wide"><button class="button" type="submit">Save server</button> <a class="button secondary" href="/system_access_servers.php">Cancel</a></div>
</form>
</div>
<script>
(function(){
 const select=document.getElementById('server-type');
 function update(){
   const type=select.value;
   document.querySelectorAll('.server-type-section').forEach(el=>{
     const show=el.classList.contains('type-'+type);
     el.classList.toggle('hidden-section',!show);
     el.querySelectorAll('input,select').forEach(input=>input.disabled=!show);
   });
 }
 select.addEventListener('change',update);update();
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
