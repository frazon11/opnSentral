<?php
declare(strict_types=1);
ini_set('display_errors','0');ini_set('html_errors','0');ob_start();
require_once __DIR__.'/inc/config.php';
require_once __DIR__.'/inc/opnsense.php';
require_once __DIR__.'/inc/backups.php';
require_login();require_csrf();
require_configuration_unlocked();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
try{
 $firewallId=(int)($_POST['firewall_id']??0);
 $uuid=trim((string)($_POST['uuid']??''));
 $vpnid=trim((string)($_POST['vpnid']??''));
 $action=(string)($_POST['action']??'');
 if($firewallId<1)throw new RuntimeException('Invalid firewall.');
 if(!preg_match('/^[A-Za-z0-9-]{8,80}$/',$uuid))throw new RuntimeException('Invalid OpenVPN instance UUID.');
 if(!in_array($action,['enable','disable','start','stop','restart','delete'],true))throw new RuntimeException('Unsupported action.');
 $fw=firewall_by_id($firewallId);$backup=null;
 if(in_array($action,['enable','disable','delete'],true)){
  $backup=backup_before_change($fw,'openvpn-'.$action.'-'.$uuid);
 }
 if($action==='enable'||$action==='disable'){
  $enabled=$action==='enable'?'1':'0';
  $response=opn_request($fw,'openvpn/instances/toggle/'.rawurlencode($uuid).'/'.$enabled,'POST',null,30);
  opn_request($fw,'openvpn/service/reconfigure','POST',null,60);
 }elseif($action==='delete'){
  $response=opn_request($fw,'openvpn/instances/del/'.rawurlencode($uuid),'POST',null,30);
  opn_request($fw,'openvpn/service/reconfigure','POST',null,60);
 }else{
  if($vpnid===''||!ctype_digit($vpnid))throw new RuntimeException('Missing OpenVPN service ID.');
  $map=['start'=>'start_service','stop'=>'stop_service','restart'=>'restart_service'];
  $response=opn_request($fw,'openvpn/service/'.$map[$action].'/'.rawurlencode($vpnid),'POST',null,60);
 }
 while(ob_get_level()>0)ob_end_clean();
 echo json_encode(['ok'=>true,'message'=>ucfirst($action).' completed.','backup_id'=>$backup['id']??null,'response'=>$response],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}catch(Throwable $e){
 http_response_code(500);while(ob_get_level()>0)ob_end_clean();
 echo json_encode(['ok'=>false,'error'=>$e->getMessage()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
