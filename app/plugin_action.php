<?php
declare(strict_types=1);
ini_set('display_errors','0');
require_once __DIR__.'/inc/config.php';
require_once __DIR__.'/inc/opnsense.php';
require_once __DIR__.'/inc/backups.php';
require_login();require_csrf();
require_configuration_unlocked();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try{
 $firewallId=(int)($_POST['firewall_id']??0);
 $package=trim((string)($_POST['package']??''));
 $operation=(string)($_POST['operation']??'');
 $allowed=['install','reinstall','remove','lock','unlock'];
 if($firewallId<1)throw new RuntimeException('Invalid firewall.');
 if(!preg_match('/^os-[A-Za-z0-9][A-Za-z0-9._+-]*$/',$package))throw new RuntimeException('Only OPNsense plugins with an os- package name are allowed.');
 if(!in_array($operation,$allowed,true))throw new RuntimeException('Unsupported operation.');
 $fw=firewall_by_id($firewallId);$backup=null;
 if(in_array($operation,['install','reinstall','remove'],true)){
  $backup=backup_before_change($fw,'plugin-'.$operation.'-'.$package);
 }
 $response=opn_request($fw,'core/firmware/'.$operation.'/'.rawurlencode($package),'POST',[],30);
 $status=strtolower((string)($response['status']??''));
 if($status!==''&&!in_array($status,['ok','success'],true))throw new RuntimeException((string)($response['status']??'Plugin action rejected.'));
 $uuid=(string)($response['msg_uuid']??'');
 $now=gmdate('c');
 $stmt=db()->prepare('INSERT INTO plugin_jobs(firewall_id,firewall_name,package_name,operation,status,message_uuid,backup_id,response_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)');
 $stmt->execute([$firewallId,(string)$fw['name'],$package,$operation,'started',$uuid,(int)($backup['id']??0)?:null,json_encode($response,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE),$now,$now]);
 @unlink(DATA_DIR.'/plugins-cache.json');
 echo json_encode(['ok'=>true,'job_id'=>(int)db()->lastInsertId(),'message_uuid'=>$uuid,'backup_id'=>$backup['id']??null,'message'=>ucfirst($operation).' started for '.$package.'.'],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}catch(Throwable $e){http_response_code(500);echo json_encode(['ok'=>false,'error'=>$e->getMessage()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);}
