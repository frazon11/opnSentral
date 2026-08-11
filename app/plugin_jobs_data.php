<?php
declare(strict_types=1);
require_once __DIR__.'/inc/config.php';
require_once __DIR__.'/inc/opnsense.php';
require_login();
if(session_status()===PHP_SESSION_ACTIVE)session_write_close();
header('Content-Type: application/json; charset=utf-8');
try{
 $firewallId=(int)($_GET['firewall_id']??0);
 if($firewallId<1)throw new RuntimeException('Select a firewall.');
 $stmt=db()->prepare('SELECT * FROM plugin_jobs WHERE firewall_id=? ORDER BY created_at DESC LIMIT 50');
 $stmt->execute([$firewallId]);
 $jobs=$stmt->fetchAll();
 foreach($jobs as &$job){
  if($job['status']==='started'&&$job['message_uuid']!==''){
   try{
    $fw=firewall_by_id((int)$job['firewall_id']);
    $running=opn_request($fw,'core/firmware/running','GET',[],10);
    $raw=strtolower(json_encode($running));
    if(str_contains($raw,strtolower((string)$job['message_uuid']))){
     $job['runtime']=$running;
    }elseif(time()-(strtotime($job['created_at'])?:time())>15){
     $stmt=db()->prepare('UPDATE plugin_jobs SET status="submitted",updated_at=? WHERE id=?');
     $stmt->execute([gmdate('c'),(int)$job['id']]);$job['status']='submitted';
    }
   }catch(Throwable $e){$job['runtime_error']=$e->getMessage();}
  }
 }
 echo json_encode(['ok'=>true,'jobs'=>$jobs],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}catch(Throwable $e){http_response_code(500);echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);}
