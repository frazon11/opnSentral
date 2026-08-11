<?php
declare(strict_types=1);
require_once dirname(__DIR__,2).'/inc/config.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
function fail_agent(int $status,string $message): never {
 http_response_code($status);echo json_encode(['ok'=>false,'error'=>$message]);exit;
}
if(($_SERVER['REQUEST_METHOD']??'')!=='POST')fail_agent(405,'POST required.');
$agentId=trim((string)($_SERVER['HTTP_X_OPNCENTRAL_AGENT_ID']??''));
$timestamp=trim((string)($_SERVER['HTTP_X_OPNCENTRAL_TIMESTAMP']??''));
$nonce=trim((string)($_SERVER['HTTP_X_OPNCENTRAL_NONCE']??''));
$signature=strtolower(trim((string)($_SERVER['HTTP_X_OPNCENTRAL_SIGNATURE']??'')));
if(!preg_match('/^[a-f0-9-]{20,80}$/i',$agentId)||!ctype_digit($timestamp)||!preg_match('/^[a-f0-9]{24,128}$/i',$nonce)||!preg_match('/^[a-f0-9]{64}$/',$signature))fail_agent(400,'Invalid authentication headers.');
$now=time();$sentAt=(int)$timestamp;
if(abs($now-$sentAt)>300)fail_agent(401,'Timestamp outside allowed window.');
$body=file_get_contents('php://input');
if($body===false||strlen($body)>262144)fail_agent(413,'Invalid or oversized payload.');
$payload=json_decode($body,true);
if(!is_array($payload))fail_agent(400,'Invalid JSON payload.');
$stmt=db()->prepare('SELECT * FROM agents WHERE agent_id=? AND enabled=1');
$stmt->execute([$agentId]);$agent=$stmt->fetch();
if(!$agent)fail_agent(401,'Unknown or disabled agent.');
$secret=decrypt_value((string)$agent['secret_enc']);
$canonical=$timestamp."\n".$nonce."\n".hash('sha256',$body);
$expected=hash_hmac('sha256',$canonical,$secret);
if(!hash_equals($expected,$signature))fail_agent(401,'Invalid signature.');
db()->exec('DELETE FROM agent_nonces WHERE seen_at < '.($now-900));
try{
 $ns=db()->prepare('INSERT INTO agent_nonces(agent_id,nonce,seen_at) VALUES(?,?,?)');
 $ns->execute([$agentId,$nonce,$now]);
}catch(PDOException $e){fail_agent(409,'Nonce already used.');}
$hostname=trim((string)($payload['hostname']??''));
$agentVersion=trim((string)($payload['agent_version']??''));
$opnsenseVersion=trim((string)($payload['opnsense_version']??''));
$up=db()->prepare('UPDATE agents SET last_seen_at=?,last_remote_ip=?,last_version=?,last_hostname=?,last_opnsense_version=?,last_payload=? WHERE agent_id=?');
$up->execute([gmdate('c'),(string)($_SERVER['REMOTE_ADDR']??''),substr($agentVersion,0,64),substr($hostname,0,255),substr($opnsenseVersion,0,128),json_encode($payload,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE),$agentId]);
echo json_encode(['ok'=>true,'server_time'=>$now]);
