<?php
declare(strict_types=1);
require_once __DIR__.'/inc/config.php';
require_login();require_csrf();
$action=(string)($_POST['action']??'');
if($action==='create'){
 $firewallId=(int)($_POST['firewall_id']??0);$name=trim((string)($_POST['name']??''));
 $agentId=bin2hex(random_bytes(16));$secret=bin2hex(random_bytes(32));
 $stmt=db()->prepare('INSERT INTO agents(firewall_id,agent_id,secret_enc,name,created_at) VALUES(?,?,?,?,?)');
 $stmt->execute([$firewallId?:null,$agentId,encrypt_value($secret),$name,gmdate('c')]);
 $_SESSION['new_agent_credentials']=['agent_id'=>$agentId,'secret'=>$secret];
}elseif($action==='delete'){
 $stmt=db()->prepare('DELETE FROM agents WHERE id=?');$stmt->execute([(int)($_POST['id']??0)]);
}elseif($action==='toggle'){
 $stmt=db()->prepare('UPDATE agents SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?');
 $stmt->execute([(int)($_POST['id']??0)]);
}
header('Location: /agents.php');
