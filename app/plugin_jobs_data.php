<?php

declare(strict_types=1);
require_once __DIR__.'/inc/config.php';
require_once __DIR__.'/inc/opnsense.php';
require_login();
if(session_status()===PHP_SESSION_ACTIVE)session_write_close();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function plugin_job_bool(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    if (!is_string($value)) return false;
    return in_array(strtolower(trim($value)), ['1','true','yes','on','installed','locked'], true);
}

function plugin_job_find(mixed $node, string $package): ?array
{
    if (!is_array($node)) return null;
    $name = trim((string)($node['name'] ?? $node['pkg_name'] ?? $node['package'] ?? ''));
    if ($name === $package) {
        $status = strtolower(trim((string)($node['status'] ?? '')));
        $current = trim((string)($node['current'] ?? ''));
        $installed = array_key_exists('installed', $node)
            ? plugin_job_bool($node['installed'])
            : ($status === 'installed' || $current !== '' || trim((string)($node['installed_version'] ?? '')) !== '');
        return [
            'installed' => $installed,
            'locked' => plugin_job_bool($node['locked'] ?? false),
            'version' => trim((string)($node['version'] ?? $node['installed_version'] ?? $current)),
        ];
    }
    foreach ($node as $child) {
        $found = plugin_job_find($child, $package);
        if ($found !== null) return $found;
    }
    return null;
}

function plugin_job_verified(array $job, ?array $package): bool
{
    $operation = strtolower(trim((string)($job['operation'] ?? '')));
    if ($operation === 'install' || $operation === 'reinstall') return $package !== null && $package['installed'] === true;
    if ($operation === 'remove') return $package === null || $package['installed'] === false;
    if ($operation === 'lock') return $package !== null && $package['installed'] === true && $package['locked'] === true;
    if ($operation === 'unlock') return $package !== null && $package['installed'] === true && $package['locked'] === false;
    return false;
}

try{
 $firewallId=(int)($_GET['firewall_id']??0);
 if($firewallId<1)throw new RuntimeException('Select a firewall.');
 $stmt=db()->prepare('SELECT * FROM plugin_jobs WHERE firewall_id=? ORDER BY created_at DESC LIMIT 50');
 $stmt->execute([$firewallId]);
 $jobs=$stmt->fetchAll();
 $fw=firewall_by_id($firewallId);
 foreach($jobs as &$job){
  if(!in_array((string)($job['status']??''),['started','submitted'],true))continue;
  $age=time()-(strtotime((string)($job['created_at']??''))?:time());
  if($age<15)continue;
  $running=false;
  if(trim((string)($job['message_uuid']??''))!==''){
   try{
    $runtime=opn_request($fw,'core/firmware/running','GET',[],10);
    $raw=strtolower(json_encode($runtime,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)?:'');
    if(str_contains($raw,strtolower((string)$job['message_uuid']))){$running=true;$job['runtime']=$runtime;}
   }catch(Throwable $e){$job['runtime_error']=$e->getMessage();}
  }
  if($running)continue;
  try{
   $inventory=opn_request($fw,'core/firmware/info','GET',[],30);
   $package=plugin_job_find($inventory,(string)$job['package_name']);
   $job['verification']=['package'=>$package,'checked_at'=>gmdate('c')];
   if(plugin_job_verified($job,$package)){
    $update=db()->prepare('UPDATE plugin_jobs SET status="completed",updated_at=? WHERE id=?');
    $update->execute([gmdate('c'),(int)$job['id']]);
    $job['status']='completed';
   }elseif((string)$job['status']==='started'){
    $update=db()->prepare('UPDATE plugin_jobs SET status="submitted",updated_at=? WHERE id=?');
    $update->execute([gmdate('c'),(int)$job['id']]);
    $job['status']='submitted';
   }
  }catch(Throwable $e){
   $job['verification_error']=$e->getMessage();
   if((string)$job['status']==='started'){
    $update=db()->prepare('UPDATE plugin_jobs SET status="submitted",updated_at=? WHERE id=?');
    $update->execute([gmdate('c'),(int)$job['id']]);
    $job['status']='submitted';
   }
  }
 }
 unset($job);
 echo json_encode(['ok'=>true,'jobs'=>$jobs],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}catch(Throwable $e){http_response_code(500);echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);}
