<?php

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('html_errors', '0');
ob_start();

register_shutdown_function(static function (): void {
    $error = error_get_last();
    if ($error === null || !in_array($error['type'], [E_ERROR,E_PARSE,E_CORE_ERROR,E_COMPILE_ERROR,E_USER_ERROR], true)) return;
    while (ob_get_level() > 0) ob_end_clean();
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo json_encode(['ok'=>false,'error'=>'PHP fatal error: '.$error['message']], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
});

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();
if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function plugin_cache_path(): string { return DATA_DIR . '/plugins-cache.json'; }
function plugin_read_cache(): ?array {
    $path=plugin_cache_path();
    if(!is_file($path)) return null;
    $raw=file_get_contents($path); $decoded=$raw===false?null:json_decode($raw,true);
    if(!is_array($decoded)||!isset($decoded['firewalls'])||!is_array($decoded['firewalls'])) return null;
    $modified=filemtime($path); $decoded['age']=$modified===false?null:max(0,time()-$modified);
    return $decoded;
}
function plugin_write_cache(array $data): void {
    if(!is_dir(DATA_DIR)) @mkdir(DATA_DIR,0770,true);
    $tmp=plugin_cache_path().'.tmp-'.bin2hex(random_bytes(4));
    $payload=json_encode($data,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
    if(file_put_contents($tmp,$payload,LOCK_EX)!==false){@chmod($tmp,0660);@rename($tmp,plugin_cache_path());}else @unlink($tmp);
}
function plugin_bool(mixed $value): bool {
    if(is_bool($value)) return $value;
    if(is_int($value)||is_float($value)) return $value!==0;
    return in_array(strtolower(trim((string)$value)),['1','true','yes','on','installed','locked'],true);
}
function plugin_find_packages(mixed $node,array &$output): void {
    if(!is_array($node)) return;
    $name=trim((string)($node['name']??$node['pkg_name']??$node['package']??''));
    if($name!==''&&str_starts_with($name,'os-')){
        $status=strtolower(trim((string)($node['status']??''))); $current=trim((string)($node['current']??''));
        $installed=array_key_exists('installed',$node)?plugin_bool($node['installed']):($status==='installed'||$current!=='');
        $output[$name]=[
            'name'=>$name,
            'version'=>trim((string)($node['version']??$node['installed_version']??$current)),
            'available_version'=>trim((string)($node['available_version']??$node['new_version']??$node['version']??'')),
            'installed'=>$installed,
            'locked'=>plugin_bool($node['locked']??false),
            'description'=>trim((string)($node['comment']??$node['description']??'')),
        ];
    }
    foreach($node as $value) plugin_find_packages($value,$output);
}
function plugin_live(array $firewalls): array {
    $requests=[];
    foreach($firewalls as $firewall){$requests[(string)$firewall['id']]=['firewall'=>$firewall,'path'=>'core/firmware/info','timeout'=>30];}
    $responses=opn_requests_parallel($requests); $rows=[];
    foreach($firewalls as $firewall){
        $key=(string)$firewall['id']; $response=$responses[$key]??['ok'=>false,'error'=>'No result']; $plugins=[];
        if(($response['ok']??false)===true) plugin_find_packages($response['value']??[],$plugins);
        uksort($plugins,'strnatcasecmp');
        $rows[]=['id'=>(int)$firewall['id'],'name'=>(string)$firewall['name'],'base_url'=>(string)$firewall['base_url'],'ok'=>($response['ok']??false)===true,'error'=>$response['error']??null,'plugins'=>array_values($plugins)];
    }
    $data=['created_at'=>gmdate('c'),'firewalls'=>$rows]; plugin_write_cache($data); $data['age']=0; return $data;
}

try{
    $force=($_GET['force']??'')==='1';
    $firewallId=(int)($_GET['firewall_id']??0);
    $all=db()->query('SELECT id,name,base_url,api_key_enc,api_secret_enc,verify_tls FROM firewalls ORDER BY name')->fetchAll();
    if($firewallId>0){$selected=[firewall_by_id($firewallId)];}else{$selected=$all;}
    if($selected===[]) throw new RuntimeException('No firewalls configured.');

    $cache=plugin_read_cache(); $source='cache'; $needsLive=$force||$cache===null;
    if(!$needsLive){
        $cachedById=[]; foreach($cache['firewalls'] as $row)$cachedById[(int)($row['id']??0)]=$row;
        foreach($selected as $fw){if(!isset($cachedById[(int)$fw['id']])){$needsLive=true;break;}}
    }
    if($needsLive){$cache=plugin_live($all);$source='live';}
    $wanted=array_fill_keys(array_map(static fn(array $fw):int=>(int)$fw['id'],$selected),true);
    $rows=array_values(array_filter($cache['firewalls'],static fn(array $row):bool=>isset($wanted[(int)($row['id']??0)])));

    $catalog=[];
    foreach($rows as $row){
        foreach(($row['plugins']??[]) as $plugin){
            $name=(string)($plugin['name']??''); if($name==='')continue;
            if(!isset($catalog[$name]))$catalog[$name]=['name'=>$name,'description'=>(string)($plugin['description']??''),'available_version'=>(string)($plugin['available_version']??'')];
            if($catalog[$name]['description']===''&&($plugin['description']??'')!=='')$catalog[$name]['description']=(string)$plugin['description'];
            if($catalog[$name]['available_version']===''&&($plugin['available_version']??'')!=='')$catalog[$name]['available_version']=(string)$plugin['available_version'];
        }
    }
    uksort($catalog,'strnatcasecmp');
    while(ob_get_level()>0)ob_end_clean();
    echo json_encode(['ok'=>true,'firewalls'=>$rows,'catalog'=>array_values($catalog),'cache'=>['source'=>$source,'age'=>$cache['age']??null,'refresh_recommended'=>$source==='cache'&&(($cache['age']??999)>=300)]],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}catch(Throwable $exception){
    http_response_code(500); while(ob_get_level()>0)ob_end_clean();
    echo json_encode(['ok'=>false,'error'=>$exception->getMessage()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
