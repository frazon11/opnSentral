<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$agentRows = db()->query('SELECT * FROM agents WHERE firewall_id IS NOT NULL ORDER BY id DESC')->fetchAll();
$agentsByFirewall = [];
foreach ($agentRows as $agent) {
    $fid = (int)($agent['firewall_id'] ?? 0);
    if ($fid > 0 && !isset($agentsByFirewall[$fid])) $agentsByFirewall[$fid] = $agent;
}

function general_matrix_value(SimpleXMLElement $xml, string $path, string $default = '—'): string
{
    $nodes = $xml->xpath($path);
    if (!is_array($nodes) || !isset($nodes[0])) return $default;
    $value = trim((string)$nodes[0]);
    return $value === '' ? $default : $value;
}
function general_matrix_values(SimpleXMLElement $xml, string $path): array
{
    $nodes = $xml->xpath($path);
    if (!is_array($nodes)) return [];
    return array_values(array_filter(array_map(static fn(SimpleXMLElement $node): string => trim((string)$node), $nodes), static fn(string $value): bool => $value !== ''));
}
function general_matrix_exists(SimpleXMLElement $xml, string $path): bool
{
    $nodes = $xml->xpath($path);
    return is_array($nodes) && isset($nodes[0]);
}
function general_agent_writable(?array $agent): bool
{
    if (!is_array($agent) || (int)($agent['enabled'] ?? 0) !== 1) return false;
    $version = trim((string)($agent['last_version'] ?? ''));
    return $version !== '' && version_compare($version, '0.1.6', '>=');
}

$settings = [
    'System' => [
        'hostname' => ['label'=>'Hostname','type'=>'text'],
        'domain' => ['label'=>'Domain','type'=>'text'],
        'timezone' => ['label'=>'Time zone','type'=>'text'],
        'language' => ['label'=>'Language','type'=>'text'],
        'theme' => ['label'=>'Theme','type'=>'text'],
    ],
    'Networking' => [
        'prefer_ipv4' => ['label'=>'Prefer IPv4 over IPv6','type'=>'boolean','help'=>'Prefer IPv4 when both IPv4 and IPv6 are available.'],
        'dns' => ['label'=>'DNS servers','type'=>'text','help'=>'Comma-separated IP addresses; optional gateway syntax: 1.1.1.1 via WAN_DHCP.'],
        'dnssearchdomain' => ['label'=>'DNS search domains','type'=>'text'],
        'dnsallowoverride' => ['label'=>'Allow DNS server list override by DHCP/PPP on WAN','type'=>'boolean'],
        'dnsallowoverride_exclude' => ['label'=>'DNS override excluded interfaces','type'=>'text'],
        'dnslocalhost' => ['label'=>'Do not use local DNS service as system nameserver','type'=>'boolean'],
        'gw_switch_default' => ['label'=>'Allow default gateway switching','type'=>'boolean'],
    ],
];

$requests=[];
foreach($firewalls as $firewall){$requests[(string)$firewall['id']]=['firewall'=>$firewall,'path'=>'core/backup/download/this','timeout'=>60];}
$downloads=opn_downloads_parallel($requests);
$matrix=[];
foreach($firewalls as $firewall){
    $fid=(int)$firewall['id'];
    $entry=['firewall'=>$firewall,'ok'=>false,'error'=>'','values'=>[],'agent'=>$agentsByFirewall[$fid]??null];
    $download=$downloads[(string)$fid]??$downloads[$fid]??['ok'=>false,'error'=>'No response.'];
    if(($download['ok']??false)!==true){$entry['error']=(string)($download['error']??'Could not read configuration.');$matrix[$fid]=$entry;continue;}
    try{
        $xml=simplexml_load_string((string)($download['value']??''),SimpleXMLElement::class,LIBXML_NONET|LIBXML_NOCDATA);
        if(!$xml instanceof SimpleXMLElement)throw new RuntimeException('Could not parse configuration XML.');
        $dnsServers=general_matrix_values($xml,'/opnsense/system/dnsserver');$dnsDisplay=[];
        foreach($dnsServers as $index=>$server){$gateway=general_matrix_value($xml,'/opnsense/system/dns'.($index+1).'gw','none');$dnsDisplay[]=strtolower($gateway)!=='none'?$server.' via '.$gateway:$server;}
        $entry['values']=[
            'hostname'=>general_matrix_value($xml,'/opnsense/system/hostname',''),
            'domain'=>general_matrix_value($xml,'/opnsense/system/domain',''),
            'timezone'=>general_matrix_value($xml,'/opnsense/system/timezone','Etc/UTC'),
            'language'=>general_matrix_value($xml,'/opnsense/system/language','Default'),
            'theme'=>general_matrix_value($xml,'/opnsense/theme','Default'),
            'prefer_ipv4'=>general_matrix_exists($xml,'/opnsense/system/prefer_ipv4'),
            'dns'=>$dnsDisplay!==[]?implode(', ',$dnsDisplay):'None configured',
            'dnssearchdomain'=>general_matrix_value($xml,'/opnsense/system/dnssearchdomain','None configured'),
            'dnsallowoverride'=>general_matrix_value($xml,'/opnsense/system/dnsallowoverride','0')==='1',
            'dnsallowoverride_exclude'=>general_matrix_value($xml,'/opnsense/system/dnsallowoverride_exclude','None'),
            'dnslocalhost'=>general_matrix_exists($xml,'/opnsense/system/dnslocalhost'),
            'gw_switch_default'=>general_matrix_exists($xml,'/opnsense/system/gw_switch_default'),
        ];$entry['ok']=true;
    }catch(Throwable $exception){$entry['error']=$exception->getMessage();}
    $matrix[$fid]=$entry;
}

require __DIR__.'/inc/header.php';
?>
<style>
.fleet-settings-toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:12px}.fleet-settings-toolbar .actions{display:flex;gap:8px}.fleet-settings-table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}.fleet-settings-table{border-collapse:separate;border-spacing:0;min-width:max(1100px,100%);width:100%}.fleet-settings-table th,.fleet-settings-table td{padding:10px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:middle;text-align:center}.fleet-settings-table th:last-child,.fleet-settings-table td:last-child{border-right:0}.fleet-settings-table thead th{position:sticky;top:0;z-index:3;background:var(--table-head)}.fleet-settings-table .setting-col{position:sticky;left:0;z-index:2;text-align:left;min-width:300px;background:var(--card)}.fleet-settings-table thead .setting-col{z-index:4;background:var(--table-head)}.fleet-settings-table .all-col{min-width:160px}.fleet-settings-table .firewall-col{min-width:190px}.fleet-settings-table .firewall-col a{display:block;font-weight:700}.fleet-settings-table .firewall-col small{display:block;margin-top:3px;color:var(--muted)}.fleet-settings-section td{background:var(--table-head);font-weight:800;text-align:left!important;padding:9px 12px!important}.fleet-setting strong{display:block}.fleet-setting small{display:block;margin-top:4px;color:var(--muted);font-weight:400}.fleet-value.dirty{background:rgba(240,173,78,.12)}.fleet-value input[type=text]{min-width:150px;width:100%;padding:6px 8px}.fleet-value input[type=checkbox],.fleet-row-all[type=checkbox]{width:20px;height:20px}.fleet-value .cell-note{display:block;margin-top:4px;font-size:.72rem;color:var(--muted)}#fleet-settings-result{margin-top:14px}
</style>
<div class="page-title"><div><h1>System → Settings → General</h1><p>Compare and deploy General settings across all managed OPNsense firewalls.</p></div></div>
<div class="alert warningbox"><strong>Fleet writes use the opnSentral agent.</strong> Agent 0.1.6 or newer is required. Every target receives a pre-change backup before deployment.</div>
<div class="fleet-settings-toolbar"><div><strong><?=count($firewalls)?> managed firewall<?=count($firewalls)===1?'':'s'?></strong><span class="muted"> · Change one cell, or use All to copy a value across writable firewalls.</span></div><div class="actions"><button type="button" class="button secondary" id="fleet-settings-reset" disabled>Reset changes</button><button type="button" class="button" id="fleet-settings-apply" disabled>Apply changes</button></div></div>
<div id="fleet-settings-root" data-fleet-settings-scope="general" data-csrf="<?=h(csrf_token())?>">
<div class="fleet-settings-table-wrap"><table class="fleet-settings-table"><thead><tr><th class="setting-col">Setting</th><th class="all-col">All</th><?php foreach($matrix as $fid=>$entry):$writable=$entry['ok']&&general_agent_writable($entry['agent']);?><th class="firewall-col"><a href="/firewall_view.php?id=<?=$fid?>"><?=h((string)$entry['firewall']['name'])?></a><?php if(!$entry['ok']):?><small><span class="badge bad">Read failed</span></small><?php elseif($writable):?><small><span class="badge good">Agent ready</span></small><?php elseif(is_array($entry['agent'])):?><small><span class="badge warning">Agent 0.1.6+ required</span></small><?php else:?><small><span class="badge neutral">Agent required</span></small><?php endif;?></th><?php endforeach;?></tr></thead><tbody>
<?php foreach($settings as $section=>$definitions):?><tr class="fleet-settings-section"><td colspan="<?=count($matrix)+2?>"><?=h($section)?></td></tr><?php foreach($definitions as $key=>$definition):?><tr data-setting="<?=h($key)?>"><td class="setting-col fleet-setting"><strong><?=h((string)$definition['label'])?></strong><?php if(($definition['help']??'')!==''):?><small><?=h((string)$definition['help'])?></small><?php endif;?></td><td class="all-col fleet-value"><?php if($definition['type']==='boolean'):?><input type="checkbox" class="fleet-row-all" aria-label="Set all"><?php else:?><input type="text" class="fleet-row-all" placeholder="Set all"><?php endif;?></td>
<?php foreach($matrix as $fid=>$entry):$writable=$entry['ok']&&general_agent_writable($entry['agent']);$value=$entry['values'][$key]??($definition['type']==='boolean'?false:'');?><td class="fleet-value"><?php if(!$entry['ok']):?><span class="badge bad" title="<?=h((string)$entry['error'])?>">Unavailable</span><?php elseif($definition['type']==='boolean'):?><input type="checkbox" class="fleet-setting-control" data-setting="<?=h($key)?>" data-firewall-id="<?=$fid?>" data-initial="<?=$value?'1':'0'?>" <?=$value?'checked':''?> <?=$writable?'':'disabled'?>><?php if(!$writable):?><span class="cell-note">Agent 0.1.6+ required</span><?php endif;?><?php else:?><input type="text" class="fleet-setting-control" data-setting="<?=h($key)?>" data-firewall-id="<?=$fid?>" data-initial="<?=h((string)$value)?>" value="<?=h((string)$value)?>" <?=$writable?'':'disabled'?>><?php if(!$writable):?><span class="cell-note">Agent 0.1.6+ required</span><?php endif;?><?php endif;?></td><?php endforeach;?></tr><?php endforeach;endforeach;?></tbody></table></div>
<div id="fleet-settings-result" class="hidden"></div></div>
<script src="/assets/fleet-settings-editor.js?v=1"></script>
<?php require __DIR__.'/inc/footer.php'; ?>