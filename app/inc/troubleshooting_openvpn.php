<?php
declare(strict_types=1);

/* Instance comparison uses the same OPNsense MVC API as Manage OpenVPN.
 * No credentials, generated UUIDs, or raw instance responses are returned.
 */
function trouble_vpn_instances(array $firewall): array
{
    $search = opn_requests_parallel(['s' => [
        'firewall'=>$firewall, 'path'=>'openvpn/instances/search',
        'method'=>'POST', 'payload'=>[
            'current'=>1,'rowCount'=>-1,'sort'=>new stdClass(),'searchPhrase'=>''
        ],'timeout'=>20
    ]])['s'] ?? [];
    if (($search['ok'] ?? false) !== true) {
        throw new RuntimeException('OpenVPN search: '.(string)($search['error'] ?? 'failed'));
    }
    $list = $search['value']['rows'] ?? null;
    if (!is_array($list)) throw new RuntimeException('Invalid OpenVPN search response');
    $instances=[]; $requests=[];
    foreach ($list as $item) {
        if (!is_array($item)) continue;
        $uuid=trim((string)($item['uuid'] ?? $item['id'] ?? ''));
        if ($uuid==='') continue;
        $name=trim((string)($item['description'] ?? $item['descr'] ?? ''));
        if ($name==='') $name='VPN ID '.trim((string)($item['vpnid'] ?? $uuid));
        if (isset($instances[$name])) throw new RuntimeException('Duplicate OpenVPN instance name: '.$name);
        $instances[$name]=['uuid'=>$uuid,'fields'=>[]];
        $requests[$uuid]=['firewall'=>$firewall,'path'=>'openvpn/instances/get/'.rawurlencode($uuid),'method'=>'GET','timeout'=>20];
    }
    if (!$requests) return [];
    $responses=opn_requests_parallel($requests);
    foreach ($instances as $name=>&$instance) {
        $response=$responses[$instance['uuid']] ?? [];
        if (($response['ok'] ?? false)!==true) {
            throw new RuntimeException('OpenVPN instance '.$name.': '.(string)($response['error'] ?? 'request failed'));
        }
        $payload=$response['value'] ?? [];
        if (!is_array($payload)) throw new RuntimeException('Invalid instance response');
        $config=$payload['instance'] ?? $payload['Instance'] ?? null;
        if (!is_array($config)) {
            foreach ($payload as $candidate) {
                if (is_array($candidate) && (isset($candidate['role']) || isset($candidate['description']) || isset($candidate['vpnid']))) {
                    $config=$candidate; break;
                }
            }
        }
        if (!is_array($config)) throw new RuntimeException('Missing instance configuration for '.$name);
        trouble_vpn_flatten($config,'',$instance['fields']);
    }
    unset($instance);
    return $instances;
}

function trouble_vpn_flatten(array $data,string $prefix,array &$out): void
{
    foreach ($data as $field=>$value) {
        $field=(string)$field;
        if ($prefix==='' && in_array(strtolower($field),['uuid','vpnid'],true)) continue;
        $path=$prefix===''?$field:$prefix.'/'.$field;
        if (troubleshooting_is_sensitive($path) || preg_match('/(^|[\\/\\-_])key($|[\\/\\-_])/i',$path)) continue;
        if (is_array($value)) trouble_vpn_flatten($value,$path,$out);
        elseif (is_scalar($value) || $value===null) $out[$path]=is_bool($value)?($value?'1':'0'):(string)($value ?? '');
    }
}

function trouble_vpn_compare(array $left,array $right): array
{
    $a=trouble_vpn_instances($left); $b=trouble_vpn_instances($right); $rows=[];
    $names=array_values(array_unique(array_merge(array_keys($a),array_keys($b))));
    natcasesort($names);
    foreach ($names as $name) {
        $aa=$a[$name]['fields'] ?? []; $bb=$b[$name]['fields'] ?? [];
        $keys=array_values(array_unique(array_merge(array_keys($aa),array_keys($bb))));
        if (!$keys) $keys=['(instance present)'];
        natcasesort($keys);
        foreach ($keys as $key) {
            $hasA=isset($a[$name]) && ($key==='(instance present)' || array_key_exists($key,$aa));
            $hasB=isset($b[$name]) && ($key==='(instance present)' || array_key_exists($key,$bb));
            $va=$hasA?(string)($aa[$key] ?? 'yes'):null;
            $vb=$hasB?(string)($bb[$key] ?? 'yes'):null;
            $rows[]=[
                'path'=>'VPN/OpenVPN/Instances/'.str_replace('/','／',$name).'/'.$key,
                'left_exists'=>$hasA,'right_exists'=>$hasB,
                'left'=>$va,'right'=>$vb,
                'different'=>!$hasA || !$hasB || !hash_equals((string)$va,(string)$vb)
            ];
        }
    }
    return $rows;
}
