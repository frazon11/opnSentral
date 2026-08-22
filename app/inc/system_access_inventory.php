<?php

declare(strict_types=1);

function access_xml_children_named(SimpleXMLElement $node, string $name): array
{
    $children = [];
    if (isset($node->{$name})) {
        foreach ($node->{$name} as $child) if ($child instanceof SimpleXMLElement) $children[] = $child;
    }
    if ($children === []) {
        $matches = $node->xpath('./*[local-name()="' . $name . '"]');
        if (is_array($matches)) foreach ($matches as $child) if ($child instanceof SimpleXMLElement) $children[] = $child;
    }
    return $children;
}

function access_xml_bool(SimpleXMLElement $node, string $name): bool
{
    $children = access_xml_children_named($node, $name);
    if ($children === []) return false;
    $value = strtolower(trim((string)$children[0]));
    if ($value === '') return true;
    return in_array($value, ['1','true','yes','on'], true);
}

function access_xml_text(SimpleXMLElement $node, string $name, string $default = ''): string
{
    $children = access_xml_children_named($node, $name);
    if ($children === []) return $default;
    $value = trim((string)$children[0]);
    return $value === '' ? $default : $value;
}

function access_xml_values(SimpleXMLElement $node, string $name): array
{
    $values=[];
    foreach (access_xml_children_named($node,$name) as $item) {
        $value=trim((string)$item);
        if ($value!=='') $values[]=$value;
    }
    return array_values(array_unique($values));
}

function access_xml_listish_values(SimpleXMLElement $node, string $name): array
{
    $result=[];
    foreach (access_xml_values($node,$name) as $value) {
        foreach (preg_split('/[\s,;]+/',$value) ?: [] as $part) {
            $part=trim($part);
            if ($part!=='') $result[]=$part;
        }
    }
    return array_values(array_unique($result));
}

function access_xml_system_nodes(SimpleXMLElement $xml, string $name): array
{
    foreach (['/opnsense/system/'.$name,'//system/'.$name,'//*[local-name()="system"]/*[local-name()="'.$name.'"]'] as $query) {
        $nodes=$xml->xpath($query);
        if (!is_array($nodes) || $nodes===[]) continue;
        $result=[];
        foreach ($nodes as $node) if ($node instanceof SimpleXMLElement) $result[]=$node;
        if ($result!==[]) return $result;
    }
    return [];
}

function access_normalize_config_xml(string $body): array
{
    $normalized=ltrim($body,"\xEF\xBB\xBF\x00\x09\x0A\x0D\x20");
    $decodedEscaping=false;
    for ($attempt=0;$attempt<2;$attempt++) {
        if (!preg_match('/^&lt;(?:\?xml\b|opnsense\b)/i',$normalized)) break;
        $decoded=html_entity_decode($normalized,ENT_QUOTES|ENT_XML1,'UTF-8');
        if ($decoded===$normalized) break;
        $normalized=ltrim($decoded,"\xEF\xBB\xBF\x00\x09\x0A\x0D\x20");
        $decodedEscaping=true;
    }
    return ['xml'=>$normalized,'decoded_escaped_xml'=>$decodedEscaping];
}

function access_decode_authorized_keys(SimpleXMLElement $node): string
{
    $encoded=access_xml_text($node,'authorizedkeys');
    if ($encoded==='') return '';
    $decoded=base64_decode($encoded,true);
    if (!is_string($decoded)) return '';
    return trim(str_replace(["\r\n","\r"],"\n",$decoded));
}

function access_parse_users(SimpleXMLElement $xml): array
{
    $users=[];
    foreach (access_xml_system_nodes($xml,'user') as $node) {
        $name=access_xml_text($node,'name');
        if ($name==='') continue;
        $groups=array_merge(access_xml_listish_values($node,'groupname'),access_xml_listish_values($node,'group'));
        $privileges=array_merge(access_xml_listish_values($node,'priv'),access_xml_listish_values($node,'privilege'));
        $authorizedKeys=access_decode_authorized_keys($node);
        $users[$name]=[
            'name'=>$name,
            'description'=>access_xml_text($node,'descr',access_xml_text($node,'description')),
            'uid'=>access_xml_text($node,'uid'),
            'scope'=>access_xml_text($node,'scope','user'),
            'groups'=>array_values(array_unique($groups)),
            'privileges'=>array_values(array_unique($privileges)),
            'shell'=>access_xml_text($node,'shell'),
            'disabled'=>access_xml_bool($node,'disabled'),
            'otp'=>access_xml_text($node,'otp_seed')!=='',
            'has_password'=>access_xml_text($node,'password')!=='',
            'authorized_keys'=>$authorizedKeys,
            'has_authorized_keys'=>$authorizedKeys!=='',
        ];
    }
    ksort($users,SORT_NATURAL|SORT_FLAG_CASE);
    return $users;
}

function access_parse_groups(SimpleXMLElement $xml): array
{
    $groups=[];
    foreach (access_xml_system_nodes($xml,'group') as $node) {
        $name=access_xml_text($node,'name');
        if ($name==='') continue;
        $members=array_merge(access_xml_listish_values($node,'member'),access_xml_listish_values($node,'members'));
        $privileges=array_merge(access_xml_listish_values($node,'priv'),access_xml_listish_values($node,'privilege'));
        $groups[$name]=[
            'name'=>$name,
            'description'=>access_xml_text($node,'description',access_xml_text($node,'descr')),
            'gid'=>access_xml_text($node,'gid'),
            'scope'=>access_xml_text($node,'scope','system'),
            'members'=>array_values(array_unique($members)),
            'privileges'=>array_values(array_unique($privileges)),
        ];
    }
    ksort($groups,SORT_NATURAL|SORT_FLAG_CASE);
    return $groups;
}

function access_reconcile_memberships(array &$users, array $groups): void
{
    $usersByUid=[];
    foreach ($users as $name=>$user) {
        $uid=trim((string)($user['uid'] ?? ''));
        if ($uid!=='') $usersByUid[$uid]=$name;
    }
    foreach ($groups as $groupName=>$group) {
        foreach (($group['members'] ?? []) as $uid) {
            $uid=trim((string)$uid);
            if ($uid==='' || !isset($usersByUid[$uid])) continue;
            $users[$usersByUid[$uid]]['groups'][]=(string)$groupName;
        }
    }
    foreach ($users as &$user) {
        $user['groups']=array_values(array_unique(array_filter(array_map(static fn($value): string=>trim((string)$value),$user['groups'] ?? []),static fn(string $value): bool=>$value!=='')));
        natcasesort($user['groups']);
        $user['groups']=array_values($user['groups']);
    }
    unset($user);
}

function access_agent_inventory_by_firewall(): array
{
    $rows=db()->query('SELECT * FROM agents WHERE firewall_id IS NOT NULL ORDER BY id DESC')->fetchAll();
    $result=[];
    foreach ($rows as $agent) {
        $fid=(int)($agent['firewall_id'] ?? 0);
        if ($fid<=0 || isset($result[$fid])) continue;
        if ((int)($agent['enabled'] ?? 0)!==1) continue;
        $version=trim((string)($agent['last_version'] ?? ''));
        if ($version==='' || version_compare($version,'0.1.11','<')) continue;
        $lastSeen=!empty($agent['last_seen_at']) ? (strtotime((string)$agent['last_seen_at']) ?: 0) : 0;
        if ($lastSeen<=0 || (time()-$lastSeen)>=300) continue;
        $payload=json_decode((string)($agent['last_payload'] ?? ''),true);
        $inventory=is_array($payload) ? ($payload['access_inventory'] ?? null) : null;
        if (!is_array($inventory) || ($inventory['ok'] ?? false)!==true) continue;
        $users=is_array($inventory['users'] ?? null) ? $inventory['users'] : [];
        $groups=is_array($inventory['groups'] ?? null) ? $inventory['groups'] : [];
        if ($users===[] && $groups===[]) continue;
        foreach ($users as &$user) {
            if (!is_array($user)) $user=[];
            $user['groups']=is_array($user['groups'] ?? null) ? array_values($user['groups']) : [];
            $user['privileges']=is_array($user['privileges'] ?? null) ? array_values($user['privileges']) : [];
            $user['authorized_keys']='';
            $user['has_authorized_keys']=!empty($user['has_authorized_keys']);
        }
        unset($user);
        foreach ($groups as &$group) {
            if (!is_array($group)) $group=[];
            $group['members']=is_array($group['members'] ?? null) ? array_values($group['members']) : [];
            $group['privileges']=is_array($group['privileges'] ?? null) ? array_values($group['privileges']) : [];
        }
        unset($group);
        access_reconcile_memberships($users,$groups);
        $result[$fid]=['users'=>$users,'groups'=>$groups,'collected_at'=>(string)($inventory['collected_at'] ?? ''),'agent_version'=>$version];
    }
    return $result;
}

function access_load_fleet_inventory(array $firewalls): array
{
    if ($firewalls===[]) return [];
    $agentInventory=access_agent_inventory_by_firewall();
    $requests=[];
    foreach ($firewalls as $firewall) {
        $id=(int)$firewall['id'];
        if (isset($agentInventory[$id])) continue;
        $requests[$id]=['firewall'=>$firewall,'path'=>'core/backup/download/this','timeout'=>60];
    }
    $downloads=$requests!==[] ? opn_downloads_parallel($requests) : [];
    $result=[];
    foreach ($firewalls as $firewall) {
        $id=(int)$firewall['id'];
        if (isset($agentInventory[$id])) {
            $result[$id]=['firewall'=>$firewall,'ok'=>true,'users'=>$agentInventory[$id]['users'],'groups'=>$agentInventory[$id]['groups'],'error'=>'','normalized_escaped_xml'=>false,'source'=>'agent','source_note'=>'Agent '.$agentInventory[$id]['agent_version'].' local config'];
            continue;
        }
        $download=$downloads[$id] ?? ['ok'=>false,'error'=>'No response.'];
        $entry=['firewall'=>$firewall,'ok'=>false,'users'=>[],'groups'=>[],'error'=>'','normalized_escaped_xml'=>false,'source'=>'backup_api','source_note'=>'OPNsense backup API'];
        if (($download['ok'] ?? false)!==true) {
            $entry['error']=(string)($download['error'] ?? 'Could not read configuration.');
            $result[$id]=$entry;
            continue;
        }
        try {
            $normalization=access_normalize_config_xml((string)($download['value'] ?? ''));
            $entry['normalized_escaped_xml']=(bool)$normalization['decoded_escaped_xml'];
            libxml_use_internal_errors(true);
            libxml_clear_errors();
            $xml=simplexml_load_string((string)$normalization['xml'],SimpleXMLElement::class,LIBXML_NONET|LIBXML_NOCDATA);
            if (!$xml instanceof SimpleXMLElement) {
                $errors=libxml_get_errors();
                $detail=$errors ? trim((string)$errors[0]->message) : 'unknown XML parser error';
                libxml_clear_errors();
                throw new RuntimeException('Could not parse OPNsense configuration XML: '.$detail);
            }
            if (strcasecmp($xml->getName(),'opnsense')!==0) throw new RuntimeException('Backup endpoint did not return an OPNsense configuration document.');
            $entry['users']=access_parse_users($xml);
            $entry['groups']=access_parse_groups($xml);
            if ($entry['users']===[] && $entry['groups']===[]) throw new RuntimeException('Configuration XML is valid, but contains no System Access users or groups. Agent 0.1.11+ will read Access inventory locally instead.');
            access_reconcile_memberships($entry['users'],$entry['groups']);
            $entry['ok']=true;
        } catch (Throwable $exception) {
            $entry['error']=$exception->getMessage();
        }
        $result[$id]=$entry;
    }
    return $result;
}
