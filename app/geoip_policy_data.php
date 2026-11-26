<?php
declare(strict_types=1);

/**
 * Read-only inspection of GeoIP policy. Never infer actual packet filtering
 * from an alias definition alone.
 */
require_once __DIR__.'/inc/config.php';
require_once __DIR__.'/inc/opnsense.php';
require_once __DIR__.'/inc/alias_central.php';
require_login();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
if (session_status() === PHP_SESSION_ACTIVE) session_write_close();

function geoip_inspect_rows(array $response): array
{
    if (!isset($response['rows']) || !is_array($response['rows'])) {
        throw new RuntimeException('Unexpected OPNsense search response (rows missing).');
    }
    return $response['rows'];
}

function geoip_inspect_value(mixed $value): string
{
    if (is_array($value)) return central_alias_scalar($value);
    return is_scalar($value) ? trim((string)$value) : '';
}

function geoip_inspect_alias_ref(mixed $value, array $names): array
{
    // Match exact configured alias identifiers (no fuzzy substring matching).
    $found = [];
    $visit = function(mixed $item) use (&$visit,&$found,$names): void {
        if (is_array($item)) {
            foreach ($item as $key=>$value) {
                if (is_string($key) && isset($names[strtolower($key)])) {
                    if (!is_array($value) || !array_key_exists('selected',$value)
                        || in_array($value['selected'], [true,1,'1','true'],true)) {
                        $found[strtolower($key)] = $names[strtolower($key)];
                    }
                }
                $visit($value);
            }
        } elseif (is_string($item)) {
            foreach (preg_split('/[\s,;{}]+/',trim($item)) ?: [] as $part) {
                $candidate = strtolower(trim($part, " !()[]\"'"));
                if (isset($names[$candidate])) $found[$candidate]=$names[$candidate];
            }
        }
    };
    $visit($value);
    return array_values($found);
}

function geoip_inspect_rules_api(array $firewall, array $names): array
{
    $response=opn_raw_request($firewall,'firewall/filter/search_rule?current=1&rowCount=-1','GET',null,30);
    $items=[];
    foreach (geoip_inspect_rows($response) as $rule) {
        if (!is_array($rule)) continue;
        $source=$rule['source_net'] ?? $rule['source'] ?? '';
        $destination=$rule['destination_net'] ?? $rule['destination'] ?? '';
        $src=geoip_inspect_alias_ref($source,$names);
        $dst=geoip_inspect_alias_ref($destination,$names);
        if ($src===[] && $dst===[]) continue;
        $items[]=[
            'origin'=>'Firewall filter API',
            'description'=>geoip_inspect_value($rule['description'] ?? $rule['descr'] ?? ''),
            'action'=>geoip_inspect_value($rule['type'] ?? ''),
            'enabled'=>geoip_inspect_value($rule['enabled'] ?? ''),
            'interface'=>geoip_inspect_value($rule['interface'] ?? ''),
            'direction'=>geoip_inspect_value($rule['direction'] ?? ''),
            'source'=>geoip_inspect_value($source),
            'destination'=>geoip_inspect_value($destination),
            'matched_source'=>$src,
            'matched_destination'=>$dst,
        ];
    }
    return $items;
}

function geoip_inspect_rules_legacy(array $firewall, array $names): array
{
    $raw=opn_download($firewall,'core/backup/download/this');
    libxml_use_internal_errors(true);
    $xml=simplexml_load_string($raw,SimpleXMLElement::class,LIBXML_NONET|LIBXML_NOCDATA);
    if (!$xml instanceof SimpleXMLElement || strcasecmp($xml->getName(),'opnsense')!==0) {
        throw new RuntimeException('Invalid OPNsense configuration backup XML.');
    }
    $items=[];
    foreach (($xml->xpath('/opnsense/filter/rule') ?: []) as $rule) {
        $source=trim((string)($rule->source->address ?? ''));
        $destination=trim((string)($rule->destination->address ?? ''));
        $src=geoip_inspect_alias_ref($source,$names);
        $dst=geoip_inspect_alias_ref($destination,$names);
        if ($src===[] && $dst===[]) continue;
        $items[]=[
            'origin'=>'Legacy configuration',
            'description'=>trim((string)($rule->descr ?? '')),
            'action'=>trim((string)($rule->type ?? '')),
            'enabled'=>isset($rule->disabled) ? '0' : '1',
            'interface'=>trim((string)($rule->interface ?? '')),
            'direction'=>trim((string)($rule->direction ?? '')),
            'source'=>$source,
            'destination'=>$destination,
            'matched_source'=>$src,
            'matched_destination'=>$dst,
        ];
    }
    return $items;
}

try {
    $id=filter_input(INPUT_GET,'firewall_id',FILTER_VALIDATE_INT);
    if (!$id || $id<=0) throw new RuntimeException('Select an OPNsense firewall.');
    $firewall=firewall_by_id($id);

    $response=opn_raw_request($firewall,'firewall/alias/search_item','POST',[
        'current'=>1,'rowCount'=>-1,'searchPhrase'=>'','sort'=>new stdClass()
    ],30);
    $aliases=[]; $names=[];
    foreach (geoip_inspect_rows($response) as $row) {
        if (!is_array($row)) continue;
        $name=trim((string)($row['name'] ?? ''));
        $uuid=trim((string)($row['uuid'] ?? ''));
        if ($name==='' || $uuid==='') continue;
        $type=strtolower(geoip_inspect_value($row['type'] ?? ''));
        $isGeoIP=$type==='geoip' || str_contains($type,'geoip');
        // Catch names such as GeoIP_Block, BlockedCountries, AllowList, GeoIPExceptions.
        // This is a candidate selector, NOT a policy classification.
        $isPolicyName=(bool)preg_match('/geo.?ip|block|allow|except|white.?list|black.?list/i',$name);
        if (!$isGeoIP && !$isPolicyName) continue;
        $details=opn_raw_request($firewall,'firewall/alias/get_item/'.rawurlencode($uuid),'GET',null,20);
        $model=$details['alias'] ?? null;
        if (!is_array($model)) throw new RuntimeException('Invalid alias details for '.$name);
        $normalized=central_alias_normalize_remote($model);
        $actualType=strtolower(geoip_inspect_value($normalized['type'] ?? $type));
        $entry=[
            'name'=>$name,'uuid'=>$uuid,'type'=>$actualType,
            'enabled'=>geoip_inspect_value($normalized['enabled'] ?? $row['enabled'] ?? ''),
            'description'=>geoip_inspect_value($normalized['description'] ?? ''),
            'content'=>(string)($normalized['content'] ?? ''),
            'geoip'=>$actualType==='geoip' || str_contains($actualType,'geoip')
        ];
        $aliases[]=$entry;
        $names[strtolower($name)]=$name;
    }
    usort($aliases,static fn($a,$b)=>strnatcasecmp($a['name'],$b['name']));
    $rules=[]; $warnings=[];
    if ($names!==[]) {
        $apiWorked = false;
        try {
            $rules=geoip_inspect_rules_api($firewall,$names);
            $apiWorked = true;
        } catch (Throwable $e) {
            $warnings[]='Firewall filter API unavailable: '.$e->getMessage();
        }
        // The OPNsense filter API already includes legacy/internal rules.
        // Consult legacy XML only as a fallback, never count both sources as
        // independent copies of the same rule.
        if (!$apiWorked || $rules===[]) {
            try {
                $fallback=geoip_inspect_rules_legacy($firewall,$names);
                if ($fallback!==[]) $rules=$fallback;
            } catch (Throwable $e) {
                $warnings[]='Legacy rule fallback unavailable: '.$e->getMessage();
            }
        }
    }
    echo json_encode(['ok'=>true,'firewall'=>$firewall['name'],'aliases'=>$aliases,
        'rules'=>$rules,'warnings'=>$warnings,
        'note'=>'Configured aliases and rule references only. This is not verification of active packet filtering.'],
        JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>$e->getMessage()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
