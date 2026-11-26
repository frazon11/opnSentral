<?php
declare(strict_types=1);

/*
 * Isolated GeoIP inspection tests. These do not call a firewall.
 * Tests use the real parsing and matching functions from the inspected page.
 */
$source = file_get_contents(dirname(__DIR__).'/app/geoip_policy_data.php');
if (!is_string($source)) throw new RuntimeException('Missing GeoIP source.');
$start = strpos($source,'function geoip_inspect_rows(');
$end = strpos($source,"\ntry {\n    \$id=filter_input", $start);
if ($start===false || $end===false) throw new RuntimeException('Could not isolate GeoIP helper functions.');
eval(substr($source,$start,$end-$start));

function check(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException('GeoIP test failed: '.$message);
}
function central_alias_scalar(mixed $value): string {
    return is_array($value) ? (string)array_key_first($value) : (string)$value;
}
function opn_raw_request(array $firewall,string $path,string $method='GET',?array $payload=null,int $timeout=20): array {
    if (str_starts_with($path,'firewall/filter/search_rule')) return ['rows'=>[
        ['description'=>'GeoIP WAN blocked','type'=>'block','enabled'=>'1',
         'source_net'=>'GeoIP_Block','destination_net'=>'any','interface'=>'wan','direction'=>'in'],
        ['description'=>'Unrelated','type'=>'pass','source_net'=>'unrelated',
         'destination_net'=>'any'],
    ]];
    throw new RuntimeException('Unexpected test request: '.$path);
}
function opn_download(array $firewall,string $path): string {
    return <<<'XML'
<opnsense><filter>
  <rule><type>block</type><interface>wan</interface>
    <descr>Block GeoIP</descr><source><address>GeoIP_Block</address></source>
    <destination><any/></destination></rule>
  <rule><type>pass</type><interface>wan</interface>
    <descr>GeoIP exception</descr><source><address>GeoIP_Allow</address></source>
    <destination><any/></destination></rule>
  <rule><type>pass</type><interface>lan</interface>
    <descr>Unrelated</descr><source><address>GeoIP_BlockExtra</address></source>
    <destination><any/></destination></rule>
</filter></opnsense>
XML;
}

$names=['geoip_block'=>'GeoIP_Block','geoip_allow'=>'GeoIP_Allow'];
check(geoip_inspect_alias_ref('GeoIP_Block',$names)===['GeoIP_Block'],'exact reference');
check(geoip_inspect_alias_ref('GeoIP_BlockExtra',$names)===[],'no substring matches');
check(geoip_inspect_alias_ref('!GeoIP_Block',$names)===['GeoIP_Block'],'negated alias captured');

$rules=geoip_inspect_rules_api([], $names);
check(count($rules)===1,'automation filters unrelated rules');
check($rules[0]['action']==='block','automation block action preserved');
check($rules[0]['matched_source']===['GeoIP_Block'],'automation source ref preserved');

$legacy=geoip_inspect_rules_legacy([], $names);
check(count($legacy)===2,'legacy XML finds block and exception, excludes substrings');
check($legacy[0]['action']==='block','legacy block rule identified');
check($legacy[1]['matched_source']===['GeoIP_Allow'],'legacy allow alias identified');
check($legacy[0]['enabled']==='1','legacy enabled correct');
check(geoip_inspect_rows(['rows'=>[]])===[],'empty response works');
try { geoip_inspect_rows(['bad'=>true]); throw new RuntimeException('Invalid response accepted'); }
catch (RuntimeException $e) { check(str_contains($e->getMessage(),'rows missing'),'bad responses are flagged'); }
echo "GeoIP alias matching, MVC rules and legacy XML tests passed.\n";
