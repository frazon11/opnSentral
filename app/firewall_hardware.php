<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

function hardware_bytes(mixed $value): ?int
{
    if (is_int($value)) return $value > 0 ? $value : null;
    if (is_float($value)) return $value > 0 ? (int)$value : null;
    if (is_string($value)) {
        $value = trim($value);
        if (ctype_digit($value)) {
            $number = (int)$value;
            return $number > 0 ? $number : null;
        }
    }
    return null;
}

function hardware_string(mixed $value): string
{
    if (!is_scalar($value)) return '';
    $value = trim((string)$value);
    if ($value === '') return '';
    if (in_array(strtolower($value), ['unknown', 'not specified', 'to be filled by o.e.m.', 'none', '<null>'], true)) return '';
    return substr($value, 0, 255);
}

function hardware_ci_value(array $row, array $names): string
{
    foreach ($row as $key => $value) {
        $normalized = strtolower(preg_replace('/[^a-z0-9]+/i', '', (string)$key) ?? '');
        foreach ($names as $name) {
            $wanted = strtolower(preg_replace('/[^a-z0-9]+/i', '', $name) ?? '');
            if ($normalized === $wanted) return hardware_string($value);
        }
    }
    return '';
}

function hardware_cpu(array $firewall): array
{
    $result = ['available'=>false,'model'=>'','cores'=>null,'logical_cpus'=>null,'error'=>''];
    try {
        $payload = opn_request($firewall, 'diagnostics/cpu_usage/getcputype', 'GET', [], 15);
        $text = '';
        if (array_is_list($payload)) $text = hardware_string($payload[0] ?? '');
        elseif (isset($payload['0'])) $text = hardware_string($payload['0']);
        elseif (isset($payload['cpu'])) $text = hardware_string($payload['cpu']);

        if ($text !== '') {
            $model = $text;
            if (preg_match('/^(.*?)\s*\((\d+)\s+cores?,\s*(\d+)\s+threads?\)\s*$/i', $text, $match)) {
                $model = trim($match[1]);
                $result['cores'] = (int)$match[2];
                $result['logical_cpus'] = (int)$match[3];
            }
            $result['model'] = $model;
            $result['available'] = true;
        }
    } catch (Throwable $exception) {
        $result['error'] = $exception->getMessage();
    }
    return $result;
}

function hardware_memory(array $firewall): array
{
    $result = ['available'=>false,'total_bytes'=>null,'error'=>''];
    try {
        $resources = opn_request($firewall, 'diagnostics/system/system_resources', 'GET', [], 15);
        $bytes = hardware_bytes($resources['memory']['total'] ?? null);
        if ($bytes !== null) {
            $result['available'] = true;
            $result['total_bytes'] = $bytes;
        }
    } catch (Throwable $exception) {
        $result['error'] = $exception->getMessage();
    }
    return $result;
}

function hardware_dmidecode(array $firewall): array
{
    $result = [
        'available'=>false,
        'system'=>['manufacturer'=>'','model'=>'','revision'=>'','serial'=>'','family'=>''],
        'bios'=>['vendor'=>'','version'=>'','date'=>''],
        'error'=>'',
    ];

    try {
        $payload = opn_request($firewall, 'dmidecode/service/get', 'GET', [], 15);
        if (strtolower((string)($payload['status'] ?? '')) !== 'ok') {
            throw new RuntimeException('os-dmidecode returned an invalid status.');
        }
        $system = is_array($payload['system'] ?? null) ? $payload['system'] : [];
        $bios = is_array($payload['bios'] ?? null) ? $payload['bios'] : [];
        $result['system'] = [
            'manufacturer' => hardware_ci_value($system, ['Manufacturer']),
            'model' => hardware_ci_value($system, ['Product Name', 'Product']),
            'revision' => hardware_ci_value($system, ['Version']),
            'serial' => hardware_ci_value($system, ['Serial Number', 'Serial']),
            'family' => hardware_ci_value($system, ['Family']),
        ];
        $result['bios'] = [
            'vendor' => hardware_ci_value($bios, ['Vendor']),
            'version' => hardware_ci_value($bios, ['Version']),
            'date' => hardware_ci_value($bios, ['Release Date', 'Release']),
        ];
        $result['available'] = true;
    } catch (Throwable $exception) {
        $result['error'] = $exception->getMessage();
    }
    return $result;
}

function hardware_storage(array $firewall): array
{
    $result = ['available'=>false,'used_pct'=>null,'device'=>'','mountpoint'=>'','error'=>''];
    try {
        // OPNsense core endpoint: this is filesystem usage (df), which is exactly
        // what the Dashboard "Storage" percentage represents. It is not used as
        // physical HDD/SSD identity information.
        $payload = opn_request($firewall, 'diagnostics/system/system_disk', 'GET', [], 15);
        $devices = is_array($payload['devices'] ?? null) ? $payload['devices'] : [];
        $selected = null;
        foreach ($devices as $device) {
            if (!is_array($device)) continue;
            if (trim((string)($device['mountpoint'] ?? '')) === '/') {
                $selected = $device;
                break;
            }
        }
        if ($selected === null) {
            foreach ($devices as $device) {
                if (is_array($device)) {
                    $selected = $device;
                    break;
                }
            }
        }
        if ($selected !== null) {
            $rawPct = trim((string)($selected['used_pct'] ?? ''));
            $rawPct = rtrim($rawPct, "% \t\r\n");
            if (is_numeric($rawPct)) {
                $pct = max(0.0, min(100.0, (float)$rawPct));
                $result['available'] = true;
                $result['used_pct'] = $pct;
                $result['device'] = hardware_string($selected['device'] ?? '');
                $result['mountpoint'] = hardware_string($selected['mountpoint'] ?? '');
            }
        }
    } catch (Throwable $exception) {
        $result['error'] = $exception->getMessage();
    }
    return $result;
}

try {
    $id = (int)($_GET['id'] ?? 0);
    if ($id < 1) throw new RuntimeException('Invalid firewall ID.');
    $firewall = firewall_by_id($id);

    $dmi = hardware_dmidecode($firewall);
    $cpu = hardware_cpu($firewall);
    $memory = hardware_memory($firewall);
    $storage = hardware_storage($firewall);

    echo json_encode([
        'ok'=>true,
        'hardware'=>[
            'source'=>'opnsense-official-apis',
            'system'=>$dmi['system'],
            'bios'=>$dmi['bios'],
            'cpu'=>[
                'model'=>$cpu['model'],
                'cores'=>$cpu['cores'],
                'logical_cpus'=>$cpu['logical_cpus'],
            ],
            'memory'=>['total_bytes'=>$memory['total_bytes']],
            'storage'=>[
                'used_pct'=>$storage['used_pct'],
                'device'=>$storage['device'],
                'mountpoint'=>$storage['mountpoint'],
            ],
            'availability'=>[
                'dmidecode'=>$dmi['available'],
                'cpu'=>$cpu['available'],
                'memory'=>$memory['available'],
                'storage'=>$storage['available'],
            ],
            'errors'=>[
                'dmidecode'=>$dmi['error'],
                'cpu'=>$cpu['error'],
                'memory'=>$memory['error'],
                'storage'=>$storage['error'],
            ],
            'collected_at'=>gmdate('c'),
        ],
    ], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>$exception->getMessage()], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
