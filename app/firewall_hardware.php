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
    if (is_string($value) && ctype_digit(trim($value))) {
        $number = (int)trim($value);
        return $number > 0 ? $number : null;
    }
    return null;
}

function hardware_fallback(array $firewall): array
{
    $result = [
        'ok' => true,
        'source' => 'opnsense-core',
        'plugin_available' => false,
        'system' => ['manufacturer'=>'','model'=>'','revision'=>'','serial'=>''],
        'baseboard' => ['manufacturer'=>'','model'=>'','revision'=>''],
        'bios' => ['vendor'=>'','version'=>'','date'=>''],
        'cpu' => ['model'=>'','packages'=>null,'cores'=>null,'logical_cpus'=>null],
        'memory' => ['total_bytes'=>null],
        'disks' => [],
        'collected_at' => gmdate('c'),
    ];

    try {
        $resources = opn_request($firewall, 'diagnostics/system/system_resources', 'GET', [], 15);
        $result['memory']['total_bytes'] = hardware_bytes($resources['memory']['total'] ?? null);
    } catch (Throwable) {
    }

    try {
        $disk = opn_request($firewall, 'diagnostics/system/system_disk', 'GET', [], 15);
        foreach (($disk['devices'] ?? []) as $device) {
            if (!is_array($device)) continue;
            $blocks = hardware_bytes($device['blocks'] ?? null);
            $result['disks'][] = [
                'name' => trim((string)($device['device'] ?? '')),
                'model' => trim((string)($device['type'] ?? '')),
                'serial' => '',
                'size_bytes' => $blocks !== null ? $blocks * 1024 : 0,
                'mountpoint' => trim((string)($device['mountpoint'] ?? '')),
                'used_pct' => $device['used_pct'] ?? null,
            ];
        }
    } catch (Throwable) {
    }

    return $result;
}

try {
    $id = (int)($_GET['id'] ?? 0);
    if ($id < 1) throw new RuntimeException('Invalid firewall ID.');
    $firewall = firewall_by_id($id);

    try {
        $hardware = opn_request($firewall, 'opnsentralagent/hardware/get', 'GET', [], 15);
        if (($hardware['ok'] ?? false) !== true) throw new RuntimeException('Hardware API returned an invalid response.');
        $hardware['source'] = 'opnsentral-agent-plugin';
        $hardware['plugin_available'] = true;
        echo json_encode(['ok'=>true,'hardware'=>$hardware], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
        exit;
    } catch (Throwable $pluginError) {
        $fallback = hardware_fallback($firewall);
        $fallback['plugin_error'] = $pluginError->getMessage();
        echo json_encode(['ok'=>true,'hardware'=>$fallback], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
    }
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>$exception->getMessage()], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
