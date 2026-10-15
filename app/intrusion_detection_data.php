<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

$grid = ['current'=>1,'rowCount'=>250,'searchPhrase'=>''];
$views = [
    'administration' => ['title'=>'Administration','requests'=>[
        ['path'=>'ids/settings/get','method'=>'GET','payload'=>null],
    ]],
    'download' => ['title'=>'Download','requests'=>[
        ['path'=>'ids/settings/list_rulesets','method'=>'GET','payload'=>null],
        ['path'=>'ids/settings/get_rulesetproperties','method'=>'GET','payload'=>null],
    ]],
    'policies' => ['title'=>'Policies','requests'=>[
        ['path'=>'ids/settings/search_policy','method'=>'POST','payload'=>$grid],
    ]],
    'rules' => ['title'=>'Rules','requests'=>[
        ['path'=>'ids/settings/search_installed_rules','method'=>'POST','payload'=>$grid],
    ]],
    'user-defined' => ['title'=>'User defined','requests'=>[
        ['path'=>'ids/settings/search_user_rule','method'=>'POST','payload'=>$grid],
    ]],
    'alerts' => ['title'=>'Alerts','requests'=>[
        ['path'=>'ids/service/query_alerts','method'=>'POST','payload'=>$grid],
        ['path'=>'ids/service/get_alert_logs','method'=>'GET','payload'=>null],
    ]],
    'schedule' => ['title'=>'Schedule','requests'=>[
        ['path'=>'cron/settings/search_jobs','method'=>'POST','payload'=>$grid],
    ]],
    'log-file' => ['title'=>'Log File','requests'=>[
        ['path'=>'ids/service/get_alert_logs','method'=>'GET','payload'=>null],
    ]],
];

function ids_scalar(mixed $value): string
{
    if ($value === null) return '';
    if (is_bool($value)) return $value ? '1' : '0';
    if (is_string($value) || is_int($value) || is_float($value)) return trim((string)$value);
    if (!is_array($value)) return '';

    foreach ($value as $key=>$item) {
        if (is_array($item) && ids_bool($item['selected'] ?? false)) {
            if (is_string($key) && $key !== '') return $key;
            foreach (['value','name','id'] as $field) {
                if (isset($item[$field]) && !is_array($item[$field])) return trim((string)$item[$field]);
            }
        }
    }
    foreach (['value','selected','name','id'] as $field) {
        if (isset($value[$field]) && !is_array($value[$field])) {
            $text=trim((string)$value[$field]);
            if ($text !== '') return $text;
        }
    }
    return '';
}

function ids_bool(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    if (is_array($value)) $value=ids_scalar($value);
    return in_array(strtolower(trim((string)$value)), ['1','true','yes','on','enabled','selected'], true);
}

function ids_list_text(mixed $value): string
{
    if (!is_array($value)) return ids_scalar($value);
    $items=[];
    foreach ($value as $key=>$item) {
        if (is_array($item) && ids_bool($item['selected'] ?? false) && is_string($key)) $items[]=$key;
        elseif (!is_array($item) && trim((string)$item)!=='') $items[]=trim((string)$item);
    }
    return implode(', ', array_values(array_unique($items)));
}

function ids_rows(array $value): array
{
    if (isset($value['rows']) && is_array($value['rows'])) {
        return $value['rows'];
    }
    foreach (['rulesets','items','data','logs'] as $key) {
        if (isset($value[$key]) && is_array($value[$key])) {
            return array_is_list($value[$key])
                ? $value[$key]
                : array_map(
                    static fn(string|int $name, mixed $item): array =>
                        is_array($item)
                            ? ['id'=>(string)$name] + $item
                            : ['id'=>(string)$name,'value'=>$item],
                    array_keys($value[$key]),
                    array_values($value[$key])
                );
        }
    }
    foreach ($value as $candidate) {
        if (is_array($candidate) && array_is_list($candidate)) {
            return $candidate;
        }
    }
    return [$value];
}

try {
    $view = (string) ($_GET['view'] ?? 'administration');
    if (!isset($views[$view])) {
        throw new RuntimeException('Unknown Intrusion Detection view.');
    }

    $firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
    $output = [];

    foreach ($firewalls as $firewall) {
        $entry = [
            'id'=>(int)$firewall['id'],
            'name'=>(string)$firewall['name'],
            'base_url'=>(string)$firewall['base_url'],
            'ok'=>false,
            'endpoint'=>null,
            'rows'=>[],
            'ids_enabled'=>null,
            'ids_mode'=>'',
            'ids_interfaces'=>'',
            'ids_promisc'=>null,
            'ids_homenet'=>'',
            'ids_detection_profile'=>'',
            'interface_options'=>[],
            'error'=>null,
        ];
        $errors = [];

        foreach ($views[$view]['requests'] as $request) {
            try {
                $value = opn_raw_request(
                    $firewall,
                    $request['path'],
                    $request['method'],
                    $request['payload'],
                    20
                );
                $entry['ok'] = true;
                $entry['endpoint'] = $request['path'];
                $entry['rows'] = ids_rows($value);
                if ($view === 'administration') {
                    $general = is_array($value['ids']['general'] ?? null) ? $value['ids']['general'] : [];
                    $entry['ids_enabled'] = ids_bool($general['enabled'] ?? false);
                    $entry['ids_mode'] = ids_scalar($general['mode'] ?? '');
                    $entry['ids_interfaces'] = ids_list_text($general['interfaces'] ?? '');
                    $entry['ids_promisc'] = ids_bool($general['promisc'] ?? false);
                    $entry['ids_homenet'] = ids_list_text($general['homenet'] ?? '');
                    $entry['ids_detection_profile'] = ids_scalar($general['detect']['Profile'] ?? '');
                    try {
                        $interfaceMap = opn_raw_request(
                            $firewall,
                            'diagnostics/interface/get_interface_names',
                            'GET',
                            null,
                            15
                        );
                        foreach ($interfaceMap as $ifName=>$ifDescription) {
                            if (!is_string($ifName) || $ifName === '') continue;
                            if (is_array($ifDescription)) {
                                $ifDescription = ids_scalar($ifDescription);
                            }
                            $entry['interface_options'][] = [
                                'value'=>$ifName,
                                'label'=>trim((string)$ifDescription) !== '' ? trim((string)$ifDescription) : $ifName,
                            ];
                        }
                    } catch (Throwable $ignored) {
                        // Existing selections remain editable even if interface-name lookup is unavailable.
                    }
                }
                break;
            } catch (Throwable $exception) {
                $errors[] = $request['path'] . ': ' . $exception->getMessage();
            }
        }

        if (!$entry['ok']) {
            $entry['error'] = implode(' | ', $errors)
                ?: 'No supported IDS API endpoint returned data.';
        }
        $output[] = $entry;
    }

    echo json_encode([
        'ok'=>true,
        'view'=>$view,
        'title'=>$views[$view]['title'],
        'firewalls'=>$output,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode(
        ['ok'=>false,'error'=>$exception->getMessage()],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
