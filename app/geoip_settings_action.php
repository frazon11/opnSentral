<?php
declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function geoip_success(array $response): bool
{
    if (isset($response['error']) && trim((string)$response['error']) !== '') return false;
    foreach (['result', 'status'] as $key) {
        if (!array_key_exists($key, $response)) continue;
        return in_array(strtolower(trim((string)$response[$key])), ['1','true','ok','saved','success','done','updated'], true);
    }
    return true;
}

function geoip_find_url(mixed $value): ?string
{
    if (!is_array($value)) return null;
    foreach ($value as $key => $child) {
        if (strtolower((string)$key) === 'url' && !is_array($child)) {
            return trim((string)$child);
        }
    }
    foreach ($value as $child) {
        $found = geoip_find_url($child);
        if ($found !== null) return $found;
    }
    return null;
}

function geoip_set_url_in_model(array &$value, string $url): bool
{
    foreach ($value as $key => &$child) {
        if (strtolower((string)$key) === 'url' && !is_array($child)) {
            $child = $url;
            return true;
        }
    }
    unset($child);
    foreach ($value as &$child) {
        if (is_array($child) && geoip_set_url_in_model($child, $url)) return true;
    }
    unset($child);
    return false;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    require_csrf();
    require_configuration_unlocked();

    $action = strtolower(trim((string)($_POST['action'] ?? '')));
    if (!in_array($action, ['save', 'update'], true)) throw new RuntimeException('Unsupported GeoIP action.');

    $ids = array_values(array_unique(array_filter(
        array_map('intval', (array)($_POST['firewall_ids'] ?? [])),
        static fn(int $id): bool => $id > 0
    )));
    if ($ids === []) throw new RuntimeException('Select at least one OPNsense firewall.');

    $url = trim((string)($_POST['url'] ?? ''));
    if ($action === 'save' && $url !== '' && filter_var($url, FILTER_VALIDATE_URL) === false) {
        throw new RuntimeException('Enter a valid GeoIP URL, including https:// or http://.');
    }

    $marks = implode(',', array_fill(0, count($ids), '?'));
    $stmt = db()->prepare('SELECT * FROM firewalls WHERE id IN (' . $marks . ') ORDER BY name');
    $stmt->execute($ids);
    $firewalls = $stmt->fetchAll();
    $results = [];

    foreach ($firewalls as $firewall) {
        $entry = ['id'=>(int)$firewall['id'], 'name'=>(string)$firewall['name'], 'ok'=>false, 'message'=>''];
        try {
            if ($action === 'save') {
                backup_before_change($firewall, 'geoip-settings');
                $current = opn_raw_request($firewall, 'firewall/alias/get_geo_i_p', 'GET', null, 20);
                $payload = $current;
                if (!geoip_set_url_in_model($payload, $url)) {
                    $payload = ['alias' => ['geoip' => ['url' => $url]]];
                }

                $response = opn_raw_request($firewall, 'firewall/alias/set', 'POST', $payload, 30);
                if (!geoip_success($response)) {
                    throw new RuntimeException('OPNsense rejected the GeoIP URL: ' . json_encode($response));
                }

                $verified = opn_raw_request($firewall, 'firewall/alias/get_geo_i_p', 'GET', null, 20);
                $actual = geoip_find_url($verified);
                if ($actual === null || $actual !== $url) {
                    throw new RuntimeException('GeoIP URL read-back verification failed. OPNsense returned: ' . ($actual ?? 'no URL'));
                }
                $entry['message'] = 'GeoIP URL saved and verified.';
            } else {
                $response = opn_raw_request($firewall, 'firewall/alias/update/geoip', 'POST', [], 120);
                if (!geoip_success($response)) {
                    throw new RuntimeException('OPNsense rejected the GeoIP update: ' . json_encode($response));
                }
                $entry['message'] = 'GeoIP update started successfully.';
            }
            $entry['ok'] = true;
        } catch (Throwable $exception) {
            $entry['message'] = $exception->getMessage();
        }
        $results[] = $entry;
    }

    echo json_encode(['ok'=>true, 'results'=>$results], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok'=>false, 'error'=>$exception->getMessage()], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
