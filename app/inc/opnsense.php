<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/managed_category.php';
require_once __DIR__ . '/network_settings.php';

function firewall_by_id(int $id): array
{
    $statement = db()->prepare('SELECT * FROM firewalls WHERE id = ?');
    $statement->execute([$id]);
    $firewall = $statement->fetch();

    if (!$firewall) {
        throw new RuntimeException('Firewall not found.');
    }

    return $firewall;
}

function opn_request_is_read_only(
    string $path,
    string $method
): bool {
    if (strtoupper($method) === 'GET') {
        return true;
    }

    $path = strtolower(trim($path, '/'));

    $readOnlyPatterns = [
        '#(^|/)search(?:_|/|$)#',
        '#(^|/)status(?:/|$)#',
        '#(^|/)get(?:/|$)#',
        '#(^|/)list(?:_|/|$)#',
        '#(^|/)providers(?:/|$)#',
        '#(^|/)sessions?(?:/|$)#',
        '#(^|/)details?(?:/|$)#',
        '#(^|/)check(?:/|$)#',
    ];

    foreach ($readOnlyPatterns as $pattern) {
        if (preg_match($pattern, $path) === 1) {
            return true;
        }
    }

    return false;
}

function require_opn_request_permission(
    string $path,
    string $method
): void {
    if (
        configuration_unlocked() ||
        opn_request_is_read_only($path, $method)
    ) {
        return;
    }

    throw new RuntimeException(
        'opnCentral is locked. Remote configuration changes are disabled.'
    );
}

function opn_raw_request(
    array $firewall,
    string $path,
    string $method = 'GET',
    ?array $payload = null,
    int $timeout = 20
): array {
    $handle = curl_init(
        rtrim((string) $firewall['base_url'], '/') .
        '/api/' .
        ltrim($path, '/')
    );

    if (!$handle instanceof CurlHandle) {
        throw new RuntimeException('Could not initialize cURL.');
    }

    $headers = ['Accept: application/json'];
    $options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERPWD =>
            decrypt_value((string) $firewall['api_key_enc']) .
            ':' .
            decrypt_value((string) $firewall['api_secret_enc']),
        CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
        CURLOPT_IPRESOLVE => opnsense_curl_ipresolve_option(),
        CURLOPT_CONNECTTIMEOUT => min(10, max(1, $timeout)),
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => (bool) $firewall['verify_tls'],
        CURLOPT_SSL_VERIFYHOST =>
            (bool) $firewall['verify_tls'] ? 2 : 0,
    ];

    if (strtoupper($method) === 'POST') {
        $options[CURLOPT_POST] = true;
        $options[CURLOPT_POSTFIELDS] = json_encode(
            $payload ?? new stdClass(),
            JSON_THROW_ON_ERROR
        );
        $headers[] = 'Content-Type: application/json';
    }

    $options[CURLOPT_HTTPHEADER] = $headers;
    curl_setopt_array($handle, $options);

    $body = curl_exec($handle);

    return opn_decode_response($handle, $body);
}

function opn_ensure_managed_category(array $firewall): void
{
    static $ensured = [];
    static $running = false;

    $firewallId = (int) ($firewall['id'] ?? 0);
    $cacheKey = $firewallId > 0
        ? (string) $firewallId
        : (string) ($firewall['base_url'] ?? '');

    if ($running || isset($ensured[$cacheKey])) {
        return;
    }

    $running = true;

    try {
        $name = managed_category_name();
        $search = opn_raw_request(
            $firewall,
            'firewall/category/search_item',
            'POST',
            [
                'current' => 1,
                'rowCount' => 500,
                'searchPhrase' => $name,
            ],
            20
        );

        foreach (($search['rows'] ?? []) as $row) {
            if (
                is_array($row) &&
                strcasecmp(
                    trim((string) ($row['name'] ?? '')),
                    $name
                ) === 0
            ) {
                $ensured[$cacheKey] = true;
                return;
            }
        }

        $response = opn_raw_request(
            $firewall,
            'firewall/category/add_item',
            'POST',
            [
                'category' => [
                    'name' => $name,
                    'color' => managed_category_color(),
                    'auto' => '0',
                ],
            ],
            20
        );

        if (
            isset($response['result']) &&
            !in_array(
                (string) $response['result'],
                ['saved', 'ok'],
                true
            ) &&
            !isset($response['uuid'])
        ) {
            throw new RuntimeException(
                'OPNsense rejected managed category creation: ' .
                json_encode($response)
            );
        }

        $ensured[$cacheKey] = true;
    } finally {
        $running = false;
    }
}

function opn_curl_handle(
    array $firewall,
    string $path,
    string $method = 'GET',
    ?array $payload = null,
    int $timeout = 20
): CurlHandle {
    require_opn_request_permission($path, $method);

    if (!opn_request_is_read_only($path, $method)) {
        opn_ensure_managed_category($firewall);
    }

    $handle = curl_init(
        rtrim((string) $firewall['base_url'], '/') .
        '/api/' .
        ltrim($path, '/')
    );

    if (!$handle instanceof CurlHandle) {
        throw new RuntimeException('Could not initialize cURL.');
    }

    $options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERPWD =>
            decrypt_value((string) $firewall['api_key_enc']) .
            ':' .
            decrypt_value((string) $firewall['api_secret_enc']),
        CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
        CURLOPT_IPRESOLVE => opnsense_curl_ipresolve_option(),
        // DNS resolution is included in cURL's connect timeout.
        // Normal firewall calls may use up to ten seconds to connect.
        CURLOPT_CONNECTTIMEOUT => min(10, max(1, $timeout)),
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => (bool) $firewall['verify_tls'],
        CURLOPT_SSL_VERIFYHOST => (bool) $firewall['verify_tls'] ? 2 : 0,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
    ];

    if (strtoupper($method) === 'POST') {
        $options[CURLOPT_POST] = true;
        $options[CURLOPT_POSTFIELDS] = json_encode(
            $payload ?? new stdClass(),
            JSON_THROW_ON_ERROR
        );
        $options[CURLOPT_HTTPHEADER][] = 'Content-Type: application/json';
    }

    curl_setopt_array($handle, $options);

    return $handle;
}

function opn_decode_response(CurlHandle $handle, string|false $body): array
{
    $error = curl_error($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

    if ($body === false) {
        throw new RuntimeException('Connection failed: ' . $error);
    }

    if ($status < 200 || $status >= 300) {
        throw new RuntimeException(
            'OPNsense API HTTP ' . $status . ': ' . substr($body, 0, 300)
        );
    }

    $decoded = json_decode($body, true);

    return is_array($decoded) ? $decoded : ['raw' => $body];
}

function opn_request(
    array $firewall,
    string $path,
    string $method = 'GET',
    ?array $payload = null,
    int $timeout = 20
): array {
    $handle = opn_curl_handle(
        $firewall,
        $path,
        $method,
        $payload,
        $timeout
    );

    $body = curl_exec($handle);

    return opn_decode_response($handle, $body);
}

/**
 * Execute independent OPNsense API requests concurrently.
 *
 * Each request entry must contain:
 * - firewall
 * - path
 * Optional:
 * - method
 * - payload
 * - timeout
 *
 * Returns keyed result entries:
 * ['ok' => true, 'value' => [...]]
 * or
 * ['ok' => false, 'error' => '...']
 */
function opn_requests_parallel(array $requests): array
{
    if ($requests === []) {
        return [];
    }

    $multi = curl_multi_init();
    $handles = [];
    $results = [];

    try {
        foreach ($requests as $key => $request) {
            try {
                $handle = opn_curl_handle(
                    $request['firewall'],
                    (string) $request['path'],
                    (string) ($request['method'] ?? 'GET'),
                    $request['payload'] ?? null,
                    (int) ($request['timeout'] ?? 20)
                );

                curl_multi_add_handle($multi, $handle);
                $handles[(int) $handle] = [
                    'key' => $key,
                    'handle' => $handle,
                ];
            } catch (Throwable $exception) {
                $results[$key] = [
                    'ok' => false,
                    'error' => $exception->getMessage(),
                ];
            }
        }

        do {
            $status = curl_multi_exec($multi, $running);

            if ($status !== CURLM_OK) {
                throw new RuntimeException(
                    'Parallel cURL execution failed: ' .
                    curl_multi_strerror($status)
                );
            }

            if ($running > 0) {
                $selected = curl_multi_select($multi, 1.0);

                if ($selected === -1) {
                    usleep(10000);
                }
            }
        } while ($running > 0);

        foreach ($handles as $item) {
            $key = $item['key'];
            $handle = $item['handle'];

            try {
                $body = curl_multi_getcontent($handle);
                $results[$key] = [
                    'ok' => true,
                    'value' => opn_decode_response($handle, $body),
                ];
            } catch (Throwable $exception) {
                $results[$key] = [
                    'ok' => false,
                    'error' => $exception->getMessage(),
                ];
            }
        }
    } finally {
        foreach ($handles as $item) {
            curl_multi_remove_handle($multi, $item['handle']);
        }

        curl_multi_close($multi);
    }

    // Preserve the original request order.
    $ordered = [];
    foreach ($requests as $key => $_request) {
        $ordered[$key] = $results[$key] ?? [
            'ok' => false,
            'error' => 'Request did not return a result.',
        ];
    }

    return $ordered;
}

function opn_download(array $firewall, string $path): string
{
    $handle = curl_init(
        rtrim((string) $firewall['base_url'], '/') .
        '/api/' .
        ltrim($path, '/')
    );

    curl_setopt_array($handle, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERPWD =>
            decrypt_value((string) $firewall['api_key_enc']) .
            ':' .
            decrypt_value((string) $firewall['api_secret_enc']),
        CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
        CURLOPT_IPRESOLVE => opnsense_curl_ipresolve_option(),
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT => 60,
        CURLOPT_SSL_VERIFYPEER => (bool) $firewall['verify_tls'],
        CURLOPT_SSL_VERIFYHOST => (bool) $firewall['verify_tls'] ? 2 : 0,
    ]);

    $body = curl_exec($handle);
    $error = curl_error($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

    if ($body === false) {
        throw new RuntimeException('Backup failed: ' . $error);
    }

    if ($status < 200 || $status >= 300) {
        throw new RuntimeException('Backup API HTTP ' . $status);
    }

    return $body;
}

function wireguard_inventory_cache_path(): string
{
    return DATA_DIR . '/wireguard-inventory-cache.json';
}

function invalidate_wireguard_inventory_cache(): void
{
    $path = wireguard_inventory_cache_path();

    if (is_file($path)) {
        @unlink($path);
    }
}


function opn_downloads_parallel(array $requests): array
{
    if ($requests === []) return [];
    $multi = curl_multi_init();
    $handles = [];
    $results = [];

    try {
        foreach ($requests as $key => $request) {
            try {
                $firewall = $request['firewall'];
                $handle = curl_init(
                    rtrim((string) $firewall['base_url'], '/') . '/api/' .
                    ltrim((string) $request['path'], '/')
                );
                if (!$handle instanceof CurlHandle) {
                    throw new RuntimeException('Could not initialize cURL.');
                }
                curl_setopt_array($handle, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_USERPWD => decrypt_value((string)$firewall['api_key_enc']) . ':' . decrypt_value((string)$firewall['api_secret_enc']),
                    CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
                    CURLOPT_IPRESOLVE => opnsense_curl_ipresolve_option(),
                    CURLOPT_CONNECTTIMEOUT => 8,
                    CURLOPT_TIMEOUT => (int)($request['timeout'] ?? 60),
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_SSL_VERIFYPEER => (bool)$firewall['verify_tls'],
                    CURLOPT_SSL_VERIFYHOST => (bool)$firewall['verify_tls'] ? 2 : 0,
                ]);
                curl_multi_add_handle($multi, $handle);
                $handles[(int)$handle] = ['key'=>$key,'handle'=>$handle];
            } catch (Throwable $e) {
                $results[$key] = ['ok'=>false,'error'=>$e->getMessage()];
            }
        }

        do {
            $status = curl_multi_exec($multi, $running);
            if ($status !== CURLM_OK) {
                throw new RuntimeException('Parallel backup execution failed: '.curl_multi_strerror($status));
            }
            if ($running > 0 && curl_multi_select($multi, 1.0) === -1) usleep(10000);
        } while ($running > 0);

        foreach ($handles as $item) {
            $key=$item['key']; $handle=$item['handle'];
            $body=curl_multi_getcontent($handle);
            $error=curl_error($handle);
            $status=(int)curl_getinfo($handle,CURLINFO_RESPONSE_CODE);
            if ($body===false) $results[$key]=['ok'=>false,'error'=>'Connection failed: '.$error];
            elseif ($status<200||$status>=300) $results[$key]=['ok'=>false,'error'=>'OPNsense API HTTP '.$status];
            else $results[$key]=['ok'=>true,'value'=>$body];
        }
    } finally {
        foreach ($handles as $item) curl_multi_remove_handle($multi,$item['handle']);
        curl_multi_close($multi);
    }

    $ordered=[];
    foreach($requests as $key=>$_) $ordered[$key]=$results[$key]??['ok'=>false,'error'=>'No result'];
    return $ordered;
}
