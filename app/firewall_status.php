<?php

declare(strict_types=1);

/*
 * JSON endpoints must never mix PHP warning/fatal HTML with JSON.
 */
ini_set('display_errors', '0');
ini_set('html_errors', '0');
ob_start();

register_shutdown_function(static function (): void {
    $error = error_get_last();

    if ($error === null || !in_array(
        $error['type'],
        [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR],
        true
    )) {
        return;
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate');
    }

    echo json_encode(
        [
            'ok' => false,
            'error' => 'PHP fatal error: ' . $error['message'],
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
});

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/firmware.php';

require_login();

if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

$id = (int) ($_GET['id'] ?? 0);
$type = (string) ($_GET['type'] ?? 'all');
$includeVersion = !isset($_GET['include_version']) || (string)$_GET['include_version'] !== '0';

function status_reject_raw_api_response(array $value, string $label): array
{
    if (array_key_exists('raw', $value)) {
        $raw = trim((string)$value['raw']);
        $looksHtml = str_starts_with(strtolower($raw), '<!doctype html') || str_starts_with(strtolower($raw), '<html');
        throw new RuntimeException(
            $looksHtml
                ? $label . ' returned HTML instead of JSON.'
                : $label . ' returned a non-JSON response.'
        );
    }
    return $value;
}

function status_extract_opnsense_version(array $systemInformation): string
{
    $versions = $systemInformation['versions'] ?? [];
    if (!is_array($versions)) {
        return '';
    }

    foreach ($versions as $candidate) {
        if (!is_scalar($candidate)) continue;
        $candidate = trim((string)$candidate);
        if ($candidate === '' || stripos($candidate, 'OPNsense ') !== 0) continue;

        $candidate = trim(substr($candidate, strlen('OPNsense ')));
        $candidate = preg_replace('/-(?:amd64|aarch64|arm64|i386)$/i', '', $candidate) ?? $candidate;
        return substr(trim($candidate), 0, 80);
    }

    return '';
}

function status_system_payload(array $firewall, bool $includeVersion): array
{
    $value = status_reject_raw_api_response(
        opn_request($firewall, 'core/system/status', 'GET', [], 10),
        'OPNsense system status API'
    );

    // core/system/status is a health/reporter endpoint; it does not reliably
    // contain the running OPNsense version. Add the version from the official
    // diagnostics system-information endpoint so the Dashboard never depends
    // on a firmware probe just to identify the running release.
    if ($includeVersion) {
        try {
            $info = status_reject_raw_api_response(
                opn_request($firewall, 'diagnostics/system/system_information', 'GET', [], 10),
                'OPNsense system information API'
            );
            $version = status_extract_opnsense_version($info);
            if ($version !== '') {
                $value['version'] = $version;
            }
        } catch (Throwable $exception) {
            // System health is still valid if this optional identity lookup is
            // unavailable. The firmware response may provide the version too.
            $value['_version_error'] = $exception->getMessage();
        }
    }

    return $value;
}

try {
    $firewall = firewall_by_id($id);

    $result = [
        'ok' => true,
        'type' => $type,
        'data' => [],
    ];

    if ($type === 'system' || $type === 'all') {
        try {
            $result['data']['system'] = [
                'ok' => true,
                'value' => status_system_payload($firewall, $includeVersion),
            ];
        } catch (Throwable $exception) {
            $result['data']['system'] = [
                'ok' => false,
                'error' => $exception->getMessage(),
            ];
        }
    }

    if ($type === 'firmware' || $type === 'all') {
        try {
            /*
             * OPNsense Core/Firmware/status has intentionally different GET and
             * POST behaviour. GET only returns the last cached product_check.
             * POST first runs a synchronous "firmware probe" and then returns
             * the newly calculated status. A dashboard refresh must therefore
             * use POST or it can incorrectly keep showing "no update available"
             * after newer packages have appeared on the configured mirror.
             */
            $value = status_reject_raw_api_response(
                opn_request(
                    $firewall,
                    'core/firmware/status',
                    'POST',
                    [],
                    45
                ),
                'OPNsense firmware status API'
            );

            $result['data']['firmware'] = [
                'ok' => true,
                'value' => $value,
                'summary' => normalize_firmware_status($value),
            ];
        } catch (Throwable $exception) {
            $result['data']['firmware'] = [
                'ok' => false,
                'error' => $exception->getMessage(),
            ];
        }
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        $result,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
    );
} catch (Throwable $exception) {
    http_response_code(500);

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => false,
            'error' => $exception->getMessage(),
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
