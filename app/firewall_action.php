<?php

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('html_errors', '0');
ob_start();

register_shutdown_function(static function (): void {
    $error = error_get_last();
    if ($error === null || !in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
        return;
    }
    while (ob_get_level() > 0) ob_end_clean();
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate');
    }
    echo json_encode(['ok' => false, 'error' => 'PHP fatal error: ' . $error['message']], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
});

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/firmware.php';
require_once __DIR__ . '/inc/backups.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    require_csrf();
    $id = (int)($_POST['id'] ?? 0);
    $action = (string)($_POST['action'] ?? '');
    $firewall = firewall_by_id($id);

    if ($action === 'firmware_check') {
        $value = opn_request($firewall, 'core/firmware/status', 'POST', [], 120);
        while (ob_get_level() > 0) ob_end_clean();
        echo json_encode(['ok' => true, 'value' => $value, 'summary' => normalize_firmware_status($value)], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        exit;
    }

    if ($action === 'firmware_audit') {
        $auditType = (string)($_POST['audit_type'] ?? '');
        $auditEndpoints = [
            'security' => 'core/firmware/audit',
            'health' => 'core/firmware/health',
            'connectivity' => 'core/firmware/connection',
            'cleanup' => 'core/firmware/cleanup',
        ];

        if ($auditType === 'upgrade_log') {
            $value = opn_request($firewall, 'core/firmware/log/0', 'POST', [], 60);
            while (ob_get_level() > 0) ob_end_clean();
            echo json_encode([
                'ok' => true,
                'audit_type' => $auditType,
                'status' => 'done',
                'log' => (string)($value['log'] ?? 'No upgrade log is available.'),
                'value' => $value,
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            exit;
        }

        if (!isset($auditEndpoints[$auditType])) {
            throw new RuntimeException('Unsupported firmware audit type.');
        }

        $value = opn_request($firewall, $auditEndpoints[$auditType], 'POST', [], 30);
        if (($value['status'] ?? '') !== 'ok') {
            throw new RuntimeException('OPNsense rejected the audit request.');
        }

        while (ob_get_level() > 0) ob_end_clean();
        echo json_encode([
            'ok' => true,
            'audit_type' => $auditType,
            'status' => 'running',
            'msg_uuid' => (string)($value['msg_uuid'] ?? ''),
            'value' => $value,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        exit;
    }

    if ($action === 'firmware_audit_status') {
        $value = opn_request($firewall, 'core/firmware/upgradestatus', 'GET', [], 30);
        while (ob_get_level() > 0) ob_end_clean();
        echo json_encode([
            'ok' => true,
            'status' => (string)($value['status'] ?? 'running'),
            'log' => (string)($value['log'] ?? ''),
            'value' => $value,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        exit;
    }

    if (!in_array($action, ['firmware_update', 'firmware_upgrade'], true)) throw new RuntimeException('Unsupported action.');
    require_configuration_unlocked();

    $statusValue = opn_request($firewall, 'core/firmware/status', 'GET', [], 20);
    $summary = normalize_firmware_status($statusValue);
    if ($summary['action'] !== $action || !$summary['update_available']) {
        throw new RuntimeException('OPNsense does not currently offer this firmware action. Run Check for updates first.');
    }

    $endpoint = $action === 'firmware_upgrade' ? 'core/firmware/upgrade' : 'core/firmware/update';
    backup_before_change($firewall, $action);
    $value = opn_request($firewall, $endpoint, 'POST', [], 30);
    if (($value['status'] ?? '') !== 'ok') {
        throw new RuntimeException('OPNsense rejected the firmware command: ' . json_encode($value, JSON_UNESCAPED_SLASHES));
    }

    while (ob_get_level() > 0) ob_end_clean();
    echo json_encode([
        'ok' => true,
        'value' => $value,
        'action' => $action,
        'message' => $action === 'firmware_upgrade' ? 'Major firmware upgrade started.' : 'Firmware update started.',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    while (ob_get_level() > 0) ob_end_clean();
    echo json_encode(['ok' => false, 'error' => $exception->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
