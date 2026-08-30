<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/firewall_notifications.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

try {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $id = (int)($_GET['id'] ?? 0);
        if ($id > 0) {
            $firewall = firewall_by_id($id);
            echo json_encode([
                'ok' => true,
                'firewall' => [
                    'id' => $id,
                    'name' => (string)$firewall['name'],
                    'notifications_enabled' => firewall_notifications_enabled($id),
                ],
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            exit;
        }

        $rows = array_map(static fn(array $row): array => [
            'id' => (int)$row['id'],
            'name' => (string)$row['name'],
            'notifications_enabled' => (int)$row['notifications_enabled'] === 1,
        ], firewall_notifications_rows());

        echo json_encode(['ok' => true, 'firewalls' => $rows], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    require_csrf();

    $id = (int)($_POST['id'] ?? 0);
    if ($id < 1) throw new RuntimeException('Invalid firewall ID.');
    $firewall = firewall_by_id($id);

    $raw = strtolower(trim((string)($_POST['enabled'] ?? '')));
    if (!in_array($raw, ['0', '1', 'false', 'true', 'off', 'on'], true)) {
        throw new RuntimeException('Invalid notification state.');
    }
    $enabled = in_array($raw, ['1', 'true', 'on'], true);
    firewall_notifications_set_enabled($id, $enabled);

    echo json_encode([
        'ok' => true,
        'firewall' => [
            'id' => $id,
            'name' => (string)$firewall['name'],
            'notifications_enabled' => $enabled,
        ],
        'message' => $enabled
            ? 'Notifications enabled for ' . (string)$firewall['name'] . '.'
            : 'Notifications disabled for ' . (string)$firewall['name'] . '.',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => $exception->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
