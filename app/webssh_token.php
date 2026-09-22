<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/webssh.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        throw new RuntimeException('POST required.');
    }
    require_csrf();

    $id = filter_var($_POST['firewall_id'] ?? null, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1],
    ]);
    if ($id === false) {
        http_response_code(400);
        throw new RuntimeException('Invalid firewall id.');
    }

    $statement = db()->prepare('SELECT id,name,base_url FROM firewalls WHERE id = ? LIMIT 1');
    $statement->execute([(int) $id]);
    $firewall = $statement->fetch();
    if (!is_array($firewall)) {
        http_response_code(404);
        throw new RuntimeException('Firewall not found.');
    }

    $target = webssh_target_from_firewall($firewall);
    echo json_encode([
        'ok' => true,
        'token' => webssh_create_target_token($firewall),
        'target' => $target,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    if (http_response_code() < 400) http_response_code(500);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
