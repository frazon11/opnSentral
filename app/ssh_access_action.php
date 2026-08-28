<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();
require_csrf();

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        throw new RuntimeException('POST required.');
    }

    $action = trim((string) ($_POST['action'] ?? ''));
    if (!in_array($action, ['check', 'ensure'], true)) {
        throw new RuntimeException('Invalid SSH access action.');
    }

    if ($action === 'check') {
        throw new RuntimeException('Legacy agent-based SSH checks are disabled. Use the live TCP/22 status shown on the Managed SSH Access page.');
    }

    throw new RuntimeException(
        'Managed SSH Enable / Repair is temporarily disabled because agent 0.1.16 does not implement the required ensure_ssh_access job. No firewall object, backup, or agent job was changed.'
    );
} catch (Throwable $exception) {
    $_SESSION['ssh_access_result'] = [
        'ok' => false,
        'message' => $exception->getMessage(),
        'results' => [],
    ];
}

header('Location: /ssh_access.php');
exit;
