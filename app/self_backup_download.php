<?php

declare(strict_types=1);

ini_set('display_errors', '0');
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/update_check.php';
require_once __DIR__ . '/inc/self_backup.php';

require_login();

if (!configuration_unlocked()) {
    http_response_code(423);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    exit(
        'opnCentral is locked. Unlock configuration changes before ' .
        'downloading backups.'
    );
}


if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('POST required.');
}

require_csrf();

$includeStoredBackups = isset($_POST['include_stored_backups']) &&
    filter_var($_POST['include_stored_backups'], FILTER_VALIDATE_BOOL);

try {
    $result = self_backup_create_archive($includeStoredBackups);
    $path = $result['path'];

    header('Content-Type: application/zip');
    header(
        'Content-Disposition: attachment; filename="' .
        self_backup_safe_filename($result['filename']) .
        '"'
    );
    header('Content-Length: ' . (string) $result['size']);
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');

    $stream = fopen($path, 'rb');
    if ($stream === false) {
        throw new RuntimeException('Could not open generated backup.');
    }

    fpassthru($stream);
    fclose($stream);
    @unlink($path);
    exit;
} catch (Throwable $exception) {
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
    }
    echo 'opnCentral backup failed: ' . $exception->getMessage();
}
