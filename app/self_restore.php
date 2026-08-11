<?php

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('max_execution_time', '600');

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/update_check.php';
require_once __DIR__ . '/inc/self_backup.php';

require_login();
require_csrf();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('POST required.');
    }

    if (!isset($_FILES['backup_file']) || !is_array($_FILES['backup_file'])) {
        throw new RuntimeException('No backup file was uploaded.');
    }

    $upload = $_FILES['backup_file'];
    $error = (int) ($upload['error'] ?? UPLOAD_ERR_NO_FILE);

    if ($error !== UPLOAD_ERR_OK) {
        throw new RuntimeException(
            match ($error) {
                UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE =>
                    'The uploaded archive exceeds the configured upload limit.',
                UPLOAD_ERR_PARTIAL =>
                    'The backup archive was uploaded only partially.',
                UPLOAD_ERR_NO_FILE =>
                    'No backup archive was selected.',
                default =>
                    'Backup upload failed with error code ' . $error . '.',
            }
        );
    }

    $temporary = (string) ($upload['tmp_name'] ?? '');
    if ($temporary === '' || !is_uploaded_file($temporary)) {
        throw new RuntimeException('The uploaded backup file is invalid.');
    }

    $size = (int) ($upload['size'] ?? 0);
    if ($size < 100 || $size > 1073741824) {
        throw new RuntimeException(
            'The backup archive must be between 100 bytes and 1 GiB.'
        );
    }

    $result = self_backup_restore_archive($temporary);

    echo json_encode([
        'ok' => true,
        'message' =>
            'Restore completed. Recreate or restart the opnCentral container before continuing.',
        'safety_backup' => $result['safety_backup'],
        'restart_required' => true,
        'restored_version' =>
            (string) ($result['manifest']['application_version'] ?? 'unknown'),
        'restored_at' =>
            (string) ($result['manifest']['created_at'] ?? 'unknown'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
