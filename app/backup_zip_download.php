<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
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


$batch = preg_replace('/[^A-Za-z0-9_-]/', '', (string) ($_GET['batch'] ?? ''));
if ($batch === '') {
    http_response_code(400);
    exit('Invalid batch.');
}
$path = BACKUP_DIR . '/batch-' . $batch . '.zip';
if (!is_file($path)) {
    http_response_code(404);
    exit('Backup ZIP not found.');
}
header('Content-Type: application/zip');
header('Content-Disposition: attachment; filename="opnCentral-backups-' . $batch . '.zip"');
header('Content-Length: ' . filesize($path));
header('X-Content-Type-Options: nosniff');
readfile($path);
