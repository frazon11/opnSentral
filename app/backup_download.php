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


$id = (int) ($_GET['id'] ?? 0);
$statement = db()->prepare('SELECT * FROM backups WHERE id=? AND status="ok"');
$statement->execute([$id]);
$row = $statement->fetch();

if (!$row) {
    http_response_code(404);
    exit('Backup not found.');
}

$filename = basename((string) $row['filename']);
$path = BACKUP_DIR . '/' . $filename;

if (!is_file($path)) {
    http_response_code(404);
    exit('Backup file is missing.');
}

header('Content-Type: application/xml');
header('Content-Disposition: attachment; filename="' . addslashes($filename) . '"');
header('Content-Length: ' . filesize($path));
header('X-Content-Type-Options: nosniff');
readfile($path);
