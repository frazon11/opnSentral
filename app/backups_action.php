<?php
declare(strict_types=1);
ini_set('display_errors', '0');
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_login();
require_csrf();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $action = (string) ($_POST['action'] ?? '');

    if ($action === 'backup_one') {
        $firewallId = (int) ($_POST['firewall_id'] ?? 0);
        if ($firewallId < 1) {
            throw new RuntimeException('Invalid firewall ID.');
        }

        $firewall = firewall_by_id($firewallId);
        $created = backup_create($firewall, 'manual', 'dashboard-backup');

        echo json_encode([
            'ok' => true,
            'firewall' => (string) $firewall['name'],
            'backup_id' => $created['id'],
            'filename' => $created['filename'],
            'size' => $created['size'],
            'download_url' => '/backup_download.php?id=' . $created['id'],
            'message' => 'Backup completed: ' . $created['filename'],
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        exit;
    }

    if ($action !== 'backup_all') {
        throw new RuntimeException('Unsupported backup action.');
    }

    $firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
    if (!$firewalls) {
        throw new RuntimeException('No managed firewalls configured.');
    }

    if (!class_exists('ZipArchive')) {
        throw new RuntimeException('PHP ZIP extension is not installed in this container image. Rebuild or pull opnCentral v0.6.11.1 and recreate the container.');
    }

    $requests = [];
    foreach ($firewalls as $firewall) {
        $requests[(string) $firewall['id']] = [
            'firewall' => $firewall,
            'path' => 'core/backup/download/this',
            'timeout' => 60,
        ];
    }

    $responses = opn_downloads_parallel($requests);
    $batch = gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3));
    $zipPath = BACKUP_DIR . '/batch-' . $batch . '.zip';
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Could not create combined backup ZIP.');
    }

    $results = [];
    $success = 0;

    foreach ($firewalls as $firewall) {
        $key = (string) $firewall['id'];
        $response = $responses[$key] ?? ['ok' => false, 'error' => 'No response'];
        try {
            if (($response['ok'] ?? false) !== true) {
                throw new RuntimeException((string) ($response['error'] ?? 'Backup failed.'));
            }
            $data = (string) ($response['value'] ?? '');
            if ($data === '' || !str_contains($data, '<')) {
                throw new RuntimeException('Empty or invalid backup returned.');
            }

            $filename = backup_safe_name((string) $firewall['name']) . '-' . gmdate('Ymd-His') . '-manual.xml';
            $path = BACKUP_DIR . '/' . $filename;
            if (file_put_contents($path, $data, LOCK_EX) === false) {
                throw new RuntimeException('Could not save backup.');
            }
            $size = (int) filesize($path);
            $sha = (string) hash_file('sha256', $path);
            if ($size < 100 || $sha === '') {
                @unlink($path);
                throw new RuntimeException('Integrity verification failed.');
            }
            $recordId = backup_store_record($firewall, $filename, 'manual', 'backup-all', $size, $sha);
            $zip->addFile($path, $filename);
            $results[] = [
                'ok' => true,
                'firewall' => (string) $firewall['name'],
                'backup_id' => $recordId,
                'filename' => $filename,
                'size' => $size,
            ];
            $success++;
        } catch (Throwable $exception) {
            backup_store_record($firewall, '', 'manual', 'backup-all', 0, '', 'failed', $exception->getMessage());
            $results[] = [
                'ok' => false,
                'firewall' => (string) $firewall['name'],
                'error' => $exception->getMessage(),
            ];
        }
    }

    $zip->close();
    if ($success === 0) {
        @unlink($zipPath);
    }

    echo json_encode([
        'ok' => true,
        'successful' => $success,
        'total' => count($firewalls),
        'results' => $results,
        'batch' => $success > 0 ? $batch : null,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>$exception->getMessage()], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
