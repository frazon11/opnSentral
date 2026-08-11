<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/opnsense.php';

function backup_safe_name(string $name): string
{
    $safe = preg_replace('/[^A-Za-z0-9._-]+/', '_', trim($name));
    return trim((string) $safe, '._-') ?: 'firewall';
}

function backup_current_user(): string
{
    start_session_secure();
    return (string) ($_SESSION['username'] ?? envv('ADMIN_USER', 'admin'));
}

function backup_store_record(
    array $firewall,
    string $filename,
    string $type,
    string $reason,
    int $size,
    string $sha256,
    string $status = 'ok',
    string $error = ''
): int {
    $statement = db()->prepare(
        'INSERT INTO backups
        (firewall_id,firewall_name,filename,backup_type,reason,byte_size,sha256,created_by,created_at,status,error)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)'
    );
    $statement->execute([
        (int) $firewall['id'],
        (string) $firewall['name'],
        $filename,
        $type,
        $reason,
        $size,
        $sha256,
        backup_current_user(),
        gmdate('c'),
        $status,
        $error,
    ]);
    return (int) db()->lastInsertId();
}

function backup_create(
    array $firewall,
    string $type = 'manual',
    string $reason = ''
): array {
    if (!is_dir(BACKUP_DIR) && !mkdir(BACKUP_DIR, 0770, true) && !is_dir(BACKUP_DIR)) {
        throw new RuntimeException('Cannot create the persistent backup directory.');
    }

    $safeName = backup_safe_name((string) $firewall['name']);
    $suffix = $reason !== '' ? '-before-' . backup_safe_name($reason) : '';
    $basename = $safeName . '-' . gmdate('Ymd-His') . $suffix . '.xml';
    $path = BACKUP_DIR . '/' . $basename;

    try {
        $data = opn_download($firewall, 'core/backup/download/this');

        if ($data === '' || !str_contains($data, '<')) {
            throw new RuntimeException('OPNsense returned an empty or invalid configuration backup.');
        }

        if (file_put_contents($path, $data, LOCK_EX) === false) {
            throw new RuntimeException('The configuration backup could not be saved.');
        }

        $size = filesize($path);
        $hash = hash_file('sha256', $path);

        if ($size === false || $size < 100 || $hash === false) {
            @unlink($path);
            throw new RuntimeException('Backup integrity verification failed.');
        }

        $id = backup_store_record(
            $firewall,
            $basename,
            $type,
            $reason,
            (int) $size,
            $hash
        );

        backup_apply_retention((int) $firewall['id']);

        return [
            'id' => $id,
            'filename' => $basename,
            'path' => $path,
            'size' => (int) $size,
            'sha256' => $hash,
        ];
    } catch (Throwable $exception) {
        if (isset($path) && is_file($path)) {
            @unlink($path);
        }
        backup_store_record(
            $firewall,
            '',
            $type,
            $reason,
            0,
            '',
            'failed',
            $exception->getMessage()
        );
        throw $exception;
    }
}

function backup_before_change(array $firewall, string $reason): array
{
    try {
        return backup_create($firewall, 'pre-change', $reason);
    } catch (Throwable $exception) {
        throw new RuntimeException(
            'Change cancelled: automatic pre-change backup failed. No configuration changes were made. ' .
            $exception->getMessage()
        );
    }
}

function backup_apply_retention(int $firewallId): void
{
    $limit = max(1, (int) envv('PRECHANGE_BACKUP_RETENTION', '20'));
    $statement = db()->prepare(
        'SELECT id,filename FROM backups
         WHERE firewall_id=? AND backup_type="pre-change" AND status="ok"
         ORDER BY created_at DESC'
    );
    $statement->execute([$firewallId]);
    $rows = $statement->fetchAll();

    foreach (array_slice($rows, $limit) as $row) {
        $path = BACKUP_DIR . '/' . basename((string) $row['filename']);
        if (is_file($path)) {
            @unlink($path);
        }
        $delete = db()->prepare('DELETE FROM backups WHERE id=?');
        $delete->execute([(int) $row['id']]);
    }
}

function backup_rows(int $limit = 250): array
{
    $statement = db()->prepare(
        'SELECT * FROM backups ORDER BY created_at DESC LIMIT ?'
    );
    $statement->bindValue(1, $limit, PDO::PARAM_INT);
    $statement->execute();
    return $statement->fetchAll();
}
