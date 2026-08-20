<?php
declare(strict_types=1);
ini_set('display_errors', '0');
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/agent_deployment.php';
require_login();
require_csrf();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $action = (string) ($_POST['action'] ?? '');

    if ($action === 'restore_one') {
        $backupId = (int) ($_POST['backup_id'] ?? 0);
        if ($backupId < 1) throw new RuntimeException('Invalid backup ID.');

        $pdo = db();
        $statement = $pdo->prepare('SELECT * FROM backups WHERE id = ? LIMIT 1');
        $statement->execute([$backupId]);
        $backup = $statement->fetch();
        if (!$backup || (string) ($backup['status'] ?? '') !== 'ok') {
            throw new RuntimeException('Backup not found or not usable.');
        }

        $firewallId = (int) ($backup['firewall_id'] ?? 0);
        $filename = basename((string) ($backup['filename'] ?? ''));
        $expectedSha = strtolower(trim((string) ($backup['sha256'] ?? '')));
        if ($firewallId < 1 || $filename === '' || !preg_match('/^[a-f0-9]{64}$/', $expectedSha)) {
            throw new RuntimeException('Backup metadata is incomplete.');
        }

        $path = BACKUP_DIR . '/' . $filename;
        if (!is_file($path) || !is_readable($path)) throw new RuntimeException('Backup file is missing from persistent storage.');
        $size = filesize($path);
        if ($size === false || $size < 100 || $size > 8 * 1024 * 1024) throw new RuntimeException('Backup file size is invalid for remote restore.');
        $actualSha = hash_file('sha256', $path);
        if (!is_string($actualSha) || !hash_equals($expectedSha, strtolower($actualSha))) {
            throw new RuntimeException('Backup integrity verification failed.');
        }
        $xml = file_get_contents($path);
        if (!is_string($xml) || strlen($xml) !== (int) $size) throw new RuntimeException('Could not read the complete backup file.');
        libxml_use_internal_errors(true);
        $parsed = simplexml_load_string($xml, SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        if (!$parsed instanceof SimpleXMLElement || $parsed->getName() !== 'opnsense') {
            throw new RuntimeException('Selected file is not a valid OPNsense configuration backup.');
        }

        $agentStatement = $pdo->prepare(
            'SELECT * FROM agents WHERE firewall_id = ? AND enabled = 1 ORDER BY id DESC LIMIT 1'
        );
        $agentStatement->execute([$firewallId]);
        $agent = $agentStatement->fetch();
        if (!$agent) throw new RuntimeException('No enabled opnSentral agent is associated with this firewall.');
        $agentVersion = trim((string) ($agent['last_version'] ?? ''));
        if ($agentVersion === '' || version_compare($agentVersion, '0.1.8', '<')) {
            throw new RuntimeException('Agent 0.1.8 or newer is required for remote backup restore. Update the agent first.');
        }

        $pending = $pdo->prepare(
            'SELECT COUNT(*) FROM agent_jobs WHERE agent_id = ? AND job_type = "restore_backup" AND status IN ("queued","running")'
        );
        $pending->execute([(int) $agent['id']]);
        if ((int) $pending->fetchColumn() > 0) throw new RuntimeException('A restore job is already queued or running for this firewall.');

        $payload = json_encode([
            'backup_id' => $backupId,
            'filename' => $filename,
            'sha256' => $expectedSha,
            'content_b64' => base64_encode($xml),
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $insert = $pdo->prepare(
            'INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at) VALUES(?,?,?,?,?)'
        );
        agent_execute_with_retry($insert, [(int) $agent['id'], 'restore_backup', $payload, 'queued', gmdate('c')]);
        $jobId = (int) $pdo->lastInsertId();

        echo json_encode([
            'ok' => true,
            'job_id' => $jobId,
            'backup_id' => $backupId,
            'firewall' => (string) ($backup['firewall_name'] ?? ('Firewall #' . $firewallId)),
            'filename' => $filename,
            'message' => 'Emergency restore job #' . $jobId . ' queued. The agent will verify the backup, preserve the current /conf/config.xml, restore this backup, report success, and reboot the firewall.',
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        exit;
    }

    if ($action === 'backup_one') {
        $firewallId = (int) ($_POST['firewall_id'] ?? 0);
        if ($firewallId < 1) throw new RuntimeException('Invalid firewall ID.');
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

    if ($action !== 'backup_all') throw new RuntimeException('Unsupported backup action.');

    $firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
    if (!$firewalls) throw new RuntimeException('No managed firewalls configured.');
    if (!class_exists('ZipArchive')) throw new RuntimeException('PHP ZIP extension is not installed in this container image.');

    $requests = [];
    foreach ($firewalls as $firewall) {
        $requests[(string) $firewall['id']] = ['firewall'=>$firewall,'path'=>'core/backup/download/this','timeout'=>60];
    }
    $responses = opn_downloads_parallel($requests);
    $batch = gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3));
    $zipPath = BACKUP_DIR . '/batch-' . $batch . '.zip';
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) throw new RuntimeException('Could not create combined backup ZIP.');

    $results = []; $success = 0;
    foreach ($firewalls as $firewall) {
        $key = (string) $firewall['id'];
        $response = $responses[$key] ?? ['ok'=>false,'error'=>'No response'];
        try {
            if (($response['ok'] ?? false) !== true) throw new RuntimeException((string) ($response['error'] ?? 'Backup failed.'));
            $data = (string) ($response['value'] ?? '');
            if ($data === '' || !str_contains($data, '<')) throw new RuntimeException('Empty or invalid backup returned.');
            $filename = backup_safe_name((string) $firewall['name']) . '-' . gmdate('Ymd-His') . '-manual.xml';
            $path = BACKUP_DIR . '/' . $filename;
            if (file_put_contents($path, $data, LOCK_EX) === false) throw new RuntimeException('Could not save backup.');
            $size = (int) filesize($path); $sha = (string) hash_file('sha256', $path);
            if ($size < 100 || $sha === '') { @unlink($path); throw new RuntimeException('Integrity verification failed.'); }
            $recordId = backup_store_record($firewall, $filename, 'manual', 'backup-all', $size, $sha);
            $zip->addFile($path, $filename);
            $results[] = ['ok'=>true,'firewall'=>(string)$firewall['name'],'backup_id'=>$recordId,'filename'=>$filename,'size'=>$size];
            $success++;
        } catch (Throwable $exception) {
            backup_store_record($firewall, '', 'manual', 'backup-all', 0, '', 'failed', $exception->getMessage());
            $results[] = ['ok'=>false,'firewall'=>(string)$firewall['name'],'error'=>$exception->getMessage()];
        }
    }
    $zip->close();
    if ($success === 0) @unlink($zipPath);
    echo json_encode(['ok'=>true,'successful'=>$success,'total'=>count($firewalls),'results'=>$results,'batch'=>$success>0?$batch:null], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>$exception->getMessage()], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
