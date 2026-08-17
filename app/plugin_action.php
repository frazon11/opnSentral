<?php
declare(strict_types=1);

ini_set('display_errors', '0');

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';

require_login();
require_csrf();
require_configuration_unlocked();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $package = trim((string) ($_POST['package'] ?? ''));
    $operation = trim((string) ($_POST['operation'] ?? ''));
    $allowed = ['install', 'reinstall', 'remove', 'lock', 'unlock'];

    if (!preg_match('/^os-[A-Za-z0-9][A-Za-z0-9._+-]*$/', $package)) {
        throw new RuntimeException(
            'Only OPNsense plugins with an os- package name are allowed.'
        );
    }
    if (!in_array($operation, $allowed, true)) {
        throw new RuntimeException('Unsupported operation.');
    }

    $firewallIds = [];
    $encodedIds = trim((string) ($_POST['firewall_ids'] ?? ''));
    if ($encodedIds !== '') {
        $decoded = json_decode($encodedIds, true);
        if (!is_array($decoded)) {
            throw new RuntimeException('Invalid firewall target list.');
        }
        foreach ($decoded as $id) {
            $id = (int) $id;
            if ($id > 0) $firewallIds[] = $id;
        }
    } else {
        $singleId = (int) ($_POST['firewall_id'] ?? 0);
        if ($singleId > 0) $firewallIds[] = $singleId;
    }

    $firewallIds = array_values(array_unique($firewallIds));
    if ($firewallIds === []) {
        throw new RuntimeException('No firewall selected.');
    }
    if (count($firewallIds) > 100) {
        throw new RuntimeException('Too many firewall targets.');
    }

    $results = [];
    $successCount = 0;
    $failureCount = 0;

    foreach ($firewallIds as $firewallId) {
        $firewallName = 'Firewall #' . $firewallId;
        try {
            $firewall = firewall_by_id($firewallId);
            $firewallName = (string) $firewall['name'];
            $backup = null;

            if (in_array($operation, ['install', 'reinstall', 'remove'], true)) {
                $backup = backup_before_change(
                    $firewall,
                    'plugin-' . $operation . '-' . $package
                );
            }

            $response = opn_request(
                $firewall,
                'core/firmware/' . $operation . '/' . rawurlencode($package),
                'POST',
                [],
                30
            );

            $status = strtolower(trim((string) ($response['status'] ?? '')));
            if ($status !== '' && !in_array($status, ['ok', 'success'], true)) {
                throw new RuntimeException(
                    (string) ($response['status'] ?? 'Plugin action rejected.')
                );
            }

            if (isset($response['result'])) {
                $resultValue = strtolower(trim((string) $response['result']));
                if ($resultValue !== '' && !in_array(
                    $resultValue,
                    ['ok', 'success', 'saved', 'started'],
                    true
                )) {
                    throw new RuntimeException(
                        'OPNsense rejected the plugin action: ' .
                        json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                    );
                }
            }

            $uuid = (string) ($response['msg_uuid'] ?? '');
            $now = gmdate('c');
            $statement = db()->prepare(
                'INSERT INTO plugin_jobs(
                    firewall_id,firewall_name,package_name,operation,status,
                    message_uuid,backup_id,response_json,created_at,updated_at
                 ) VALUES(?,?,?,?,?,?,?,?,?,?)'
            );
            $statement->execute([
                $firewallId,
                $firewallName,
                $package,
                $operation,
                'started',
                $uuid,
                (int) ($backup['id'] ?? 0) ?: null,
                json_encode(
                    $response,
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                ),
                $now,
                $now,
            ]);

            $successCount++;
            $results[] = [
                'ok' => true,
                'firewall_id' => $firewallId,
                'firewall_name' => $firewallName,
                'job_id' => (int) db()->lastInsertId(),
                'message_uuid' => $uuid,
                'backup_id' => $backup['id'] ?? null,
                'message' => ucfirst($operation) . ' started for ' . $package . '.',
            ];
        } catch (Throwable $exception) {
            $failureCount++;
            $results[] = [
                'ok' => false,
                'firewall_id' => $firewallId,
                'firewall_name' => $firewallName,
                'error' => $exception->getMessage(),
            ];
        }
    }

    @unlink(DATA_DIR . '/plugins-cache.json');

    echo json_encode([
        'ok' => $successCount > 0,
        'package' => $package,
        'operation' => $operation,
        'success_count' => $successCount,
        'failure_count' => $failureCount,
        'results' => $results,
        'message' => $successCount . ' firewall' . ($successCount === 1 ? '' : 's') .
            ' accepted the ' . $operation . ' request' .
            ($failureCount > 0 ? '; ' . $failureCount . ' failed.' : '.'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
