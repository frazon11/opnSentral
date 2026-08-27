<?php
declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/category_central.php';
require_login();
central_category_init();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function category_deploy_success(array $response): bool
{
    if (($response['error'] ?? '') !== '') return false;
    foreach (['result', 'status'] as $key) {
        if (!array_key_exists($key, $response)) continue;
        $value = strtolower(trim((string) $response[$key]));
        if (in_array($value, ['0', 'false', 'failed', 'failure', 'error', 'invalid', 'rejected'], true)) return false;
    }
    return true;
}

function category_deploy_firewall(int $id): array
{
    $stmt = db()->prepare('SELECT * FROM firewalls WHERE id = ?');
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    if (!$row) throw new RuntimeException('Firewall not found.');
    return $row;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    require_csrf();
    require_configuration_unlocked();

    $name = trim((string) ($_POST['name'] ?? ''));
    $sourceId = (int) ($_POST['source_firewall_id'] ?? 0);
    $targetIds = array_values(array_unique(array_filter(
        array_map('intval', (array) ($_POST['target_firewall_ids'] ?? [])),
        static fn(int $id): bool => $id > 0
    )));

    if ($name === '' || $sourceId <= 0) throw new RuntimeException('Category and source firewall are required.');
    if ($targetIds === []) throw new RuntimeException('No target firewalls selected.');
    $targetIds = array_values(array_filter($targetIds, static fn(int $id): bool => $id !== $sourceId));
    if ($targetIds === []) throw new RuntimeException('No remaining target firewalls selected.');

    $sourceFirewall = category_deploy_firewall($sourceId);
    $source = central_category_search($sourceFirewall, $name);
    if ($source === null) throw new RuntimeException('Source category no longer exists.');

    $color = central_category_normalize_color((string) ($source['color'] ?? ''));
    $automatic = (int) ($source['auto'] ?? $source['automatic'] ?? 0);
    $categoryId = central_category_save_definition($name, $color, $automatic);

    $marks = implode(',', array_fill(0, count($targetIds), '?'));
    $stmt = db()->prepare('SELECT * FROM firewalls WHERE id IN (' . $marks . ') ORDER BY name');
    $stmt->execute($targetIds);
    $results = [];

    foreach ($stmt->fetchAll() as $firewall) {
        $entry = ['id' => (int) $firewall['id'], 'name' => (string) $firewall['name'], 'ok' => false, 'message' => ''];
        try {
            if (central_category_search($firewall, $name) !== null) {
                $entry['ok'] = true;
                $entry['message'] = 'Already exists; no change.';
                $results[] = $entry;
                continue;
            }

            backup_before_change($firewall, 'category-deploy-missing');
            $response = opn_request(
                $firewall,
                'firewall/category/add_item',
                'POST',
                central_category_payload($name, $color, $automatic),
                25
            );
            if (!category_deploy_success($response)) {
                throw new RuntimeException('OPNsense rejected the category: ' . json_encode($response));
            }

            $verified = central_category_search($firewall, $name);
            if ($verified === null) throw new RuntimeException('OPNsense returned success, but the category was not found afterward.');
            $verifiedColor = central_category_normalize_color((string) ($verified['color'] ?? ''));
            $verifiedAutomatic = (int) ($verified['auto'] ?? $verified['automatic'] ?? 0);
            if ($verifiedColor !== $color || $verifiedAutomatic !== $automatic) {
                throw new RuntimeException('Category verification failed: remote definition differs from the source.');
            }

            central_category_target_status($categoryId, (int) $firewall['id'], 'synchronized', 'Created from ' . (string) $sourceFirewall['name'] . ' and verified.');
            $entry['ok'] = true;
            $entry['message'] = 'Created and verified.';
        } catch (Throwable $exception) {
            central_category_target_status($categoryId, (int) $firewall['id'], 'error', $exception->getMessage());
            $entry['message'] = $exception->getMessage();
        }
        $results[] = $entry;
    }

    echo json_encode(['ok' => true, 'results' => $results], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => $exception->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
