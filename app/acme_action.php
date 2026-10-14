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
    $firewallId = (int) ($_POST['firewall_id'] ?? 0);
    $certificateUuid = trim((string) ($_POST['certificate_uuid'] ?? ''));

    if ($firewallId < 1) throw new RuntimeException('Invalid firewall.');
    if (!preg_match('/^[A-Fa-f0-9-]{8,64}$/', $certificateUuid)) {
        throw new RuntimeException('Invalid certificate UUID.');
    }

    $firewall = firewall_by_id($firewallId);

    $certificate = opn_request(
        $firewall,
        'acmeclient/certificates/get/' . rawurlencode($certificateUuid),
        'GET',
        [],
        20
    );
    $certificateData = is_array($certificate['certificate'] ?? null)
        ? $certificate['certificate']
        : (is_array($certificate['acmeclient']['certificate'] ?? null)
            ? $certificate['acmeclient']['certificate']
            : []);
    if ($certificateData === []) {
        throw new RuntimeException('Certificate was not found on this firewall.');
    }

    $name = trim((string) ($certificateData['name'] ?? ''));
    $backup = backup_before_change(
        $firewall,
        'acme-issue-renew-' . ($name !== '' ? $name : substr($certificateUuid, 0, 8))
    );

    $response = opn_request(
        $firewall,
        'acmeclient/certificates/sign/' . rawurlencode($certificateUuid),
        'POST',
        [],
        180
    );

    echo json_encode([
        'ok' => true,
        'firewall_id' => $firewallId,
        'certificate_uuid' => $certificateUuid,
        'certificate_name' => $name,
        'backup_id' => $backup['id'] ?? null,
        'response' => $response,
        'message' => 'ACME issue / renew completed for ' . ($name !== '' ? $name : 'certificate') . '.',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
