<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';

require_login();
require_csrf();
require_configuration_unlocked();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

function action_rows(array $value): array
{
    return isset($value['rows']) && is_array($value['rows']) ? $value['rows'] : [];
}

function action_enabled(mixed $value): bool
{
    return in_array(strtolower(trim((string) $value)), ['1', 'true', 'yes', 'on', 'enabled'], true);
}

function find_client(array $firewall, string $uuid): array
{
    foreach (action_rows(opn_request($firewall, 'wireguard/client/search_client', 'GET', [], 15)) as $row) {
        if ((string) ($row['uuid'] ?? $row['id'] ?? '') === $uuid) {
            return $row;
        }
    }
    throw new RuntimeException('WireGuard peer ' . $uuid . ' was not found on ' . $firewall['name'] . '.');
}

function set_client_state(array $firewall, string $uuid, bool $enabled): bool
{
    $row = find_client($firewall, $uuid);
    $current = action_enabled($row['enabled'] ?? '1');
    if ($current === $enabled) {
        return false;
    }
    opn_request($firewall, 'wireguard/client/toggle_client/' . rawurlencode($uuid), 'POST', [], 20);
    opn_request($firewall, 'wireguard/service/reconfigure', 'POST', [], 30);
    $verified = action_enabled(find_client($firewall, $uuid)['enabled'] ?? '1');
    if ($verified !== $enabled) {
        throw new RuntimeException('OPNsense did not confirm the requested peer state on ' . $firewall['name'] . '.');
    }
    return true;
}

try {
    $localId = (int) ($_POST['local_firewall_id'] ?? 0);
    $remoteId = (int) ($_POST['remote_firewall_id'] ?? 0);
    $localUuid = trim((string) ($_POST['local_client_uuid'] ?? ''));
    $remoteUuid = trim((string) ($_POST['remote_client_uuid'] ?? ''));
    $localExpectedPeerKey = trim((string) ($_POST['local_expected_peer_key'] ?? ''));
    $remoteExpectedPeerKey = trim((string) ($_POST['remote_expected_peer_key'] ?? ''));
    $enable = filter_var($_POST['enable'] ?? false, FILTER_VALIDATE_BOOL);

    if ($localId < 1 || $remoteId < 1 || $localId === $remoteId || $localUuid === '' || $remoteUuid === '') {
        throw new RuntimeException('Invalid managed WireGuard link request.');
    }

    $local = firewall_by_id($localId);
    $remote = firewall_by_id($remoteId);
    $localBefore = find_client($local, $localUuid);
    $remoteBefore = find_client($remote, $remoteUuid);

    $localPeerKey = (string) ($localBefore['pubkey'] ?? $localBefore['public-key'] ?? '');
    $remotePeerKey = (string) ($remoteBefore['pubkey'] ?? $remoteBefore['public-key'] ?? '');
    if (!hash_equals($localExpectedPeerKey, $localPeerKey) || !hash_equals($remoteExpectedPeerKey, $remotePeerKey)) {
        throw new RuntimeException('WireGuard peer identity changed. Refresh the page before trying again.');
    }

    $localOriginal = action_enabled($localBefore['enabled'] ?? '1');
    $remoteOriginal = action_enabled($remoteBefore['enabled'] ?? '1');

    backup_before_change($local, $enable ? 'wireguard-enable' : 'wireguard-disable');
    backup_before_change($remote, $enable ? 'wireguard-enable' : 'wireguard-disable');

    $localChanged = false;

    try {
        $localChanged = set_client_state($local, $localUuid, $enable);
        set_client_state($remote, $remoteUuid, $enable);
    } catch (Throwable $exception) {
        $rollbackError = '';
        if ($localChanged) {
            try {
                set_client_state($local, $localUuid, $localOriginal);
            } catch (Throwable $rollbackException) {
                $rollbackError = ' Rollback also failed: ' . $rollbackException->getMessage();
            }
        }
        throw new RuntimeException($exception->getMessage() . $rollbackError);
    }

    invalidate_wireguard_inventory_cache();

    echo json_encode([
        'ok' => true,
        'enabled' => $enable,
        'message' => 'WireGuard peer pair ' . ($enable ? 'enabled' : 'disabled') . ' on ' . $local['name'] . ' and ' . $remote['name'] . '.',
        'previous' => ['local' => $localOriginal, 'remote' => $remoteOriginal],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $exception->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
