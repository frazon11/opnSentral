<?php
declare(strict_types=1);

$page = (string) file_get_contents(dirname(__DIR__) . '/app/wireguard_overview.php');

$checks = [
    ["function normalizedConnection(connection)", 'WireGuard overview must normalize connection direction.'],
    ["toLowerCase() === 'kryszon'", 'Kryszon must be treated as the primary firewall.'],
    ["function sortedConnections(connections)", 'WireGuard overview must sort managed connections.'],
    ["aPrimary - bPrimary", 'Kryszon connections must sort before all other pairs.'],
    ['class="wg-link-line"', 'WireGuard overview must show a simple visual link between firewalls.'],
    ['class="wg-link-status"', 'WireGuard overview must show configuration status as plain text.'],
    ["connections.length + ' existing managed tunnel'", 'Summary must describe only existing managed tunnels.'],
    ["data.connections.filter(function(connection)", 'Overview must filter out non-existing/incomplete tunnel records.'],
    ["String(connection.local.client_uuid || '') !== ''", 'Existing tunnel filter must require the local managed peer.'],
    ["String(connection.remote.client_uuid || '') !== ''", 'Existing tunnel filter must require the remote managed peer.'],
];

foreach ($checks as [$needle,$message]) {
    if (!str_contains($page, $needle)) {
        fwrite(STDERR, "WireGuard overview check failed: {$message}\n");
        exit(1);
    }
}

foreach (['connectionStateClass','enabledCount + \' / \' + totalCount'] as $forbidden) {
    if (str_contains($page, $forbidden)) {
        fwrite(STDERR, "WireGuard overview check failed: old color/count summary remains: {$forbidden}\n");
        exit(1);
    }
}

fwrite(STDOUT, "WireGuard overview checks passed.\n");
