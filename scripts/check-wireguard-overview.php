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
    ["connections.length + ' managed connection'", 'Summary must describe managed connections without color state counts.'],
];

foreach ($checks as [$needle,$message]) {
    if (!str_contains($page, $needle)) {
        fwrite(STDERR, "WireGuard overview check failed: {$message}\n");
        exit(1);
    }
}

foreach (['badge good','badge bad','connectionStateClass','enabledCount + \' / \' + totalCount'] as $forbidden) {
    if (str_contains($page, $forbidden)) {
        fwrite(STDERR, "WireGuard overview check failed: old color/count summary remains: {$forbidden}\n");
        exit(1);
    }
}

fwrite(STDOUT, "WireGuard overview checks passed.\n");
