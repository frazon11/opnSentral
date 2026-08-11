<?php
declare(strict_types=1);

function distribution_target_ids(array $firewalls): array
{
    $scope = (string) ($_POST['target_scope'] ?? 'one');

    if ($scope === 'all') {
        return array_values(array_map(
            static fn(array $firewall): int => (int) $firewall['id'],
            $firewalls
        ));
    }

    if ($scope !== 'one') {
        throw new RuntimeException('Invalid target scope.');
    }

    $firewallId = (int) ($_POST['target_firewall_id'] ?? 0);

    if ($firewallId < 1) {
        throw new RuntimeException('Select one OPNsense firewall.');
    }

    foreach ($firewalls as $firewall) {
        if ((int) $firewall['id'] === $firewallId) {
            return [$firewallId];
        }
    }

    throw new RuntimeException('Selected firewall does not exist.');
}
