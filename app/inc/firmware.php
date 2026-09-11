<?php

declare(strict_types=1);

/**
 * Convert the OPNsense firmware/status response into a stable structure
 * for the WebUI.
 *
 * OPNsense uses the firmware API for both base-system updates and ordinary
 * package/plugin updates. Keep those states separate so a package such as
 * OpenVPN does not make the UI claim that the OPNsense firmware itself is
 * outdated.
 */
function normalize_firmware_status(array $value): array
{
    $product = is_array($value['product'] ?? null)
        ? $value['product']
        : [];

    $currentVersion = (string) (
        $product['product_version']
        ?? $value['product_version']
        ?? ''
    );

    $status = (string) ($value['status'] ?? 'none');
    $message = (string) (
        $value['status_msg']
        ?? $value['message']
        ?? ''
    );

    $availableVersion = '';
    $firmwareUpdateAvailable = false;
    $packageUpdates = [];
    $action = null;

    if ($status === 'upgrade') {
        $versions = [];

        foreach (($value['all_sets'] ?? []) as $package) {
            if (is_array($package) && !empty($package['new'])) {
                $versions[] = (string) $package['new'];
            }
        }

        if (!$versions && !empty($value['product_target'])) {
            $versions[] = (string) $value['product_target'];
        }

        if ($versions) {
            usort($versions, 'version_compare');
            $availableVersion = (string) end($versions);
        }

        $firmwareUpdateAvailable = true;
        $action = 'firmware_upgrade';
    } elseif ($status === 'update') {
        foreach (($value['all_packages'] ?? []) as $package) {
            if (!is_array($package) || empty($package['new'])) {
                continue;
            }

            $name = trim((string) ($package['name'] ?? ''));
            $nameLower = strtolower($name);
            $current = (string) (
                $package['current']
                ?? $package['old']
                ?? $package['installed']
                ?? ''
            );
            $new = (string) $package['new'];

            if ($nameLower === 'opnsense' || $nameLower === 'os-opnsense') {
                $availableVersion = $new;
                $firmwareUpdateAvailable = true;
                continue;
            }

            $packageUpdates[] = [
                'name' => $name !== '' ? $name : 'package',
                'current' => $current,
                'new' => $new,
            ];
        }

        /*
         * product_target is a firmware target only when it differs from the
         * currently installed OPNsense version. Do not use an unrelated
         * package version as the firmware target.
         */
        if (
            !$firmwareUpdateAvailable
            && !empty($value['product_target'])
            && (string) $value['product_target'] !== $currentVersion
        ) {
            $availableVersion = (string) $value['product_target'];
            $firmwareUpdateAvailable = true;
        }

        $action = 'firmware_update';
    }

    $overallUpdateAvailable = in_array($status, ['update', 'upgrade'], true);

    return [
        'checked' => $status !== 'none' || stripos($message, 'requires to check') === false,
        'status' => $status,
        'message' => $message,
        'current_version' => $currentVersion,
        'available_version' => $availableVersion,
        'firmware_update_available' => $firmwareUpdateAvailable,
        'package_update_available' => count($packageUpdates) > 0,
        'package_update_count' => count($packageUpdates),
        'package_updates' => $packageUpdates,
        'update_available' => $overallUpdateAvailable,
        'action' => $action,
        'action_label' => $status === 'upgrade' ? 'Upgrade now' : 'Update now',
        'requires_reboot' => (string) ($value['status_reboot'] ?? '0') === '1',
    ];
}
