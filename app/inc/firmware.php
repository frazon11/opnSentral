<?php

declare(strict_types=1);

/**
 * Convert the OPNsense firmware/status response into a stable structure
 * for the WebUI.
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

        $action = 'firmware_upgrade';
    } elseif ($status === 'update') {
        $versions = [];

        foreach (($value['all_packages'] ?? []) as $package) {
            if (!is_array($package) || empty($package['new'])) {
                continue;
            }

            $name = strtolower((string) ($package['name'] ?? ''));

            /*
             * Prefer the main OPNsense package as the displayed target.
             * Fall back to the highest package version below.
             */
            if ($name === 'opnsense' || $name === 'os-opnsense') {
                $availableVersion = (string) $package['new'];
                break;
            }

            $versions[] = (string) $package['new'];
        }

        if ($availableVersion === '' && $versions) {
            usort($versions, 'version_compare');
            $availableVersion = (string) end($versions);
        }

        if ($availableVersion === '' && !empty($value['product_target'])) {
            $availableVersion = (string) $value['product_target'];
        }

        $action = 'firmware_update';
    }

    return [
        'checked' => $status !== 'none' || stripos($message, 'requires to check') === false,
        'status' => $status,
        'message' => $message,
        'current_version' => $currentVersion,
        'available_version' => $availableVersion,
        'update_available' => in_array($status, ['update', 'upgrade'], true),
        'action' => $action,
        'action_label' => $status === 'upgrade' ? 'Upgrade now' : 'Update now',
        'requires_reboot' => (string) ($value['status_reboot'] ?? '0') === '1',
    ];
}
