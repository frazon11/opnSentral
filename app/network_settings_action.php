<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/network_settings.php';
require_login();

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('POST required.');
    }

    require_csrf();
    save_opnsense_ipv6_disabled(isset($_POST['disable_ipv6']));

    header('Location: /settings.php?network_settings_saved=1');
    exit;
} catch (Throwable $exception) {
    header(
        'Location: /settings.php?network_settings_error=' .
        rawurlencode($exception->getMessage())
    );
    exit;
}
