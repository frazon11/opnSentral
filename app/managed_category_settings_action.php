<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/managed_category.php';

require_login();
require_csrf();
require_configuration_unlocked(false);

try {
    save_managed_category_settings(
        (string) ($_POST['managed_category_name'] ?? ''),
        (string) ($_POST['managed_category_color'] ?? '')
    );

    header(
        'Location: /settings.php?' .
        http_build_query(['managed_category_saved' => '1'])
    );
    exit;
} catch (Throwable $exception) {
    header(
        'Location: /settings.php?' .
        http_build_query([
            'managed_category_error' => $exception->getMessage(),
        ])
    );
    exit;
}
