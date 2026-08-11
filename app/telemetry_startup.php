<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/update_check.php';
require_once __DIR__ . '/inc/telemetry.php';

try {
    $state = telemetry_send(true);
    $status = (string) ($state['last_status'] ?? 'unknown');

    if ($status === 'sent') {
        fwrite(STDOUT, "opnSentral telemetry sent on container startup.\n");
    } elseif ($status === 'disabled') {
        fwrite(STDOUT, "opnSentral telemetry disabled; startup send skipped.\n");
    } else {
        $error = trim((string) ($state['last_error'] ?? ''));
        fwrite(
            STDERR,
            "opnSentral telemetry startup status: {$status}" .
            ($error !== '' ? " ({$error})" : '') .
            "\n"
        );
    }
} catch (Throwable $exception) {
    fwrite(
        STDERR,
        'opnSentral telemetry startup send failed: ' .
        $exception->getMessage() .
        "\n"
    );
}
