<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/alerts.php';

$lockFile = DATA_DIR . '/alert-worker.lock';
$lock = fopen($lockFile, 'c');
if (!is_resource($lock) || !flock($lock, LOCK_EX | LOCK_NB)) {
    exit(0);
}

while (true) {
    try {
        run_alert_checks();
    } catch (Throwable $exception) {
        error_log('[opnCentral alerts] ' . $exception->getMessage());
    }
    $interval = max(60, (int) notification_settings()['check_interval']);
    sleep($interval);
}
