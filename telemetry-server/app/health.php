<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';
telemetry_db();
header('Content-Type: text/plain; charset=utf-8');
echo 'ok';
