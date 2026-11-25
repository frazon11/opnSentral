<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/mfa.php';
require_login();
start_session_secure();

$secret = (string)($_SESSION['mfa_enroll_secret'] ?? '');
$created = (int)($_SESSION['mfa_enroll_created'] ?? 0);
if ($secret === '' || $created < time()-600 || $created > time() || mfa_enabled()) {
    http_response_code(404);
    exit;
}
$account = envv('ADMIN_USER','admin');
$issuer = 'opnSentral';
$uri = 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($account)
    . '?secret=' . rawurlencode($secret) . '&issuer=' . rawurlencode($issuer)
    . '&algorithm=SHA1&digits=6&period=30';

$cmd = ['/usr/bin/qrencode', '-t', 'PNG', '-s', '6', '-m', '2', '-o', '-', $uri];
$process = proc_open($cmd, [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
if (!is_resource($process)) {
    http_response_code(503);
    exit;
}
fclose($pipes[0]);
$image = stream_get_contents($pipes[1]);
$diagnostics = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$status = proc_close($process);
if ($status !== 0 || !is_string($image) || !str_starts_with($image, "\x89PNG\r\n\x1a\n")) {
    error_log('Local MFA QR generation failed (exit=' . $status . ')');
    http_response_code(503);
    exit;
}
header('Content-Type: image/png');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');
echo $image;
