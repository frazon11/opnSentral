<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/inc/agent_auth.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$request = authenticate_agent_request(262144);
$agent = $request['agent'];
$payload = $request['payload'];
$now = (int) $request['now'];

$hostname = trim((string) ($payload['hostname'] ?? ''));
$agentVersion = trim((string) ($payload['agent_version'] ?? ''));
$opnsenseVersion = trim((string) ($payload['opnsense_version'] ?? ''));

$update = db()->prepare(
    'UPDATE agents
     SET last_seen_at = ?, last_remote_ip = ?, last_version = ?,
         last_hostname = ?, last_opnsense_version = ?, last_payload = ?
     WHERE id = ?'
);
$update->execute([
    gmdate('c'),
    (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
    substr($agentVersion, 0, 64),
    substr($hostname, 0, 255),
    substr($opnsenseVersion, 0, 128),
    json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
    (int) $agent['id'],
]);

echo json_encode([
    'ok' => true,
    'server_time' => $now,
    'poll_interval' => 60,
], JSON_UNESCAPED_SLASHES);
