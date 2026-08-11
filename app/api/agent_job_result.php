<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/inc/agent_auth.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$request = authenticate_agent_request(262144);
$agent = $request['agent'];
$payload = $request['payload'];

$jobId = (int) ($payload['job_id'] ?? 0);
$success = ($payload['success'] ?? false) === true;
$result = $payload['result'] ?? null;
$error = trim((string) ($payload['error'] ?? ''));

if ($jobId <= 0) {
    agent_fail(400, 'Valid job_id required.');
}

$resultJson = json_encode(
    $result,
    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
);
if ($resultJson === false || strlen($resultJson) > 200000) {
    agent_fail(413, 'Invalid or oversized job result.');
}

$statement = db()->prepare(
    'UPDATE agent_jobs
     SET status = ?, result_json = ?, error = ?, finished_at = ?
     WHERE id = ? AND agent_id = ? AND status = ?'
);
$statement->execute([
    $success ? 'completed' : 'failed',
    $resultJson,
    substr($error, 0, 2000),
    gmdate('c'),
    $jobId,
    (int) $agent['id'],
    'running',
]);

if ($statement->rowCount() !== 1) {
    agent_fail(409, 'Job is not running for this agent.');
}

echo json_encode(['ok' => true], JSON_UNESCAPED_SLASHES);
