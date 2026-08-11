<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/inc/agent_auth.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$request = authenticate_agent_request(32768);
$agent = $request['agent'];
$agentDbId = (int) $agent['id'];
$now = gmdate('c');
$pdo = db();

try {
    $pdo->beginTransaction();

    $statement = $pdo->prepare(
        'SELECT id, job_type, payload_json, created_at
         FROM agent_jobs
         WHERE agent_id = ? AND status = "queued"
         ORDER BY id
         LIMIT 1'
    );
    $statement->execute([$agentDbId]);
    $job = $statement->fetch();

    if (!$job) {
        $pdo->commit();
        echo json_encode(['ok' => true, 'job' => null], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $claim = $pdo->prepare(
        'UPDATE agent_jobs
         SET status = "running", picked_at = ?
         WHERE id = ? AND status = "queued"'
    );
    $claim->execute([$now, (int) $job['id']]);

    if ($claim->rowCount() !== 1) {
        $pdo->rollBack();
        echo json_encode(['ok' => true, 'job' => null], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $pdo->commit();

    $payload = json_decode((string) $job['payload_json'], true);
    if (!is_array($payload)) {
        $payload = [];
    }

    echo json_encode([
        'ok' => true,
        'job' => [
            'id' => (int) $job['id'],
            'type' => (string) $job['job_type'],
            'payload' => $payload,
            'created_at' => (string) $job['created_at'],
        ],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $exception) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    agent_fail(500, 'Could not fetch agent job.');
}
