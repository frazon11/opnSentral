<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $ids = array_values(array_unique(array_filter(array_map(
        'intval',
        preg_split('/\s*,\s*/', trim((string) ($_GET['ids'] ?? ''))) ?: []
    ), static fn(int $id): bool => $id > 0)));

    if ($ids === []) {
        throw new RuntimeException('No job IDs supplied.');
    }
    if (count($ids) > 100) {
        throw new RuntimeException('Too many job IDs.');
    }

    $marks = implode(',', array_fill(0, count($ids), '?'));
    $statement = db()->prepare(
        'SELECT id,status,result_json,error,finished_at
         FROM agent_jobs
         WHERE id IN (' . $marks . ')'
    );
    $statement->execute($ids);

    $jobs = [];
    foreach ($statement->fetchAll() as $row) {
        $message = '';
        $result = json_decode((string) ($row['result_json'] ?? ''), true);
        if (is_array($result)) {
            $message = trim((string) ($result['message'] ?? ''));
        }
        $jobs[] = [
            'id' => (int) $row['id'],
            'status' => (string) $row['status'],
            'message' => $message,
            'error' => (string) ($row['error'] ?? ''),
            'finished_at' => (string) ($row['finished_at'] ?? ''),
        ];
    }

    echo json_encode([
        'ok' => true,
        'jobs' => $jobs,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
