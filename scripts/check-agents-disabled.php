<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$page = file_get_contents($root . '/app/agents.php');
$action = file_get_contents($root . '/app/agents_action.php');

if ($page === false || $action === false) {
    fwrite(STDERR, "Agents disabled regression: required files could not be read.\n");
    exit(1);
}

$requiredPage = [
    'Agent management is disabled.',
    'ChatGPT is unable to provide a working solution',
];
foreach ($requiredPage as $needle) {
    if (!str_contains($page, $needle)) {
        fwrite(STDERR, "Agents disabled regression: missing page marker: {$needle}\n");
        exit(1);
    }
}

$forbiddenPage = [
    'Generate install command',
    'Repair stale agents',
    'Update all agents',
    'queue_job',
    'self_update',
    'repair_stale',
];
foreach ($forbiddenPage as $needle) {
    if (str_contains($page, $needle)) {
        fwrite(STDERR, "Agents disabled regression: interactive agent control remains on page: {$needle}\n");
        exit(1);
    }
}

if (!str_contains($action, 'http_response_code(503);')) {
    fwrite(STDERR, "Agents disabled regression: actions endpoint is not fail-closed.\n");
    exit(1);
}
if (!str_contains($action, 'ChatGPT is unable to provide a working solution')) {
    fwrite(STDERR, "Agents disabled regression: actions endpoint does not return the disabled notice.\n");
    exit(1);
}

echo "Agents disabled checks passed.\n";
