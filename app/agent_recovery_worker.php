#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/agent_recovery.php';

function agent_recovery_worker_log(string $message): void
{
    fwrite(STDERR, gmdate('c') . ' agent-recovery: ' . $message . PHP_EOL);
}

function agent_recovery_worker_cycle(): void
{
    $pdo = db();
    $agents = $pdo->query(
        'SELECT * FROM agents WHERE enabled = 1 AND firewall_id IS NOT NULL ORDER BY id'
    )->fetchAll();
    $state = agent_recovery_state_load();
    $known = [];

    foreach ($agents as $agent) {
        $agentId = (int) ($agent['id'] ?? 0);
        if ($agentId <= 0) continue;
        $key = (string) $agentId;
        $known[$key] = true;

        if (agent_recovery_is_fresh($agent)) {
            if (isset($state[$key])) unset($state[$key]);
            continue;
        }

        $entry = is_array($state[$key] ?? null) ? $state[$key] : [];
        if (!agent_recovery_due($entry)) continue;

        $attempts = max(0, (int) ($entry['attempts'] ?? 0));
        $action = $attempts === 0 ? 'start' : 'restart';
        $now = gmdate('c');

        try {
            $firewall = agent_recovery_request_service($pdo, $agent, $action);
            $state[$key] = [
                'attempts' => $attempts + 1,
                'last_attempt' => $now,
                'last_action' => $action,
                'last_firewall' => $firewall,
                'last_error' => '',
                'message' => 'Recovery request accepted; waiting for heartbeat.',
            ];
            agent_recovery_worker_log(
                'requested ' . $action . ' for agent #' . $agentId . ' on ' . $firewall
            );
        } catch (Throwable $exception) {
            $state[$key] = [
                'attempts' => $attempts + 1,
                'last_attempt' => $now,
                'last_action' => $action,
                'last_firewall' => '',
                'last_error' => $exception->getMessage(),
                'message' => 'Automatic recovery failed.',
            ];
            agent_recovery_worker_log(
                'agent #' . $agentId . ' recovery failed: ' . $exception->getMessage()
            );
        }
    }

    foreach (array_keys($state) as $key) {
        if (!isset($known[(string) $key])) unset($state[$key]);
    }

    agent_recovery_state_save($state);
}

while (true) {
    try {
        agent_recovery_worker_cycle();
    } catch (Throwable $exception) {
        agent_recovery_worker_log('cycle failed: ' . $exception->getMessage());
    }
    sleep(AGENT_RECOVERY_LOOP_SECONDS);
}
