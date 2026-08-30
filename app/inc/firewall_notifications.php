<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

function firewall_notifications_prepare_database(): void
{
    static $prepared = false;
    if ($prepared) return;

    $columns = db()->query('PRAGMA table_info(firewalls)')->fetchAll();
    $hasColumn = false;
    foreach ($columns as $column) {
        if (strcasecmp((string)($column['name'] ?? ''), 'notifications_enabled') === 0) {
            $hasColumn = true;
            break;
        }
    }

    if (!$hasColumn) {
        try {
            db()->exec('ALTER TABLE firewalls ADD COLUMN notifications_enabled INTEGER NOT NULL DEFAULT 1');
        } catch (Throwable $exception) {
            $columns = db()->query('PRAGMA table_info(firewalls)')->fetchAll();
            $hasColumn = false;
            foreach ($columns as $column) {
                if (strcasecmp((string)($column['name'] ?? ''), 'notifications_enabled') === 0) {
                    $hasColumn = true;
                    break;
                }
            }
            if (!$hasColumn) throw $exception;
        }
    }

    $prepared = true;
}

function firewall_notifications_enabled(int $firewallId): bool
{
    firewall_notifications_prepare_database();
    $statement = db()->prepare('SELECT notifications_enabled FROM firewalls WHERE id = ?');
    $statement->execute([$firewallId]);
    $value = $statement->fetchColumn();
    if ($value === false) throw new RuntimeException('Firewall not found.');
    return (int)$value === 1;
}

function firewall_notifications_set_enabled(int $firewallId, bool $enabled): void
{
    firewall_notifications_prepare_database();
    $statement = db()->prepare('UPDATE firewalls SET notifications_enabled = ?, updated_at = ? WHERE id = ?');
    $statement->execute([$enabled ? 1 : 0, gmdate('c'), $firewallId]);
    if ($statement->rowCount() < 1) {
        $exists = db()->prepare('SELECT 1 FROM firewalls WHERE id = ?');
        $exists->execute([$firewallId]);
        if ($exists->fetchColumn() === false) throw new RuntimeException('Firewall not found.');
    }

    // Clear runtime alert state whenever monitoring is toggled so re-enabling
    // starts from a fresh baseline instead of emitting a stale recovery/down event.
    $delete = db()->prepare('DELETE FROM alert_states WHERE state_key = ? OR state_key LIKE ?');
    $delete->execute(['firewall:' . $firewallId, 'vpn:' . $firewallId . ':%']);
}

function firewall_notifications_rows(): array
{
    firewall_notifications_prepare_database();
    return db()->query('SELECT id,name,notifications_enabled FROM firewalls ORDER BY name')->fetchAll();
}
