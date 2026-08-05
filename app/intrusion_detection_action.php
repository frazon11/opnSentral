<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

function ids_bool(mixed $value): string
{
    return in_array(strtolower(trim((string) $value)), ['1','true','yes','on','enabled'], true)
        ? '1'
        : '0';
}

function ids_set_recursive(array &$node, array $keys, string $value): bool
{
    foreach ($node as $key => &$child) {
        if (in_array(strtolower((string) $key), $keys, true)) {
            $child = $value;
            return true;
        }
        if (is_array($child) && ids_set_recursive($child, $keys, $value)) {
            return true;
        }
    }
    unset($child);
    return false;
}

function ids_find_recursive(array $node, array $keys): mixed
{
    foreach ($node as $key => $child) {
        if (in_array(strtolower((string) $key), $keys, true)) {
            return $child;
        }
        if (is_array($child)) {
            $found = ids_find_recursive($child, $keys);
            if ($found !== null) {
                return $found;
            }
        }
    }
    return null;
}

function ids_response_assert_success(array $response, string $operation): void
{
    foreach (['result', 'status'] as $key) {
        if (!array_key_exists($key, $response)) {
            continue;
        }
        $value = strtolower(trim((string) $response[$key]));
        if ($value !== '' && !in_array($value, ['ok', 'saved', 'success', 'done'], true)) {
            throw new RuntimeException(
                'OPNsense rejected ' . $operation . ': ' .
                json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            );
        }
    }

    if (($response['error'] ?? '') !== '') {
        throw new RuntimeException(
            'OPNsense rejected ' . $operation . ': ' . (string) $response['error']
        );
    }
}

function ids_ruleset_rows(array $response): array
{
    if (isset($response['rows']) && is_array($response['rows'])) {
        return $response['rows'];
    }
    foreach (['rulesets', 'items', 'data'] as $key) {
        if (!isset($response[$key]) || !is_array($response[$key])) {
            continue;
        }
        if (array_is_list($response[$key])) {
            return $response[$key];
        }
        $rows = [];
        foreach ($response[$key] as $id => $item) {
            $rows[] = is_array($item)
                ? ['id' => (string) $id] + $item
                : ['id' => (string) $id, 'value' => $item];
        }
        return $rows;
    }
    return [];
}

function ids_ruleset_enabled(array $firewall, string $filename): ?string
{
    try {
        $response = opn_raw_request(
            $firewall,
            'ids/settings/get_ruleset/' . rawurlencode($filename),
            'GET',
            null,
            20
        );
        $enabled = ids_find_recursive($response, ['enabled']);
        if ($enabled !== null) {
            return ids_bool($enabled);
        }
    } catch (Throwable) {
        // Fall back to the full ruleset list below.
    }

    $response = opn_raw_request($firewall, 'ids/settings/list_rulesets', 'GET', null, 20);
    foreach (ids_ruleset_rows($response) as $row) {
        if (!is_array($row)) {
            continue;
        }
        $candidate = trim((string) (
            $row['filename'] ?? $row['id'] ?? $row['name'] ?? $row['ruleset'] ?? ''
        ));
        if ($candidate !== $filename) {
            continue;
        }
        $enabled = ids_find_recursive($row, ['enabled']);
        return $enabled === null ? null : ids_bool($enabled);
    }

    return null;
}

function ids_selected_firewalls(array $ids): array
{
    if ($ids === []) {
        throw new RuntimeException('Select at least one firewall.');
    }
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $statement = db()->prepare(
        'SELECT * FROM firewalls WHERE id IN (' . $placeholders . ') ORDER BY name'
    );
    $statement->execute($ids);
    return $statement->fetchAll();
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('POST required.');
    }
    require_csrf();
    require_configuration_unlocked();

    $action = trim((string) ($_POST['action'] ?? ''));
    $firewallIds = array_values(array_unique(array_filter(
        array_map('intval', (array) ($_POST['firewall_ids'] ?? [])),
        static fn(int $id): bool => $id > 0
    )));
    $firewalls = ids_selected_firewalls($firewallIds);
    $results = [];

    foreach ($firewalls as $firewall) {
        $entry = [
            'id' => (int) $firewall['id'],
            'name' => (string) $firewall['name'],
            'ok' => false,
            'message' => '',
        ];

        try {
            if ($action === 'set_ids') {
                $enabled = ids_bool($_POST['enabled'] ?? '0');
                $mode = trim((string) ($_POST['capture_mode'] ?? 'keep'));
                $settings = opn_raw_request($firewall, 'ids/settings/get', 'GET', null, 15);

                $changed = ids_set_recursive($settings, ['enabled'], $enabled);
                if (!$changed) {
                    throw new RuntimeException('The IDS enabled field was not found in the OPNsense response.');
                }

                if ($mode !== 'keep') {
                    $modeChanged = ids_set_recursive($settings, ['capture_mode','capturemode'], $mode);
                    if (!$modeChanged) {
                        $legacy = $mode === 'pcap' ? '0' : '1';
                        $modeChanged = ids_set_recursive($settings, ['ips_mode','ipsmode'], $legacy);
                    }
                    if (!$modeChanged) {
                        throw new RuntimeException('No supported IDS/IPS capture-mode field was found.');
                    }
                }

                ids_response_assert_success(
                    opn_raw_request($firewall, 'ids/settings/set', 'POST', $settings, 20),
                    'IDS settings update'
                );
                ids_response_assert_success(
                    opn_raw_request($firewall, 'ids/service/reconfigure', 'POST', [], 45),
                    'IDS reconfiguration'
                );
                $entry['message'] = $enabled === '1'
                    ? 'IDS configuration enabled and applied.'
                    : 'IDS configuration disabled and applied.';
            } elseif ($action === 'toggle_rulesets') {
                $rulesets = array_values(array_unique(array_filter(array_map(
                    static fn(mixed $value): string => trim((string) $value),
                    (array) ($_POST['rulesets'] ?? [])
                ))));
                if ($rulesets === []) {
                    throw new RuntimeException('Select at least one ruleset.');
                }

                $enabled = ids_bool($_POST['enabled'] ?? '0');
                $verified = [];
                $failed = [];

                foreach ($rulesets as $ruleset) {
                    try {
                        $response = opn_raw_request(
                            $firewall,
                            'ids/settings/toggle_ruleset/' . rawurlencode($ruleset) . '/' . $enabled,
                            'POST',
                            [],
                            30
                        );
                        ids_response_assert_success($response, 'ruleset toggle for ' . $ruleset);

                        $actual = ids_ruleset_enabled($firewall, $ruleset);
                        if ($actual === null) {
                            throw new RuntimeException('OPNsense did not return an enabled state after the change.');
                        }
                        if ($actual !== $enabled) {
                            throw new RuntimeException(
                                'Read-back verification failed; expected enabled=' . $enabled .
                                ', received enabled=' . $actual . '.'
                            );
                        }
                        $verified[] = $ruleset;
                    } catch (Throwable $exception) {
                        $failed[] = $ruleset . ': ' . $exception->getMessage();
                    }
                }

                if ($verified !== []) {
                    ids_response_assert_success(
                        opn_raw_request($firewall, 'ids/service/reload_rules', 'POST', [], 60),
                        'IDS rules reload'
                    );
                }

                if ($failed !== []) {
                    throw new RuntimeException(
                        count($verified) . ' verified, ' . count($failed) . ' failed. ' .
                        implode(' | ', $failed)
                    );
                }

                $entry['message'] = count($verified) .
                    ' ruleset(s) changed, verified and reloaded.';
            } elseif ($action === 'update_rules') {
                ids_response_assert_success(
                    opn_raw_request($firewall, 'ids/service/update_rules/1', 'POST', [], 180),
                    'rules download and reload'
                );
                $entry['message'] = 'Rules downloaded and reloaded.';
            } elseif ($action === 'deploy_policy') {
                $description = trim((string) ($_POST['description'] ?? ''));
                if ($description === '') {
                    throw new RuntimeException('Policy description is required.');
                }
                $priority = max(0, (int) ($_POST['priority'] ?? 0));
                $policyAction = strtolower(trim((string) ($_POST['action_value'] ?? 'alert')));
                if (!in_array($policyAction, ['alert','drop','reject','pass'], true)) {
                    throw new RuntimeException('Unsupported policy action.');
                }
                $rulesets = array_values(array_unique(array_filter(array_map(
                    static fn(string $value): string => trim($value),
                    explode(',', (string) ($_POST['rulesets'] ?? ''))
                ))));
                $uuid = trim((string) ($_POST['policy_uuid'] ?? ''));
                $payload = [
                    'policy' => [
                        'enabled' => ids_bool($_POST['enabled'] ?? '1'),
                        'priority' => (string) $priority,
                        'action' => $policyAction,
                        'new_action' => $policyAction,
                        'rulesets' => implode(',', $rulesets),
                        'description' => $description,
                    ],
                ];
                if ($uuid === '') {
                    $response = opn_raw_request($firewall, 'ids/settings/add_policy', 'POST', $payload, 30);
                    ids_response_assert_success($response, 'policy creation');
                    $createdUuid = trim((string) ($response['uuid'] ?? ''));
                    $entry['message'] = 'Policy created' . ($createdUuid !== '' ? ' (' . $createdUuid . ')' : '') . ' and applied.';
                } else {
                    ids_response_assert_success(
                        opn_raw_request(
                            $firewall,
                            'ids/settings/set_policy/' . rawurlencode($uuid),
                            'POST',
                            $payload,
                            30
                        ),
                        'policy update'
                    );
                    $entry['message'] = 'Policy updated and applied.';
                }
                ids_response_assert_success(
                    opn_raw_request($firewall, 'ids/service/reconfigure', 'POST', [], 60),
                    'IDS policy reconfiguration'
                );
            } else {
                throw new RuntimeException('Unknown IDS action.');
            }

            $entry['ok'] = true;
        } catch (Throwable $exception) {
            $entry['message'] = $exception->getMessage();
        }

        $results[] = $entry;
    }

    echo json_encode(
        ['ok' => true, 'results' => $results],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
    );
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(
        ['ok' => false, 'error' => $exception->getMessage()],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
