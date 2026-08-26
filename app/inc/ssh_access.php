<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/opnsense.php';
require_once __DIR__ . '/backups.php';
require_once __DIR__ . '/alias_central.php';
require_once __DIR__ . '/managed_category.php';

const SSH_ACCESS_ALIAS = 'opnSentral';
const SSH_ACCESS_CATEGORY = 'Managed by opnSentral';
const SSH_ACCESS_RULE_DESCRIPTION = 'Managed by opnSentral - Allow SSH management';
const SSH_ACCESS_ALIAS_DESCRIPTION = 'Managed by opnSentral - SSH source';
const SSH_ACCESS_AGENT_MIN_VERSION = '0.1.5';

function ssh_access_public_source(): string
{
    $raw = trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_HOST'] ?? ''))[0] ?? '');
    if ($raw === '') $raw = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
    if ($raw === '') throw new RuntimeException('Could not determine the public opnSentral FQDN/IP.');

    $host = parse_url('https://' . $raw, PHP_URL_HOST);
    $host = is_string($host) ? trim($host, '[]') : '';
    if ($host === '' || (!filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME))) {
        throw new RuntimeException('The public opnSentral host is not a valid FQDN or IP address.');
    }
    return $host;
}

function ssh_access_agent(int $firewallId): ?array
{
    $statement = db()->prepare('SELECT * FROM agents WHERE firewall_id = ? AND enabled = 1 ORDER BY id DESC LIMIT 1');
    $statement->execute([$firewallId]);
    $row = $statement->fetch();
    return is_array($row) ? $row : null;
}

function ssh_access_agent_ready(?array $agent): bool
{
    if ($agent === null) return false;
    $version = trim((string) ($agent['last_version'] ?? ''));
    return $version !== '' && version_compare($version, SSH_ACCESS_AGENT_MIN_VERSION, '>=');
}

function ssh_access_selected_values(mixed $value): array
{
    if (is_string($value) || is_int($value)) {
        return array_values(array_filter(
            preg_split('/[\s,;]+/', trim((string) $value)) ?: [],
            static fn(string $item): bool => $item !== ''
        ));
    }
    if (!is_array($value)) return [];

    $result = [];

    /*
     * OPNsense MVC fields are returned in more than one shape depending on
     * endpoint/field type. Examples seen from get_rule/search_rule include:
     *   {"pass":"Pass"}
     *   {"uuid":"Managed by opnSentral"}
     *   {"wan":{"selected":1,"value":"wan"}}
     *   ["wan","lan"]
     * Normalize all of them to the underlying selected values/keys.
     */
    foreach ($value as $key => $item) {
        if (is_array($item)) {
            $selected = $item['selected'] ?? false;
            if (in_array($selected, [1, '1', true, 'true', 'selected'], true)) {
                $candidate = is_string($key) && !ctype_digit($key)
                    ? $key
                    : trim((string) ($item['value'] ?? ''));
                if ($candidate !== '') $result[] = $candidate;
                continue;
            }

            if (array_key_exists('value', $item) && count($item) === 1) {
                $candidate = trim((string) $item['value']);
                if ($candidate !== '') $result[] = $candidate;
            }
            continue;
        }

        if (is_int($key)) {
            $candidate = trim((string) $item);
            if ($candidate !== '') $result[] = $candidate;
            continue;
        }

        if (in_array($item, [1, '1', true, 'true', 'selected'], true)) {
            $result[] = (string) $key;
            continue;
        }

        /*
         * get_rule() renders selected OptionField/ModelRelation choices as
         * associative key => display-label maps, e.g. "pass" => "Pass".
         */
        if (is_scalar($item) && trim((string) $key) !== '') {
            $result[] = (string) $key;
        }
    }

    return array_values(array_unique(array_filter(
        $result,
        static fn(string $item): bool => trim($item) !== ''
    )));
}

function ssh_access_single_value(mixed $value): string
{
    if (is_string($value) || is_int($value)) return trim((string) $value);
    $selected = ssh_access_selected_values($value);
    return $selected[0] ?? '';
}

function ssh_access_category_uuid(array $firewall, bool $create): ?string
{
    $response = opn_request($firewall, 'firewall/category/search_item', 'POST', [
        'current' => 1,
        'rowCount' => 500,
        'searchPhrase' => SSH_ACCESS_CATEGORY,
    ], 20);
    foreach (($response['rows'] ?? []) as $row) {
        if (!is_array($row) || strcasecmp(trim((string) ($row['name'] ?? '')), SSH_ACCESS_CATEGORY) !== 0) continue;
        $uuid = trim((string) ($row['uuid'] ?? ''));
        if ($uuid === '') continue;
        if ($create && (string) ($row['name'] ?? '') !== SSH_ACCESS_CATEGORY) {
            opn_request($firewall, 'firewall/category/set_item/' . rawurlencode($uuid), 'POST', [
                'category' => [
                    'name' => SSH_ACCESS_CATEGORY,
                    'color' => trim((string) ($row['color'] ?? managed_category_color())),
                    'auto' => (string) ($row['auto'] ?? '0'),
                ],
            ], 20);
        }
        return $uuid;
    }
    if (!$create) return null;

    opn_request($firewall, 'firewall/category/add_item', 'POST', [
        'category' => [
            'name' => SSH_ACCESS_CATEGORY,
            'color' => managed_category_color(),
            'auto' => '0',
        ],
    ], 20);

    $response = opn_request($firewall, 'firewall/category/search_item', 'POST', [
        'current' => 1,
        'rowCount' => 500,
        'searchPhrase' => SSH_ACCESS_CATEGORY,
    ], 20);
    foreach (($response['rows'] ?? []) as $row) {
        if (is_array($row) && (string) ($row['name'] ?? '') === SSH_ACCESS_CATEGORY) {
            $uuid = trim((string) ($row['uuid'] ?? ''));
            if ($uuid !== '') return $uuid;
        }
    }
    throw new RuntimeException('Could not create or resolve the Managed by opnSentral category.');
}

function ssh_access_alias_status(array $firewall, string $source, ?string $categoryUuid): array
{
    $alias = central_alias_find($firewall, SSH_ACCESS_ALIAS);
    $present = is_array($alias);
    $categories = $present ? ssh_access_selected_values($alias['categories'] ?? '') : [];
    $content = $present ? ssh_access_selected_values($alias['content'] ?? '') : [];
    $type = $present ? ssh_access_single_value($alias['type'] ?? '') : '';
    $enabledValue = $present ? ssh_access_single_value($alias['enabled'] ?? '1') : '0';
    $categoryOk = $present && $categoryUuid !== null && in_array($categoryUuid, $categories, true);
    $contentOk = count($content) === 1 && strcasecmp($content[0], $source) === 0;
    $typeOk = $type === 'host';
    $enabled = $present && !in_array($enabledValue, ['0', 'false'], true);
    return [
        'present' => $present,
        'enabled' => $enabled,
        'type_ok' => $typeOk,
        'content_ok' => $contentOk,
        'category_ok' => $categoryOk,
        'content' => $content,
        'ok' => $present && $enabled && $typeOk && $contentOk && $categoryOk,
    ];
}

function ssh_access_ensure_alias(array $firewall, string $source, string $categoryUuid): void
{
    $existing = central_alias_find($firewall, SSH_ACCESS_ALIAS);
    if ($existing !== null) {
        $uuid = trim((string) ($existing['uuid'] ?? ''));
        if ($uuid === '') throw new RuntimeException('Existing opnSentral alias has no UUID.');
        $categories = ssh_access_selected_values($existing['categories'] ?? '');
        if (!in_array($categoryUuid, $categories, true)) $categories[] = $categoryUuid;
        opn_request($firewall, 'firewall/alias/set_item/' . rawurlencode($uuid), 'POST', ['alias' => [
            'enabled' => '1',
            'name' => SSH_ACCESS_ALIAS,
            'type' => 'host',
            'content' => $source,
            'description' => SSH_ACCESS_ALIAS_DESCRIPTION,
            'categories' => implode(',', $categories),
        ]], 25);
    } else {
        opn_request($firewall, 'firewall/alias/add_item', 'POST', ['alias' => [
            'enabled' => '1',
            'name' => SSH_ACCESS_ALIAS,
            'type' => 'host',
            'content' => $source,
            'description' => SSH_ACCESS_ALIAS_DESCRIPTION,
            'categories' => $categoryUuid,
        ]], 25);
    }
    opn_request($firewall, 'firewall/alias/reconfigure', 'POST', [], 30);
}

function ssh_access_find_rule(array $firewall): ?array
{
    $query = http_build_query([
        'current' => 1,
        'rowCount' => 500,
        'searchPhrase' => SSH_ACCESS_RULE_DESCRIPTION,
    ], '', '&', PHP_QUERY_RFC3986);
    $response = opn_request($firewall, 'firewall/filter/search_rule?' . $query, 'GET', null, 20);
    foreach (($response['rows'] ?? []) as $row) {
        if (!is_array($row) || (string) ($row['description'] ?? '') !== SSH_ACCESS_RULE_DESCRIPTION) continue;
        $uuid = trim((string) ($row['uuid'] ?? ''));
        if ($uuid === '') return $row;
        $item = opn_request($firewall, 'firewall/filter/get_rule/' . rawurlencode($uuid), 'GET', null, 20);
        $rule = is_array($item['rule'] ?? null) ? $item['rule'] : $item;
        $rule['uuid'] = $uuid;
        return $rule;
    }
    return null;
}

function ssh_access_rule_status(array $firewall, ?string $categoryUuid): array
{
    $rule = ssh_access_find_rule($firewall);
    $present = is_array($rule);
    $categories = $present ? ssh_access_selected_values($rule['categories'] ?? '') : [];
    $interfaces = $present ? ssh_access_selected_values($rule['interface'] ?? '') : [];
    $action = $present ? strtolower(ssh_access_single_value($rule['action'] ?? '')) : '';
    $protocol = $present ? strtolower(ssh_access_single_value($rule['protocol'] ?? '')) : '';
    $direction = $present ? strtolower(ssh_access_single_value($rule['direction'] ?? '')) : '';
    $sourceNet = $present ? ssh_access_single_value($rule['source_net'] ?? '') : '';
    $destination = $present ? ssh_access_single_value($rule['destination_net'] ?? '') : '';
    $port = $present ? ssh_access_single_value($rule['destination_port'] ?? '') : '';
    $replyTo = $present ? strtolower(ssh_access_single_value($rule['disablereplyto'] ?? '0')) : '0';
    $enabledValue = $present ? strtolower(ssh_access_single_value($rule['enabled'] ?? '1')) : '0';

    /* Empty interface is how OPNsense returns an all-interface/floating rule. */
    $interfaceOk = $interfaces === [] || in_array('any', array_map('strtolower', $interfaces), true);
    $categoryOk = $present && $categoryUuid !== null && in_array($categoryUuid, $categories, true);
    $enabled = $present && !in_array($enabledValue, ['0', 'false', 'off', 'disabled'], true);

    $status = [
        'present' => $present,
        'enabled' => $enabled,
        'action_ok' => $action === 'pass',
        'protocol_ok' => $protocol === 'tcp',
        'direction_ok' => $direction === 'in',
        'interface_ok' => $interfaceOk,
        'source_ok' => strcasecmp($sourceNet, SSH_ACCESS_ALIAS) === 0,
        'destination_ok' => $destination === '(self)',
        'port_ok' => $port === '22',
        'category_ok' => $categoryOk,
        'reply_to_disabled' => in_array($replyTo, ['1', 'true', 'on', 'enabled'], true),
        'actual' => [
            'enabled' => $enabledValue,
            'action' => $action,
            'protocol' => $protocol,
            'direction' => $direction,
            'interfaces' => $interfaces,
            'source_net' => $sourceNet,
            'destination_net' => $destination,
            'destination_port' => $port,
            'categories' => $categories,
            'disablereplyto' => $replyTo,
        ],
    ];

    $status['ok'] = $status['present'] && $status['enabled'] && $status['action_ok'] && $status['protocol_ok']
        && $status['direction_ok'] && $status['interface_ok'] && $status['source_ok'] && $status['destination_ok']
        && $status['port_ok'] && $status['category_ok'] && $status['reply_to_disabled'];

    return $status;
}

function ssh_access_rule_verification_failures(array $status): array
{
    $labels = [
        'present' => 'rule missing',
        'enabled' => 'enabled',
        'action_ok' => 'action',
        'protocol_ok' => 'protocol',
        'direction_ok' => 'direction',
        'interface_ok' => 'interface',
        'source_ok' => 'source',
        'destination_ok' => 'destination',
        'port_ok' => 'port',
        'category_ok' => 'category',
        'reply_to_disabled' => 'disable-reply-to',
    ];
    $failed = [];
    foreach ($labels as $key => $label) {
        if (($status[$key] ?? false) !== true) $failed[] = $label;
    }
    return $failed;
}

function ssh_access_ensure_rule(array $firewall, string $categoryUuid): void
{
    $existing = ssh_access_find_rule($firewall);
    $uuid = is_array($existing) ? trim((string) ($existing['uuid'] ?? '')) : '';
    $payload = [
        'enabled' => '1',
        'statetype' => 'keep',
        'action' => 'pass',
        'quick' => '1',
        'interfacenot' => '0',
        'interface' => 'any',
        'direction' => 'in',
        'ipprotocol' => 'inet46',
        'protocol' => 'tcp',
        'source_net' => SSH_ACCESS_ALIAS,
        'source_not' => '0',
        'source_port' => '',
        'destination_net' => '(self)',
        'destination_not' => '0',
        'destination_port' => '22',
        'disablereplyto' => '1',
        'log' => '0',
        'allowopts' => '0',
        'nosync' => '0',
        'nopfsync' => '0',
        'categories' => $categoryUuid,
        'description' => SSH_ACCESS_RULE_DESCRIPTION,
    ];

    if ($uuid !== '') {
        opn_request($firewall, 'firewall/filter/set_rule/' . rawurlencode($uuid), 'POST', ['rule' => $payload], 25);
    } else {
        opn_request($firewall, 'firewall/filter/add_rule', 'POST', ['rule' => $payload], 25);
    }

    $apply = opn_request($firewall, 'firewall/filter/apply', 'POST', [], 40);
    $applyStatus = strtolower(trim((string) ($apply['status'] ?? '')));
    if ($applyStatus !== '' && !in_array($applyStatus, ['ok', 'done'], true)) {
        throw new RuntimeException('OPNsense rejected the SSH firewall-rule apply: ' . ($apply['status'] ?? 'unknown status'));
    }

    $verified = ssh_access_rule_status($firewall, $categoryUuid);
    if (($verified['ok'] ?? false) !== true) {
        $failed = ssh_access_rule_verification_failures($verified);
        $actual = json_encode($verified['actual'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        throw new RuntimeException(
            'SSH firewall rule verification failed for: ' . implode(', ', $failed) .
            '. Actual OPNsense values: ' . ($actual !== false ? $actual : 'unavailable') .
            '. Restore the pre-change opnSentral backup if required.'
        );
    }
}

function ssh_access_objects_status(array $firewall, string $source): array
{
    $categoryUuid = ssh_access_category_uuid($firewall, false);
    $alias = ssh_access_alias_status($firewall, $source, $categoryUuid);
    $rule = ssh_access_rule_status($firewall, $categoryUuid);
    return [
        'source' => $source,
        'category' => ['name' => SSH_ACCESS_CATEGORY, 'present' => $categoryUuid !== null, 'uuid' => $categoryUuid],
        'alias' => $alias,
        'rule' => $rule,
        'ok' => $categoryUuid !== null && ($alias['ok'] ?? false) === true && ($rule['ok'] ?? false) === true,
    ];
}

function ssh_access_ensure_objects(array $firewall, string $source): array
{
    $categoryUuid = ssh_access_category_uuid($firewall, true);
    ssh_access_ensure_alias($firewall, $source, $categoryUuid);
    ssh_access_ensure_rule($firewall, $categoryUuid);
    return ssh_access_objects_status($firewall, $source);
}

function ssh_access_queue_job(array $agent, string $type, array $payload = []): int
{
    if (!in_array($type, ['ssh_access_status', 'ensure_ssh_access'], true)) throw new RuntimeException('Unsupported SSH access job.');
    $statement = db()->prepare('INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at) VALUES(?, ?, ?, ?, ?)');
    $statement->execute([
        (int) $agent['id'],
        $type,
        json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
        'queued',
        gmdate('c'),
    ]);
    return (int) db()->lastInsertId();
}

function ssh_access_latest_job(int $agentId): ?array
{
    $statement = db()->prepare("SELECT * FROM agent_jobs WHERE agent_id = ? AND job_type IN ('ssh_access_status','ensure_ssh_access') ORDER BY id DESC LIMIT 1");
    $statement->execute([$agentId]);
    $row = $statement->fetch();
    return is_array($row) ? $row : null;
}
