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
    if ($raw === '') {
        $raw = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
    }
    if ($raw === '') {
        throw new RuntimeException('Could not determine the public opnSentral FQDN/IP.');
    }

    $host = parse_url('https://' . $raw, PHP_URL_HOST);
    $host = is_string($host) ? trim($host, '[]') : '';
    if ($host === '' || (!filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME))) {
        throw new RuntimeException('The public opnSentral host is not a valid FQDN or IP address.');
    }
    return $host;
}

function ssh_access_agent(int $firewallId): ?array
{
    $statement = db()->prepare(
        'SELECT * FROM agents WHERE firewall_id = ? AND enabled = 1 ORDER BY id DESC LIMIT 1'
    );
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

function ssh_access_category_uuid(array $firewall, bool $create): ?string
{
    $response = opn_request($firewall, 'firewall/category/search_item', 'POST', [
        'current' => 1,
        'rowCount' => 500,
        'searchPhrase' => SSH_ACCESS_CATEGORY,
    ], 20);
    foreach (($response['rows'] ?? []) as $row) {
        if (strcasecmp((string) ($row['name'] ?? ''), SSH_ACCESS_CATEGORY) === 0) {
            $uuid = trim((string) ($row['uuid'] ?? ''));
            if ($uuid !== '') return $uuid;
        }
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
        if (strcasecmp((string) ($row['name'] ?? ''), SSH_ACCESS_CATEGORY) === 0) {
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
    $categoryOk = $present && $categoryUuid !== null && central_alias_has_category($alias, $categoryUuid);
    $content = $present ? central_alias_lines((string) ($alias['content'] ?? '')) : [];
    $contentOk = count($content) === 1 && strcasecmp($content[0], $source) === 0;
    $typeOk = $present && (string) ($alias['type'] ?? '') === 'host';
    $enabled = $present && !in_array((string) ($alias['enabled'] ?? '1'), ['0', 'false'], true);
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
        $payload = $existing;
        $uuid = (string) ($payload['uuid'] ?? '');
        if ($uuid === '') throw new RuntimeException('Existing opnSentral alias has no UUID.');
        unset($payload['uuid']);
        $payload['enabled'] = '1';
        $payload['name'] = SSH_ACCESS_ALIAS;
        $payload['type'] = 'host';
        $payload['content'] = $source;
        $payload['description'] = SSH_ACCESS_ALIAS_DESCRIPTION;
        $payload['categories'] = central_alias_merge_category($existing['categories'] ?? '', $categoryUuid);
        opn_request($firewall, 'firewall/alias/set_item/' . rawurlencode($uuid), 'POST', ['alias' => $payload], 25);
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
        if ((string) ($row['description'] ?? '') !== SSH_ACCESS_RULE_DESCRIPTION) continue;
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
    $categories = $present ? ($rule['categories'] ?? '') : '';
    $parts = is_array($categories)
        ? array_map('strval', $categories)
        : (preg_split('/[\s,;]+/', (string) $categories) ?: []);
    $categoryOk = $present && $categoryUuid !== null && in_array($categoryUuid, $parts, true);
    $interface = $present ? $rule['interface'] ?? '' : '';
    $interfaceOk = $interface === 'any' || (is_array($interface) && in_array('any', array_map('strval', $interface), true));
    return [
        'present' => $present,
        'enabled' => $present && !in_array((string) ($rule['enabled'] ?? '1'), ['0', 'false'], true),
        'action_ok' => $present && (string) ($rule['action'] ?? '') === 'pass',
        'protocol_ok' => $present && strtolower((string) ($rule['protocol'] ?? '')) === 'tcp',
        'direction_ok' => $present && (string) ($rule['direction'] ?? '') === 'in',
        'interface_ok' => $interfaceOk,
        'source_ok' => $present && (string) ($rule['source_net'] ?? '') === SSH_ACCESS_ALIAS,
        'destination_ok' => $present && (string) ($rule['destination_net'] ?? '') === '(self)',
        'port_ok' => $present && (string) ($rule['destination_port'] ?? '') === '22',
        'category_ok' => $categoryOk,
        'reply_to_disabled' => $present && (string) ($rule['disablereplyto'] ?? '0') === '1',
        'ok' => $present
            && !in_array((string) ($rule['enabled'] ?? '1'), ['0', 'false'], true)
            && (string) ($rule['action'] ?? '') === 'pass'
            && strtolower((string) ($rule['protocol'] ?? '')) === 'tcp'
            && (string) ($rule['direction'] ?? '') === 'in'
            && $interfaceOk
            && (string) ($rule['source_net'] ?? '') === SSH_ACCESS_ALIAS
            && (string) ($rule['destination_net'] ?? '') === '(self)'
            && (string) ($rule['destination_port'] ?? '') === '22'
            && $categoryOk
            && (string) ($rule['disablereplyto'] ?? '0') === '1',
    ];
}

function ssh_access_ensure_rule(array $firewall, string $categoryUuid): void
{
    $existing = ssh_access_find_rule($firewall);
    $payload = is_array($existing) ? $existing : [];
    $uuid = trim((string) ($payload['uuid'] ?? ''));
    unset($payload['uuid'], $payload['sort_order'], $payload['prio_group']);

    $payload = array_replace($payload, [
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
        'categories' => central_alias_merge_category($payload['categories'] ?? '', $categoryUuid),
        'description' => SSH_ACCESS_RULE_DESCRIPTION,
    ]);

    $savepoint = opn_request($firewall, 'firewall/filter_base/savepoint', 'POST', [], 20);
    $revision = trim((string) ($savepoint['revision'] ?? ''));
    if ($revision === '') throw new RuntimeException('Could not create firewall-rule rollback savepoint.');

    if ($uuid !== '') {
        opn_request($firewall, 'firewall/filter/set_rule/' . rawurlencode($uuid), 'POST', ['rule' => $payload], 25);
    } else {
        opn_request($firewall, 'firewall/filter/add_rule', 'POST', ['rule' => $payload], 25);
    }
    opn_request($firewall, 'firewall/filter_base/apply/' . rawurlencode($revision), 'POST', [], 40);

    $verified = ssh_access_rule_status($firewall, $categoryUuid);
    if (($verified['ok'] ?? false) !== true) {
        throw new RuntimeException('SSH firewall rule did not verify after apply; OPNsense rollback remains armed.');
    }
    opn_request($firewall, 'firewall/filter_base/cancel_rollback/' . rawurlencode($revision), 'POST', [], 20);
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
    if (!in_array($type, ['ssh_access_status', 'ensure_ssh_access'], true)) {
        throw new RuntimeException('Unsupported SSH access job.');
    }
    $statement = db()->prepare(
        'INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at) VALUES(?, ?, ?, ?, ?)'
    );
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
    $statement = db()->prepare(
        "SELECT * FROM agent_jobs WHERE agent_id = ? AND job_type IN ('ssh_access_status','ensure_ssh_access') ORDER BY id DESC LIMIT 1"
    );
    $statement->execute([$agentId]);
    $row = $statement->fetch();
    return is_array($row) ? $row : null;
}
