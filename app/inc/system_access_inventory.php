<?php

declare(strict_types=1);

function access_xml_text(SimpleXMLElement $node, string $name, string $default = ''): string
{
    if (!isset($node->{$name})) return $default;
    $value = trim((string) $node->{$name});
    return $value === '' ? $default : $value;
}

function access_xml_values(SimpleXMLElement $node, string $name): array
{
    if (!isset($node->{$name})) return [];
    $values = [];
    foreach ($node->{$name} as $item) {
        $value = trim((string) $item);
        if ($value !== '') $values[] = $value;
    }
    return array_values(array_unique($values));
}

function access_xml_listish_values(SimpleXMLElement $node, string $name): array
{
    $values = access_xml_values($node, $name);
    $result = [];
    foreach ($values as $value) {
        foreach (preg_split('/[\s,;]+/', $value) ?: [] as $part) {
            $part = trim($part);
            if ($part !== '') $result[] = $part;
        }
    }
    return array_values(array_unique($result));
}

function access_parse_users(SimpleXMLElement $xml): array
{
    $users = [];
    $nodes = $xml->xpath('/opnsense/system/user');
    if (!is_array($nodes)) return [];

    foreach ($nodes as $node) {
        if (!$node instanceof SimpleXMLElement) continue;
        $name = access_xml_text($node, 'name');
        if ($name === '') continue;

        $groups = array_merge(
            access_xml_listish_values($node, 'groupname'),
            access_xml_listish_values($node, 'group')
        );
        $privileges = array_merge(
            access_xml_listish_values($node, 'priv'),
            access_xml_listish_values($node, 'privilege')
        );

        $users[$name] = [
            'name' => $name,
            'description' => access_xml_text($node, 'descr', access_xml_text($node, 'description')),
            'uid' => access_xml_text($node, 'uid'),
            'scope' => access_xml_text($node, 'scope', 'user'),
            'groups' => array_values(array_unique($groups)),
            'privileges' => array_values(array_unique($privileges)),
            'shell' => access_xml_text($node, 'shell'),
            'disabled' => isset($node->disabled),
            'otp' => isset($node->otp_seed) && trim((string) $node->otp_seed) !== '',
            'has_password' => isset($node->password) && trim((string) $node->password) !== '',
        ];
    }

    ksort($users, SORT_NATURAL | SORT_FLAG_CASE);
    return $users;
}

function access_parse_groups(SimpleXMLElement $xml): array
{
    $groups = [];
    $nodes = $xml->xpath('/opnsense/system/group');
    if (!is_array($nodes)) return [];

    foreach ($nodes as $node) {
        if (!$node instanceof SimpleXMLElement) continue;
        $name = access_xml_text($node, 'name');
        if ($name === '') continue;

        $members = array_merge(
            access_xml_listish_values($node, 'member'),
            access_xml_listish_values($node, 'members')
        );
        $privileges = array_merge(
            access_xml_listish_values($node, 'priv'),
            access_xml_listish_values($node, 'privilege')
        );

        $groups[$name] = [
            'name' => $name,
            'description' => access_xml_text($node, 'description', access_xml_text($node, 'descr')),
            'gid' => access_xml_text($node, 'gid'),
            'scope' => access_xml_text($node, 'scope', 'system'),
            'members' => array_values(array_unique($members)),
            'privileges' => array_values(array_unique($privileges)),
        ];
    }

    ksort($groups, SORT_NATURAL | SORT_FLAG_CASE);
    return $groups;
}

function access_reconcile_memberships(array &$users, array $groups): void
{
    $usersByUid = [];
    foreach ($users as $name => $user) {
        $uid = trim((string) ($user['uid'] ?? ''));
        if ($uid !== '') $usersByUid[$uid] = $name;
    }

    foreach ($groups as $groupName => $group) {
        foreach (($group['members'] ?? []) as $uid) {
            $uid = trim((string) $uid);
            if ($uid === '' || !isset($usersByUid[$uid])) continue;
            $userName = $usersByUid[$uid];
            $users[$userName]['groups'][] = (string) $groupName;
        }
    }

    foreach ($users as &$user) {
        $user['groups'] = array_values(array_unique(array_filter(array_map(
            static fn($value): string => trim((string) $value),
            $user['groups'] ?? []
        ), static fn(string $value): bool => $value !== '')));
        natcasesort($user['groups']);
        $user['groups'] = array_values($user['groups']);
    }
    unset($user);
}

function access_load_fleet_inventory(array $firewalls): array
{
    if ($firewalls === []) return [];

    $requests = [];
    foreach ($firewalls as $firewall) {
        $requests[(int) $firewall['id']] = [
            'firewall' => $firewall,
            'path' => 'core/backup/download/this',
            'timeout' => 60,
        ];
    }

    $downloads = opn_downloads_parallel($requests);
    $result = [];
    foreach ($firewalls as $firewall) {
        $id = (int) $firewall['id'];
        $download = $downloads[$id] ?? ['ok' => false, 'error' => 'No response.'];
        $entry = ['firewall' => $firewall, 'ok' => false, 'users' => [], 'groups' => [], 'error' => ''];

        if (($download['ok'] ?? false) !== true) {
            $entry['error'] = (string) ($download['error'] ?? 'Could not read configuration.');
            $result[$id] = $entry;
            continue;
        }

        try {
            libxml_use_internal_errors(true);
            $xml = simplexml_load_string(
                (string) ($download['value'] ?? ''),
                SimpleXMLElement::class,
                LIBXML_NONET | LIBXML_NOCDATA
            );
            if (!$xml instanceof SimpleXMLElement) {
                throw new RuntimeException('Could not parse OPNsense configuration XML.');
            }
            $entry['users'] = access_parse_users($xml);
            $entry['groups'] = access_parse_groups($xml);
            access_reconcile_memberships($entry['users'], $entry['groups']);
            $entry['ok'] = true;
        } catch (Throwable $exception) {
            $entry['error'] = $exception->getMessage();
        }
        $result[$id] = $entry;
    }

    return $result;
}
