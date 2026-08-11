<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/opnsense.php';
require_once __DIR__ . '/backups.php';
require_once __DIR__ . '/category_central.php';

function wg_create_find_string(array $value, array $keys): ?string
{
    foreach ($keys as $key) {
        if (isset($value[$key]) && is_scalar($value[$key])) {
            $candidate = trim((string) $value[$key]);
            if ($candidate !== '') return $candidate;
        }
    }
    foreach ($value as $child) {
        if (is_array($child)) {
            $found = wg_create_find_string($child, $keys);
            if ($found !== null) return $found;
        }
    }
    return null;
}

function wg_create_response_uuid(array $response): string
{
    $uuid = wg_create_find_string($response, ['uuid', 'id']);
    if ($uuid === null || !preg_match('/^[A-Za-z0-9._:-]+$/', $uuid)) {
        throw new RuntimeException('OPNsense did not return a usable UUID: ' . json_encode($response));
    }
    return $uuid;
}

function wg_create_keypair(array $firewall): array
{
    $response = opn_request($firewall, 'wireguard/server/key_pair', 'GET', [], 15);
    $public = wg_create_find_string($response, ['pubkey','public','public_key','public-key']);
    $private = wg_create_find_string($response, ['privkey','private','private_key','private-key']);
    if ($public === null || $private === null) {
        throw new RuntimeException('Could not read generated WireGuard keypair from ' . $firewall['name'] . '.');
    }
    return ['public' => $public, 'private' => $private];
}

function wg_create_validate_network(string $network): string
{
    $network = trim($network);
    if (!preg_match('/^([^\/]+)\/(\d{1,2})$/', $network, $m)) {
        throw new InvalidArgumentException('Invalid IPv4 CIDR network: ' . $network);
    }
    if (filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || (int)$m[2] > 32) {
        throw new InvalidArgumentException('Invalid IPv4 CIDR network: ' . $network);
    }
    return $network;
}

function wg_create_validate_host(string $host): string
{
    $host = trim($host);
    if (filter_var($host, FILTER_VALIDATE_IP) === false && !preg_match('/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/', $host)) {
        throw new InvalidArgumentException('Invalid endpoint host: ' . $host);
    }
    return $host;
}

function wg_create_validate_name(string $name): string
{
    $name = trim($name);
    if (!preg_match('/^[A-Za-z0-9._-]{1,64}$/', $name)) {
        throw new InvalidArgumentException('Names and interface keys may contain letters, numbers, dot, dash and underscore only.');
    }
    return $name;
}

function wg_create_add_server(array $fw, string $name, array $keypair, int $port, string $tunnel): string
{
    $response = opn_request($fw, 'wireguard/server/add_server', 'POST', ['server' => [
        'enabled'=>'0','name'=>$name,'pubkey'=>$keypair['public'],'privkey'=>$keypair['private'],
        'port'=>(string)$port,'mtu'=>'1420','tunneladdress'=>$tunnel,'disableroutes'=>'0',
        'debug'=>'0','peers'=>''
    ]], 25);
    return wg_create_response_uuid($response);
}

function wg_create_add_client(array $fw, string $name, string $remoteKey, string $remoteTunnel, string $remoteLan, string $endpoint, int $port, int $keepalive): string
{
    $response = opn_request($fw, 'wireguard/client/add_client_builder', 'POST', ['client' => [
        'enabled'=>'0','name'=>$name,'pubkey'=>$remoteKey,'psk'=>'',
        'tunneladdress'=>$remoteTunnel . ',' . $remoteLan,
        'serveraddress'=>$endpoint,'serverport'=>(string)$port,
        'keepalive'=>$keepalive > 0 ? (string)$keepalive : '', 'servers'=>''
    ]], 25);
    return wg_create_response_uuid($response);
}

function wg_create_attach_peer(array $fw, string $serverUuid, string $clientUuid): void
{
    $response = opn_request($fw, 'wireguard/server/get_server/' . rawurlencode($serverUuid), 'GET', [], 15);
    $server = is_array($response['server'] ?? null) ? $response['server'] : $response;
    unset($server['uuid']);
    $server['peers'] = $clientUuid;
    $server['enabled'] = '0';
    opn_request($fw, 'wireguard/server/set_server/' . rawurlencode($serverUuid), 'POST', ['server'=>$server], 25);
}

function wg_create_enable_pair(array $fw, string $serverUuid, string $clientUuid): void
{
    opn_request($fw, 'wireguard/client/toggle_client/' . rawurlencode($clientUuid), 'POST', [], 20);
    opn_request($fw, 'wireguard/server/toggle_server/' . rawurlencode($serverUuid), 'POST', [], 20);
    opn_request($fw, 'wireguard/service/reconfigure', 'POST', [], 35);
}

function wg_create_delete_pair(array $fw, ?string $clientUuid, ?string $serverUuid): void
{
    if ($clientUuid) try { opn_request($fw, 'wireguard/client/del_client/' . rawurlencode($clientUuid), 'POST', [], 20); } catch (Throwable) {}
    if ($serverUuid) try { opn_request($fw, 'wireguard/server/del_server/' . rawurlencode($serverUuid), 'POST', [], 20); } catch (Throwable) {}
    try { opn_request($fw, 'wireguard/service/reconfigure', 'POST', [], 25); } catch (Throwable) {}
}

function wg_create_category_uuid(array $fw): string
{
    $existing = central_category_search($fw, 'WireGuard');
    if ($existing !== null) {
        $uuid = trim((string)($existing['uuid'] ?? ''));
        if ($uuid === '') throw new RuntimeException('Existing WireGuard category has no UUID on ' . $fw['name'] . '.');
        return $uuid;
    }
    return wg_create_response_uuid(opn_request($fw, 'firewall/category/add_item', 'POST', central_category_payload('WireGuard', 'e85d04', 0), 20));
}

function wg_create_filter_rule(array $fw, string $interface, string $protocol, string $source, string $destination, string $port, string $category, string $description): string
{
    $response = opn_request($fw, 'firewall/filter/add_rule', 'POST', ['rule' => [
        'enabled'=>'1','sequence'=>'1','action'=>'pass','quick'=>'1','interfacenot'=>'0',
        'interface'=>$interface,'direction'=>'in','ipprotocol'=>'inet','protocol'=>$protocol,
        'source_net'=>$source,'source_not'=>'0','source_port'=>'',
        'destination_net'=>$destination,'destination_not'=>'0','destination_port'=>$port,
        'log'=>'0','categories'=>$category,'description'=>$description
    ]], 25);
    return wg_create_response_uuid($response);
}

function wg_create_delete_rule(array $fw, ?string $uuid): void
{
    if (!$uuid) return;
    try { opn_request($fw, 'firewall/filter/del_rule/' . rawurlencode($uuid), 'POST', [], 20); } catch (Throwable) {}
}

function wg_create_apply_rules(array $fw): void
{
    opn_request($fw, 'firewall/filter_base/apply', 'POST', [], 35);
}
