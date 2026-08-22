<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();

$firewallId = (int)($_GET['firewall_id'] ?? 0);
$userName = trim((string)($_GET['user'] ?? ''));
$query = [];
if ($firewallId > 0) $query['firewall_id'] = $firewallId;
if ($userName !== '') $query['user'] = $userName;
$location = '/system_access_ssh_key.php' . ($query ? '?' . http_build_query($query) : '');
header('Location: ' . $location, true, 302);
exit;
