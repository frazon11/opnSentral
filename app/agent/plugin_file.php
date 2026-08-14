<?php

declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');

$files = [
    'rc' => '/opt/opnsentral-agent-plugin/etc/rc.d/opnsentral_agent',
    'bootstrap' => '/opt/opnsentral-agent-plugin/opnsense/scripts/OPNsense/OpnSentralAgent/bootstrap.php',
    'controller' => '/opt/opnsentral-agent-plugin/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/IndexController.php',
    'acl' => '/opt/opnsentral-agent-plugin/opnsense/mvc/app/models/OPNsense/OpnSentralAgent/ACL/ACL.xml',
    'menu' => '/opt/opnsentral-agent-plugin/opnsense/mvc/app/models/OPNsense/OpnSentralAgent/Menu/Menu.xml',
    'view' => '/opt/opnsentral-agent-plugin/opnsense/mvc/app/views/OPNsense/OpnSentralAgent/index.volt',
];

$key = strtolower(trim((string) ($_GET['file'] ?? '')));
$path = $files[$key] ?? null;
if (!is_string($path)) {
    http_response_code(404);
    exit("Unknown plugin file.\n");
}
if (!is_file($path) || !is_readable($path)) {
    http_response_code(503);
    exit("Plugin file is unavailable.\n");
}

$content = file_get_contents($path);
if (!is_string($content) || $content === '') {
    http_response_code(503);
    exit("Plugin file is invalid.\n");
}

header('Content-Length: ' . strlen($content));
header('X-Content-SHA256: ' . hash('sha256', $content));
echo $content;
