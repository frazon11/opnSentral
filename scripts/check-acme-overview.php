<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$page = (string) file_get_contents($root . '/app/acme.php');
$action = (string) file_get_contents($root . '/app/acme_action.php');

$checks = [
    [$page, 'IP Auto-Discovery', 'ACME page must show HTTP-01 IP auto-discovery.'],
    [$page, "http_opn_autodiscovery", 'ACME page must read the OPNsense HTTP-01 auto-discovery setting.'],
    [$page, 'HTTP-01 interface', 'ACME page must show the selected HTTP-01 interface.'],
    [$page, "http_opn_interface", 'ACME page must read the HTTP-01 interface field.'],
    [$page, 'HTTP-01 IP addresses', 'ACME page must show manually configured HTTP-01 IP addresses.'],
    [$page, "http_opn_ipaddresses", 'ACME page must read HTTP-01 IP addresses.'],
    [$page, 'Last ACME status', 'ACME page must show the last ACME status.'],
    [$page, 'statusLastUpdate', 'ACME page must show the last ACME run timestamp.'],
    [$page, 'Issue / renew now', 'ACME page must expose a run action.'],
    [$page, "gmdate('Y-m-d H:i:s'", 'ACME timestamps must be rendered as human-readable dates.'],
    [$action, 'require_csrf();', 'ACME run action must require CSRF.'],
    [$action, 'require_configuration_unlocked();', 'ACME run action must require configuration unlock.'],
    [$action, "backup_before_change(", 'ACME run must create a pre-change backup.'],
    [$action, "'acmeclient/certificates/sign/'", 'ACME run must use the narrow certificate sign endpoint.'],
    [$action, "'acmeclient/certificates/get/'", 'ACME run must verify the target certificate first.'],
];

foreach ($checks as [$content,$needle,$message]) {
    if (!str_contains($content,$needle)) {
        fwrite(STDERR, "ACME overview check failed: {$message}\n");
        exit(1);
    }
}

if (str_contains($action, '$_POST[\'path\']') || str_contains($action, '$_POST["path"]')) {
    fwrite(STDERR, "ACME overview check failed: action must not accept arbitrary API paths.\n");
    exit(1);
}

fwrite(STDOUT, "ACME overview checks passed.\n");
