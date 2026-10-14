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
    [$page, "function acme_relation_uuid", 'ACME page must resolve ModelRelationField UUID keys instead of display labels.'],
    [$page, 'acme_relation_uuid($certificateConfig[\'validationMethod\']', 'Certificate validation relation must be resolved to its UUID.'],
    [$page, "Auto-discovered", 'Empty HTTP-01 IP lists must be explained when auto-discovery is active.'],
    [$page, "Not explicitly set", 'Empty HTTP-01 interfaces must be explained instead of rendered as a dash.'],
    [$page, "'acmeclient/validations/search'", 'ACME page must load the validation catalog for reliable relation resolution.'],
    [$page, "$validationByName", 'ACME page must support validation relation lookup by display name.'],
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

foreach (['HTTP-01 challenge port','TLS-ALPN challenge port','Restart timeout','HAProxy integration','Validation data unavailable'] as $forbidden) {
    if (str_contains($page, $forbidden)) {
        fwrite(STDERR, "ACME overview check failed: low-value/noisy field remains: {$forbidden}\n");
        exit(1);
    }
}

if (str_contains($page, 'N/A (') || str_contains($page, 'unknown validation')) {
    fwrite(STDERR, "ACME overview check failed: ambiguous validation placeholders must not be rendered.\n");
    exit(1);
}

if (str_contains($action, '$_POST[\'path\']') || str_contains($action, '$_POST["path"]')) {
    fwrite(STDERR, "ACME overview check failed: action must not accept arbitrary API paths.\n");
    exit(1);
}

fwrite(STDOUT, "ACME overview checks passed.\n");
