<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$page = (string) file_get_contents($root . '/app/plugins.php');
$action = (string) file_get_contents($root . '/app/plugin_action.php');

$requirements = [
    [$page, 'data-operation="remove"', 'Plugins page must expose per-firewall plugin removal.'],
    [$page, 'Remove from all (', 'Plugins page must expose fleet plugin removal.'],
    [$page, "form.set('operation', operation)", 'Plugins page must send the selected install/remove operation.'],
    [$page, "operation === 'remove'", 'Plugins page must handle removal confirmations and status text.'],
    [$action, "\$allowed = ['install', 'reinstall', 'remove', 'lock', 'unlock'];", 'Backend must allow the OPNsense remove operation.'],
    [$action, "in_array(\$operation, ['install', 'reinstall', 'remove'], true)", 'Plugin removal must create a pre-change backup.'],
    [$action, "'core/firmware/' . \$operation . '/' . rawurlencode(\$package)", 'Plugin actions must use the OPNsense firmware API.'],
    [$action, "/^os-[A-Za-z0-9][A-Za-z0-9._+-]*$/", 'Backend must restrict management to os-* packages.'],
];

foreach ($requirements as [$content, $needle, $message]) {
    if (!str_contains($content, $needle)) {
        fwrite(STDERR, "Plugin management check failed: {$message}\n");
        exit(1);
    }
}

if (str_contains($page, "data-operation=\"remove\" data-package=\"'+escapeHtml(packageName)+'\" data-firewall-ids=\"[]\"")) {
    fwrite(STDERR, "Plugin management check failed: remove action must have explicit targets.\n");
    exit(1);
}

fwrite(STDOUT, "Plugin management checks passed.\n");
