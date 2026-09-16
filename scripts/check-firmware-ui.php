<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$page = $root . '/app/system_firmware_status.php';
$content = is_file($page) ? file_get_contents($page) : false;
if (!is_string($content)) {
    fwrite(STDERR, "Firmware UI check failed: system_firmware_status.php is unavailable.\n");
    exit(1);
}

$required = [
    '<details class="package-updates" hidden>' => 'package updates must use a native collapsed details element',
    'panel.open=false;' => 'package list must be collapsed after every refresh',
    "label.textContent='Available packages ('+updates.length+')';" => 'collapsed summary must show the package count',
    "name.textContent=String(pkg?.name||'package');" => 'package names must be rendered as text, not HTML',
    "version.textContent=current&&next?current+' → '+next" => 'package version transitions must be rendered safely',
    'panel.hidden=updates.length===0' => 'unused package list must be hidden',
];

foreach ($required as $needle => $message) {
    if (!str_contains($content, $needle)) {
        fwrite(STDERR, "Firmware UI check failed: {$message}.\n");
        exit(1);
    }
}

if (str_contains($content, '<details class="package-updates" open')) {
    fwrite(STDERR, "Firmware UI check failed: package list must not be open by default.\n");
    exit(1);
}

fwrite(STDOUT, "Firmware UI checks passed.\n");
