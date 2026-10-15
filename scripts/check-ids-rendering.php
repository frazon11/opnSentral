<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$path = $root . '/app/intrusion_detection.php';
$content = file_get_contents($path);
$data = file_get_contents($root . '/app/intrusion_detection_data.php');
$action = file_get_contents($root . '/app/intrusion_detection_action.php');
if (!is_string($content) || !is_string($data) || !is_string($action)) {
    fwrite(STDERR, "Could not read IDS page.\n");
    exit(1);
}

$required = [
    "function isDocumentationColumn(column)",
    "function isDocumentationUrlColumn(column)",
    "function safeHttpUrl(value)",
    "function renderCell(column,value)",
    "if(hasDocumentationUrl&&isDocumentationColumn(key)) return;",
    "return '<a href=\"'+esc(url)+'\" target=\"_blank\" rel=\"noopener noreferrer\">Open documentation</a>';",
    "columns.map(c=>'<td>'+renderCell(c,row[c])+'</td>')",
    "function renderAdministration(data,firewalls)",
    "class=\"button secondary ids-state-action\"",
    "action:'set_enabled'",
    "/intrusion_detection_action.php",
];

foreach ($required as $needle) {
    if (!str_contains($content, $needle)) {
        fwrite(STDERR, "IDS rendering regression: missing contract: {$needle}\n");
        exit(1);
    }
}

$forbidden = [
    "columns.map(c=>'<td>'+esc(display(row[c]))+'</td>')",
];

$contracts = [
    [$data, "'ids_enabled'=>null", 'IDS data must expose normalized enabled state.'],
    [$data, "'ids_mode'=>'',", 'IDS data must expose normalized mode.'],
    [$action, "require_configuration_unlocked();", 'IDS write action must require configuration unlock.'],
    [$action, "backup_before_change(", 'IDS state change must create a backup.'],
    [$action, "'ids/settings/set'", 'IDS action must use the official IDS settings endpoint.'],
    [$action, "'ids/service/reconfigure'", 'IDS action must reconfigure IDS after a change.'],
    [$action, "'ids/settings/get'", 'IDS action must verify state after applying.'],
];

foreach ($contracts as [$source,$needle,$message]) {
    if (!str_contains($source,$needle)) {
        fwrite(STDERR, "IDS rendering regression: {$message}\n");
        exit(1);
    }
}

if (str_contains($content, "columnFilters[enabledColumn]='enabled'")) {
    fwrite(STDERR, "IDS rendering regression: administration must not hide disabled firewalls by default.\n");
    exit(1);
}

foreach ($forbidden as $needle) {
    if (str_contains($content, $needle)) {
        fwrite(STDERR, "IDS rendering regression: raw generic cell renderer returned.\n");
        exit(1);
    }
}

fwrite(STDOUT, "IDS rendering checks passed.\n");
