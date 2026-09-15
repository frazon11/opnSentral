<?php

declare(strict_types=1);

$path = dirname(__DIR__) . '/app/intrusion_detection.php';
$content = file_get_contents($path);
if (!is_string($content)) {
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

foreach ($forbidden as $needle) {
    if (str_contains($content, $needle)) {
        fwrite(STDERR, "IDS rendering regression: raw generic cell renderer returned.\n");
        exit(1);
    }
}

fwrite(STDOUT, "IDS rendering checks passed.\n");
