<?php

declare(strict_types=1);

$path = __DIR__ . '/../app/agent/opnsentral-agent';
$source = file_get_contents($path);
if (!is_string($source) || $source === '') {
    fwrite(STDERR, "Could not read agent source.\n");
    exit(1);
}

$checks = [
    'agent version 0.1.13+' => preg_match("/const AGENT_VERSION = '([^']+)'/", $source, $m) === 1 && version_compare((string)$m[1], '0.1.13', '>='),
    'runtime config uses dedicated variable' => preg_match('/^\$agentConfig\s*=\s*load_config\(\);$/m', $source) === 1,
    'legacy global runtime assignment is absent' => preg_match('/^\$config\s*=\s*load_config\(\);$/m', $source) !== 1,
    'once uses dedicated runtime config' => str_contains($source, "if (\$command==='once') { run_once(\$agentConfig); exit(0); }"),
    'poll interval uses dedicated runtime config' => str_contains($source, "\$interval=max(30,(int)(\$agentConfig['poll_interval']??60));"),
    'persistent loop uses dedicated runtime config' => str_contains($source, 'run_once($agentConfig)'),
    'OPNsense loader still uses OPNsense global config' => str_contains($source, "function load_opnsense_config(): array\n{\n    global \$config;"),
];

$failed = [];
foreach ($checks as $name => $ok) {
    if (!$ok) $failed[] = $name;
}

// Reproduce the exact PHP scope collision that broke 0.1.12 and prove the
// dedicated runtime variable survives an OPNsense-style global $config write.
$agentConfig = ['server_url' => 'https://example.invalid', 'agent_id' => 'agent', 'agent_secret' => 'secret', 'poll_interval' => 60];
$config = $agentConfig;
$overwriteOpnsenseGlobal = static function (): void {
    global $config;
    $config = ['system' => ['user' => [['name' => 'root']]]];
};
$overwriteOpnsenseGlobal();
if (($agentConfig['server_url'] ?? '') !== 'https://example.invalid' || ($agentConfig['agent_secret'] ?? '') !== 'secret') {
    $failed[] = 'dedicated runtime variable survives OPNsense global overwrite';
}
if (($config['system']['user'][0]['name'] ?? '') !== 'root') {
    $failed[] = 'OPNsense global overwrite model';
}

if ($failed !== []) {
    foreach ($failed as $name) fwrite(STDERR, "FAILED: {$name}\n");
    exit(1);
}

echo "Agent runtime config isolation regression checks passed.\n";
