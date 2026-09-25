<?php

declare(strict_types=1);

$root = dirname(__DIR__);

function recovery_read(string $path): string
{
    if (!is_file($path)) {
        fwrite(STDERR, "Missing required recovery file: {$path}\n");
        exit(1);
    }
    $content = file_get_contents($path);
    if (!is_string($content) || $content === '') {
        fwrite(STDERR, "Could not read recovery file: {$path}\n");
        exit(1);
    }
    return $content;
}

function recovery_require(string $content, string $needle, string $message): void
{
    if (!str_contains($content, $needle)) {
        fwrite(STDERR, "Agent recovery check failed: {$message}\n");
        exit(1);
    }
}

$registry = recovery_read($root . '/opnsense-plugin/opnsentral-agent/src/etc/inc/plugins.inc.d/opnsentralagent.inc');
recovery_require($registry, 'function opnsentralagent_services()', 'OPNsense service registry function is missing');
recovery_require($registry, "'name' => 'opnsentral_agent'", 'service registry must expose opnsentral_agent');
recovery_require($registry, "'start' => ['opnsentralagent agent.start']", 'service registry must expose the recovery start action');
recovery_require($registry, "'pidfile' => '/var/run/opnsentral_agent.pid'", 'service registry must use the real daemon pidfile');

$actions = recovery_read($root . '/opnsense-plugin/opnsentral-agent/src/opnsense/service/conf/actions.d/actions_opnsentralagent.conf');
foreach (['[agent.status]', '[agent.start]', '[agent.stop]', '[agent.restart]'] as $section) {
    recovery_require($actions, $section, 'missing configd service action ' . $section);
}
recovery_require($actions, 'parameters:opnsentral_agent start', 'agent.start must start only the opnSentral service');
recovery_require($actions, 'parameters:opnsentral_agent restart', 'agent.restart must restart only the opnSentral service');

$installer = recovery_read($root . '/app/agent/install-plugin.sh');
recovery_require($installer, 'fetch_plugin_file service_registry /usr/local/etc/inc/plugins.inc.d/opnsentralagent.inc 0644', 'installer must deploy service registry');
recovery_require($installer, "grep -q 'opnsentralagent agent.start'", 'installer must verify recovery action registration');
recovery_require($installer, '/usr/local/sbin/pluginctl -S opnsentral_agent', 'installer must verify OPNsense service registration');
recovery_require($installer, '[ -x /usr/local/etc/rc.syshook.d/start/50-opnsentral-agent ]', 'installer must verify boot recovery hook');

$pluginFiles = recovery_read($root . '/app/agent/plugin_file.php');
recovery_require($pluginFiles, "'service_registry' => '/opt/opnsentral-agent-plugin/etc/inc/plugins.inc.d/opnsentralagent.inc'", 'plugin file endpoint must serve service registry');

$helper = recovery_read($root . '/app/inc/agent_recovery.php');
recovery_require($helper, 'AGENT_RECOVERY_STALE_SECONDS = 300', 'automatic recovery must use the same five-minute stale threshold as the UI');
recovery_require($helper, 'agent_recovery_backoff_seconds', 'automatic recovery must use retry backoff');
recovery_require($helper, "'core/service/' . \$action . '/opnsentral_agent'", 'automatic recovery must use the standard OPNsense service API');
recovery_require($helper, "['start', 'restart']", 'automatic recovery must support both start and restart requests');

$worker = recovery_read($root . '/app/agent_recovery_worker.php');
recovery_require($worker, "SELECT * FROM agents WHERE enabled = 1 AND firewall_id IS NOT NULL", 'watchdog must only recover enabled associated agents');
recovery_require($worker, "agent_recovery_request_service($pdo, $agent, $action)", 'watchdog must request service recovery for stale agents');
recovery_require($worker, 'agent_recovery_due($entry)', 'watchdog must respect recovery backoff');
recovery_require($worker, 'sleep(AGENT_RECOVERY_LOOP_SECONDS)', 'watchdog must run continuously at the configured interval');

$entrypoint = recovery_read($root . '/entrypoint.sh');
recovery_require($entrypoint, "php /var/www/html/agent_recovery_worker.php", 'container must start the automatic agent recovery watchdog');

$agentsPage = recovery_read($root . '/app/agents.php');
recovery_require($agentsPage, 'Automatic stale-agent recovery is active', 'Agents page must explain automatic stale recovery');
recovery_require($agentsPage, 'agent_recovery_repair_command($publicBase)', 'Agents page must provide a one-time legacy repair command');

$actionsPage = recovery_read($root . '/app/agents_action.php');
recovery_require($actionsPage, 'agent_recovery_is_fresh', 'agent update path must check heartbeat freshness');
recovery_require($actionsPage, 'agent_recovery_request_service', 'agent update path must attempt service recovery through the shared helper');
recovery_require($actionsPage, 'older installation predates the recoverable-service registration', 'legacy stale agents must fail with an explicit repair explanation');

fwrite(STDOUT, "Agent recovery checks passed.\n");
