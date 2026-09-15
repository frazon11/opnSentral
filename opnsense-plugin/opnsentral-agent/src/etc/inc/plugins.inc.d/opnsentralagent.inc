<?php

/**
 * Register the opnSentral worker with OPNsense's native service registry.
 * This makes the service visible to System > Diagnostics > Services and
 * allows the standard core/service API to recover a stopped worker.
 */
function opnsentralagent_services(): array
{
    return [[
        'description' => gettext('opnSentral Agent'),
        'configd' => [
            'restart' => ['opnsentralagent agent.restart'],
            'start' => ['opnsentralagent agent.start'],
            'stop' => ['opnsentralagent agent.stop'],
        ],
        'name' => 'opnsentral_agent',
        'pidfile' => '/var/run/opnsentral_agent.pid',
    ]];
}
