<div class="content-box" style="padding: 20px;">
    <h2>{{ lang._('opnSentral Agent') }}</h2>
    <p>{{ lang._('Outbound management agent for opnSentral.') }}</p>

    <table class="table table-striped">
        <tbody>
            <tr>
                <th style="width: 220px;">{{ lang._('Connection model') }}</th>
                <td>{{ lang._('Outbound HTTPS only') }}</td>
            </tr>
            <tr>
                <th>{{ lang._('Worker') }}</th>
                <td><code>/usr/local/sbin/opnsentral-agent</code></td>
            </tr>
            <tr>
                <th>{{ lang._('Configuration') }}</th>
                <td><code>/usr/local/etc/opnsentral-agent.json</code></td>
            </tr>
            <tr>
                <th>{{ lang._('Service') }}</th>
                <td><code>opnsentral_agent</code></td>
            </tr>
        </tbody>
    </table>
</div>

<div class="content-box" style="padding: 20px;">
    <h3>{{ lang._('Registration') }}</h3>
    <p>{{ lang._('The plugin bootstrap validates the opnSentral HTTPS endpoint, retrieves the canonical agent manifest, registers with a one-time token, verifies the downloaded worker by SHA-256, runs one connectivity cycle and starts the service.') }}</p>
    <p>{{ lang._('GUI registration controls will be enabled after the backend action layer is completed and tested. The bootstrap worker path is already part of this plugin source.') }}</p>
</div>

<div class="content-box" style="padding: 20px;">
    <h3>{{ lang._('Recovery') }}</h3>
    <p>{{ lang._('If registration succeeds but worker installation or service startup fails, the registered identity is preserved. The repair operation re-downloads and verifies the canonical worker without creating a second agent identity.') }}</p>
</div>
