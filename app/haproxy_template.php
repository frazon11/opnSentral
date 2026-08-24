<?php
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$error = '';
$preflight = null;
$preview = null;
$pluginStatus = null;

$defaults = [
    'template' => 'guacamole',
    'firewall_id' => '',
    'public_hostname' => '',
    'wan_interface' => 'wan',
    'frontend_port' => '443',
    'backend_ip' => '',
    'backend_port' => '8348',
    'backend_protocol' => 'http',
    'certificate' => '',
    'websocket' => '1',
    'healthcheck' => '1',
];

$form = array_merge($defaults, array_map(
    static fn($value) => is_string($value) ? trim($value) : $value,
    $_POST
));

function reverse_proxy_slug(string $hostname): string
{
    $slug = strtolower(preg_replace('/[^a-z0-9]+/i', '_', trim($hostname)) ?? '');
    return trim($slug, '_');
}

function reverse_proxy_valid_hostname(string $hostname): bool
{
    return $hostname !== ''
        && strlen($hostname) <= 253
        && filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
}

function reverse_proxy_plugin_bool(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    return in_array(strtolower(trim((string) $value)), ['1', 'true', 'yes', 'on', 'installed', 'locked'], true);
}

function reverse_proxy_find_plugin(mixed $node, string $packageName): ?array
{
    if (!is_array($node)) return null;

    $name = trim((string) ($node['name'] ?? $node['pkg_name'] ?? $node['package'] ?? ''));
    if ($name === $packageName) {
        $status = strtolower(trim((string) ($node['status'] ?? '')));
        $current = trim((string) ($node['current'] ?? ''));
        $installed = array_key_exists('installed', $node)
            ? reverse_proxy_plugin_bool($node['installed'])
            : ($status === 'installed' || $current !== '');

        return [
            'name' => $name,
            'installed' => $installed,
            'version' => trim((string) ($node['version'] ?? $node['installed_version'] ?? $current)),
            'available_version' => trim((string) ($node['available_version'] ?? $node['new_version'] ?? $node['version'] ?? '')),
        ];
    }

    foreach ($node as $value) {
        $found = reverse_proxy_find_plugin($value, $packageName);
        if ($found !== null) return $found;
    }

    return null;
}

function reverse_proxy_validate(array $form): void
{
    if (!in_array((string) ($form['template'] ?? ''), ['generic', 'guacamole', 'synology'], true)) {
        throw new RuntimeException('Unknown reverse proxy template.');
    }

    if (!reverse_proxy_valid_hostname((string) ($form['public_hostname'] ?? ''))) {
        throw new RuntimeException('Enter a valid public hostname, for example guac.example.com.');
    }

    $frontendPort = filter_var($form['frontend_port'] ?? null, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1, 'max_range' => 65535],
    ]);
    if ($frontendPort === false) {
        throw new RuntimeException('Frontend port must be between 1 and 65535.');
    }

    if (filter_var((string) ($form['backend_ip'] ?? ''), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        throw new RuntimeException('Backend IP must be a valid IPv4 address.');
    }

    $backendPort = filter_var($form['backend_port'] ?? null, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1, 'max_range' => 65535],
    ]);
    if ($backendPort === false) {
        throw new RuntimeException('Backend port must be between 1 and 65535.');
    }

    if (!in_array((string) ($form['backend_protocol'] ?? ''), ['http', 'https'], true)) {
        throw new RuntimeException('Backend protocol must be HTTP or HTTPS.');
    }

    if (!preg_match('/^[A-Za-z0-9_.:-]+$/', (string) ($form['wan_interface'] ?? ''))) {
        throw new RuntimeException('WAN interface contains unsupported characters.');
    }
}

function reverse_proxy_build_preview(array $form): array
{
    $slug = reverse_proxy_slug((string) $form['public_hostname']);
    $prefix = 'opnsentral_' . $slug;
    $frontendPort = (int) $form['frontend_port'];
    $backendPort = (int) $form['backend_port'];
    $backendProtocol = (string) $form['backend_protocol'];
    $template = (string) $form['template'];
    $websocket = isset($form['websocket']) && (string) $form['websocket'] !== '0';
    $healthcheck = isset($form['healthcheck']) && (string) $form['healthcheck'] !== '0';

    $timeouts = [
        'client' => '30s',
        'connect' => '10s',
        'server' => $template === 'guacamole' ? '1h' : '30s',
        'tunnel' => $template === 'guacamole' ? '1h' : '30s',
    ];

    return [
        'required_plugin' => 'os-haproxy',
        'managed_names' => [
            'server' => $prefix . '_server',
            'backend' => $prefix . '_backend',
            'acl' => $prefix . '_host',
            'action' => $prefix . '_use_backend',
            'frontend' => $prefix . '_frontend',
        ],
        'frontend' => [
            'bind' => (string) $form['wan_interface'] . ':' . $frontendPort,
            'mode' => 'http',
            'ssl_offloading' => true,
            'certificate' => (string) $form['certificate'],
            'hostname' => (string) $form['public_hostname'],
        ],
        'backend' => [
            'target' => $backendProtocol . '://' . $form['backend_ip'] . ':' . $backendPort,
            'mode' => 'http',
            'healthcheck' => $healthcheck,
            'websocket' => $websocket,
            'timeouts' => $timeouts,
        ],
        'firewall_rule' => [
            'interface' => (string) $form['wan_interface'],
            'protocol' => 'TCP',
            'source' => 'any',
            'destination' => 'This Firewall',
            'destination_port' => $frontendPort,
        ],
        'notes' => array_values(array_filter([
            'No DNAT rule is required because HAProxy listens on the firewall itself.',
            $template === 'guacamole' ? 'Guacamole preset uses long server/tunnel timeouts for interactive sessions.' : null,
            $backendProtocol === 'https' ? 'Backend TLS certificate verification needs an explicit policy before deployment.' : null,
            $websocket ? 'WebSocket/HTTP upgrade traffic is expected and preserved by the HTTP proxy path.' : null,
        ])),
    ];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    try {
        reverse_proxy_validate($form);

        $firewallId = filter_var($form['firewall_id'] ?? null, FILTER_VALIDATE_INT);
        if ($firewallId === false) {
            throw new RuntimeException('Select a target firewall.');
        }

        $selectedFirewall = null;
        foreach ($firewalls as $firewall) {
            if ((int) $firewall['id'] === (int) $firewallId) {
                $selectedFirewall = $firewall;
                break;
            }
        }
        if ($selectedFirewall === null) {
            throw new RuntimeException('Selected firewall no longer exists.');
        }

        // HAProxy is a hard requirement for this template. Check it before doing
        // any HAProxy-specific API request or allowing a future deployment path.
        $firmwareInfo = opn_request($selectedFirewall, 'core/firmware/info', 'GET', [], 30);
        $pluginStatus = reverse_proxy_find_plugin($firmwareInfo, 'os-haproxy');
        if ($pluginStatus === null || ($pluginStatus['installed'] ?? false) !== true) {
            throw new RuntimeException(
                'Required plugin os-haproxy is not installed on ' . (string) $selectedFirewall['name'] .
                '. Install it under System → Firmware → Plugins in opnSentral before using this template.'
            );
        }

        $preview = reverse_proxy_build_preview($form);

        if (($_POST['operation'] ?? 'preview') === 'preflight') {
            $status = opn_request($selectedFirewall, 'haproxy/service/status', 'GET', [], 15);
            $frontends = opn_request($selectedFirewall, 'haproxy/settings/search_frontends', 'GET', [], 20);
            $servers = opn_request($selectedFirewall, 'haproxy/settings/search_servers', 'GET', [], 20);
            $preflight = [
                'firewall' => (string) $selectedFirewall['name'],
                'required_plugin' => $pluginStatus,
                'service_status' => $status,
                'frontends' => $frontends,
                'servers' => $servers,
            ];
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.rp-grid{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(320px,.95fr);gap:20px}.rp-form label{display:block;font-weight:700;margin:13px 0 6px}.rp-form input,.rp-form select{width:100%;box-sizing:border-box}.rp-options{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px}.rp-option{display:flex!important;gap:8px;align-items:center;font-weight:600!important;margin:0!important;padding:10px;border:1px solid rgba(127,127,127,.25);border-radius:7px}.rp-option input{width:auto}.rp-preview{font-family:monospace;white-space:pre-wrap;overflow:auto}.rp-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.rp-actions button{width:auto}.rp-note{padding:10px 12px;border-radius:7px;background:rgba(127,127,127,.08);margin-top:10px}.rp-warning{border-left:4px solid #d9a400}.rp-ok{border-left:4px solid #2aa84a}.rp-raw{max-height:320px;overflow:auto;background:rgba(127,127,127,.08);padding:10px;border-radius:7px;font-family:monospace;font-size:.9em;white-space:pre-wrap}@media(max-width:900px){.rp-grid{grid-template-columns:1fr}.rp-options{grid-template-columns:1fr}}
</style>
<div class="page-title">
    <div>
        <h1>HAProxy Reverse Proxy Template (testing)</h1>
        <p>Build and validate an opnSentral-managed HTTPS reverse proxy definition before deployment.</p>
    </div>
</div>

<div class="alert warningbox">
    <strong>Requirement:</strong> the selected OPNsense firewall must have <code>os-haproxy</code> installed. opnSentral checks this requirement before preview/preflight and refuses to continue when the plugin is missing.
</div>

<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>
<?php if ($pluginStatus && ($pluginStatus['installed'] ?? false) === true): ?>
<div class="alert goodbox"><strong>HAProxy plugin detected.</strong> <code>os-haproxy</code><?= !empty($pluginStatus['version']) ? ' ' . h((string) $pluginStatus['version']) : '' ?> is installed on the selected firewall.</div>
<?php endif; ?>

<div class="rp-grid">
<section class="card">
    <h2>Template parameters</h2>
    <form method="post" class="rp-form">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">

        <label for="template">Template</label>
        <select id="template" name="template">
            <option value="guacamole" <?= $form['template'] === 'guacamole' ? 'selected' : '' ?>>Guacamole</option>
            <option value="synology" <?= $form['template'] === 'synology' ? 'selected' : '' ?>>Synology DSM</option>
            <option value="generic" <?= $form['template'] === 'generic' ? 'selected' : '' ?>>Generic HTTPS reverse proxy</option>
        </select>

        <label for="firewall_id">Target firewall</label>
        <select id="firewall_id" name="firewall_id" required>
            <option value="">Select firewall…</option>
            <?php foreach ($firewalls as $firewall): ?>
                <option value="<?= (int) $firewall['id'] ?>" <?= (string) $form['firewall_id'] === (string) $firewall['id'] ? 'selected' : '' ?>><?= h((string) $firewall['name']) ?></option>
            <?php endforeach; ?>
        </select>

        <label for="public_hostname">Public hostname</label>
        <input id="public_hostname" type="text" name="public_hostname" required value="<?= h((string) $form['public_hostname']) ?>" placeholder="guac.kryszon.eu">

        <label for="wan_interface">WAN interface</label>
        <input id="wan_interface" type="text" name="wan_interface" required value="<?= h((string) $form['wan_interface']) ?>" placeholder="wan">

        <label for="frontend_port">Frontend HTTPS port</label>
        <input id="frontend_port" type="number" min="1" max="65535" name="frontend_port" required value="<?= h((string) $form['frontend_port']) ?>">

        <label for="backend_ip">Backend IPv4</label>
        <input id="backend_ip" type="text" name="backend_ip" required value="<?= h((string) $form['backend_ip']) ?>" placeholder="192.168.1.150">

        <label for="backend_port">Backend port</label>
        <input id="backend_port" type="number" min="1" max="65535" name="backend_port" required value="<?= h((string) $form['backend_port']) ?>">

        <label for="backend_protocol">Backend protocol</label>
        <select id="backend_protocol" name="backend_protocol">
            <option value="http" <?= $form['backend_protocol'] === 'http' ? 'selected' : '' ?>>HTTP</option>
            <option value="https" <?= $form['backend_protocol'] === 'https' ? 'selected' : '' ?>>HTTPS</option>
        </select>

        <label for="certificate">Certificate / certificate reference</label>
        <input id="certificate" type="text" name="certificate" value="<?= h((string) $form['certificate']) ?>" placeholder="guac.kryszon.eu">

        <div class="rp-options">
            <label class="rp-option"><input type="checkbox" name="websocket" value="1" <?= isset($form['websocket']) && (string) $form['websocket'] !== '0' ? 'checked' : '' ?>> WebSocket support</label>
            <label class="rp-option"><input type="checkbox" name="healthcheck" value="1" <?= isset($form['healthcheck']) && (string) $form['healthcheck'] !== '0' ? 'checked' : '' ?>> Health check</label>
        </div>

        <div class="rp-actions">
            <button type="submit" name="operation" value="preview">Preview template</button>
            <button class="secondary" type="submit" name="operation" value="preflight">Run read-only preflight</button>
        </div>
    </form>
</section>

<section class="card">
    <h2>Deployment preview</h2>
    <?php if ($preview): ?>
        <div class="rp-note rp-ok"><strong>Managed object names are deterministic.</strong> Reusing the same hostname will target the same opnSentral object names instead of inventing duplicates.</div>
        <pre class="rp-preview"><?= h(json_encode($preview, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
        <div class="rp-note rp-warning"><strong>Deployment is intentionally disabled in this first prototype.</strong> It performs validation and read-only HAProxy API checks only. Write support should be added after validating the exact HAProxy model payloads on OPNsense 26.7.</div>
    <?php else: ?>
        <p>Enter the proxy parameters and select <strong>Preview template</strong>.</p>
    <?php endif; ?>

    <?php if ($preflight): ?>
        <h3>Read-only preflight</h3>
        <p>Target: <strong><?= h((string) $preflight['firewall']) ?></strong></p>
        <div class="rp-raw"><?= h(json_encode($preflight, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></div>
    <?php endif; ?>
</section>
</div>
<script>
(function(){
    const template=document.getElementById('template');
    const port=document.getElementById('backend_port');
    const websocket=document.querySelector('input[name="websocket"]');
    function applyPreset(){
        if(template.value==='guacamole'){
            if(!port.dataset.userChanged) port.value='8348';
            websocket.checked=true;
        }else if(template.value==='synology'){
            if(!port.dataset.userChanged) port.value='5001';
        }
    }
    port.addEventListener('input',()=>port.dataset.userChanged='1');
    template.addEventListener('change',applyPreset);
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
