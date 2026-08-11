<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';

require_login();

$firewalls = db()
    ->query('SELECT id,name,base_url FROM firewalls ORDER BY name')
    ->fetchAll();

require __DIR__ . '/inc/header.php';
?>

<div class="page-title">
    <div>
        <h1>Create OpenVPN Roadwarrior Server</h1>
        <p>Create a modern OpenVPN server instance on one managed OPNsense.</p>
    </div>
</div>

<div class="alert warning">
    <strong>First implementation.</strong>
    The wizard uses existing CA, server certificate, TLS key and authentication
    objects. It does not create firewall rules automatically yet.
</div>

<div id="ovpn-error" class="alert error hidden"></div>
<div id="ovpn-success" class="alert goodbox hidden"></div>

<form id="ovpn-form" class="form-card ovpn-roadwarrior-form">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">

    <section class="wizard-section">
        <h2>Target firewall</h2>

        <div class="field-grid">
            <label>
                OPNsense
                <select name="firewall_id" id="firewall-id" required>
                    <option value="">Select firewall</option>
                    <?php foreach ($firewalls as $firewall): ?>
                        <option value="<?= (int) $firewall['id'] ?>">
                            <?= h((string) $firewall['name']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </label>

            <label>
                OpenVPN instance ID
                <input
                    name="vpnid"
                    id="vpnid"
                    type="number"
                    min="1"
                    required
                    readonly
                >
            </label>
        </div>

        <div id="object-status" class="muted">
            Select a firewall to load available certificates and providers.
        </div>
    </section>

    <section class="wizard-section">
        <h2>Server</h2>

        <div class="field-grid">
            <label>
                Description
                <input
                    name="description"
                    placeholder="Roadwarrior"
                    value="Roadwarrior"
                    required
                >
            </label>

            <label>
                Protocol
                <select name="proto" required>
                    <option value="udp4" selected>UDP IPv4</option>
                    <option value="tcp4">TCP IPv4</option>
                    <option value="udp6">UDP IPv6</option>
                    <option value="tcp6">TCP IPv6</option>
                </select>
            </label>

            <label>
                Port
                <input
                    name="port"
                    type="number"
                    min="1"
                    max="65535"
                    value="1194"
                    required
                >
            </label>

            <label>
                Bind address
                <input
                    name="local"
                    placeholder="Optional — leave empty for all addresses"
                >
            </label>

            <label>
                Tunnel network
                <input
                    name="server"
                    placeholder="10.81.0.0/24"
                    required
                >
            </label>

            <label>
                Maximum clients
                <input
                    name="maxclients"
                    type="number"
                    min="1"
                    max="10000"
                    value="50"
                >
            </label>
        </div>
    </section>

    <section class="wizard-section">
        <h2>Trust and authentication</h2>

        <div class="field-grid">
            <label>
                Certificate authority
                <select name="ca" id="ca-select" required>
                    <option value="">Load from firewall</option>
                </select>
            </label>

            <label>
                Server certificate
                <select name="cert" id="cert-select" required>
                    <option value="">Load from firewall</option>
                </select>
            </label>

            <label>
                TLS static key
                <select name="tls_key" id="tls-key-select">
                    <option value="">None</option>
                </select>
            </label>

            <label>
                Authentication provider
                <select name="authmode" id="authmode-select">
                    <option value="">Certificate only</option>
                </select>
            </label>

            <label>
                Client certificate
                <select name="verify_client_cert">
                    <option value="require" selected>Required</option>
                    <option value="none">Not required</option>
                </select>
            </label>

            <label>
                Strict User/CN matching
                <select name="strictusercn">
                    <option value="1" selected>Yes</option>
                    <option value="2">Yes, case insensitive</option>
                    <option value="0">No</option>
                </select>
            </label>
        </div>

        <label class="checkbox">
            <input
                type="checkbox"
                name="username_as_common_name"
                value="1"
            >
            Use username as Common Name
        </label>
    </section>

    <section class="wizard-section">
        <h2>Client access</h2>

        <div class="field-grid">
            <label>
                Local networks
                <textarea
                    name="push_route"
                    rows="3"
                    placeholder="192.168.1.0/24&#10;192.168.10.0/24"
                    required
                ></textarea>
                <small>One CIDR network per line.</small>
            </label>

            <label>
                DNS servers
                <textarea
                    name="dns_servers"
                    rows="3"
                    placeholder="192.168.1.1&#10;192.168.1.2"
                ></textarea>
                <small>One IP address per line.</small>
            </label>

            <label>
                DNS domain
                <input
                    name="dns_domain"
                    placeholder="example.local"
                >
            </label>

            <label>
                Redirect gateway
                <select name="redirect_gateway">
                    <option value="">Do not redirect internet traffic</option>
                    <option value="default">Redirect IPv4 through VPN</option>
                </select>
            </label>
        </div>
    </section>

    <section class="wizard-section">
        <h2>Encryption and reliability</h2>

        <div class="field-grid">
            <label>
                Data ciphers
                <select name="data_ciphers[]" multiple size="4" required>
                    <option value="AES-256-GCM" selected>AES-256-GCM</option>
                    <option value="AES-128-GCM" selected>AES-128-GCM</option>
                    <option value="CHACHA20-POLY1305">
                        CHACHA20-POLY1305
                    </option>
                    <option value="AES-256-CBC">AES-256-CBC (legacy)</option>
                </select>
            </label>

            <label>
                Digest
                <select name="auth">
                    <option value="SHA256" selected>SHA256</option>
                    <option value="SHA384">SHA384</option>
                    <option value="SHA512">SHA512</option>
                </select>
            </label>

            <label>
                Keepalive interval
                <input
                    name="keepalive_interval"
                    type="number"
                    min="0"
                    max="3600"
                    value="10"
                >
            </label>

            <label>
                Keepalive timeout
                <input
                    name="keepalive_timeout"
                    type="number"
                    min="0"
                    max="3600"
                    value="60"
                >
            </label>

            <label>
                Renegotiation interval
                <input
                    name="reneg_sec"
                    type="number"
                    min="0"
                    value="3600"
                >
            </label>

            <label>
                Device type
                <select name="dev_type">
                    <option value="tun" selected>TUN</option>
                    <option value="ovpn">DCO</option>
                </select>
            </label>
        </div>

        <label class="checkbox">
            <input
                type="checkbox"
                name="enabled"
                value="1"
                checked
            >
            Enable server instance
        </label>

        <label class="checkbox">
            <input
                type="checkbox"
                name="acknowledge_rules"
                value="1"
                required
            >
            I understand that WAN and OpenVPN firewall rules must still be
            created or verified manually.
        </label>
    </section>

    <div class="actions">
        <button type="submit" id="create-button">
            Create Roadwarrior server
        </button>
    </div>
</form>

<script>
(function(){
    const form = document.getElementById('ovpn-form');
    const firewall = document.getElementById('firewall-id');
    const vpnid = document.getElementById('vpnid');
    const caSelect = document.getElementById('ca-select');
    const certSelect = document.getElementById('cert-select');
    const tlsKeySelect = document.getElementById('tls-key-select');
    const authmodeSelect = document.getElementById('authmode-select');
    const status = document.getElementById('object-status');
    const errorBox = document.getElementById('ovpn-error');
    const successBox = document.getElementById('ovpn-success');
    const button = document.getElementById('create-button');

    function option(value, label){
        const node = document.createElement('option');
        node.value = value;
        node.textContent = label;
        return node;
    }

    function resetSelect(select, label){
        select.innerHTML = '';
        select.append(option('', label));
    }

    async function readJson(response){
        const raw = await response.text();

        try{
            return JSON.parse(raw);
        }catch(error){
            throw new Error(
                'Server returned invalid JSON: ' +
                raw.replace(/\s+/g, ' ').trim().slice(0, 700)
            );
        }
    }

    async function loadObjects(){
        const firewallId = firewall.value;

        resetSelect(caSelect, 'Loading…');
        resetSelect(certSelect, 'Loading…');
        resetSelect(tlsKeySelect, 'None');
        resetSelect(authmodeSelect, 'Certificate only');
        vpnid.value = '';
        status.textContent = 'Loading OPNsense objects…';

        if(!firewallId){
            status.textContent = 'Select a firewall.';
            return;
        }

        try{
            const response = await fetch(
                '/openvpn_roadwarrior_options.php?firewall_id=' +
                encodeURIComponent(firewallId),
                {
                    credentials: 'same-origin',
                    cache: 'no-store'
                }
            );
            const data = await readJson(response);

            if(!response.ok || data.ok !== true){
                throw new Error(data.error || 'Could not load objects.');
            }

            vpnid.value = data.next_vpnid || 1;

            resetSelect(caSelect, 'Select CA');
            data.cas.forEach(function(item){
                caSelect.append(option(item.id, item.label));
            });

            resetSelect(certSelect, 'Select server certificate');
            data.certificates.forEach(function(item){
                certSelect.append(option(item.id, item.label));
            });

            resetSelect(tlsKeySelect, 'None');
            data.static_keys.forEach(function(item){
                tlsKeySelect.append(option(item.id, item.label));
            });

            resetSelect(authmodeSelect, 'Certificate only');
            data.providers.forEach(function(item){
                authmodeSelect.append(option(item.id, item.label));
            });

            const warnings = Object.entries(data.errors || {});
            status.textContent =
                `${data.cas.length} CAs, ` +
                `${data.certificates.length} certificates, ` +
                `${data.static_keys.length} static keys and ` +
                `${data.providers.length} authentication providers loaded.` +
                (warnings.length
                    ? ' Some optional API calls failed: ' +
                      warnings.map(([key, value]) => key + ': ' + value).join(' | ')
                    : '');

            if(data.cas.length === 0 || data.certificates.length === 0){
                throw new Error(
                    'A CA and server certificate must exist on this firewall.'
                );
            }
        }catch(error){
            status.textContent = error.message;
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
        }
    }

    firewall.addEventListener('change', function(){
        errorBox.classList.add('hidden');
        loadObjects();
    });

    form.addEventListener('submit', async function(event){
        event.preventDefault();
        errorBox.classList.add('hidden');
        successBox.classList.add('hidden');

        if(!confirm(
            'Create this OpenVPN Roadwarrior server?\n\n' +
            'A configuration backup will be created first.'
        )){
            return;
        }

        button.disabled = true;
        button.textContent = 'Creating and applying…';

        try{
            const response = await fetch(
                '/openvpn_roadwarrior_create_action.php',
                {
                    method: 'POST',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    body: new URLSearchParams(new FormData(form))
                }
            );
            const data = await readJson(response);

            if(!response.ok || data.ok !== true){
                throw new Error(data.error || 'Creation failed.');
            }

            successBox.innerHTML =
                '<strong>Roadwarrior server created.</strong><br>' +
                'Firewall: ' + data.firewall + '<br>' +
                'Instance UUID: <code>' + data.uuid + '</code><br>' +
                'Backup: <code>' + data.backup_filename + '</code><br><br>' +
                'Next: create or verify the WAN rule for port ' +
                data.port + '/' + data.protocol.toUpperCase() +
                ' and an allow rule on the OpenVPN interface.';

            successBox.classList.remove('hidden');
            window.scrollTo({top: 0, behavior: 'smooth'});
        }catch(error){
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
            window.scrollTo({top: 0, behavior: 'smooth'});
        }finally{
            button.disabled = false;
            button.textContent = 'Create Roadwarrior server';
        }
    });
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
