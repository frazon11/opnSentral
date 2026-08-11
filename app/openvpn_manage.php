<?php
declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();

$firewalls = db()
    ->query('SELECT id,name,base_url FROM firewalls ORDER BY name')
    ->fetchAll();

require __DIR__ . '/inc/header.php';
?>

<div class="page-title management-page-title">
    <div>
        <h1>Manage OpenVPN</h1>
        <p>OpenVPN status and instance configuration grouped by managed OPNsense firewall.</p>
    </div>

    <div class="management-toolbar">
        <button class="button secondary" id="refresh">Refresh</button>
        <a class="button" href="/openvpn_roadwarrior_create.php">
            Create Roadwarrior Server
        </a>
    </div>
</div>

<div class="management-overview-bar">
    <div>
        <strong>OpenVPN overview</strong>
        <div id="ovpn-summary" class="management-summary">
            Loading OpenVPN data…
        </div>
    </div>
</div>

<div id="ovpn-error" class="alert error hidden"></div>

<div id="ovpn-list" class="vpn-summary-list">
    <section class="card vpn-summary-card">
        <p class="muted">Loading…</p>
    </section>
</div>

<script>
(function(){
    const firewalls = <?= json_encode(
        array_map(
            static fn(array $firewall): array => [
                'id' => (int) $firewall['id'],
                'name' => (string) $firewall['name'],
                'base_url' => (string) $firewall['base_url'],
            ],
            $firewalls
        ),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    ) ?>;

    const csrf = <?= json_encode(
        csrf_token(),
        JSON_UNESCAPED_SLASHES
    ) ?>;

    const list = document.getElementById('ovpn-list');
    const summary = document.getElementById('ovpn-summary');
    const errorBox = document.getElementById('ovpn-error');
    const refresh = document.getElementById('refresh');

    let opnForm = [];
    let knownKeys = new Set();

    const optionLabels = {
        role:{client:'Client',server:'Server'},
        dev_type:{tun:'TUN',tap:'TAP',ovpn:'DCO'},
        proto:{udp:'UDP',udp4:'UDP (IPv4)',udp6:'UDP (IPv6)',tcp:'TCP',tcp4:'TCP (IPv4)',tcp6:'TCP (IPv6)'},
        topology:{net30:'net30',p2p:'p2p',subnet:'subnet'},
        verify_client_cert:{none:'none',require:'require'},
        cert_depth:{
            '':'Do Not Check',
            '1':'One (Client+Server)',
            '2':'Two (Client+Intermediate+Server)',
            '3':'Three (Client+2xIntermediate+Server)',
            '4':'Four (Client+3xIntermediate+Server)',
            '5':'Five (Client+4xIntermediate+Server)'
        },
        strictusercn:{'0':'No','1':'Yes','2':'Yes, case insensitive'},
        auth:{'':'OpenVPN default',none:'None (No Authentication)'},
        verb:{
            '0':'0 (No output except fatal errors.)',
            '1':'1 (Normal)','2':'2 (Normal)','3':'3 (Normal)','4':'4 (Normal)',
            '5':'5 (log packets)','6':'6 (debug)','7':'7 (debug)',
            '8':'8 (debug)','9':'9 (debug)','10':'10 (debug)','11':'11 (debug)'
        }
    };


    function escapeHtml(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
    }

    function readJson(response){
        return response.text().then(raw => {
            try{
                return JSON.parse(raw);
            }catch(error){
                throw new Error(
                    'Invalid JSON: ' +
                    raw.replace(/\s+/g, ' ').slice(0, 700)
                );
            }
        });
    }

    function empty(value){
        return value === null ||
            value === undefined ||
            value === '' ||
            (Array.isArray(value) && value.length === 0);
    }

    function yesNo(value){
        if(value === true || String(value) === '1'){
            return 'Yes';
        }
        if(value === false || String(value) === '0'){
            return 'No';
        }
        return null;
    }

    function displayValue(value){
        if(empty(value)){
            return '<span class="muted">Not set</span>';
        }

        const boolean = yesNo(value);
        if(boolean !== null){
            return escapeHtml(boolean);
        }

        if(Array.isArray(value)){
            return value.length
                ? '<div class="ovpn-config-values">' +
                    value.map(item =>
                        '<code>' + escapeHtml(item) + '</code>'
                    ).join('') +
                  '</div>'
                : '<span class="muted">Not set</span>';
        }

        if(typeof value === 'object'){
            return '<pre class="ovpn-config-json">' +
                escapeHtml(JSON.stringify(value, null, 2)) +
            '</pre>';
        }

        const text = String(value);
        if(text.includes('\n') || text.includes(',')){
            const parts = text.split(/[\n,]+/)
                .map(item => item.trim())
                .filter(Boolean);

            if(parts.length > 1){
                return '<div class="ovpn-config-values">' +
                    parts.map(item =>
                        '<code>' + escapeHtml(item) + '</code>'
                    ).join('') +
                '</div>';
            }
        }

        return escapeHtml(text);
    }

    function statusBadge(enabled){
        return enabled
            ? '<span class="badge good">Enabled</span>'
            : '<span class="badge neutral">Disabled</span>';
    }

    function sessionRows(sessions){
        if(!sessions.length){
            return '<tr><td colspan="4">No active OpenVPN sessions.</td></tr>';
        }

        return sessions.map(session => `
            <tr>
                <td>${displayValue(
                    session.common_name ||
                    session.username ||
                    session.user_name
                )}</td>
                <td>${displayValue(
                    session.virtual_address ||
                    session.virtual_addr ||
                    session.vpn_ip
                )}</td>
                <td>${displayValue(
                    session.real_address ||
                    session.remote_address ||
                    session.remote_host
                )}</td>
                <td>${displayValue(
                    session.connected_since ||
                    session.connect_time ||
                    session.since
                )}</td>
            </tr>
        `).join('');
    }

    function actionButtons(instance, firewallId){
        return `
            <div
                class="management-row-actions"
                data-firewall-id="${firewallId}"
                data-uuid="${escapeHtml(instance.uuid)}"
                data-vpnid="${escapeHtml(instance.vpnid)}"
            >
                <button class="button secondary" data-action="${
                    instance.enabled ? 'disable' : 'enable'
                }">
                    ${instance.enabled ? 'Disable' : 'Enable'}
                </button>
                <button class="button secondary" data-action="start">Start</button>
                <button class="button secondary" data-action="stop">Stop</button>
                <button class="button secondary" data-action="restart">Restart</button>
                <button class="button danger" data-action="delete">Delete</button>
            </div>
        `;
    }

    function instanceRows(instances, firewallId){
        if(!instances.length){
            return '<tr><td colspan="6">No OpenVPN instances found.</td></tr>';
        }

        return instances.map(instance => {
            const listener = instance.remote
                ? instance.remote
                : (instance.local || '*') +
                    (instance.port ? ':' + instance.port : '') +
                    (instance.proto ? ' ' + instance.proto : '');

            return `
                <tr>
                    <td>
                        <strong>${escapeHtml(
                            instance.description || 'Unnamed'
                        )}</strong>
                        <br><small>ID ${escapeHtml(instance.vpnid || '—')}</small>
                    </td>
                    <td>${displayValue(instance.role)}</td>
                    <td>${escapeHtml(listener)}</td>
                    <td>${displayValue(instance.server)}</td>
                    <td>${statusBadge(instance.enabled)}</td>
                    <td>${actionButtons(instance, firewallId)}</td>
                </tr>
            `;
        }).join('');
    }

    function referenceLabel(field, value, references){
        const rows = references?.[field.reference] || [];
        const match = rows.find(row => String(row.id) === String(value));
        return match ? match.label : value;
    }

    function selectedOptionValues(value){
        if(
            value === null ||
            value === undefined ||
            typeof value !== 'object' ||
            Array.isArray(value)
        ){
            return null;
        }

        const selected = [];

        Object.entries(value).forEach(([key, option]) => {
            if(
                option === null ||
                option === undefined
            ){
                return;
            }

            if(typeof option !== 'object'){
                return;
            }

            const flag =
                option.selected ??
                option.is_selected ??
                option.checked ??
                false;

            const isSelected =
                flag === true ||
                String(flag) === '1' ||
                String(flag).toLowerCase() === 'true' ||
                String(flag).toLowerCase() === 'selected';

            if(!isSelected){
                return;
            }

            const label =
                option.value ??
                option.label ??
                option.name ??
                option.description ??
                key;

            selected.push(String(label));
        });

        return selected;
    }

    function normalizeModelValue(value){
        const selected = selectedOptionValues(value);

        if(selected !== null){
            return selected.length <= 1
                ? (selected[0] ?? '')
                : selected;
        }

        if(Array.isArray(value)){
            return value.map(item => {
                if(
                    item !== null &&
                    typeof item === 'object'
                ){
                    return (
                        item.value ??
                        item.label ??
                        item.name ??
                        item.description ??
                        JSON.stringify(item)
                    );
                }

                return item;
            });
        }

        if(
            value !== null &&
            typeof value === 'object'
        ){
            if('value' in value){
                return value.value;
            }

            if('label' in value){
                return value.label;
            }

            if('name' in value){
                return value.name;
            }
        }

        return value;
    }

    function mappedValue(field, value, references){
        value = normalizeModelValue(value);

        if(field.sensitive && !empty(value)){
            return '••••••••';
        }

        if(field.reference){
            if(Array.isArray(value)){
                return value.map(item =>
                    referenceLabel(field, item, references)
                );
            }

            const parts = String(value ?? '')
                .split(/[\n,]+/)
                .map(item => item.trim())
                .filter(Boolean);

            if(parts.length > 1){
                return parts.map(item =>
                    referenceLabel(field, item, references)
                );
            }

            return referenceLabel(field, value, references);
        }

        const map = optionLabels[field.key];

        if(map){
            if(Array.isArray(value)){
                return value.map(item =>
                    map[String(item)] ?? item
                );
            }

            const parts = String(value ?? '')
                .split(/[\n,]+/)
                .map(item => item.trim())
                .filter(Boolean);

            if(parts.length > 1){
                return parts.map(item =>
                    map[item] ?? item
                );
            }

            return map[String(value)] ?? value;
        }

        return value;
    }

    function fieldVisible(field, config, advanced){
        if(field.advanced && !advanced){
            return false;
        }

        const role = String(config.role || 'server');
        const device = String(config.dev_type || 'tun');
        const classes = String(field.style || '')
            .split(/\s+/)
            .filter(Boolean);

        const roleClasses = classes.filter(
            value => value.startsWith('role_')
        );

        if(!roleClasses.length){
            return true;
        }

        const candidates = new Set([
            'role_' + role,
            'role_' + role + '_' + device
        ]);

        return roleClasses.some(value => candidates.has(value));
    }

    function controlMarkup(field, rawValue, value){
        if(field.type === 'checkbox'){
            const normalizedRaw = normalizeModelValue(
                rawValue
            );
            const checked =
                normalizedRaw === true ||
                String(normalizedRaw) === '1' ||
                String(normalizedRaw).toLowerCase() === 'true' ||
                String(normalizedRaw).toLowerCase() === 'yes' ||
                String(normalizedRaw).toLowerCase() === 'enabled';

            return `
                <label class="opn-readonly-checkbox">
                    <input type="checkbox" ${checked ? 'checked' : ''} disabled>
                    <span></span>
                </label>
            `;
        }

        if(
            field.type === 'dropdown' ||
            field.type === 'select_multiple'
        ){
            return `
                <div class="opn-readonly-select">
                    <span>${displayValue(value)}</span>
                    <span class="opn-select-arrow">▾</span>
                </div>
            `;
        }

        if(
            field.type === 'textbox' ||
            (
                typeof value === 'string' &&
                value.includes('\n')
            )
        ){
            return `
                <div class="opn-readonly-textarea">
                    ${displayValue(value)}
                </div>
            `;
        }

        return `
            <div class="opn-readonly-input">
                ${displayValue(value)}
            </div>
        `;
    }

    function renderFormRows(config, references, advanced, fullHelp){
        let html = '';
        let currentHeaderOpen = false;
        let sectionHasRows = false;
        let sectionBuffer = '';
        let sectionIndex = 0;

        function flushSection(){
            if(!currentHeaderOpen){
                return;
            }

            if(sectionHasRows){
                html += sectionBuffer + '</div></section>';
            }

            currentHeaderOpen = false;
            sectionHasRows = false;
            sectionBuffer = '';
        }

        opnForm.forEach(item => {
            if(item.header){
                flushSection();
                currentHeaderOpen = true;
                sectionIndex += 1;
                sectionBuffer = `
                    <section class="opn-config-section"
                             data-section="${sectionIndex}">
                        <button type="button"
                                class="opn-config-section-toggle"
                                aria-expanded="true">
                            <span class="opn-section-chevron">⌄</span>
                            <span>${escapeHtml(item.header)}</span>
                        </button>
                        <div class="opn-config-section-body">
                `;
                return;
            }

            if(!fieldVisible(item, config, advanced)){
                return;
            }

            sectionHasRows = true;
            const hasValue = Object.prototype.hasOwnProperty.call(
                config,
                item.key
            );
            const rawValue = hasValue ? config[item.key] : '';
            const value = mappedValue(item, rawValue, references);
            const helpText = fullHelp
                ? `<div class="opn-field-help">
                    ${escapeHtml(
                        item.help ||
                        'This field is shown as defined by the OPNsense OpenVPN instance form.'
                    )}
                   </div>`
                : '';

            sectionBuffer += `
                <div class="opn-config-row">
                    <div class="opn-config-label">
                        <span class="opn-info-icon">i</span>
                        <span>${escapeHtml(item.label)}</span>
                    </div>
                    <div class="opn-config-control">
                        ${controlMarkup(item, rawValue, value)}
                        ${helpText}
                    </div>
                </div>
            `;
        });

        flushSection();
        return html;
    }

    function unknownConfig(config, advanced){
        if(!advanced){
            return '';
        }

        const keys = Object.keys(config)
            .filter(key => !knownKeys.has(key))
            .sort((a, b) => a.localeCompare(b));

        if(!keys.length){
            return '';
        }

        return `<section class="ovpn-opnsense-section">
            <div class="ovpn-opnsense-section-title">Additional model fields</div>
            <div class="ovpn-opnsense-form">
                ${keys.map(key => `
                    <div class="ovpn-opnsense-row">
                        <div class="ovpn-opnsense-label">${escapeHtml(key)}</div>
                        <div class="ovpn-opnsense-control">${displayValue(config[key])}</div>
                    </div>
                `).join('')}
            </div>
        </section>`;
    }

    function instanceConfig(instance, references, instanceIndex){
        if(instance.config_error){
            return `<div class="alert error ovpn-config-error">
                ${escapeHtml(instance.config_error)}
            </div>`;
        }

        const config = instance.config || {};
        if(!Object.keys(config).length){
            return '<div class="ovpn-config-empty">No configuration returned.</div>';
        }

        return `
            <article class="opn-modal-shell"
                     data-config-instance="${instanceIndex}">
                <div class="opn-modal-titlebar">
                    <h3>Edit Instance</h3>
                    <button type="button"
                            class="opn-modal-close"
                            aria-label="Close">×</button>
                </div>

                <div class="opn-modal-toolbar">
                    <label class="opn-switch-label">
                        <span class="opn-switch">
                            <input type="checkbox"
                                   class="opn-advanced-checkbox">
                            <span class="opn-switch-track"></span>
                        </span>
                        <span>advanced mode</span>
                    </label>

                    <label class="opn-switch-label opn-full-help-label">
                        <span>full help</span>
                        <span class="opn-switch">
                            <input type="checkbox"
                                   class="opn-full-help-checkbox">
                            <span class="opn-switch-track"></span>
                        </span>
                    </label>
                </div>

                <div class="opn-modal-content">
                    <div class="ovpn-opnsense-form-wrap"
                         data-advanced="false"
                         data-full-help="false">
                        ${renderFormRows(
                            config,
                            references,
                            false,
                            false
                        )}
                    </div>
                </div>

                <div class="opn-modal-footer">
                    <button type="button"
                            class="button secondary opn-modal-close-button">
                        Close
                    </button>
                </div>
            </article>
        `;
    }

    function configMarkup(instances, references){
        if(!instances.length){
            return '<div class="ovpn-config-empty">No OpenVPN instances found.</div>';
        }

        return instances.map((instance, index) =>
            instanceConfig(instance, references, index)
        ).join('');
    }

    function bindConfigControls(card, result){
        card.querySelectorAll('.opn-modal-shell').forEach(article => {
            const index = Number(article.dataset.configInstance);
            const instance = result.instances[index];
            const config = instance.config || {};
            const wrap = article.querySelector('.ovpn-opnsense-form-wrap');
            const advancedToggle = article.querySelector(
                '.opn-advanced-checkbox'
            );
            const helpToggle = article.querySelector(
                '.opn-full-help-checkbox'
            );

            function rerender(){
                const advanced = advancedToggle.checked;
                const fullHelp = helpToggle.checked;

                wrap.dataset.advanced = advanced ? 'true' : 'false';
                wrap.dataset.fullHelp = fullHelp ? 'true' : 'false';
                wrap.innerHTML = renderFormRows(
                    config,
                    result.references || {},
                    advanced,
                    fullHelp
                );

                bindSectionToggles(article);
            }

            advancedToggle.addEventListener('change', rerender);
            helpToggle.addEventListener('change', rerender);

            article.querySelectorAll(
                '.opn-modal-close, .opn-modal-close-button'
            ).forEach(button => {
                button.addEventListener('click', function(){
                    const panel = article.closest('.ovpn-config-panel');
                    const card = article.closest('.vpn-summary-card');
                    const configButton = card.querySelector(
                        '.ovpn-panel-toggle[data-panel="config"]'
                    );

                    panel.hidden = true;
                    card.classList.remove('vpn-summary-expanded');
                    configButton.setAttribute(
                        'aria-expanded',
                        'false'
                    );
                    configButton.textContent = 'Config';
                });
            });

            bindSectionToggles(article);
        });
    }

    function bindSectionToggles(container){
        container.querySelectorAll(
            '.opn-config-section-toggle'
        ).forEach(button => {
            button.addEventListener('click', function(){
                const section = button.closest('.opn-config-section');
                const body = section.querySelector(
                    '.opn-config-section-body'
                );
                const expanded =
                    button.getAttribute('aria-expanded') === 'true';

                button.setAttribute(
                    'aria-expanded',
                    expanded ? 'false' : 'true'
                );
                body.hidden = expanded;
                button.querySelector(
                    '.opn-section-chevron'
                ).textContent = expanded ? '›' : '⌄';
            });
        });
    }

    async function loadFormSchema(){
        const response = await fetch(
            '/openvpn_form_schema.php',
            {
                credentials: 'same-origin',
                cache: 'no-store'
            }
        );
        const data = await readJson(response);

        if(!response.ok || data.ok !== true){
            throw new Error(
                data.error ||
                'Could not load the OPNsense OpenVPN form definition.'
            );
        }

        opnForm = Array.isArray(data.schema)
            ? data.schema
            : [];
        knownKeys = new Set(
            opnForm
                .filter(item => item.key)
                .map(item => item.key)
        );
    }

    async function loadFirewall(firewall){
        try{
            const [dataResponse, optionsResponse] = await Promise.all([
                fetch(
                    '/openvpn_manage_data.php?firewall_id=' +
                    encodeURIComponent(firewall.id),
                    {credentials:'same-origin',cache:'no-store'}
                ),
                fetch(
                    '/openvpn_roadwarrior_options.php?firewall_id=' +
                    encodeURIComponent(firewall.id),
                    {credentials:'same-origin',cache:'no-store'}
                )
            ]);

            const data = await readJson(dataResponse);
            const options = await readJson(optionsResponse);

            if(!dataResponse.ok || data.ok !== true){
                throw new Error(data.error || 'Load failed.');
            }

            return {
                ok:true,
                firewall,
                instances:Array.isArray(data.instances)?data.instances:[],
                sessions:Array.isArray(data.sessions)?data.sessions:[],
                sessions_error:data.sessions_error||null,
                references:
                    optionsResponse.ok && options.ok === true
                        ? {
                            cas:Array.isArray(options.cas)?options.cas:[],
                            certificates:Array.isArray(options.certificates)
                                ? options.certificates
                                : [],
                            static_keys:Array.isArray(options.static_keys)
                                ? options.static_keys
                                : [],
                            providers:Array.isArray(options.providers)
                                ? options.providers
                                : []
                        }
                        : {}
            };
        }catch(error){
            return {
                ok:false,
                firewall,
                error:error.message,
                instances:[],
                sessions:[],
                references:{}
            };
        }
    }

    function render(results){
        const available = results.filter(item => item.ok).length;
        const instanceTotal = results.reduce(
            (sum, item) => sum + item.instances.length, 0
        );
        const sessionTotal = results.reduce(
            (sum, item) => sum + item.sessions.length, 0
        );

        summary.textContent =
            results.length + ' firewalls · ' +
            available + ' reachable · ' +
            instanceTotal + ' OpenVPN instances · ' +
            sessionTotal + ' active sessions';

        list.innerHTML = results.length
            ? results.map(result => {
                const enabledCount = result.instances.filter(
                    instance => instance.enabled
                ).length;

                return `
                    <section class="card vpn-summary-card">
                        <div class="vpn-summary-main">
                            <div class="vpn-summary-identity">
                                <h2>${escapeHtml(result.firewall.name)}</h2>
                                <a class="muted"
                                   href="${escapeHtml(result.firewall.base_url)}"
                                   target="_blank" rel="noopener">
                                    ${escapeHtml(result.firewall.base_url)}
                                </a>
                            </div>

                            <div class="vpn-summary-metric">
                                <span class="vpn-summary-label">Instances</span>
                                ${
                                    result.ok
                                        ? `<span class="badge neutral">${
                                            result.instances.length
                                        }</span>`
                                        : '<span class="badge bad">Unavailable</span>'
                                }
                            </div>

                            <div class="vpn-summary-metric">
                                <span class="vpn-summary-label">Summary</span>
                                <span class="muted">
                                    ${
                                        result.ok
                                            ? enabledCount + ' enabled · ' +
                                                result.sessions.length + ' sessions'
                                            : escapeHtml(result.error)
                                    }
                                </span>
                            </div>

                            <div class="vpn-summary-actions ovpn-summary-actions">
                                <button type="button"
                                    class="button secondary ovpn-panel-toggle"
                                    data-panel="details"
                                    aria-expanded="false">
                                    Details
                                </button>
                                <button type="button"
                                    class="button secondary ovpn-panel-toggle"
                                    data-panel="config"
                                    aria-expanded="false">
                                    Config
                                </button>
                            </div>
                        </div>

                        <div class="vpn-details-panel ovpn-details-panel"
                             data-panel-name="details" hidden>
                            ${
                                result.ok
                                    ? `
                                    <div class="vpn-details-header">
                                        <div>
                                            <strong>OpenVPN instances</strong>
                                            <div class="muted">${
                                                escapeHtml(result.firewall.name)
                                            }</div>
                                        </div>
                                    </div>
                                    <div class="table-scroll management-table-wrap">
                                        <table class="management-table">
                                            <thead><tr>
                                                <th>Instance</th>
                                                <th>Role</th>
                                                <th>Listener / Remote</th>
                                                <th>Tunnel</th>
                                                <th>Status</th>
                                                <th>Actions</th>
                                            </tr></thead>
                                            <tbody>${instanceRows(
                                                result.instances,
                                                result.firewall.id
                                            )}</tbody>
                                        </table>
                                    </div>
                                    <div class="vpn-details-header vpn-session-subheader">
                                        <div>
                                            <strong>Active sessions</strong>
                                            <div class="muted">${
                                                result.sessions_error
                                                    ? escapeHtml(
                                                        result.sessions_error
                                                      )
                                                    : result.sessions.length +
                                                        ' active'
                                            }</div>
                                        </div>
                                    </div>
                                    <div class="table-scroll management-table-wrap">
                                        <table class="management-table">
                                            <thead><tr>
                                                <th>User / Common Name</th>
                                                <th>Virtual address</th>
                                                <th>Remote address</th>
                                                <th>Connected</th>
                                            </tr></thead>
                                            <tbody>${sessionRows(
                                                result.sessions
                                            )}</tbody>
                                        </table>
                                    </div>`
                                    : `<div class="alert error vpn-details-error">
                                        ${escapeHtml(result.error)}
                                      </div>`
                            }
                        </div>

                        <div class="vpn-details-panel ovpn-config-panel"
                             data-panel-name="config" hidden>
                            ${
                                result.ok
                                    ? configMarkup(result.instances, result.references)
                                    : `<div class="alert error vpn-details-error">
                                        ${escapeHtml(result.error)}
                                      </div>`
                            }
                        </div>
                    </section>
                `;
            }).join('')
            : '<section class="card vpn-summary-card">' +
                '<p class="muted">No firewalls configured.</p>' +
              '</section>';

        list.querySelectorAll('.ovpn-panel-toggle').forEach(button => {
            button.addEventListener('click', function(){
                const card = button.closest('.vpn-summary-card');
                const targetName = button.dataset.panel;
                const panels = card.querySelectorAll('[data-panel-name]');
                const buttons = card.querySelectorAll('.ovpn-panel-toggle');
                const target = card.querySelector(
                    '[data-panel-name="' + targetName + '"]'
                );
                const opening = target.hidden;

                panels.forEach(panel => panel.hidden = true);
                buttons.forEach(item => {
                    item.setAttribute('aria-expanded', 'false');
                    item.textContent =
                        item.dataset.panel === 'details'
                            ? 'Details'
                            : 'Config';
                });

                if(opening){
                    target.hidden = false;
                    button.setAttribute('aria-expanded', 'true');
                    button.textContent =
                        targetName === 'details'
                            ? 'Hide details'
                            : 'Hide config';
                }

                card.classList.toggle('vpn-summary-expanded', opening);
            });
        });

        list.querySelectorAll('[data-action]').forEach(button => {
            button.addEventListener('click', () => runAction(button));
        });

        list.querySelectorAll('.vpn-summary-card').forEach((card, index) => {
            if(results[index]?.ok){
                bindConfigControls(card, results[index]);
            }
        });
    }

    async function runAction(button){
        const row = button.closest('[data-uuid]');
        const action = button.dataset.action;
        const firewallId = row.dataset.firewallId;
        const uuid = row.dataset.uuid;
        const vpnid = row.dataset.vpnid;
        const destructive = ['delete', 'disable'].includes(action);

        if(!confirm(
            action.toUpperCase() + ' OpenVPN instance ' + vpnid + '?' +
            (destructive
                ? '\n\nA configuration backup will be created first.'
                : '')
        )){
            return;
        }

        button.disabled = true;

        try{
            const form = new URLSearchParams({
                csrf,
                firewall_id: firewallId,
                uuid,
                vpnid,
                action
            });
            const response = await fetch('/openvpn_manage_action.php', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type':
                        'application/x-www-form-urlencoded;charset=UTF-8'
                },
                body: form
            });
            const data = await readJson(response);

            if(!response.ok || data.ok !== true){
                throw new Error(data.error || 'Action failed.');
            }

            await load();
        }catch(error){
            alert(error.message);
        }finally{
            button.disabled = false;
        }
    }

    async function load(){
        refresh.disabled = true;
        refresh.textContent = 'Loading…';
        errorBox.classList.add('hidden');

        try{
            await loadFormSchema();

            const results = await Promise.all(
                firewalls.map(loadFirewall)
            );
            render(results);

            const failed = results.filter(item => !item.ok);
            if(failed.length){
                errorBox.textContent = failed.map(
                    item => item.firewall.name + ': ' + item.error
                ).join(' | ');
                errorBox.classList.remove('hidden');
            }
        }catch(error){
            summary.textContent = 'OpenVPN unavailable';
            list.innerHTML =
                '<section class="card vpn-summary-card">' +
                    '<p class="muted">Could not load OpenVPN data.</p>' +
                '</section>';
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
        }finally{
            refresh.disabled = false;
            refresh.textContent = 'Refresh';
        }
    }

    refresh.addEventListener('click', load);
    load();
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
