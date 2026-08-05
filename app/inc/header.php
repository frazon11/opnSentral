<?php
require_once __DIR__ . '/config.php';
start_session_secure();
$presentationFirewallNames = [];

if (logged_in()) {
    try {
        $presentationFirewallNames = array_values(
            array_filter(
                array_map(
                    static fn(array $row): string =>
                        trim((string) ($row['name'] ?? '')),
                    db()->query(
                        'SELECT name FROM firewalls ORDER BY id'
                    )->fetchAll()
                ),
                static fn(string $name): bool => $name !== ''
            )
        );
    } catch (Throwable $exception) {
        $presentationFirewallNames = [];
    }
}
$currentPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
function nav_active(array $paths): string {
    global $currentPath;
    return in_array($currentPath, $paths, true) ? ' active' : '';
}
?>
<!doctype html>
<html lang="<?= h(current_language()) ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>opnSentral</title>
<link rel="icon" href="/assets/favicon.ico?v=06111" sizes="any">
<link rel="icon" type="image/svg+xml" href="/assets/opncentral-icon.svg?v=06111">
<link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.png?v=06111">
<link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.png?v=06111">
<link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png?v=06111">
<link rel="manifest" href="/assets/site.webmanifest?v=06111">
<meta name="theme-color" content="#26313a" id="browser-theme-color">
<script>
(function(){
    const saved=localStorage.getItem('opncentral-theme');
    const theme=saved==='dark'?'dark':'light';
    document.documentElement.dataset.theme=theme;
})();
</script>
<link rel="stylesheet" href="/assets/style.css?v=06111">
</head>
<body class="<?= logged_in() ? 'app-shell' : 'login-shell' ?><?= logged_in() && !configuration_unlocked() ? ' configuration-locked' : ' configuration-unlocked' ?>">
<?php if (logged_in()): ?>
<aside class="sidebar" id="sidebar">
    <div class="sidebar-brand">
        <img src="/assets/opncentral-icon.svg" alt="" class="sidebar-logo">
        <div>
            <strong><?= h(app_name()) ?></strong>
            <div class="sidebar-meta">
                <span>v0.6.11.1</span><span>·</span>
                <a
                    href="https://buymeacoffee.com/frazon11"
                    target="_blank"
                    rel="noopener noreferrer"
                    title="Buy me a coffee"
                >☕ Buy me a coffee</a>
            </div>
        </div>
    </div>

    <nav class="side-nav">
        <a class="<?= nav_active(['/','/index.php']) ?>" href="/">▦ <span><?= h(t('menu.dashboard')) ?></span></a>

        <div class="nav-group">Firewalls</div>
        <a class="<?= nav_active(['/firewall_edit.php']) ?>" href="/firewall_edit.php">＋ <span><?= h(t('menu.add_firewall')) ?></span></a>

        <div class="nav-section-label">Settings</div>
        <span class="nav-child nav-disabled"><span>Firewall</span></span>
        <a class="nav-child<?= nav_active(['/firewall_advanced.php']) ?>"
           href="/firewall_advanced.php?firewall_id=1">
            <span>Advanced</span>
        </a>
        <span class="nav-child nav-disabled"><span>System</span></span>
        <a class="nav-child<?= nav_active(['/system_administration.php']) ?>"
           href="/system_administration.php">
            <span>Administration</span>
        </a>

        <a class="<?= nav_active(['/services.php']) ?>" href="/services.php">⚙ <span>Services</span></a>
        <a class="<?= nav_active(['/agents.php']) ?>" href="/agents.php">⇄ <span>Agents</span></a>

        <div class="nav-group">VPN</div>

        <div class="nav-section-label">WireGuard</div>
        <a class="nav-child<?= nav_active(['/wireguard_overview.php']) ?>" href="/wireguard_overview.php">
            <span>Manage</span>
        </a>
        <a class="nav-child<?= nav_active(['/wireguard_create.php']) ?>" href="/wireguard_create.php">
            <span>Create Site-to-Site VPN</span>
        </a>

        <div class="nav-section-label">OpenVPN</div>
        <a
            class="nav-child<?= nav_active(['/openvpn_manage.php']) ?>"
            href="/openvpn_manage.php"
        >
            <span>Manage</span>
        </a>
        <span class="nav-child nav-disabled" aria-disabled="true">
            <span>Create Site-to-Site VPN</span>
            <small>coming soon</small>
        </span>
        <a
            class="nav-child<?= nav_active(['/openvpn_roadwarrior_create.php']) ?>"
            href="/openvpn_roadwarrior_create.php"
        >
            <span>Create Roadwarrior Server</span>
        </a>

        <div class="nav-group"><?= h(t('menu.actions')) ?></div>
        <a
            class="<?= nav_active(['/troubleshooting.php']) ?>"
            href="/troubleshooting.php"
        >
            ⎇ <span>Troubleshooting</span>
        </a>
        <a class="<?= nav_active(['/aliases.php','/alias_overview.php']) ?>" href="/alias_overview.php">≡ <span><?= h(t('menu.aliases')) ?></span></a>
        <a class="<?= nav_active(['/categories.php','/category_overview.php']) ?>" href="/category_overview.php">▤ <span><?= h(t('menu.categories')) ?></span></a>
        <a class="<?= nav_active(['/backups.php']) ?>" href="/backups.php">⬇ <span>Backups</span></a>

        <div class="nav-group"><?= h(t('menu.settings')) ?></div>
        <a class="<?= nav_active(['/settings.php']) ?>" href="/settings.php">⚙ <span><?= h(t('menu.settings')) ?></span></a>
        <a class="<?= nav_active(['/notifications.php']) ?>" href="/notifications.php">● <span><?= h(t('menu.notifications')) ?></span></a>
    </nav>

    <div class="sidebar-footer-actions">
        <a class="sidebar-logout" href="/logout.php">
            ⇥ <?= h(t('menu.logout')) ?>
        </a>

    </div>
</aside>
<div class="page-shell">
<header class="topbar">
    <button type="button" class="sidebar-toggle" id="sidebar-toggle" aria-label="Toggle navigation">☰</button>
    <div class="topbar-heading">
        <div class="topbar-title"><?= h(app_name()) ?></div>
        <div
            class="configuration-lock-state <?= configuration_unlocked()
                ? 'is-unlocked'
                : 'is-locked' ?>"
            tabindex="0"
            aria-describedby="configuration-lock-tooltip"
        >
            <?= configuration_unlocked()
                ? 'Configuration unlocked'
                : 'Read-only mode' ?>
            <span
                id="configuration-lock-tooltip"
                class="configuration-lock-tooltip"
                role="tooltip"
            >
                <?= configuration_unlocked()
                    ? 'Write features are enabled'
                    : 'Click Unlock to enable write features' ?>
            </span>
        </div>
    </div>
    <div class="topbar-right">
        <div class="presentation-mode-stack">
            <button
                type="button"
                id="presentation-mode-button"
                class="button secondary"
                aria-pressed="false"
                title="Replace visible names, addresses and domains with presentation-safe values"
            >
                Presentation
            </button>
            <span
                id="presentation-mode-state"
                class="presentation-mode-state"
                hidden
            >
                Presentation mode active
            </span>
        </div>

        <div class="configuration-lock-stack">
            <button
                type="button"
                id="configuration-lock-button"
                class="button <?= configuration_unlocked()
                    ? 'warning'
                    : 'secondary' ?>"
                data-unlocked="<?= configuration_unlocked() ? '1' : '0' ?>"
                data-support-url="https://www.paypal.com/paypalme/FrazoN11"
            >
                <?= configuration_unlocked() ? 'Lock' : 'Unlock' ?>
            </button>
            <a
                id="configuration-support-link"
                class="configuration-support-link"
                href="https://www.paypal.com/paypalme/FrazoN11"
                target="_blank"
                rel="noopener noreferrer"
                title="Support opnCentral via PayPal"
            >
                ♥ Support me
            </a>
        </div>
    </div>
</header>

<div id="configuration-unlock-dialog"
     class="configuration-unlock-dialog"
     hidden>
    <div class="configuration-unlock-backdrop"></div>
    <section class="configuration-unlock-card"
             role="dialog"
             aria-modal="true"
             aria-labelledby="configuration-unlock-title">
        <h2 id="configuration-unlock-title">
            Unlock configuration changes
        </h2>
        <p>
            Enter the configuration password to enable changes on managed
            OPNsense firewalls for this login session.
        </p>
        <label for="configuration-unlock-password">Password</label>
        <input
            type="password"
            id="configuration-unlock-password"
            autocomplete="current-password"
        >
        <div id="configuration-unlock-error"
             class="alert error hidden"></div>
        <div class="actions">
            <button type="button"
                    class="button secondary"
                    id="configuration-unlock-cancel">
                Cancel
            </button>
            <button type="button"
                    class="button"
                    id="configuration-unlock-submit">
                Unlock
            </button>
        </div>
    </section>
</div>

<main class="content">
<?php else: ?>
<header class="login-header"><img src="/assets/opncentral-icon.svg" alt="" class="sidebar-logo"><strong><?= h(app_name()) ?></strong></header>
<main class="content login-content">
<?php endif; ?>
<script>
window.opnCentralPresentationNames = <?= json_encode(
    $presentationFirewallNames,
    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
) ?>;
</script>
<script>
(function(){
    'use strict';

    const storageKey = 'opncentral-presentation-mode';
    const mappingKey = 'opncentral-presentation-mapping-v1';
    const button = document.getElementById('presentation-mode-button');
    const state = document.getElementById('presentation-mode-state');

    const fantasyNames = [
        'Dragonhold',
        'Moonspire',
        'Silverkeep',
        'Ravenwatch',
        'Stormhaven',
        'Emberfall',
        'Frostgate',
        'Ironvale',
        'Starforge',
        'Shadowfen',
        'Oakshield',
        'Crystalreach',
        'Thunderpeak',
        'Wolfden',
        'Suncrest',
        'Nightfall',
        'Goldenmoor',
        'Mistwatch',
        'Phoenixrest',
        'Winterhold'
    ];

    let enabled = localStorage.getItem(storageKey) === '1';
    let mappings = loadMappings();
    let observer = null;
    let applying = false;
    const originalTextValues = new WeakMap();
    const originalAttributeValues = new WeakMap();

    function loadMappings(){
        try{
            const parsed = JSON.parse(
                sessionStorage.getItem(mappingKey) || '{}'
            );

            return parsed && typeof parsed === 'object'
                ? parsed
                : {};
        }catch(error){
            return {};
        }
    }

    function saveMappings(){
        sessionStorage.setItem(
            mappingKey,
            JSON.stringify(mappings)
        );
    }

    function hashString(value){
        let hash = 2166136261;

        for(let index = 0; index < value.length; index++){
            hash ^= value.charCodeAt(index);
            hash = Math.imul(hash, 16777619);
        }

        return hash >>> 0;
    }

    function stableNumber(value, minimum, maximum){
        const span = maximum - minimum + 1;
        return minimum + (hashString(value) % span);
    }

    function mapped(category, original, producer){
        const key = category + ':' + original;

        if(!Object.prototype.hasOwnProperty.call(mappings, key)){
            mappings[key] = producer();
            saveMappings();
        }

        return mappings[key];
    }

    function fantasyName(original){
        return mapped('name', original, function(){
            const base = fantasyNames[
                hashString(original) % fantasyNames.length
            ];

            const duplicates = Object.values(mappings).filter(
                value => value === base ||
                    String(value).startsWith(base + ' ')
            ).length;

            return duplicates === 0
                ? base
                : base + ' ' + (duplicates + 1);
        });
    }

    function anonymizeIpv4(address){
        return mapped('ipv4', address, function(){
            const parts = address.split('.').map(Number);

            if(parts.length !== 4){
                return '192.0.2.' + stableNumber(address, 1, 254);
            }

            const first = parts[0];

            if(first === 10){
                return [
                    10,
                    stableNumber(address + ':b', 1, 254),
                    stableNumber(address + ':c', 1, 254),
                    stableNumber(address + ':d', 1, 254)
                ].join('.');
            }

            if(first === 172 && parts[1] >= 16 && parts[1] <= 31){
                return [
                    172,
                    stableNumber(address + ':b', 16, 31),
                    stableNumber(address + ':c', 1, 254),
                    stableNumber(address + ':d', 1, 254)
                ].join('.');
            }

            if(first === 192 && parts[1] === 168){
                return [
                    192,
                    168,
                    stableNumber(address + ':c', 1, 254),
                    stableNumber(address + ':d', 1, 254)
                ].join('.');
            }

            return [
                192,
                0,
                2,
                stableNumber(address, 1, 254)
            ].join('.');
        });
    }

    function anonymizeIpv6(address){
        return mapped('ipv6', address, function(){
            const a = stableNumber(address + ':a', 1, 65535)
                .toString(16);
            const b = stableNumber(address + ':b', 1, 65535)
                .toString(16);
            const c = stableNumber(address + ':c', 1, 65535)
                .toString(16);

            return '2001:db8:' + a + ':' + b + '::' + c;
        });
    }

    function anonymizeEmail(email){
        return mapped('email', email, function(){
            return 'user' +
                stableNumber(email, 1, 999) +
                '@example.invalid';
        });
    }

    function anonymizeHost(host){
        return mapped('host', host, function(){
            const lower = host.toLowerCase();

            if(lower === 'localhost'){
                return 'demo-host.local';
            }

            const suffix = lower.endsWith('.local')
                ? '.demo.local'
                : '.example.invalid';

            return 'host-' +
                stableNumber(host, 1, 999) +
                suffix;
        });
    }

    function replaceVisibleText(input){
        let output = String(input);

        const names = Array.isArray(
            window.opnCentralPresentationNames
        ) ? window.opnCentralPresentationNames : [];

        names
            .slice()
            .sort((a, b) => b.length - a.length)
            .forEach(function(name){
                if(!name){
                    return;
                }

                output = output.split(name).join(
                    fantasyName(name)
                );
            });

        output = output.replace(
            /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
            anonymizeEmail
        );

        output = output.replace(
            /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
            anonymizeIpv4
        );

        output = output.replace(
            /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{0,4}\b/gi,
            anonymizeIpv6
        );

        output = output.replace(
            /\b(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?\b/gi,
            function(match){
                const protocolMatch = match.match(/^https?:\/\//i);
                const protocol = protocolMatch
                    ? protocolMatch[0]
                    : '';
                const withoutProtocol = match.slice(protocol.length);
                const portMatch = withoutProtocol.match(/:\d+$/);
                const port = portMatch ? portMatch[0] : '';
                const host = port
                    ? withoutProtocol.slice(0, -port.length)
                    : withoutProtocol;

                return protocol + anonymizeHost(host) + port;
            }
        );

        return output;
    }

    function shouldSkip(node){
        const parent = node.parentElement;

        if(!parent){
            return true;
        }

        return Boolean(parent.closest(
            'script,style,noscript,template,' +
            '[data-presentation-exempt="true"],' +
            '.presentation-mode-stack,' +
            '.configuration-unlock-dialog'
        ));
    }

    function transformTextNode(node){
        if(shouldSkip(node)){
            return;
        }

        if(!originalTextValues.has(node)){
            originalTextValues.set(node, node.nodeValue || '');
        }

        const original = originalTextValues.get(node) || '';
        const replacement = replaceVisibleText(original);

        if(node.nodeValue !== replacement){
            node.nodeValue = replacement;
        }
    }

    function restoreTextNode(node){
        if(!originalTextValues.has(node)){
            return;
        }

        const original = originalTextValues.get(node) || '';

        if(node.nodeValue !== original){
            node.nodeValue = original;
        }

        originalTextValues.delete(node);
    }

    function transformElementAttributes(element){
        const attributes = ['title','aria-label','placeholder'];
        let originals = originalAttributeValues.get(element);

        if(!originals){
            originals = {};
            originalAttributeValues.set(element, originals);
        }

        attributes.forEach(function(attribute){
            if(!element.hasAttribute(attribute)){
                return;
            }

            if(!Object.prototype.hasOwnProperty.call(originals, attribute)){
                originals[attribute] = element.getAttribute(attribute);
            }

            element.setAttribute(
                attribute,
                replaceVisibleText(originals[attribute] || '')
            );
        });
    }

    function restoreElementAttributes(element){
        const originals = originalAttributeValues.get(element);

        if(!originals){
            return;
        }

        Object.entries(originals).forEach(function(entry){
            const attribute = entry[0];
            const value = entry[1];

            if(value === null){
                element.removeAttribute(attribute);
            }else{
                element.setAttribute(attribute, value);
            }
        });

        originalAttributeValues.delete(element);
    }

    function walk(root, transform){
        if(root.nodeType === Node.TEXT_NODE){
            transform
                ? transformTextNode(root)
                : restoreTextNode(root);
            return;
        }

        if(root.nodeType !== Node.ELEMENT_NODE &&
           root.nodeType !== Node.DOCUMENT_NODE &&
           root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE){
            return;
        }

        if(root.nodeType === Node.ELEMENT_NODE){
            if(root.closest(
                '[data-presentation-exempt="true"],' +
                '.presentation-mode-stack'
            )){
                return;
            }

            transform
                ? transformElementAttributes(root)
                : restoreElementAttributes(root);
        }

        const walker = document.createTreeWalker(
            root,
            NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT
        );

        let current;
        while((current = walker.nextNode())){
            if(current.nodeType === Node.TEXT_NODE){
                transform
                    ? transformTextNode(current)
                    : restoreTextNode(current);
            }else{
                transform
                    ? transformElementAttributes(current)
                    : restoreElementAttributes(current);
            }
        }
    }

    function startObserver(){
        if(observer){
            return;
        }

        observer = new MutationObserver(function(mutations){
            if(!enabled || applying){
                return;
            }

            applying = true;

            try{
                mutations.forEach(function(mutation){
                    mutation.addedNodes.forEach(function(node){
                        walk(node, true);
                    });

                    if(
                        mutation.type === 'characterData' &&
                        mutation.target.nodeType === Node.TEXT_NODE
                    ){
                        transformTextNode(mutation.target);
                    }
                });
            }finally{
                applying = false;
            }
        });

        observer.observe(document.body, {
            childList:true,
            subtree:true
        });
    }

    function stopObserver(){
        if(observer){
            observer.disconnect();
            observer = null;
        }
    }

    function updateUi(){
        document.body.classList.toggle(
            'presentation-mode',
            enabled
        );

        if(button){
            button.classList.toggle('warning', enabled);
            button.classList.toggle('secondary', !enabled);
            button.setAttribute(
                'aria-pressed',
                enabled ? 'true' : 'false'
            );
            button.textContent = enabled
                ? 'Exit presentation'
                : 'Presentation';
        }

        if(state){
            state.hidden = !enabled;
        }
    }

    function apply(){
        applying = true;

        try{
            if(enabled){
                walk(document.body, true);
                startObserver();
            }else{
                stopObserver();
                walk(document.body, false);
            }

            updateUi();
        }finally{
            applying = false;
        }
    }

    button?.addEventListener('click', function(){
        enabled = !enabled;
        localStorage.setItem(storageKey, enabled ? '1' : '0');
        apply();
    });

    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', apply, {
            once:true
        });
    }else{
        apply();
    }
})();
</script>
<script>
window.opnCentralSetTheme=function(theme){
    const selected=theme==='dark'?'dark':'light';
    document.documentElement.dataset.theme=selected;
    localStorage.setItem('opncentral-theme',selected);
    const meta=document.getElementById('browser-theme-color');
    if(meta) meta.setAttribute('content',selected==='dark'?'#1b2228':'#26313a');
};
window.opnCentralSetTheme(document.documentElement.dataset.theme||'light');
document.getElementById('sidebar-toggle')?.addEventListener('click',function(){
    document.body.classList.toggle('sidebar-open');
});


window.opnCentralConfigurationUnlocked =
    document.body.classList.contains('configuration-unlocked');

function markRemoteChangeControls(){
    const locked = !window.opnCentralConfigurationUnlocked;
    const currentPath = window.location.pathname;
    const mutatingPages = new Set([
        '/aliases.php',
        '/categories.php',
        '/wireguard_create.php',
        '/openvpn_roadwarrior_create.php'
    ]);

    const selectors = [
        '[data-action]:not([data-action="firmware_check"])',
        '.wg-state-action',
        '.vpn-state-action',
        '.plugin-action',
        '.remote-change-control'
    ];

    if(mutatingPages.has(currentPath)){
        selectors.push(
            'form button[type="submit"]',
            'form input[type="submit"]'
        );
    }

    document.querySelectorAll(selectors.join(',')).forEach(element => {
        element.classList.add('remote-change-control');
        element.dataset.configurationLocked = locked ? '1' : '0';

        if('disabled' in element){
            element.disabled = locked;
        }

        element.setAttribute(
            'aria-disabled',
            locked ? 'true' : 'false'
        );
        element.title = locked
            ? 'Unlock configuration changes first.'
            : '';
    });

    const changeLinks = [
        'a[href="/wireguard_create.php"]',
        'a[href="/openvpn_roadwarrior_create.php"]',
        'a[href="/aliases.php"]',
        'a[href^="/aliases.php?"]',
        'a[href="/categories.php"]',
        'a[href^="/categories.php?"]',
        'a[href^="/backup_download.php"]',
        'a[href^="/backup_zip_download.php"]',
        'form[action="/self_backup_download.php"] button[type="submit"]',
        '.backup-download-control'
    ];

    document.querySelectorAll(changeLinks.join(',')).forEach(link => {
        link.classList.add('remote-change-control');
        link.dataset.configurationLocked = locked ? '1' : '0';
        link.setAttribute(
            'aria-disabled',
            locked ? 'true' : 'false'
        );
        link.title = locked
            ? 'Unlock configuration changes first.'
            : '';
    });
}

document.addEventListener('click', function(event){
    const target = event.target.closest(
        '.remote-change-control[data-configuration-locked="1"]'
    );

    if(target){
        event.preventDefault();
        event.stopImmediatePropagation();

        document.getElementById(
            'configuration-lock-button'
        )?.click();
    }
}, true);

const lockButton = document.getElementById(
    'configuration-lock-button'
);
const unlockDialog = document.getElementById(
    'configuration-unlock-dialog'
);
const unlockPassword = document.getElementById(
    'configuration-unlock-password'
);
const unlockError = document.getElementById(
    'configuration-unlock-error'
);

async function submitConfigurationLock(action, password = ''){
    const form = new URLSearchParams({
        csrf: <?= json_encode(
            csrf_token(),
            JSON_UNESCAPED_SLASHES
        ) ?>,
        action,
        password
    });

    const response = await fetch('/configuration_lock.php', {
        method:'POST',
        credentials:'same-origin',
        cache:'no-store',
        headers:{
            'Content-Type':
                'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body:form
    });

    const raw = await response.text();
    let data;

    try{
        data = JSON.parse(raw);
    }catch(error){
        throw new Error(
            'Invalid server response: ' +
            raw.replace(/\s+/g, ' ').slice(0, 500)
        );
    }

    if(!response.ok || data.ok !== true){
        throw new Error(data.error || 'Lock action failed.');
    }

    window.location.reload();
}

lockButton?.addEventListener('click', async function(){
    const unlocked = lockButton.dataset.unlocked === '1';

    if(unlocked){
        lockButton.disabled = true;

        try{
            await submitConfigurationLock('lock');
        }catch(error){
            alert(error.message);
            lockButton.disabled = false;
        }

        return;
    }

    const supportUrl = lockButton.dataset.supportUrl;

    if(supportUrl){
        window.open(
            supportUrl,
            '_blank',
            'noopener,noreferrer'
        );
    }

    unlockError?.classList.add('hidden');
    if(unlockError) unlockError.textContent = '';
    if(unlockPassword) unlockPassword.value = '';
    if(unlockDialog) unlockDialog.hidden = false;
    window.setTimeout(() => unlockPassword?.focus(), 0);
});

document.getElementById(
    'configuration-unlock-cancel'
)?.addEventListener('click', function(){
    if(unlockDialog) unlockDialog.hidden = true;
});

document.getElementById(
    'configuration-unlock-submit'
)?.addEventListener('click', async function(){
    const submit = this;
    submit.disabled = true;
    unlockError?.classList.add('hidden');

    try{
        await submitConfigurationLock(
            'unlock',
            unlockPassword?.value || ''
        );
    }catch(error){
        if(unlockError){
            unlockError.textContent = error.message;
            unlockError.classList.remove('hidden');
        }
        submit.disabled = false;
        unlockPassword?.focus();
        unlockPassword?.select();
    }
});

unlockPassword?.addEventListener('keydown', function(event){
    if(event.key === 'Enter'){
        event.preventDefault();
        document.getElementById(
            'configuration-unlock-submit'
        )?.click();
    }

    if(event.key === 'Escape'){
        if(unlockDialog) unlockDialog.hidden = true;
    }
});

markRemoteChangeControls();

const remoteChangeObserver = new MutationObserver(function(){
    markRemoteChangeControls();
});

if(document.body.classList.contains('app-shell')){
    remoteChangeObserver.observe(
        document.body,
        {
            childList:true,
            subtree:true
        }
    );
}

if(document.body.classList.contains('app-shell')){
    window.setTimeout(function(){
        fetch('/update_check.php',{credentials:'same-origin',cache:'no-store'}).catch(function(){});
    },1500);
    window.setTimeout(function(){
        fetch('/telemetry_background.php',{credentials:'same-origin',cache:'no-store'}).catch(function(){});
    },3000);
}
</script>
