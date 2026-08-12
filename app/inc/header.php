<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/update_check.php';
start_session_secure();
$presentationFirewallNames = [];

if (logged_in()) {
    try {
        $presentationFirewallNames = array_values(
            array_filter(
                array_map(
                    static fn(array $row): string =>
                        trim((string) ($row['name'] ?? '')),
                    db()->query('SELECT name FROM firewalls ORDER BY id')->fetchAll()
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
    const key='opnsentral-theme';
    const legacyKey='opncentral-theme';
    if(localStorage.getItem(key)===null && localStorage.getItem(legacyKey)!==null){
        localStorage.setItem(key,localStorage.getItem(legacyKey));
        localStorage.removeItem(legacyKey);
    }
    const saved=localStorage.getItem(key);
    document.documentElement.dataset.theme=saved==='dark'?'dark':'light';
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
                <span>v<?= h(OPNSENTRAL_VERSION) ?></span><span>·</span>
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

        <div class="nav-group">System</div>
        <div class="nav-section-label">Access</div>
        <a class="nav-child<?= nav_active(['/system_access_users.php','/system_access_user_edit.php']) ?>" href="/system_access_users.php"><span>Users</span></a>
        <a class="nav-child<?= nav_active(['/system_access_groups.php']) ?>" href="/system_access_groups.php"><span>Groups</span></a>

        <div class="nav-section-label">Settings</div>
        <a class="nav-child<?= nav_active(['/system_general.php']) ?>" href="/system_general.php"><span>General</span></a>
        <a class="nav-child<?= nav_active(['/system_administration_matrix.php','/system_administration.php']) ?>" href="/system_administration_matrix.php"><span>Administration</span></a>

        <div class="nav-section-label">Diagnostics</div>
        <a class="nav-child<?= nav_active(['/services.php']) ?>" href="/services.php"><span>Services</span></a>

        <div class="nav-group">Firewall</div>
        <a class="nav-child<?= nav_active(['/aliases.php','/alias_overview.php']) ?>" href="/alias_overview.php"><span><?= h(t('menu.aliases')) ?></span></a>
        <a class="nav-child<?= nav_active(['/categories.php','/category_overview.php']) ?>" href="/category_overview.php"><span><?= h(t('menu.categories')) ?></span></a>
        <div class="nav-section-label">Settings</div>
        <a class="nav-child<?= nav_active(['/firewall_advanced.php']) ?>" href="/firewall_advanced.php?firewall_id=1"><span>Advanced</span></a>

        <div class="nav-group">VPN</div>
        <div class="nav-section-label">OpenVPN</div>
        <a class="nav-child<?= nav_active(['/openvpn_manage.php']) ?>" href="/openvpn_manage.php"><span>Manage</span></a>
        <span class="nav-child nav-disabled" aria-disabled="true"><span>Create Site-to-Site VPN</span><small>coming soon</small></span>
        <a class="nav-child<?= nav_active(['/openvpn_roadwarrior_create.php']) ?>" href="/openvpn_roadwarrior_create.php"><span>Create Roadwarrior Server</span></a>

        <div class="nav-section-label">WireGuard</div>
        <a class="nav-child<?= nav_active(['/wireguard_overview.php']) ?>" href="/wireguard_overview.php"><span>Manage</span></a>
        <a class="nav-child<?= nav_active(['/wireguard_create.php']) ?>" href="/wireguard_create.php"><span>Create Site-to-Site VPN</span></a>

        <div class="nav-group">opnSentral</div>
        <a class="nav-child<?= nav_active(['/firewall_edit.php']) ?>" href="/firewall_edit.php"><span><?= h(t('menu.add_firewall')) ?></span></a>
        <a class="nav-child<?= nav_active(['/agents.php','/agent_bootstrap.php']) ?>" href="/agents.php"><span>Agents</span></a>
        <a class="nav-child<?= nav_active(['/backups.php']) ?>" href="/backups.php"><span>Backups</span></a>
        <a class="nav-child<?= nav_active(['/troubleshooting.php']) ?>" href="/troubleshooting.php"><span>Troubleshooting</span></a>
        <a class="nav-child<?= nav_active(['/settings.php']) ?>" href="/settings.php"><span>Application Settings</span></a>
        <a class="nav-child<?= nav_active(['/notifications.php']) ?>" href="/notifications.php"><span><?= h(t('menu.notifications')) ?></span></a>
    </nav>

    <div class="sidebar-footer-actions">
        <a class="sidebar-logout" href="/logout.php">⇥ <?= h(t('menu.logout')) ?></a>
    </div>
</aside>
<div class="page-shell">
<header class="topbar">
    <button type="button" class="sidebar-toggle" id="sidebar-toggle" aria-label="Toggle navigation">☰</button>
    <div class="topbar-heading">
        <div class="topbar-title"><?= h(app_name()) ?></div>
        <div
            class="configuration-lock-state <?= configuration_unlocked() ? 'is-unlocked' : 'is-locked' ?>"
            tabindex="0"
            aria-describedby="configuration-lock-tooltip"
        >
            <?= configuration_unlocked() ? 'Configuration unlocked' : 'Read-only mode' ?>
            <span id="configuration-lock-tooltip" class="configuration-lock-tooltip" role="tooltip">
                <?= configuration_unlocked()
                    ? 'Write features are enabled. Configuration access is managed in Settings.'
                    : 'Unlock configuration changes in Settings.' ?>
            </span>
        </div>
    </div>
    <div class="topbar-right">
        <a
            id="configuration-support-link"
            class="configuration-support-link"
            href="https://www.paypal.com/paypalme/FrazoN11"
            target="_blank"
            rel="noopener noreferrer"
            title="Support opnSentral via PayPal"
        >♥ Support me</a>
    </div>
</header>

<main class="content">
<?php else: ?>
<header class="login-header"><img src="/assets/opncentral-icon.svg" alt="" class="sidebar-logo"><strong><?= h(app_name()) ?></strong></header>
<main class="content login-content">
<?php endif; ?>
<script>
window.opnSentralPresentationNames = <?= json_encode(
    $presentationFirewallNames,
    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
) ?>;
window.opnSentralCsrf = <?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>;

window.opnSentralSetTheme=function(theme){
    const selected=theme==='dark'?'dark':'light';
    document.documentElement.dataset.theme=selected;
    localStorage.setItem('opnsentral-theme',selected);
    const meta=document.getElementById('browser-theme-color');
    if(meta) meta.setAttribute('content',selected==='dark'?'#1b2228':'#26313a');
};
window.opnSentralSetTheme(document.documentElement.dataset.theme||'light');

document.getElementById('sidebar-toggle')?.addEventListener('click',function(){
    document.body.classList.toggle('sidebar-open');
});

if(document.body.classList.contains('app-shell')){
    window.setTimeout(function(){
        fetch('/update_check.php',{credentials:'same-origin',cache:'no-store'}).catch(function(){});
    },1500);
    window.setTimeout(function(){
        fetch('/telemetry_background.php',{credentials:'same-origin',cache:'no-store'}).catch(function(){});
    },3000);
}
</script>
