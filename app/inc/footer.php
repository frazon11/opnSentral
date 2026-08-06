</main>
<?php if (logged_in()): ?></div><?php endif; ?>
<footer class="app-footer"><?= h(t('footer')) ?></footer>
<link rel="stylesheet" href="/assets/topbar-controls.css?v=06204">
<link rel="stylesheet" href="/assets/sidebar-opnsense.css?v=06204">
<link rel="stylesheet" href="/assets/sidebar-submenus.css?v=06204">
<link rel="stylesheet" href="/assets/ids-bulk-actions.css?v=06204">
<script src="/assets/ids-menu.js?v=06204"></script>
<script src="/assets/sidebar-opnsense.js?v=06204"></script>
<script src="/assets/ids-write-label.js?v=06204"></script>
<script src="/assets/ids-bulk-actions.js?v=06204"></script>
<script src="/assets/ids-ruleset-filter.js?v=06204"></script>
<script src="/assets/ids-policy-editor.js?v=06204"></script>
<script src="/assets/shared-inventory-management.js?v=06204"></script>
<script src="/assets/category-edit-links.js?v=06204"></script>
<script>
(function(){
    document.title = 'opnSentral';
    const version = document.querySelector('.sidebar-meta span:first-child');
    if(version) version.textContent = 'v0.6.20.4';

    const aliasLink = document.querySelector('.side-nav a[href="/alias_overview.php"]');
    if(aliasLink && !document.querySelector('.side-nav a[href="/geoip_settings.php"]')){
        const geoIpLink = document.createElement('a');
        geoIpLink.href = '/geoip_settings.php';
        geoIpLink.innerHTML = '◉ <span>GeoIP Settings</span>';
        if(location.pathname === '/geoip_settings.php') geoIpLink.classList.add('active');
        aliasLink.insertAdjacentElement('afterend', geoIpLink);
    }

    const settingsGroup = Array.from(document.querySelectorAll('.side-nav .nav-group')).find(el => el.textContent.trim() === 'Settings');
    if(settingsGroup && !document.getElementById('system-main-menu')){
        const wrapper = document.createElement('div');
        wrapper.id = 'system-main-menu';
        wrapper.innerHTML = `
            <div class="nav-group">System</div>
            <div class="nav-section-label">Configuration</div>
            <a class="nav-child" href="/backups.php"><span>Backup</span></a>
            <div class="nav-section-label">Firmware</div>
            <a class="nav-child" href="/system_firmware_status.php"><span>Status</span></a>
            <a class="nav-child" href="/plugins.php"><span>Plugins</span></a>`;
        settingsGroup.parentNode.insertBefore(wrapper, settingsGroup);
        wrapper.querySelectorAll('a').forEach(a => {
            if(a.getAttribute('href') === location.pathname) a.classList.add('active');
        });
    }

    const path = location.pathname;
    let settings = null;
    if(path === '/category_overview.php') settings = {type:'categories',label:'categories',anchorId:'category-inventory-list'};
    else if(path === '/alias_overview.php') settings = {type:'aliases',label:'variables',anchorId:'alias-inventory-list'};

    if(settings && typeof window.opnSentralSharedInventory === 'function'){
        const anchor = document.getElementById(settings.anchorId);
        if(anchor){
            const mount = document.createElement('div');
            mount.id = 'shared-inventory-management';
            anchor.parentNode.insertBefore(mount, anchor);
            window.opnSentralSharedInventory({type:settings.type,label:settings.label,mountId:mount.id});
        }
    }
})();
</script>
</body></html>
