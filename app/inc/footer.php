</main>
<?php if (logged_in()): ?></div><?php endif; ?>
<footer class="app-footer"><?= h(t('footer')) ?></footer>
<link rel="stylesheet" href="/assets/topbar-controls.css?v=06200">
<link rel="stylesheet" href="/assets/sidebar-opnsense.css?v=06200">
<link rel="stylesheet" href="/assets/sidebar-submenus.css?v=06200">
<link rel="stylesheet" href="/assets/ids-bulk-actions.css?v=06200">
<script src="/assets/ids-menu.js?v=06200"></script>
<script src="/assets/sidebar-opnsense.js?v=06200"></script>
<script src="/assets/ids-write-label.js?v=06200"></script>
<script src="/assets/ids-bulk-actions.js?v=06200"></script>
<script src="/assets/ids-ruleset-filter.js?v=06200"></script>
<script src="/assets/ids-policy-editor.js?v=06200"></script>
<script src="/assets/shared-inventory-management.js?v=06200"></script>
<script src="/assets/category-edit-links.js?v=06200"></script>
<script>
(function(){
    document.title = 'opnSentral';

    const version = document.querySelector('.sidebar-meta span:first-child');
    if(version){
        version.textContent = 'v0.6.20.0';
    }

    const path = location.pathname;
    let settings = null;
    if(path === '/category_overview.php'){
        settings = {
            type: 'categories',
            label: 'categories',
            anchorId: 'category-inventory-list'
        };
    }else if(path === '/alias_overview.php'){
        settings = {
            type: 'aliases',
            label: 'variables',
            anchorId: 'alias-inventory-list'
        };
    }

    if(settings && typeof window.opnSentralSharedInventory === 'function'){
        const anchor = document.getElementById(settings.anchorId);
        if(anchor){
            const mount = document.createElement('div');
            mount.id = 'shared-inventory-management';
            anchor.parentNode.insertBefore(mount, anchor);
            window.opnSentralSharedInventory({
                type: settings.type,
                label: settings.label,
                mountId: mount.id
            });
        }
    }
})();
</script>
</body></html>
