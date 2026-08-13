</main>
<?php if (logged_in()): ?></div><?php endif; ?>
<footer class="app-footer"><?= h(t('footer')) ?></footer>
<link rel="stylesheet" href="/assets/topbar-controls.css?v=06215">
<link rel="stylesheet" href="/assets/ids-bulk-actions.css?v=06215">
<link rel="stylesheet" href="/assets/sidebar-collapse.css?v=062119">
<script src="/assets/sidebar-collapse.js?v=062119"></script>
<script src="/assets/sidebar-scroll.js?v=062116"></script>
<script src="/assets/ids-write-label.js?v=06215"></script>
<script src="/assets/ids-bulk-actions.js?v=06215"></script>
<script src="/assets/ids-ruleset-filter.js?v=06215"></script>
<script src="/assets/ids-policy-editor.js?v=06215"></script>
<script src="/assets/shared-inventory-management.js?v=06215"></script>
<script src="/assets/category-edit-links.js?v=06215"></script>
<script src="/assets/network-settings.js?v=06215"></script>
<script src="/assets/presentation-mode.js?v=062020"></script>
<script src="/assets/configuration-access.js?v=062100"></script>
<script src="/assets/presentation-settings.js?v=062020"></script>
<script src="/assets/alias-geoip-type.js?v=06215"></script>
<script src="/assets/deployment-results.js?v=062106"></script>
<script>
(function(){
    document.title = 'opnSentral';

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
