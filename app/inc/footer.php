</main>
<?php if (logged_in()): ?></div><?php endif; ?>
<footer class="app-footer"><?= h(t('footer')) ?></footer>
<link rel="stylesheet" href="/assets/topbar-controls.css?v=06215">
<link rel="stylesheet" href="/assets/ids-bulk-actions.css?v=06215">
<link rel="stylesheet" href="/assets/sidebar-collapse.css?v=062119">
<link rel="stylesheet" href="/assets/system-status-indicator.css?v=062163">
<link rel="stylesheet" href="/assets/alias-edit-layout.css?v=062177">
<link rel="stylesheet" href="/assets/firewall-hardware-card.css?v=062185">
<script src="/assets/sidebar-collapse.js?v=062119"></script>
<script src="/assets/sidebar-scroll.js?v=062116"></script>
<script src="/assets/ids-ruleset-filter.js?v=06215"></script>
<script src="/assets/shared-inventory-management.js?v=062178"></script>
<script src="/assets/category-edit-links.js?v=062178"></script>
<script src="/assets/network-settings.js?v=06215"></script>
<script src="/assets/presentation-mode.js?v=062234"></script>
<script src="/assets/configuration-access.js?v=062100"></script>
<script src="/assets/presentation-settings.js?v=062020"></script>
<script src="/assets/alias-geoip-type.js?v=06215"></script>
<script src="/assets/deployment-results.js?v=062106"></script>
<script src="/assets/system-status-indicator.js?v=062175"></script>
<script>window.opnSentralCsrf=<?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;</script>
<script src="/assets/firewall-card-actions.js?v=062185"></script>
<script src="/assets/firewall-hardware-card.js?v=062185"></script>
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

    const fleetRoot = document.querySelector('[data-fleet-settings-scope]');
    if(fleetRoot){
        document.querySelectorAll('.fleet-setting-control,.fleet-row-all').forEach(control=>{control.disabled=true;});
        const apply=document.getElementById('fleet-settings-apply');
        const reset=document.getElementById('fleet-settings-reset');
        if(apply){apply.disabled=true;apply.title='Read-only safety mode';}
        if(reset)reset.disabled=true;
        const result=document.getElementById('fleet-settings-result');
        if(result){
            result.className='alert warningbox';
            result.innerHTML='<strong>Read-only safety mode.</strong> Fleet configuration writes are disabled until the agent-side write implementation is safely restored and regression-tested.';
        }
    }

    if(path === '/ssh_access.php'){
        document.querySelectorAll('.ssh-enable-one,.ssh-fleet-check,#ssh-select-all,#ssh-enable-selected').forEach(control=>{
            control.disabled=true;
            control.title='Managed SSH Enable / Repair is temporarily disabled; live status remains available.';
        });
        const pageTitle=document.querySelector('.page-title');
        if(pageTitle){
            const warning=document.createElement('div');
            warning.className='alert warningbox';
            warning.innerHTML='<strong>Enable / Repair is temporarily disabled.</strong> Agent 0.1.16 does not implement the required local SSH repair job. Live TCP/22 status and managed-rule inspection remain available.';
            pageTitle.insertAdjacentElement('afterend',warning);
        }
    }
})();
</script>
</body></html>
