</main>
<?php if (logged_in()): ?></div><?php endif; ?>
<footer class="app-footer"><?= h(t('footer')) ?></footer>
<link rel="stylesheet" href="/assets/topbar-controls.css?v=06115">
<link rel="stylesheet" href="/assets/sidebar-opnsense.css?v=06116">
<link rel="stylesheet" href="/assets/sidebar-submenus.css?v=06117">
<link rel="stylesheet" href="/assets/ids-bulk-actions.css?v=06118">
<script src="/assets/ids-menu.js?v=06118"></script>
<script src="/assets/sidebar-opnsense.js?v=06118"></script>
<script src="/assets/ids-write-label.js?v=06118"></script>
<script src="/assets/ids-bulk-actions.js?v=06119"></script>
<script src="/assets/ids-ruleset-filter.js?v=061112"></script>
<script src="/assets/ids-policy-editor.js?v=061113"></script>
<script>
(function(){
    document.title = 'opnSentral';

    const version = document.querySelector('.sidebar-meta span:first-child');
    if(version){
        version.textContent = 'v0.6.11.13';
    }
})();
</script>
</body></html>
