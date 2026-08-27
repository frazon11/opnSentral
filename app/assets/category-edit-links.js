(function(){
    'use strict';
    if(location.pathname !== '/category_overview.php') return;

    function normalizeButtons(root){
        (root || document).querySelectorAll('.inventory-rename').forEach(function(button){
            button.classList.remove('inventory-rename');
            button.classList.add('inventory-edit');
            button.textContent = 'Edit';
            button.setAttribute('aria-label','Edit category definition');
        });
    }

    normalizeButtons(document);
    const observer = new MutationObserver(function(){ normalizeButtons(document); });
    observer.observe(document.documentElement,{childList:true,subtree:true});

    document.addEventListener('click', function(event){
        const button = event.target.closest('.inventory-edit');
        if(!button) return;

        event.preventDefault();
        event.stopImmediatePropagation();

        const firewallId = Number(button.dataset.firewallId || 0);
        const name = String(button.dataset.name || '').trim();
        if(!firewallId || !name) return;

        location.href = '/category_edit.php?source_firewall_id=' +
            encodeURIComponent(String(firewallId)) +
            '&name=' + encodeURIComponent(name);
    }, true);
})();
