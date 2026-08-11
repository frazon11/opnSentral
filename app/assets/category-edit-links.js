(function(){
    'use strict';
    if(location.pathname !== '/category_overview.php') return;

    document.addEventListener('click', function(event){
        const button = event.target.closest('.inventory-edit');
        if(!button) return;

        event.preventDefault();
        event.stopImmediatePropagation();

        const firewallId = Number(button.dataset.firewallId || 0);
        const name = String(button.dataset.name || '').trim();
        if(!firewallId || !name) return;

        location.href = '/category_edit.php?firewall_id=' +
            encodeURIComponent(String(firewallId)) +
            '&name=' + encodeURIComponent(name);
    }, true);
})();
