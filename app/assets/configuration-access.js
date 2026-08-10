(function(){
    'use strict';

    function init(){
        // 0.6.21+: authenticated users are no longer gated by a separate
        // configuration read-only/unlock state.
        window.opnCentralConfigurationUnlocked = true;

        document.getElementById('configuration-access-settings')?.remove();
        document.getElementById('configuration-unlock-dialog')?.remove();

        const interfaceCard = document.getElementById('interface-access-settings');
        if(interfaceCard){
            const intro = interfaceCard.querySelector(':scope > p.muted');
            if(intro) intro.textContent = 'Control presentation mode.';
        }

        document.querySelectorAll('[data-configuration-locked]').forEach(function(element){
            element.dataset.configurationLocked = '0';
            element.setAttribute('aria-disabled', 'false');
            element.removeAttribute('title');
        });
    }

    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', init, {once:true});
    }else{
        init();
    }
})();
