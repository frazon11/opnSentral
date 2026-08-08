(function(){
    'use strict';

    function init(){
        const button = document.getElementById('presentation-mode-button');
        const state = document.getElementById('presentation-mode-state');
        if(!button) return;

        const storageKey = 'opncentral-presentation-mode';

        function render(){
            const enabled = localStorage.getItem(storageKey) === '1';
            button.classList.toggle('warning', enabled);
            button.classList.toggle('secondary', !enabled);
            button.setAttribute('aria-pressed', enabled ? 'true' : 'false');
            button.textContent = enabled ? 'Exit presentation' : 'Enable presentation mode';
            if(state) state.hidden = !enabled;
        }

        button.addEventListener('click', function(){
            const enabled = localStorage.getItem(storageKey) === '1';
            localStorage.setItem(storageKey, enabled ? '0' : '1');
            window.location.reload();
        });

        render();
    }

    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', init, {once:true});
    }else{
        init();
    }
})();
