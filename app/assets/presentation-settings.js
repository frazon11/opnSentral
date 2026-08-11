(function(){
    'use strict';

    function init(){
        const button = document.getElementById('presentation-mode-button');
        const state = document.getElementById('presentation-mode-state');
        if(!button) return;

        function isEnabled(){
            if(typeof window.opnSentralPresentationEnabled === 'function'){
                return window.opnSentralPresentationEnabled() === true;
            }
            return localStorage.getItem('opnsentral-presentation-mode') === '1';
        }

        function render(){
            const enabled = isEnabled();
            button.classList.toggle('warning', enabled);
            button.classList.toggle('secondary', !enabled);
            button.setAttribute('aria-pressed', enabled ? 'true' : 'false');
            button.textContent = enabled ? 'Exit presentation' : 'Enable presentation mode';
            if(state) state.hidden = !enabled;
        }

        button.addEventListener('click', function(){
            const enabled = isEnabled();

            if(typeof window.opnSentralSetPresentationMode === 'function'){
                window.opnSentralSetPresentationMode(!enabled);
                render();
                return;
            }

            localStorage.setItem('opnsentral-presentation-mode', enabled ? '0' : '1');
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
