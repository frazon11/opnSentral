(function(){
    'use strict';

    const nav = document.querySelector('#sidebar .side-nav');
    if (!nav) return;

    const key = 'opnsentral-sidebar-scroll-top';

    function restore(){
        const stored = sessionStorage.getItem(key);
        if (stored === null) return;
        const value = Number.parseInt(stored, 10);
        if (!Number.isFinite(value) || value < 0) return;
        nav.scrollTop = value;
        requestAnimationFrame(function(){ nav.scrollTop = value; });
    }

    function save(){
        sessionStorage.setItem(key, String(nav.scrollTop));
    }

    restore();
    nav.addEventListener('scroll', save, {passive:true});
    nav.addEventListener('click', function(event){
        if (event.target.closest('a')) save();
    });
    window.addEventListener('pagehide', save);
})();
