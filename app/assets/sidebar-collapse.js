(function(){
    'use strict';

    const sections = Array.from(document.querySelectorAll('#sidebar .menu-section'));
    if (!sections.length) return;

    const storageKey = 'opnsentral-sidebar-sections-v2';
    let stored = {};
    try {
        const parsed = JSON.parse(localStorage.getItem(storageKey) || '{}');
        stored = parsed && typeof parsed === 'object' ? parsed : {};
    } catch (error) {
        stored = {};
    }

    function keyFor(section, index){
        const label = section.querySelector(':scope > .menu-level1')?.textContent?.trim() || ('section-' + index);
        return label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || ('section-' + index);
    }

    function setState(section, key, open, persist){
        const heading = section.querySelector(':scope > .menu-level1');
        if (!heading) return;
        section.classList.toggle('is-collapsed', !open);
        heading.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (persist) {
            stored[key] = open;
            localStorage.setItem(storageKey, JSON.stringify(stored));
        }
    }

    sections.forEach(function(section, index){
        const heading = section.querySelector(':scope > .menu-level1');
        if (!heading) return;

        const key = keyFor(section, index);
        heading.setAttribute('role', 'button');
        heading.setAttribute('tabindex', '0');
        heading.setAttribute('aria-label', 'Toggle ' + heading.textContent.trim() + ' menu');

        const hasActive = Boolean(section.querySelector('.menu-link.active'));
        const configured = Object.prototype.hasOwnProperty.call(stored, key) ? stored[key] : true;
        setState(section, key, hasActive ? true : configured !== false, false);

        function toggle(){
            const open = heading.getAttribute('aria-expanded') === 'true';
            setState(section, key, !open, true);
        }

        heading.addEventListener('click', toggle);
        heading.addEventListener('keydown', function(event){
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggle();
            }
        });
    });
})();
