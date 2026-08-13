(function(){
    'use strict';

    const sections = Array.from(document.querySelectorAll('#sidebar .menu-section'));
    if (!sections.length) return;

    const sectionStorageKey = 'opnsentral-sidebar-sections-v3';
    const subsectionStorageKey = 'opnsentral-sidebar-subsections-v1';

    function loadState(key){
        try {
            const parsed = JSON.parse(localStorage.getItem(key) || '{}');
            return parsed && typeof parsed === 'object' ? parsed : {};
        } catch (error) {
            return {};
        }
    }

    const sectionState = loadState(sectionStorageKey);
    const subsectionState = loadState(subsectionStorageKey);

    function slug(value, fallback){
        return String(value || '')
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-|-$/g, '') || fallback;
    }

    function sectionKey(section, index){
        const label = section.querySelector(':scope > .menu-level1')?.textContent?.trim();
        return slug(label, 'section-' + index);
    }

    function createSubsections(section, parentKey){
        const children = Array.from(section.children);
        let current = null;
        let subsectionIndex = 0;

        children.forEach(function(child){
            if (child.classList.contains('menu-level1')) return;

            if (child.classList.contains('menu-level2')) {
                current = document.createElement('div');
                current.className = 'menu-subsection';
                current.dataset.subsectionKey = parentKey + ':' + slug(child.textContent.trim(), 'subsection-' + subsectionIndex++);
                section.insertBefore(current, child);
                current.appendChild(child);
                return;
            }

            if (current) current.appendChild(child);
        });
    }

    function setSectionState(section, key, open, persist){
        const heading = section.querySelector(':scope > .menu-level1');
        if (!heading) return;
        section.classList.toggle('is-collapsed', !open);
        heading.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (persist) {
            sectionState[key] = open;
            localStorage.setItem(sectionStorageKey, JSON.stringify(sectionState));
        }
    }

    function setSubsectionState(subsection, key, open, persist){
        const heading = subsection.querySelector(':scope > .menu-level2');
        if (!heading) return;
        subsection.classList.toggle('is-collapsed', !open);
        heading.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (persist) {
            subsectionState[key] = open;
            localStorage.setItem(subsectionStorageKey, JSON.stringify(subsectionState));
        }
    }

    sections.forEach(function(section, index){
        const key = sectionKey(section, index);
        createSubsections(section, key);

        Array.from(section.querySelectorAll(':scope > .menu-subsection')).forEach(function(subsection){
            const heading = subsection.querySelector(':scope > .menu-level2');
            if (!heading) return;

            const subKey = subsection.dataset.subsectionKey || key + ':subsection';
            heading.setAttribute('role', 'button');
            heading.setAttribute('tabindex', '0');
            heading.setAttribute('aria-label', 'Toggle ' + heading.textContent.trim() + ' menu');

            const hasActive = Boolean(subsection.querySelector('.menu-link.active'));
            const configured = Object.prototype.hasOwnProperty.call(subsectionState, subKey)
                ? subsectionState[subKey]
                : true;
            setSubsectionState(subsection, subKey, hasActive ? true : configured !== false, false);

            function toggleSubsection(){
                const open = heading.getAttribute('aria-expanded') === 'true';
                setSubsectionState(subsection, subKey, !open, true);
            }

            heading.addEventListener('click', toggleSubsection);
            heading.addEventListener('keydown', function(event){
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    toggleSubsection();
                }
            });
        });

        const heading = section.querySelector(':scope > .menu-level1');
        if (!heading) return;

        heading.setAttribute('role', 'button');
        heading.setAttribute('tabindex', '0');
        heading.setAttribute('aria-label', 'Toggle ' + heading.textContent.trim() + ' menu');

        const hasActive = Boolean(section.querySelector('.menu-link.active'));
        const configured = Object.prototype.hasOwnProperty.call(sectionState, key)
            ? sectionState[key]
            : true;
        setSectionState(section, key, hasActive ? true : configured !== false, false);

        function toggleSection(){
            const open = heading.getAttribute('aria-expanded') === 'true';
            setSectionState(section, key, !open, true);
        }

        heading.addEventListener('click', toggleSection);
        heading.addEventListener('keydown', function(event){
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggleSection();
            }
        });
    });
})();
