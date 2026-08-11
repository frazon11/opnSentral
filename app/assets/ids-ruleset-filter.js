(function(){
    'use strict';

    if(location.pathname !== '/intrusion_detection.php') return;
    if((new URLSearchParams(location.search).get('view') || 'administration') !== 'download') return;

    const presets = {
        'high-confidence': [
            'botcc','botcc.portgrouped','ciarmy','compromised','drop','dshield',
            'emerging-coinminer','emerging-malware','emerging-web_client',
            'emerging-web_server','emerging-shellcode'
        ],
        'start-blocking': [
            'botcc','botcc.portgrouped','ciarmy','compromised','drop','dshield',
            'emerging-coinminer','emerging-malware'
        ],
        'avoid': [
            'emerging-activex','emerging-adware_pup','emerging-chat','emerging-dos',
            'emerging-file_sharing','emerging-games','emerging-info','emerging-misc',
            'emerging-p2p','emerging-policy','emerging-scan'
        ]
    };

    function normalize(value){
        return String(value || '')
            .toLowerCase()
            .replace(/^et[ _-]*open[\/ _-]*/,'')
            .replace(/\.rules$/,'')
            .trim();
    }

    function install(){
        const controls = document.querySelector('.ids-ruleset-presets');
        const textFilter = document.getElementById('ids-ruleset-filter');
        const rulesetSelect = document.querySelector('.ids-ruleset-select');

        if(!controls || !textFilter || !rulesetSelect) return false;
        if(document.getElementById('ids-ruleset-preset-filter')) return true;

        controls.querySelectorAll('[data-preset]:not([data-preset="clear"])').forEach(function(button){
            button.remove();
        });

        const toolbar = document.createElement('div');
        toolbar.className = 'ids-ruleset-filter-toolbar';
        toolbar.style.display = 'flex';
        toolbar.style.alignItems = 'end';
        toolbar.style.gap = '8px';
        toolbar.style.flexWrap = 'wrap';

        const presetLabel = document.createElement('label');
        presetLabel.textContent = 'Filter rulesets';
        presetLabel.style.margin = '0';
        presetLabel.style.flex = '0 1 260px';

        const presetSelect = document.createElement('select');
        presetSelect.id = 'ids-ruleset-preset-filter';
        presetSelect.style.width = '100%';
        presetSelect.style.minWidth = '180px';
        presetSelect.innerHTML =
            '<option value="all">All rulesets</option>' +
            '<option value="high-confidence">High-confidence ET</option>' +
            '<option value="start-blocking">Start-blocking set</option>' +
            '<option value="avoid">Noisy / avoid set</option>';
        presetLabel.appendChild(presetSelect);
        toolbar.appendChild(presetLabel);

        const clearButton = controls.querySelector('[data-preset="clear"]');
        if(clearButton){
            clearButton.classList.add('ids-clear-selection');
            toolbar.appendChild(clearButton);
        }

        const textLabel = textFilter.closest('label');
        controls.insertBefore(toolbar, controls.firstChild);
        if(textLabel){
            textLabel.firstChild.textContent = 'Free-text filter';
        }

        const oldActions = controls.querySelector('.actions');
        if(oldActions && !oldActions.children.length){
            oldActions.remove();
        }

        function applyCombinedFilter(){
            const preset = presetSelect.value;
            const query = textFilter.value.trim().toLowerCase();
            const allowed = preset === 'all' ? null : new Set(presets[preset] || []);

            Array.from(rulesetSelect.options).forEach(function(option){
                const normalized = option.dataset.normalized || normalize(option.value);
                const matchesPreset = allowed === null || allowed.has(normalized);
                const matchesText = query === '' || option.textContent.toLowerCase().includes(query);
                option.hidden = !(matchesPreset && matchesText);
            });
        }

        presetSelect.addEventListener('change', applyCombinedFilter);
        textFilter.addEventListener('input', applyCombinedFilter);
        applyCombinedFilter();
        return true;
    }

    if(install()) return;

    const observer = new MutationObserver(function(){
        if(install()) observer.disconnect();
    });
    observer.observe(document.documentElement, {childList:true, subtree:true});
})();
