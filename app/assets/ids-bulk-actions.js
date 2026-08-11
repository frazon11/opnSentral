(function(){
    'use strict';

    if(location.pathname !== '/intrusion_detection.php') return;

    const view = new URLSearchParams(location.search).get('view') || 'administration';
    if(!['administration','download'].includes(view)) return;

    const pageTitle = document.querySelector('.page-title');
    if(!pageTitle || document.getElementById('ids-bulk-panel')) return;

    const highConfidence = [
        'botcc','botcc.portgrouped','ciarmy','compromised','drop','dshield',
        'emerging-coinminer','emerging-malware','emerging-web_client',
        'emerging-web_server','emerging-shellcode'
    ];
    const startBlocking = [
        'botcc','botcc.portgrouped','ciarmy','compromised','drop','dshield',
        'emerging-coinminer','emerging-malware'
    ];
    const avoidInitially = [
        'emerging-activex','emerging-adware_pup','emerging-chat','emerging-dos',
        'emerging-file_sharing','emerging-games','emerging-info','emerging-misc',
        'emerging-p2p','emerging-policy','emerging-scan'
    ];

    const panel = document.createElement('section');
    panel.id = 'ids-bulk-panel';
    panel.className = 'card ids-bulk-panel';
    panel.innerHTML =
        '<div class="card-head">' +
            '<div><h2>Bulk management</h2>' +
            '<p class="muted">Apply the same IDS change to selected OPNsense firewalls.</p></div>' +
        '</div>' +
        '<div id="ids-bulk-loading" class="muted">Loading managed firewalls…</div>' +
        '<form id="ids-bulk-form" class="hidden"></form>' +
        '<div id="ids-bulk-results"></div>';
    pageTitle.insertAdjacentElement('afterend', panel);

    const loading = document.getElementById('ids-bulk-loading');
    const form = document.getElementById('ids-bulk-form');
    const results = document.getElementById('ids-bulk-results');
    let csrf = '';
    let firewalls = [];
    let rulesets = [];

    function esc(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
    }

    function normalizeRuleset(value){
        return String(value || '')
            .toLowerCase()
            .replace(/^et[ _-]*open[\/ _-]*/,'')
            .replace(/\.rules$/,'')
            .trim();
    }

    function firewallChoices(){
        return '<fieldset class="ids-targets"><legend>Target firewalls</legend>' +
            '<label class="checkbox ids-select-all"><input type="checkbox" id="ids-select-all" checked> <span>Select all</span></label>' +
            firewalls.map(function(fw){
                return '<label class="checkbox"><input type="checkbox" name="firewall_ids[]" value="' +
                    Number(fw.id) + '" checked> <span>' + esc(fw.name) + '</span></label>';
            }).join('') +
        '</fieldset>';
    }

    function rulesetPresetControls(){
        return '<div class="ids-ruleset-presets">' +
            '<label>Ruleset filter<input type="search" id="ids-ruleset-filter" placeholder="Filter rulesets…"></label>' +
            '<div class="actions">' +
                '<button type="button" class="button secondary" data-preset="high-confidence">Select high-confidence ET</button>' +
                '<button type="button" class="button warning" data-preset="start-blocking">Select start-blocking set</button>' +
                '<button type="button" class="button secondary" data-preset="avoid">Deselect noisy/avoid set</button>' +
                '<button type="button" class="button secondary" data-preset="clear">Clear selection</button>' +
            '</div>' +
            '<p id="ids-ruleset-preset-status" class="muted"></p>' +
        '</div>';
    }

    function renderForm(){
        let body = firewallChoices();

        if(view === 'administration'){
            body +=
                '<div class="field-grid ids-action-fields">' +
                    '<label>IDS state<select name="enabled">' +
                        '<option value="1">Enabled</option>' +
                        '<option value="0">Disabled</option>' +
                    '</select></label>' +
                    '<label>Capture mode<select name="capture_mode">' +
                        '<option value="keep">Keep current mode</option>' +
                        '<option value="pcap">PCAP live mode (IDS)</option>' +
                        '<option value="netmap">Netmap (IPS)</option>' +
                        '<option value="divert">Divert (IPS)</option>' +
                    '</select></label>' +
                '</div>' +
                '<input type="hidden" name="action" value="set_ids">' +
                '<div class="actions"><button type="submit" class="button warning">Apply IDS settings</button></div>';
        }else{
            body += rulesetPresetControls() +
                '<label>Rulesets<select name="rulesets[]" multiple size="16" class="ids-ruleset-select">' +
                    rulesets.map(function(item){
                        return '<option value="' + esc(item) + '" data-normalized="' + esc(normalizeRuleset(item)) + '">' + esc(item) + '</option>';
                    }).join('') +
                '</select></label>' +
                '<div class="ids-ruleset-actions">' +
                    '<button type="submit" class="button" data-action="toggle_rulesets" data-enabled="1">Enable selected rulesets</button>' +
                    '<button type="submit" class="button secondary" data-action="toggle_rulesets" data-enabled="0">Disable selected rulesets</button>' +
                    '<button type="submit" class="button warning" data-action="update_rules">Download & reload rules</button>' +
                '</div>';
        }

        form.innerHTML = body;
        form.classList.remove('hidden');
        loading.classList.add('hidden');

        const selectAll = document.getElementById('ids-select-all');
        selectAll?.addEventListener('change', function(){
            form.querySelectorAll('input[name="firewall_ids[]"]').forEach(function(box){
                box.checked = selectAll.checked;
            });
        });

        if(view === 'download') bindRulesetPresets();
    }

    function bindRulesetPresets(){
        const select = form.querySelector('.ids-ruleset-select');
        const filter = document.getElementById('ids-ruleset-filter');
        const status = document.getElementById('ids-ruleset-preset-status');
        if(!select || !filter || !status) return;

        function applyPreset(names, selected){
            const wanted = new Set(names);
            let matched = 0;
            Array.from(select.options).forEach(function(option){
                if(wanted.has(option.dataset.normalized || normalizeRuleset(option.value))){
                    option.selected = selected;
                    matched++;
                }
            });
            status.textContent = matched + ' matching ruleset(s) ' + (selected ? 'selected.' : 'deselected.');
        }

        form.querySelectorAll('[data-preset]').forEach(function(button){
            button.addEventListener('click', function(){
                const preset = button.dataset.preset;
                if(preset === 'high-confidence') applyPreset(highConfidence, true);
                if(preset === 'start-blocking') applyPreset(startBlocking, true);
                if(preset === 'avoid') applyPreset(avoidInitially, false);
                if(preset === 'clear'){
                    Array.from(select.options).forEach(option => option.selected = false);
                    status.textContent = 'Ruleset selection cleared.';
                }
            });
        });

        filter.addEventListener('input', function(){
            const query = filter.value.trim().toLowerCase();
            Array.from(select.options).forEach(function(option){
                option.hidden = query !== '' && !option.textContent.toLowerCase().includes(query);
            });
        });
    }

    function collectRulesets(data){
        const found = new Set();
        (data.firewalls || []).forEach(function(fw){
            (fw.rows || []).forEach(function(row){
                if(!row || typeof row !== 'object') return;
                const candidate = row.filename || row.name || row.id || row.ruleset;
                if(candidate) found.add(String(candidate));
            });
        });
        return Array.from(found).sort(function(a,b){return a.localeCompare(b);});
    }

    async function bootstrap(){
        try{
            const [tokenResponse, dataResponse] = await Promise.all([
                fetch('/session_token.php',{credentials:'same-origin',cache:'no-store'}),
                fetch('/intrusion_detection_data.php?view=' + encodeURIComponent(view),{credentials:'same-origin',cache:'no-store'})
            ]);
            const tokenData = await tokenResponse.json();
            const idsData = await dataResponse.json();
            if(!tokenResponse.ok || tokenData.ok !== true) throw new Error(tokenData.error || 'Could not obtain session token.');
            if(!dataResponse.ok || idsData.ok !== true) throw new Error(idsData.error || 'Could not load IDS data.');
            csrf = tokenData.csrf;
            firewalls = (idsData.firewalls || []).map(function(fw){return {id:fw.id,name:fw.name};});
            if(view === 'download') rulesets = collectRulesets(idsData);
            renderForm();
        }catch(error){
            loading.textContent = error.message;
        }
    }

    form.addEventListener('click', function(event){
        const button = event.target.closest('button[type="submit"]');
        if(!button) return;
        form.dataset.clickedAction = button.dataset.action || '';
        form.dataset.clickedEnabled = button.dataset.enabled || '';
    });

    form.addEventListener('submit', async function(event){
        event.preventDefault();
        const payload = new FormData(form);
        payload.set('csrf', csrf);

        if(view === 'download'){
            const action = form.dataset.clickedAction || 'toggle_rulesets';
            payload.set('action', action);
            if(action === 'toggle_rulesets') payload.set('enabled', form.dataset.clickedEnabled || '1');
        }

        const selected = payload.getAll('firewall_ids[]');
        if(!selected.length){
            results.innerHTML = '<div class="alert error">Select at least one firewall.</div>';
            return;
        }

        const actionLabel = payload.get('action') === 'update_rules'
            ? 'download and reload IDS rules'
            : payload.get('action') === 'set_ids'
                ? 'apply these IDS settings'
                : 'change the selected rulesets';
        if(!window.confirm('Confirm: ' + actionLabel + ' on ' + selected.length + ' firewall(s)?')) return;

        form.querySelectorAll('button').forEach(function(button){button.disabled = true;});
        results.innerHTML = '<div class="alert">Applying changes…</div>';

        try{
            const response = await fetch('/intrusion_detection_action.php',{
                method:'POST', credentials:'same-origin', cache:'no-store', body:payload
            });
            const raw = await response.text();
            let data;
            try{data = JSON.parse(raw);}catch(error){throw new Error('Invalid server response: ' + raw.replace(/\s+/g,' ').slice(0,400));}
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'IDS action failed.');
            results.innerHTML = '<div class="table-wrap"><table class="management-table"><thead><tr><th>Firewall</th><th>Status</th><th>Result</th></tr></thead><tbody>' +
                data.results.map(function(item){
                    return '<tr><td><strong>' + esc(item.name) + '</strong></td><td><span class="badge ' +
                        (item.ok ? 'good' : 'bad') + '">' + (item.ok ? 'Success' : 'Failed') +
                        '</span></td><td>' + esc(item.message) + '</td></tr>';
                }).join('') + '</tbody></table></div>';
        }catch(error){
            results.innerHTML = '<div class="alert error">' + esc(error.message) + '</div>';
        }finally{
            form.querySelectorAll('button').forEach(function(button){button.disabled = false;});
        }
    });

    bootstrap();
})();
