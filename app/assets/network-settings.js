(function(){
    'use strict';

    if(location.pathname !== '/settings.php') return;

    const grid = document.getElementById('opnsense-settings-grid');
    if(!grid || document.getElementById('opnsense-network-settings')) return;

    const card = document.createElement('section');
    card.className = 'card';
    card.id = 'opnsense-network-settings';
    card.innerHTML = `
        <h2>Network connections</h2>
        <p class="muted">Control how opnSentral connects to managed OPNsense firewalls.</p>
        <form method="post" action="/network_settings_action.php">
            <input type="hidden" name="csrf" value="">
            <label class="checkbox">
                <input type="checkbox" name="disable_ipv6" value="1" id="opnsense-disable-ipv6">
                Disable IPv6 for OPNsense connections (force IPv4)
            </label>
            <p class="muted">When enabled, OPNsense API, parallel inventory and backup connections use IPv4 only.</p>
            <button type="submit">Save network settings</button>
        </form>
        <div id="opnsense-network-settings-message" class="card-message"></div>`;

    grid.appendChild(card);

    const csrfSource = document.querySelector('input[name="csrf"]');
    const csrfTarget = card.querySelector('input[name="csrf"]');
    if(csrfSource && csrfTarget) csrfTarget.value = csrfSource.value;

    const checkbox = document.getElementById('opnsense-disable-ipv6');
    const message = document.getElementById('opnsense-network-settings-message');

    fetch('/network_settings_status.php', {credentials:'same-origin', cache:'no-store'})
        .then(response => response.json())
        .then(result => {
            if(!result.ok) throw new Error(result.error || 'Could not load network settings.');
            checkbox.checked = result.disable_ipv6 === true;
        })
        .catch(error => {
            message.textContent = error.message;
        });

    const url = new URL(location.href);
    if(url.searchParams.has('network_settings_saved')){
        message.textContent = 'Network settings saved.';
    }else if(url.searchParams.has('network_settings_error')){
        message.textContent = url.searchParams.get('network_settings_error') || 'Could not save network settings.';
    }
})();
