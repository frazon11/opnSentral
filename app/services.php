<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();
require __DIR__ . '/inc/header.php';
?>

<div class="page-title management-page-title">
    <div>
        <h1>Services</h1>
        <p>Service status across all managed OPNsense firewalls.</p>
    </div>

    <div class="management-toolbar">
        <button type="button" class="button secondary" id="services-refresh">
            Refresh
        </button>
    </div>
</div>

<div class="management-overview-bar">
    <div>
        <strong>Service overview</strong>
        <div id="services-summary" class="management-summary">
            Loading services…
        </div>
    </div>
</div>

<div id="services-error" class="alert error hidden"></div>

<div id="services-list" class="service-summary-list">
    <section class="card service-summary-card">
        <p class="muted">Loading…</p>
    </section>
</div>

<script>
(function(){
    const list = document.getElementById('services-list');
    const summary = document.getElementById('services-summary');
    const errorBox = document.getElementById('services-error');
    const refresh = document.getElementById('services-refresh');

    let rendered = false;
    let refreshing = false;

    function escapeHtml(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
    }

    function formatAge(seconds){
        if(seconds === null || seconds === undefined){
            return '';
        }

        if(seconds < 60){
            return seconds + ' sec ago';
        }

        if(seconds < 3600){
            return Math.floor(seconds / 60) + ' min ago';
        }

        return Math.floor(seconds / 3600) + ' h ago';
    }

    function serviceLabel(service){
        return service.description || service.name || 'Unnamed service';
    }

    function renderDetails(services){
        if(!services.length){
            return '<div class="service-details-empty">' +
                'No active services reported.' +
            '</div>';
        }

        return '<div class="service-details-table-wrap">' +
            '<table class="management-table service-details-table">' +
                '<thead>' +
                    '<tr>' +
                        '<th>Service</th>' +
                        '<th>Technical name</th>' +
                        '<th>Status</th>' +
                    '</tr>' +
                '</thead>' +
                '<tbody>' +
                    services.map(function(service){
                        const label = serviceLabel(service);
                        const technical =
                            service.name && service.name !== label
                                ? service.name
                                : '—';

                        return '<tr>' +
                            '<td><strong>' + escapeHtml(label) + '</strong></td>' +
                            '<td><code>' + escapeHtml(technical) + '</code></td>' +
                            '<td><span class="badge good">Running</span></td>' +
                        '</tr>';
                    }).join('') +
                '</tbody>' +
            '</table>' +
        '</div>';
    }

    function render(data){
        const firewalls = Array.isArray(data.firewalls)
            ? data.firewalls
            : [];

        const activeTotal = firewalls.reduce(
            (sum, item) => sum + Number(item.active_count || 0),
            0
        );

        const reachable = firewalls.filter(
            item => item.ok === true
        ).length;

        summary.textContent =
            activeTotal + ' active services across ' +
            reachable + ' of ' + firewalls.length + ' firewalls' +
            (
                data.cache?.age !== null &&
                data.cache?.age !== undefined
                    ? ' · updated ' + formatAge(data.cache.age)
                    : ''
            );

        if(!firewalls.length){
            list.innerHTML =
                '<section class="card service-summary-card">' +
                    '<p class="muted">No firewalls configured.</p>' +
                '</section>';
            rendered = true;
            return;
        }

        list.innerHTML = firewalls.map(function(firewall){
            const services = Array.isArray(firewall.active_services)
                ? firewall.active_services
                : [];

            const statusBadge = firewall.ok
                ? '<span class="badge good">Online</span>'
                : '<span class="badge bad">Unavailable</span>';

            const serviceBadge = firewall.ok
                ? '<span class="badge neutral">' +
                    Number(firewall.active_count || 0) +
                    ' active services</span>'
                : '';

            const details = firewall.ok
                ? renderDetails(services)
                : '<div class="alert error service-details-error">' +
                    escapeHtml(firewall.error || 'Unavailable') +
                  '</div>';

            return '<section class="card service-summary-card">' +
                '<div class="service-summary-main">' +
                    '<div class="service-summary-identity">' +
                        '<div>' +
                            '<h2>' + escapeHtml(firewall.name) + '</h2>' +
                            '<a class="muted" target="_blank" rel="noopener" ' +
                                'href="' + escapeHtml(firewall.base_url) + '">' +
                                escapeHtml(firewall.base_url) +
                            '</a>' +
                        '</div>' +
                    '</div>' +

                    '<div class="service-summary-metric">' +
                        '<span class="service-summary-label">Status</span>' +
                        statusBadge +
                    '</div>' +

                    '<div class="service-summary-metric">' +
                        '<span class="service-summary-label">Services</span>' +
                        (
                            serviceBadge ||
                            '<span class="muted">Unavailable</span>'
                        ) +
                    '</div>' +

                    '<div class="service-summary-actions">' +
                        '<button type="button" ' +
                            'class="button secondary service-details-toggle" ' +
                            'aria-expanded="false">' +
                            'Details' +
                        '</button>' +
                    '</div>' +
                '</div>' +

                '<div class="service-details-panel" hidden>' +
                    '<div class="service-details-header">' +
                        '<strong>Services on ' +
                            escapeHtml(firewall.name) +
                        '</strong>' +
                        '<span class="muted">' +
                            Number(firewall.active_count || 0) +
                            ' active' +
                        '</span>' +
                    '</div>' +
                    details +
                '</div>' +
            '</section>';
        }).join('');

        list.querySelectorAll('.service-details-toggle').forEach(
            function(button){
                button.addEventListener('click', function(){
                    const card = button.closest('.service-summary-card');
                    const panel = card.querySelector(
                        '.service-details-panel'
                    );
                    const expanded =
                        button.getAttribute('aria-expanded') === 'true';

                    button.setAttribute(
                        'aria-expanded',
                        expanded ? 'false' : 'true'
                    );
                    button.textContent = expanded
                        ? 'Details'
                        : 'Hide details';
                    panel.hidden = expanded;
                    card.classList.toggle(
                        'service-summary-expanded',
                        !expanded
                    );
                });
            }
        );

        rendered = true;
    }

    async function requestData(force){
        const response = await fetch(
            '/services_data.php' + (force ? '?force=1' : ''),
            {
                credentials: 'same-origin',
                cache: 'no-store'
            }
        );

        const raw = await response.text();
        let data;

        try{
            data = JSON.parse(raw);
        }catch(parseError){
            throw new Error(
                'Server returned invalid JSON: ' +
                raw.replace(/\s+/g, ' ').trim().slice(0, 500)
            );
        }

        if(!response.ok || data.ok !== true){
            throw new Error(
                data.error || 'Could not load services.'
            );
        }

        return data;
    }

    async function refreshLive(manual){
        if(refreshing){
            return;
        }

        refreshing = true;

        const original = refresh.textContent;
        refresh.disabled = true;
        refresh.textContent = manual
            ? 'Refreshing…'
            : 'Updating…';

        try{
            const data = await requestData(true);
            render(data);
            errorBox.classList.add('hidden');
            errorBox.textContent = '';
        }catch(error){
            if(manual || !rendered){
                errorBox.textContent = error.message;
                errorBox.classList.remove('hidden');
            }
        }finally{
            refresh.disabled = false;
            refresh.textContent = original;
            refreshing = false;
        }
    }

    async function loadInitial(){
        refresh.disabled = true;

        try{
            const data = await requestData(false);
            render(data);

            if(data.cache?.refresh_recommended){
                window.setTimeout(
                    () => refreshLive(false),
                    150
                );
            }
        }catch(error){
            summary.textContent = 'Services unavailable';
            list.innerHTML =
                '<section class="card service-summary-card">' +
                    '<p class="muted">Could not load services.</p>' +
                '</section>';

            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
        }finally{
            refresh.disabled = false;
        }
    }

    refresh.addEventListener(
        'click',
        () => refreshLive(true)
    );

    loadInitial();
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
