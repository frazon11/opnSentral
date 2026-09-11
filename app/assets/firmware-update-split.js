(function(){
    if(location.pathname !== '/system_firmware_status.php') return;

    function ensurePackageMetric(card){
        let metric = card.querySelector('.package-update-metric');
        if(metric) return metric;

        const firmwareMetric = card.querySelector('.vpn-summary-metric');
        if(!firmwareMetric) return null;

        metric = document.createElement('div');
        metric.className = 'vpn-summary-metric package-update-metric';
        metric.innerHTML = '<span class="vpn-summary-label">Plugins / Packages</span><span class="package-update-state badge neutral">Not checked</span>';
        firmwareMetric.insertAdjacentElement('afterend', metric);
        return metric;
    }

    function ensurePackageDetails(card){
        let details = card.querySelector('.package-update-details');
        if(details) return details;

        const firmwareDetails = card.querySelector('.firmware-details');
        if(!firmwareDetails) return null;

        details = document.createElement('div');
        details.className = 'package-update-details firmware-details muted';
        details.hidden = true;
        firmwareDetails.insertAdjacentElement('afterend', details);
        return details;
    }

    function renderSplit(card, summary){
        if(!card || !summary) return;

        const firmwareState = card.querySelector('.firmware-state');
        const packageMetric = ensurePackageMetric(card);
        const packageState = packageMetric?.querySelector('.package-update-state');
        const packageDetails = ensurePackageDetails(card);
        const updateButton = card.querySelector('.firmware-update');

        if(firmwareState){
            const firmwareUpdate = summary.firmware_update_available === true;
            firmwareState.textContent = firmwareUpdate ? 'Update available' : 'Up to date';
            firmwareState.className = 'firmware-state badge ' + (firmwareUpdate ? 'warning' : 'good');
        }

        if(packageState){
            const count = Number(summary.package_update_count || 0);
            packageState.textContent = count > 0
                ? count + (count === 1 ? ' update' : ' updates')
                : 'Up to date';
            packageState.className = 'package-update-state badge ' + (count > 0 ? 'warning' : 'good');
        }

        if(packageDetails){
            const packages = Array.isArray(summary.package_updates) ? summary.package_updates : [];
            if(packages.length){
                packageDetails.hidden = false;
                packageDetails.innerHTML = '<strong>Package updates</strong><div class="package-update-list">' +
                    packages.map(function(pkg){
                        const name = escapeHtml(pkg.name || 'package');
                        const current = escapeHtml(pkg.current || '?');
                        const next = escapeHtml(pkg.new || '?');
                        return '<div><code>' + name + '</code> ' + current + ' → ' + next + '</div>';
                    }).join('') +
                    '</div>';
            }else{
                packageDetails.hidden = true;
                packageDetails.textContent = '';
            }
        }

        if(updateButton && summary.update_available){
            const packageCount = Number(summary.package_update_count || 0);
            if(summary.firmware_update_available && packageCount > 0){
                updateButton.textContent = summary.action === 'firmware_upgrade' ? 'Upgrade all' : 'Update all';
            }else if(!summary.firmware_update_available && packageCount > 0){
                updateButton.textContent = packageCount === 1 ? 'Update package' : 'Update packages';
            }
        }
    }

    function escapeHtml(value){
        const div = document.createElement('div');
        div.textContent = String(value ?? '');
        return div.innerHTML;
    }

    document.querySelectorAll('[data-firewall-id]').forEach(function(card){
        ensurePackageMetric(card);
        ensurePackageDetails(card);
    });

    const originalFetch = window.fetch.bind(window);
    window.fetch = async function(input, init){
        const response = await originalFetch(input, init);

        try{
            const url = typeof input === 'string' ? input : input?.url || '';
            const body = init?.body;
            if(url.includes('/firewall_action.php') && body instanceof URLSearchParams && body.get('action') === 'firmware_check'){
                const firewallId = body.get('id');
                const clone = response.clone();
                clone.json().then(function(data){
                    if(data?.ok !== true || !data?.summary) return;
                    window.setTimeout(function(){
                        const card = document.querySelector('[data-firewall-id="' + CSS.escape(String(firewallId)) + '"]');
                        renderSplit(card, data.summary);
                    }, 0);
                }).catch(function(){});
            }
        }catch(e){}

        return response;
    };
})();
