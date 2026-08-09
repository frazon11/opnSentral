(function(){
    'use strict';

    if(location.pathname !== '/aliases.php') return;

    const typeSelect = document.querySelector('select[name="type"]');
    const content = document.querySelector('textarea[name="content"]');
    if(!typeSelect || !content) return;

    if(!typeSelect.querySelector('option[value="geoip"]')){
        const option = document.createElement('option');
        option.value = 'geoip';
        option.textContent = 'GeoIP';

        const networkGroup = typeSelect.querySelector('option[value="networkgroup"]');
        if(networkGroup) typeSelect.insertBefore(option, networkGroup);
        else typeSelect.appendChild(option);
    }

    const defaultPlaceholder = content.getAttribute('placeholder') || 'One value per line';

    function updateGeoIpHelp(){
        const geoip = typeSelect.value === 'geoip';
        content.placeholder = geoip
            ? 'Country codes, one per line (e.g. BE, DE, NL)'
            : defaultPlaceholder;

        let help = document.getElementById('alias-geoip-help');
        if(geoip){
            if(!help){
                help = document.createElement('p');
                help.id = 'alias-geoip-help';
                help.className = 'muted';
                help.textContent = 'GeoIP aliases use ISO country codes as content, one code per line.';
                content.insertAdjacentElement('afterend', help);
            }
            help.hidden = false;
        }else if(help){
            help.hidden = true;
        }
    }

    typeSelect.addEventListener('change', updateGeoIpHelp);
    updateGeoIpHelp();
})();
