(function(){
    'use strict';

    if(!['/aliases.php','/categories.php'].includes(location.pathname)) return;

    const successNodes = [
        ...document.querySelectorAll('.results .result.good'),
        ...document.querySelectorAll('.result-list .result-item.ok')
    ];
    const failureNodes = [
        ...document.querySelectorAll('.results .result.bad'),
        ...document.querySelectorAll('.result-list .result-item.bad')
    ];

    if(successNodes.length === 0 && failureNodes.length === 0) return;

    const style = document.createElement('style');
    style.textContent = `
        .deployment-result-badge{display:inline-block;margin:0 0 6px 8px;padding:3px 8px;border-radius:3px;font-size:.78rem;font-weight:700;vertical-align:middle}
        .deployment-result-badge.success{background:#d9f0df;color:#21723a}
        .deployment-result-badge.failure{background:#f6dddd;color:#9c2929}
        .deployment-summary{margin:0 0 14px;padding:12px 14px;border:1px solid var(--border);background:var(--soft);border-radius:3px}
        .deployment-summary strong{display:block;margin-bottom:3px}
        :root[data-theme="dark"] .deployment-result-badge.success{background:#1f4a2d;color:#a9e5ba}
        :root[data-theme="dark"] .deployment-result-badge.failure{background:#542a2a;color:#ffb5b5}
    `;
    document.head.appendChild(style);

    function addBadge(node, successful){
        const strong = node.querySelector('strong');
        if(!strong || node.querySelector('.deployment-result-badge')) return;
        const badge = document.createElement('span');
        badge.className = 'deployment-result-badge ' + (successful ? 'success' : 'failure');
        badge.textContent = successful ? 'Successfully deployed' : 'Deployment failed';
        strong.insertAdjacentElement('afterend', badge);
    }

    successNodes.forEach(node => addBadge(node, true));
    failureNodes.forEach(node => addBadge(node, false));

    const container = document.querySelector('.results, .result-list');
    if(!container) return;

    const summary = document.createElement('div');
    summary.className = 'deployment-summary';

    if(failureNodes.length === 0){
        summary.innerHTML = '<strong>Deployment successful</strong>' +
            successNodes.length + ' firewall' + (successNodes.length === 1 ? '' : 's') +
            ' updated successfully.';
    }else if(successNodes.length === 0){
        summary.innerHTML = '<strong>Deployment failed</strong>No target firewall was updated successfully.';
    }else{
        summary.innerHTML = '<strong>Deployment partially successful</strong>' +
            successNodes.length + ' succeeded, ' + failureNodes.length + ' failed.';
    }

    container.parentNode.insertBefore(summary, container);
})();
