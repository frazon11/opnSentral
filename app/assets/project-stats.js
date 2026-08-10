(function(){
    'use strict';

    const path = window.location.pathname;
    if(path !== '/' && path !== '/index.php') return;

    function presentationEnabled(){
        if(typeof window.opnSentralPresentationEnabled === 'function'){
            return window.opnSentralPresentationEnabled() === true;
        }
        return localStorage.getItem('opnsentral-presentation-mode') === '1';
    }

    if(presentationEnabled()) return;

    const dashboard = document.getElementById('firewall-dashboard');
    if(!dashboard) return;

    const style = document.createElement('style');
    style.textContent = `
        .project-stats-panel{margin:0 0 18px}
        .project-stats-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;margin-bottom:12px}
        .project-stats-head h2{margin:0 0 3px}
        .project-stats-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}
        .project-stat{padding:13px;border:1px solid rgba(127,127,127,.24);border-radius:8px;background:rgba(127,127,127,.06)}
        .project-stat-label{font-size:.78rem;color:var(--muted);margin-bottom:5px}
        .project-stat-value{font-size:1.45rem;font-weight:750;line-height:1.1}
        .project-stat-note{font-size:.72rem;color:var(--muted);margin-top:4px}
        .project-stats-warning{margin-top:10px;font-size:.82rem;color:var(--muted)}
        @media(max-width:1100px){.project-stats-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
        @media(max-width:620px){.project-stats-grid{grid-template-columns:1fr}}
    `;
    document.head.appendChild(style);

    const panel = document.createElement('section');
    panel.className = 'card project-stats-panel';
    panel.setAttribute('data-presentation-exempt', 'true');
    panel.innerHTML = `
        <div class="project-stats-head">
            <div>
                <h2>Project usage</h2>
                <div class="muted">Docker Hub lifetime pulls and GitHub traffic for the last 14 days.</div>
            </div>
        </div>
        <div class="project-stats-grid">
            <div class="project-stat"><div class="project-stat-label">Docker Hub pulls</div><div class="project-stat-value" data-stat="docker-pulls">…</div><div class="project-stat-note">Lifetime repository pulls</div></div>
            <div class="project-stat"><div class="project-stat-label">GitHub views</div><div class="project-stat-value" data-stat="github-views">…</div><div class="project-stat-note">Total page views</div></div>
            <div class="project-stat"><div class="project-stat-label">Unique visitors</div><div class="project-stat-value" data-stat="github-unique-views">…</div><div class="project-stat-note">GitHub unique visitors</div></div>
            <div class="project-stat"><div class="project-stat-label">GitHub clones</div><div class="project-stat-value" data-stat="github-clones">…</div><div class="project-stat-note">Full repository clones</div></div>
            <div class="project-stat"><div class="project-stat-label">Unique cloners</div><div class="project-stat-value" data-stat="github-unique-clones">…</div><div class="project-stat-note">GitHub unique cloners</div></div>
        </div>
        <div class="project-stats-warning" data-stat="message"></div>
    `;

    dashboard.parentNode.insertBefore(panel, dashboard);

    const fmt = new Intl.NumberFormat();
    function set(name, value){
        const el = panel.querySelector('[data-stat="' + name + '"]');
        if(el) el.textContent = value === null || value === undefined ? '—' : fmt.format(value);
    }

    fetch('/project_stats.php', {credentials:'same-origin', cache:'no-store'})
        .then(function(response){
            return response.json().then(function(data){
                if(!response.ok) throw new Error(data.error || ('HTTP ' + response.status));
                return data;
            });
        })
        .then(function(data){
            set('docker-pulls', data.docker_hub?.pulls);
            set('github-views', data.github?.views?.count);
            set('github-unique-views', data.github?.views?.uniques);
            set('github-clones', data.github?.clones?.count);
            set('github-unique-clones', data.github?.clones?.uniques);

            const message = panel.querySelector('[data-stat="message"]');
            if(!data.github?.configured){
                message.textContent = 'GitHub traffic is not configured. Set GITHUB_TRAFFIC_TOKEN to enable views and unique clone statistics.';
            }else if(data.github?.error){
                message.textContent = 'GitHub traffic unavailable: ' + data.github.error;
            }else if(data.docker_hub?.error){
                message.textContent = 'Docker Hub statistics unavailable: ' + data.docker_hub.error;
            }else{
                message.textContent = '';
            }
        })
        .catch(function(error){
            const message = panel.querySelector('[data-stat="message"]');
            if(message) message.textContent = 'Project statistics unavailable: ' + error.message;
            panel.querySelectorAll('.project-stat-value').forEach(function(el){el.textContent='—';});
        });
})();
