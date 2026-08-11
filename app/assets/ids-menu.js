(function(){
    'use strict';
    const nav=document.querySelector('#sidebar .side-nav');
    if(!nav||nav.dataset.idsMenuReady==='1') return;
    nav.dataset.idsMenuReady='1';

    const agents=Array.from(nav.children).find(el=>el.matches('a[href="/agents.php"]'));
    if(!agents) return;

    const group=document.createElement('div');
    group.className='nav-group';
    group.textContent='Services';

    const label=document.createElement('div');
    label.className='nav-section-label';
    label.textContent='Intrusion Detection';

    const entries=[
        ['administration','Administration'],
        ['download','Download'],
        ['policies','Policies'],
        ['rules','Rules'],
        ['user-defined','User defined'],
        ['alerts','Alerts'],
        ['schedule','Schedule'],
        ['log-file','Log File']
    ];

    agents.before(group,label);
    entries.forEach(function(entry){
        const link=document.createElement('a');
        link.className='nav-child';
        link.href='/intrusion_detection.php?view='+encodeURIComponent(entry[0]);
        link.innerHTML='<span>'+entry[1]+'</span>';
        if(location.pathname==='/intrusion_detection.php' && new URLSearchParams(location.search).get('view')===entry[0]){
            link.classList.add('active');
        }
        agents.before(link);
    });
})();
