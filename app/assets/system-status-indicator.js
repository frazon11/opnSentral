(function(){
    'use strict';

    function classifyStatus(status){
        const value=String(status??'').trim().toLowerCase();
        if(value===''||['ok','success','normal','none','green'].includes(value)) return 'ok';
        if(value.includes('warn')||value.includes('notice')||value.includes('orange')||value.includes('yellow')) return 'warning';
        return 'bad';
    }

    function statusLabel(status){
        const cls=classifyStatus(status);
        if(cls==='ok') return 'No pending system messages';
        if(cls==='warning') return 'OPNsense system warning';
        return 'OPNsense system problem detected';
    }

    async function fetchSystemStatus(id){
        const response=await fetch('/firewall_status.php?id='+encodeURIComponent(id)+'&type=system',{credentials:'same-origin',cache:'no-store'});
        const text=await response.text();
        let result;
        try{result=JSON.parse(text);}catch(error){throw new Error('Invalid system status response');}
        if(!response.ok||result?.ok!==true) throw new Error(result?.error||('HTTP '+response.status));
        const payload=result?.data?.system;
        if(!payload||payload.ok!==true) throw new Error(payload?.error||'System status unavailable');
        return payload.value||{};
    }

    function highestStatus(data){
        const system=data?.metadata?.system||{};
        const subsystems=data?.subsystems&&typeof data.subsystems==='object'?data.subsystems:{};
        let status=system.status??'';
        let message=String(system.message??'').trim();
        let title=String(system.title??'System').trim()||'System';

        const entries=Object.values(subsystems).filter(item=>item&&typeof item==='object');
        const nonOk=entries.find(item=>classifyStatus(item.status)!=='ok');
        if(nonOk){
            status=nonOk.status??status;
            title=String(nonOk.title??title).trim()||title;
            message=String(nonOk.message??message).trim()||message;
        }
        return {status,title,message};
    }

    function addDashboardLed(card){
        const head=card.querySelector('.card-head');
        if(!head||head.querySelector('.opnsentral-system-led')) return null;
        const existingBadge=head.querySelector('.status-badge');
        const wrap=document.createElement('div');
        wrap.className='opnsentral-system-indicator-wrap';
        const led=document.createElement('span');
        led.className='opnsentral-system-led loading';
        led.setAttribute('role','img');
        led.setAttribute('aria-label','Loading OPNsense system status');
        led.title='Loading OPNsense system status…';
        if(existingBadge){
            existingBadge.parentNode.insertBefore(wrap,existingBadge);
            wrap.append(existingBadge,led);
        }else{
            head.appendChild(wrap);
            wrap.appendChild(led);
        }
        return led;
    }

    async function loadDashboardLed(card){
        const id=card.dataset.firewallId;
        const led=addDashboardLed(card)||card.querySelector('.opnsentral-system-led');
        if(!id||!led) return;
        led.className='opnsentral-system-led loading';
        try{
            const data=await fetchSystemStatus(id);
            const top=highestStatus(data);
            const cls=classifyStatus(top.status);
            led.className='opnsentral-system-led '+cls;
            const description=(top.title&&top.title!=='System'?top.title+': ':'')+(top.message||statusLabel(top.status));
            led.title=description;
            led.setAttribute('aria-label',description);
        }catch(error){
            led.className='opnsentral-system-led bad';
            led.title='System status unavailable: '+error.message;
            led.setAttribute('aria-label',led.title);
        }
    }

    function renderDetails(data){
        const systemPanel=document.getElementById('system-state')?.closest('.firewall-opn-panel');
        if(!systemPanel||systemPanel.querySelector('.opnsentral-system-notifications')) return;

        const details=document.createElement('details');
        details.className='firewall-opn-section opnsentral-system-notifications';
        const summary=document.createElement('summary');
        summary.textContent='System notifications / Reporter';
        details.appendChild(summary);
        const body=document.createElement('div');
        details.appendChild(body);

        const subsystems=data?.subsystems&&typeof data.subsystems==='object'?Object.values(data.subsystems):[];
        const items=subsystems.filter(item=>item&&typeof item==='object');

        if(items.length===0){
            const empty=document.createElement('div');
            empty.className='opnsentral-system-notification-empty';
            empty.textContent='No pending system notifications.';
            body.appendChild(empty);
        }else{
            items.forEach(item=>{
                const row=document.createElement('div');
                row.className='opnsentral-system-notification';
                const head=document.createElement('div');
                head.className='opnsentral-system-notification-head';
                const led=document.createElement('span');
                led.className='opnsentral-system-led '+classifyStatus(item.status);
                const title=document.createElement('span');
                title.className='opnsentral-system-notification-title';
                title.textContent=String(item.title||'System notification');
                head.append(led,title);
                row.appendChild(head);
                const message=document.createElement('div');
                message.className='opnsentral-system-notification-message';
                message.textContent=String(item.message||'No details returned.');
                row.appendChild(message);
                if(item.age){
                    const age=document.createElement('div');
                    age.className='opnsentral-system-notification-age';
                    age.textContent=String(item.age);
                    row.appendChild(age);
                }
                body.appendChild(row);
            });
        }

        const firstSection=systemPanel.querySelector('.firewall-opn-section');
        if(firstSection) firstSection.insertAdjacentElement('beforebegin',details);
        else systemPanel.appendChild(details);

        if(items.some(item=>classifyStatus(item.status)!=='ok')) details.open=true;
    }

    async function initDetails(){
        if(!document.getElementById('system-state')) return;
        const id=new URLSearchParams(location.search).get('id');
        if(!id) return;
        try{renderDetails(await fetchSystemStatus(id));}catch(error){
            renderDetails({subsystems:{opnsentral:{status:'error',title:'System status',message:'Could not load reporter details: '+error.message}}});
        }
    }

    document.querySelectorAll('.firewall-card[data-firewall-id]').forEach(loadDashboardLed);
    initDetails();
})();
