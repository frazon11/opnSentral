(function(){
    const path=location.pathname;
    const csrf=String(window.opnSentralCsrf||document.querySelector('input[name="csrf"]')?.value||'');

    function setToggle(button,enabled){
        button.dataset.enabled=enabled?'1':'0';
        button.textContent='Notifications: '+(enabled?'On':'Off');
        button.classList.toggle('warning',!enabled);
        button.classList.toggle('secondary',enabled);
        button.title=enabled
            ? 'Notifications are enabled for this managed firewall. Click to disable.'
            : 'Notifications are disabled for this managed firewall. Click to enable.';
    }

    async function readOne(id){
        const response=await fetch('/firewall_notifications_action.php?id='+encodeURIComponent(id),{credentials:'same-origin',cache:'no-store'});
        const data=await response.json();
        if(!response.ok||data.ok!==true)throw new Error(data.error||'Could not read notification state.');
        return data.firewall;
    }

    async function writeOne(id,enabled){
        const body=new URLSearchParams();
        body.set('csrf',csrf);body.set('id',String(id));body.set('enabled',enabled?'1':'0');
        const response=await fetch('/firewall_notifications_action.php',{
            method:'POST',credentials:'same-origin',cache:'no-store',
            headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body
        });
        const data=await response.json();
        if(!response.ok||data.ok!==true)throw new Error(data.error||'Could not change notification state.');
        return data.firewall;
    }

    function bindToggle(button,id){
        button.addEventListener('click',async()=>{
            if(!csrf){alert('Could not find CSRF token.');return;}
            const current=button.dataset.enabled==='1';
            const next=!current;
            if(!confirm((next?'Enable':'Disable')+' notifications for this firewall?'))return;
            button.disabled=true;
            try{
                const state=await writeOne(id,next);
                document.querySelectorAll('[data-notification-firewall-id="'+id+'"]').forEach(item=>setToggle(item,state.notifications_enabled===true));
            }catch(error){alert(error instanceof Error?error.message:String(error));}
            finally{button.disabled=false;}
        });
    }

    async function enhanceDashboard(){
        const cards=[...document.querySelectorAll('.firewall-card[data-firewall-id]')];
        for(const card of cards){
            const id=Number(card.dataset.firewallId||0);if(!id)continue;
            const actions=card.querySelector('.actions');
            if(actions){
                actions.querySelectorAll('a[href^="/firewall_view.php?id="]').forEach(details=>{
                    details.textContent='Manage';
                    details.title='Open live status and operational controls';
                });
                actions.querySelectorAll('a[href^="/firewall_edit.php?id="]').forEach(edit=>{
                    edit.textContent='Connection settings';
                    edit.title='Edit the opnSentral connection and credentials for this firewall';
                });
            }

            if(!actions||actions.querySelector('[data-notification-firewall-id]'))continue;
            const toggle=document.createElement('button');
            toggle.type='button';toggle.className='button secondary notification-toggle';
            toggle.dataset.notificationFirewallId=String(id);toggle.textContent='Notifications: …';toggle.disabled=true;
            actions.appendChild(toggle);
            bindToggle(toggle,id);
            try{const state=await readOne(id);setToggle(toggle,state.notifications_enabled===true);}catch(error){toggle.textContent='Notifications: ?';toggle.title=error instanceof Error?error.message:String(error);}
            toggle.disabled=false;
        }
    }

    function enhanceManagePage(){
        const remove=document.querySelector('form.danger-zone button[name="action"][value="delete"]');
        if(!remove)return;
        remove.textContent='Remove from opnSentral';
        remove.title='Remove only this managed-firewall record from opnSentral';
        remove.onclick=function(){
            const name=document.querySelector('.page-title h1')?.textContent?.trim()||'this firewall';
            return confirm('Remove “'+name+'” from opnSentral management?\n\nThis removes only the opnSentral record. It does not modify or delete the OPNsense firewall itself.');
        };
    }

    async function enhanceNotificationsPage(){
        const recent=[...document.querySelectorAll('section.card h2')].find(h=>h.textContent.trim().toLowerCase().includes('recent'))?.closest('section.card');
        if(!recent)return;
        const section=document.createElement('section');section.className='card';section.style.marginTop='18px';
        section.innerHTML='<h2>Managed firewalls</h2><p class="muted">Enable or disable opnSentral alert notifications independently for each firewall.</p><div data-notification-list>Loading…</div>';
        recent.parentNode.insertBefore(section,recent);
        const list=section.querySelector('[data-notification-list]');
        try{
            const response=await fetch('/firewall_notifications_action.php',{credentials:'same-origin',cache:'no-store'});
            const data=await response.json();if(!response.ok||data.ok!==true)throw new Error(data.error||'Could not read firewall notification settings.');
            const firewalls=Array.isArray(data.firewalls)?data.firewalls:[];
            if(!firewalls.length){list.innerHTML='<p class="muted">No managed firewalls.</p>';return;}
            list.innerHTML='';
            firewalls.forEach(fw=>{
                const row=document.createElement('div');row.style.cssText='display:flex;align-items:center;justify-content:space-between;gap:16px;padding:10px 0;border-top:1px solid var(--border,rgba(127,127,127,.25))';
                const name=document.createElement('strong');name.textContent=fw.name;
                const button=document.createElement('button');button.type='button';button.className='button secondary';button.dataset.notificationFirewallId=String(fw.id);setToggle(button,fw.notifications_enabled===true);bindToggle(button,Number(fw.id));
                row.append(name,button);list.appendChild(row);
            });
        }catch(error){list.innerHTML='<div class="alert error"></div>';list.firstElementChild.textContent=error instanceof Error?error.message:String(error);}
    }

    if(path==='/'||path==='/index.php')enhanceDashboard();
    if(path==='/firewall_view.php')enhanceManagePage();
    if(path==='/notifications.php')enhanceNotificationsPage();
})();
