(function(){
    const root=document.querySelector('[data-fleet-settings-scope]');
    if(!root)return;
    const scope=root.dataset.fleetSettingsScope;
    const csrf=root.dataset.csrf||'';
    const apply=document.getElementById('fleet-settings-apply');
    const reset=document.getElementById('fleet-settings-reset');
    const result=document.getElementById('fleet-settings-result');
    const controls=Array.from(document.querySelectorAll('.fleet-setting-control'));

    function valueOf(control){return control.type==='checkbox'?control.checked:String(control.value);}
    function initialOf(control){return control.type==='checkbox'?control.dataset.initial==='1':String(control.dataset.initial||'');}
    function isDirty(control){return !control.disabled && valueOf(control)!==initialOf(control);}
    function refresh(){
        let dirty=false;
        controls.forEach(control=>{const d=isDirty(control);dirty=dirty||d;control.closest('.fleet-value')?.classList.toggle('dirty',d);});
        if(apply)apply.disabled=!dirty;
        if(reset)reset.disabled=!dirty;
    }
    controls.forEach(control=>control.addEventListener('change',refresh));
    controls.filter(c=>c.type!=='checkbox').forEach(control=>control.addEventListener('input',refresh));

    document.querySelectorAll('.fleet-row-all').forEach(all=>{
        const row=all.closest('tr[data-setting]');
        if(!row)return;
        const targets=()=>Array.from(row.querySelectorAll('.fleet-setting-control:not(:disabled)'));
        all.addEventListener(all.type==='checkbox'?'change':'input',()=>{
            const list=targets();
            if(all.type==='checkbox')list.forEach(control=>{control.checked=all.checked;});
            else list.forEach(control=>{control.value=all.value;});
            refresh();
        });
    });

    reset?.addEventListener('click',()=>{
        controls.forEach(control=>{if(control.disabled)return;if(control.type==='checkbox')control.checked=control.dataset.initial==='1';else control.value=control.dataset.initial||'';});
        document.querySelectorAll('.fleet-row-all').forEach(all=>{if(all.type==='checkbox'){all.checked=false;all.indeterminate=false;}else all.value='';});
        refresh();
    });

    function escapeHtml(value){const div=document.createElement('div');div.textContent=String(value??'');return div.innerHTML;}
    async function poll(jobs){
        const ids=jobs.map(j=>j.job_id).filter(Boolean);if(!ids.length)return;
        const deadline=Date.now()+120000;
        while(Date.now()<deadline){
            await new Promise(r=>setTimeout(r,1500));
            const response=await fetch('/system_administration_matrix_status.php?ids='+encodeURIComponent(ids.join(',')),{credentials:'same-origin',cache:'no-store'});
            const data=await response.json();if(!response.ok||data.ok!==true)throw new Error(data.error||'Could not read deployment status.');
            const byId=new Map((data.jobs||[]).map(j=>[Number(j.id),j]));let pending=false,failed=false;
            jobs.forEach(item=>{const job=byId.get(Number(item.job_id));if(!job){pending=true;return;}if(!['completed','failed'].includes(String(job.status||'')))pending=true;if(job.status==='failed')failed=true;});
            if(!pending){
                result.className='alert '+(failed?'warningbox':'goodbox');
                result.textContent=failed?'Deployment finished with errors. Refreshing…':'Deployment finished successfully. Refreshing…';
                setTimeout(()=>location.reload(),900);return;
            }
        }
        result.className='alert warningbox';result.textContent='Jobs are still queued or running. Refresh later to see the current values.';
    }

    apply?.addEventListener('click',async()=>{
        const changed=controls.filter(isDirty);
        if(!changed.length)return;
        const changes=changed.map(control=>({firewall_id:Number(control.dataset.firewallId),setting:String(control.dataset.setting),value:valueOf(control)}));
        const firewallCount=new Set(changes.map(c=>c.firewall_id)).size;
        if(!confirm('Apply '+changes.length+' setting change'+(changes.length===1?'':'s')+' to '+firewallCount+' firewall'+(firewallCount===1?'':'s')+'?\n\nA pre-change backup will be created for every target.'))return;
        apply.disabled=true;reset.disabled=true;result.className='alert warningbox';result.textContent='Creating backups and queueing deployment…';
        try{
            const body=new URLSearchParams();body.set('csrf',csrf);body.set('scope',scope);body.set('changes',JSON.stringify(changes));
            const response=await fetch('/fleet_settings_action.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
            const data=await response.json();if(!response.ok||data.ok!==true)throw new Error(data.error||'Could not queue deployment.');
            const jobs=Array.isArray(data.jobs)?data.jobs:[];const failures=Array.isArray(data.failures)?data.failures:[];
            if(failures.length){result.className='alert warningbox';result.innerHTML='<strong>Some targets could not be queued:</strong><br>'+failures.map(f=>escapeHtml(f.firewall_name+': '+f.error)).join('<br>');}
            if(jobs.length)await poll(jobs);else if(failures.length===0)throw new Error('No deployment jobs were created.');
        }catch(error){result.className='alert error';result.textContent=error instanceof Error?error.message:String(error);apply.disabled=false;reset.disabled=false;}
    });
    refresh();
})();
