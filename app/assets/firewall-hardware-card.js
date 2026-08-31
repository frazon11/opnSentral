(function(){
    const path=location.pathname;
    if(path!=='/'&&path!=='/index.php')return;

    function bytes(value){
        const n=Number(value||0);
        if(!Number.isFinite(n)||n<=0)return '—';
        const gib=n/1073741824;
        if(gib>=1)return (gib>=100?gib.toFixed(0):gib.toFixed(1)).replace(/\.0$/,'')+' GB';
        const mib=n/1048576;
        return (mib>=100?mib.toFixed(0):mib.toFixed(1)).replace(/\.0$/,'')+' MB';
    }

    function clean(parts){
        return parts.map(v=>String(v??'').trim()).filter(v=>v&&v!=='—').join(' ');
    }

    function hardwareLabel(hw){
        const system=hw.system||{};
        let label=clean([system.manufacturer,system.model]);
        const rev=String(system.revision||'').trim();
        if(rev)label+=(label?' · ':'')+'Rev. '+rev;
        return label||'—';
    }

    function cpuLabel(hw){
        const cpu=hw.cpu||{};
        const model=String(cpu.model||'').trim();
        const cores=Number(cpu.cores||0);
        const logical=Number(cpu.logical_cpus||0);
        let suffix='';
        if(cores>0&&logical>0)suffix=cores+'C / '+logical+'T';
        else if(logical>0)suffix=logical+' thread'+(logical===1?'':'s');
        return clean([model,suffix])||'—';
    }

    function storageLabel(hw){
        const disks=Array.isArray(hw.disks)?hw.disks:[];
        if(!disks.length)return '—';
        const list=disks.slice(0,4).map(d=>{
            const size=bytes(d.size_bytes);
            const model=String(d.model||'').trim();
            const name=String(d.name||'').trim();
            return clean([size,model||name]);
        }).filter(Boolean);
        return list.join(' + ')||'—';
    }

    function ensurePanel(card){
        let panel=card.querySelector('.hardware-card-summary');
        if(panel)return panel;
        panel=document.createElement('dl');
        panel.className='hardware-card-summary';
        panel.innerHTML='<dt>Hardware</dt><dd data-hardware>Loading…</dd><dt>CPU</dt><dd data-cpu>Loading…</dd><dt>RAM</dt><dd data-ram>Loading…</dd><dt>Storage</dt><dd data-storage>Loading…</dd>';
        const system=card.querySelector('dl');
        if(system)system.insertAdjacentElement('afterend',panel);
        else card.querySelector('.card-head')?.insertAdjacentElement('afterend',panel);
        return panel;
    }

    async function load(card){
        const id=Number(card.dataset.firewallId||0);if(!id)return;
        const panel=ensurePanel(card);
        try{
            const response=await fetch('/firewall_hardware.php?id='+encodeURIComponent(id),{credentials:'same-origin',cache:'no-store'});
            const data=await response.json();
            if(!response.ok||data.ok!==true)throw new Error(data.error||'Hardware inventory unavailable.');
            const hw=data.hardware||{};
            const availability=hw.availability||{};

            panel.querySelector('[data-hardware]').textContent=availability.dmidecode===true
                ? hardwareLabel(hw)
                : 'Install os-dmidecode';
            panel.querySelector('[data-cpu]').textContent=availability.cpu===true
                ? cpuLabel(hw)
                : 'Unavailable';
            panel.querySelector('[data-ram]').textContent=availability.memory===true
                ? bytes(hw.memory?.total_bytes)
                : 'Unavailable';
            panel.querySelector('[data-storage]').textContent=availability.smart===true
                ? storageLabel(hw)
                : 'Install os-smart';

            const notes=[];
            if(availability.dmidecode!==true)notes.push('Hardware manufacturer/model/revision requires the official OPNsense os-dmidecode plugin.');
            if(availability.cpu!==true)notes.push('CPU information could not be read from the OPNsense core CPU API.');
            if(availability.memory!==true)notes.push('RAM information could not be read from the OPNsense core system-resources API.');
            if(availability.smart!==true)notes.push('Physical disk model/capacity requires the official OPNsense os-smart plugin.');
            panel.classList.toggle('hardware-fallback',notes.length>0);
            panel.title=notes.length?notes.join(' '):'Hardware data from official OPNsense APIs: os-dmidecode, core CPU/resources and os-smart.';
        }catch(error){
            panel.querySelectorAll('dd').forEach(dd=>dd.textContent='Unavailable');
            panel.title=error instanceof Error?error.message:String(error);
        }
    }

    document.querySelectorAll('.firewall-card[data-firewall-id]').forEach(load);
})();
