(function(){
    const root=document.querySelector('[data-fleet-settings-scope]');
    if(!root)return;
    const apply=document.getElementById('fleet-settings-apply');
    const reset=document.getElementById('fleet-settings-reset');
    const result=document.getElementById('fleet-settings-result');
    const controls=Array.from(document.querySelectorAll('.fleet-setting-control'));
    const rowAll=Array.from(document.querySelectorAll('.fleet-row-all'));

    controls.forEach(control=>{control.disabled=true;});
    rowAll.forEach(control=>{control.disabled=true;});
    if(apply){apply.disabled=true;apply.title='Fleet writes are disabled until a safe agent implementation is available.';}
    if(reset)reset.disabled=true;

    if(result){
        result.className='alert warningbox';
        result.innerHTML='<strong>Read-only safety mode.</strong> General and Advanced fleet writes are currently disabled because the installed opnSentral agent intentionally rejects these configuration job types. Values can still be compared, but this page will not queue backups or configuration changes.';
    }
})();
