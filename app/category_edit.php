<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_login();

$firewallId = max(0, (int)($_GET['source_firewall_id'] ?? $_GET['firewall_id'] ?? 0));
$name = trim((string)($_GET['name'] ?? ''));
if ($firewallId < 1 || $name === '') {
    http_response_code(400);
    exit('A firewall and category name are required.');
}
require __DIR__ . '/inc/header.php';
?>
<style>
.category-edit-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(300px,.8fr);gap:20px}.category-edit-form label{display:block;font-weight:700;margin:14px 0 6px}.category-edit-form input[type=text],.category-edit-form select{width:100%;box-sizing:border-box}.category-edit-automatic{display:flex!important;align-items:center;gap:9px}.category-edit-automatic input{width:auto}.category-edit-source{padding:10px;border-radius:6px;background:rgba(127,127,127,.08)}.category-edit-results{display:grid;gap:8px}.category-edit-result{padding:10px;border-radius:6px;background:rgba(127,127,127,.08)}.category-edit-result.good{border-left:4px solid #2aa84a}.category-edit-result.bad{border-left:4px solid #d74747}.category-targets{margin-top:18px;padding:12px;border:1px solid rgba(127,127,127,.35);border-radius:7px}.category-targets legend{padding:0 7px;font-weight:700}.category-target-option{display:grid!important;grid-template-columns:20px minmax(0,1fr);gap:10px;align-items:start;margin:0!important;padding:11px 12px;border:1px solid transparent;border-radius:6px;cursor:pointer}.category-target-option:has(input:checked){background:rgba(55,139,220,.10);border-color:rgba(55,139,220,.45)}.category-target-option input{margin-top:3px}.category-target-option strong{display:block}.category-target-option small{display:block;margin-top:3px}.category-target-select{margin:5px 12px 10px 42px}.category-target-select select{width:100%}.category-target-select select:disabled{opacity:.5}@media(max-width:850px){.category-edit-grid{grid-template-columns:1fr}.category-target-select{margin-left:12px}}
</style>
<div class="page-title">
    <div>
        <h1>Edit category</h1>
        <p>Edit name, color and automatic state.</p>
    </div>
    <a class="button secondary" href="/category_overview.php">Back to categories</a>
</div>

<div id="category-edit-error" class="alert error hidden"></div>
<div class="category-edit-grid">
<section class="card">
    <h2 id="category-edit-title"><?= h($name) ?></h2>
    <div class="category-edit-source"><strong>Source:</strong> <span id="category-edit-source">Loading…</span></div>
    <form id="category-edit-form" class="category-edit-form">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="old_name" value="<?= h($name) ?>">

        <label for="category-edit-name">Name</label>
        <input id="category-edit-name" name="new_name" type="text" required maxlength="255">

        <label for="category-edit-color">Color</label>
        <input id="category-edit-color" name="color" type="text" maxlength="7" placeholder="F0AD4E">
        <small class="muted">Six hexadecimal digits, with or without #.</small>

        <label class="category-edit-automatic">
            <input id="category-edit-automatic" name="automatic" type="checkbox" value="1">
            <span>Automatic</span>
        </label>
        <small class="muted">Automatic categories may be removed by OPNsense when no longer used.</small>

        <fieldset class="category-targets">
            <legend>Apply changes to</legend>
            <label class="category-target-option">
                <input type="radio" name="edit_scope" value="one" checked>
                <span><strong>One OPNsense</strong><small class="muted">Update only the selected firewall.</small></span>
            </label>
            <div class="category-target-select">
                <select id="category-edit-target" aria-label="Target firewall"></select>
            </div>
            <label class="category-target-option">
                <input type="radio" name="edit_scope" value="all-matching">
                <span><strong>All OPNsense where this category already exists</strong><small id="category-edit-all-label" class="muted">Never creates a missing category.</small></span>
            </label>
        </fieldset>

        <div class="actions"><button type="submit" id="category-edit-save">Save changes</button></div>
    </form>
</section>
<section class="card"><h2>Results</h2><div id="category-edit-result" class="empty">No changes saved yet.</div></section>
</div>

<script>
(function(){
    'use strict';
    const oldName = <?= json_encode($name, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;
    const selectedFirewallId = <?= $firewallId ?>;
    const form = document.getElementById('category-edit-form');
    const errorBox = document.getElementById('category-edit-error');
    const resultBox = document.getElementById('category-edit-result');
    const saveButton = document.getElementById('category-edit-save');
    const target = document.getElementById('category-edit-target');
    let matching = [];

    function esc(value){const node=document.createElement('div');node.textContent=String(value??'');return node.innerHTML;}
    function sync(){const all=form.querySelector('input[name="edit_scope"]:checked')?.value==='all-matching';target.disabled=all;}
    form.querySelectorAll('input[name="edit_scope"]').forEach(r=>r.addEventListener('change',sync));

    async function load(){
        try{
            const response = await fetch('/alias_category_inventory_data.php',{credentials:'same-origin',cache:'no-store'});
            const data = await response.json();
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'Could not load categories.');
            let selected = null;
            let selectedFirewall = null;
            matching = [];
            (data.firewalls || []).forEach(function(entry){
                const match=(entry.categories||[]).find(item=>String(item.name||'').toLowerCase()===oldName.toLowerCase());
                if(!match) return;
                matching.push({id:Number(entry.firewall.id),name:String(entry.firewall.name),item:match});
                if(Number(entry.firewall.id)===selectedFirewallId){selected=match;selectedFirewall=entry.firewall;}
            });
            if(!selected) throw new Error('The selected category no longer exists on this OPNsense.');
            document.getElementById('category-edit-name').value=selected.name||oldName;
            document.getElementById('category-edit-color').value=selected.color||'';
            document.getElementById('category-edit-automatic').checked=selected.automatic===true;
            document.getElementById('category-edit-title').textContent=selected.name||oldName;
            document.getElementById('category-edit-source').textContent=selectedFirewall.name;
            target.innerHTML=matching.map(fw=>'<option value="'+fw.id+'"'+(fw.id===selectedFirewallId?' selected':'')+'>'+esc(fw.name)+'</option>').join('');
            document.getElementById('category-edit-all-label').textContent='Update all '+matching.length+' firewall(s) where this category exists. Missing categories are not created.';
            sync();
        }catch(error){
            errorBox.textContent=error.message;errorBox.classList.remove('hidden');saveButton.disabled=true;
        }
    }

    form.addEventListener('submit',async function(event){
        event.preventDefault();
        if(!form.checkValidity()) return;
        const scope=form.querySelector('input[name="edit_scope"]:checked').value;
        const ids=scope==='all-matching'?matching.map(fw=>fw.id):[Number(target.value)];
        if(!ids.length) return;
        const question=scope==='all-matching'?'Save these category changes to every OPNsense where the category already exists?':'Save these category changes to the selected OPNsense?';
        if(!confirm(question)) return;
        saveButton.disabled=true;saveButton.textContent='Saving…';resultBox.className='';resultBox.innerHTML='';
        try{
            const payload=new FormData(form);ids.forEach(id=>payload.append('firewall_ids[]',String(id)));
            const response=await fetch('/category_edit_action.php',{method:'POST',credentials:'same-origin',body:payload});
            const raw=await response.text();let data;try{data=JSON.parse(raw);}catch(e){throw new Error(raw.slice(0,700));}
            if(!response.ok||data.ok!==true) throw new Error(data.error||'Save failed.');
            resultBox.className='category-edit-results';
            resultBox.innerHTML=(data.results||[]).map(item=>'<div class="category-edit-result '+(item.ok?'good':'bad')+'"><strong>'+esc(item.name)+'</strong><br>'+esc(item.message)+'</div>').join('');
        }catch(error){resultBox.className='alert error';resultBox.textContent=error.message;}
        finally{saveButton.disabled=false;saveButton.textContent='Save changes';}
    });
    load();
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
