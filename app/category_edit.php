<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_login();

$firewallId = max(0, (int)($_GET['firewall_id'] ?? 0));
$name = trim((string)($_GET['name'] ?? ''));
if ($firewallId < 1 || $name === '') {
    http_response_code(400);
    exit('A firewall and category name are required.');
}
require __DIR__ . '/inc/header.php';
?>
<div class="page-title">
    <div>
        <h1>Edit category</h1>
        <p>Edit the selected category on one OPNsense or on every OPNsense where the same category exists.</p>
    </div>
    <a class="button secondary" href="/category_overview.php">Back to categories</a>
</div>

<div id="category-edit-error" class="alert error hidden"></div>
<section class="card" style="max-width:900px">
    <form id="category-edit-form" class="category-form">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="old_name" value="<?= h($name) ?>">

        <label for="category-edit-name">Category name</label>
        <input id="category-edit-name" name="new_name" type="text" required maxlength="255">

        <label for="category-edit-color">Category color</label>
        <input id="category-edit-color" name="color" type="text" maxlength="7" placeholder="F0AD4E">

        <label class="checkbox">
            <input id="category-edit-automatic" name="automatic" type="checkbox" value="1">
            Automatic category
        </label>
        <p class="muted">Leave this disabled for a persistent category.</p>

        <fieldset class="distribution-targets">
            <legend>Apply change to</legend>
            <label class="distribution-scope-option">
                <input type="radio" name="edit_scope" value="one" checked>
                <span><strong>This OPNsense only</strong><small id="category-edit-one-label">Only the selected firewall.</small></span>
            </label>
            <label class="distribution-scope-option">
                <input type="radio" name="edit_scope" value="all-matching">
                <span><strong>All matching OPNsense firewalls</strong><small id="category-edit-all-label">Every firewall where this category currently exists.</small></span>
            </label>
        </fieldset>

        <div class="actions">
            <button type="submit" id="category-edit-save">Save category</button>
            <a class="button secondary" href="/category_overview.php">Cancel</a>
        </div>
    </form>
</section>
<div id="category-edit-result"></div>

<script>
(function(){
    'use strict';
    const oldName = <?= json_encode($name, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;
    const selectedFirewallId = <?= $firewallId ?>;
    const form = document.getElementById('category-edit-form');
    const errorBox = document.getElementById('category-edit-error');
    const resultBox = document.getElementById('category-edit-result');
    const saveButton = document.getElementById('category-edit-save');
    let matchingIds = [];

    function esc(value){
        const node = document.createElement('div');
        node.textContent = String(value ?? '');
        return node.innerHTML;
    }

    async function load(){
        try{
            const response = await fetch('/alias_category_inventory_data.php', {credentials:'same-origin',cache:'no-store'});
            const data = await response.json();
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'Could not load categories.');
            let selected = null;
            let selectedFirewall = null;
            (data.firewalls || []).forEach(function(entry){
                const match = (entry.categories || []).find(item => String(item.name || '').toLowerCase() === oldName.toLowerCase());
                if(match){
                    matchingIds.push(Number(entry.firewall.id));
                    if(Number(entry.firewall.id) === selectedFirewallId){
                        selected = match;
                        selectedFirewall = entry.firewall;
                    }
                }
            });
            if(!selected) throw new Error('The selected category no longer exists on this OPNsense.');
            document.getElementById('category-edit-name').value = selected.name || oldName;
            document.getElementById('category-edit-color').value = selected.color || '';
            document.getElementById('category-edit-automatic').checked = selected.automatic === true;
            document.getElementById('category-edit-one-label').textContent = selectedFirewall.name;
            document.getElementById('category-edit-all-label').textContent = matchingIds.length + ' matching firewall(s).';
        }catch(error){
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
            saveButton.disabled = true;
        }
    }

    form.addEventListener('submit', async function(event){
        event.preventDefault();
        const scope = form.querySelector('input[name="edit_scope"]:checked').value;
        const ids = scope === 'all-matching' ? matchingIds : [selectedFirewallId];
        if(!ids.length) return;
        if(!confirm('Save this category on ' + ids.length + ' firewall(s)?')) return;

        saveButton.disabled = true;
        saveButton.textContent = 'Saving…';
        resultBox.innerHTML = '';
        try{
            const payload = new FormData(form);
            ids.forEach(id => payload.append('firewall_ids[]', String(id)));
            const response = await fetch('/category_edit_action.php', {method:'POST',credentials:'same-origin',body:payload});
            const raw = await response.text();
            let data;
            try{ data = JSON.parse(raw); }catch(error){ throw new Error(raw.slice(0,700)); }
            if(!response.ok || data.ok !== true) throw new Error(data.error || 'Save failed.');
            const failures = (data.results || []).filter(item => !item.ok);
            if(failures.length) throw new Error(failures.map(item => item.name + ': ' + item.message).join(' | '));
            resultBox.innerHTML = '<div class="alert goodbox">Category saved on ' + data.results.length + ' firewall(s).</div>';
            setTimeout(() => location.href='/category_overview.php', 700);
        }catch(error){
            resultBox.innerHTML = '<div class="alert error">' + esc(error.message) + '</div>';
        }finally{
            saveButton.disabled = false;
            saveButton.textContent = 'Save category';
        }
    });
    load();
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
