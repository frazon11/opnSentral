<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$results = [];
function geoip_page_find_url(mixed $value): string {
    if (!is_array($value)) return '';
    foreach ($value as $key => $child) {
        if (strtolower((string)$key) === 'url' && !is_array($child)) return trim((string)$child);
    }
    foreach ($value as $child) {
        $found = geoip_page_find_url($child);
        if ($found !== '') return $found;
    }
    return '';
}
foreach ($firewalls as $firewall) {
    try {
        $settings = opn_raw_request($firewall, 'firewall/alias/get_geo_i_p', 'GET', null, 20);
        $results[] = ['firewall'=>$firewall,'ok'=>true,'url'=>geoip_page_find_url($settings),'error'=>''];
    } catch (Throwable $e) {
        $results[] = ['firewall'=>$firewall,'ok'=>false,'url'=>'','error'=>$e->getMessage()];
    }
}
require __DIR__ . '/inc/header.php';
?>
<div class="page-title management-page-title">
  <div><h1>GeoIP Settings</h1><p>Set the GeoIP source URL and update the database on one or all managed OPNsense firewalls.</p></div>
  <a class="button secondary" href="/alias_overview.php">Back to aliases</a>
</div>

<section class="card" style="max-width:1100px">
  <h2>GeoIP source</h2>
  <form id="geoip-form">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
    <label for="geoip-url">URL</label>
    <input id="geoip-url" name="url" type="url" placeholder="https://example.org/geoip.csv.gz">
    <p class="muted">Location from which OPNsense fetches GeoIP address ranges. IPinfo and MaxMind compatible sources are supported.</p>

    <fieldset class="distribution-targets">
      <legend>Apply to</legend>
      <label class="distribution-scope-option">
        <input type="radio" name="scope" value="one" checked>
        <span><strong>One OPNsense</strong><small>Apply only to the selected firewall.</small></span>
      </label>
      <label class="distribution-firewall-select">OPNsense
        <select id="geoip-firewall">
          <?php foreach ($firewalls as $firewall): ?>
          <option value="<?= (int)$firewall['id'] ?>"><?= h((string)$firewall['name']) ?></option>
          <?php endforeach; ?>
        </select>
      </label>
      <label class="distribution-scope-option">
        <input type="radio" name="scope" value="all">
        <span><strong>All OPNsense firewalls</strong><small>Apply to every configured firewall.</small></span>
      </label>
    </fieldset>

    <div class="actions">
      <button type="button" id="geoip-save" class="remote-change-control">Save URL</button>
      <button type="button" id="geoip-update" class="button secondary remote-change-control">Update GeoIP</button>
    </div>
  </form>
  <div id="geoip-action-result"></div>
</section>

<section class="card">
  <h2>Current configuration</h2>
  <div class="table-scroll management-table-wrap">
    <table class="management-table">
      <thead><tr><th>OPNsense</th><th>Status</th><th>Current URL</th><th>Open native settings</th></tr></thead>
      <tbody>
      <?php foreach ($results as $result): $fw=$result['firewall']; $native=rtrim((string)$fw['base_url'],'/').'/ui/firewall/alias/geoip'; ?>
        <tr>
          <td><strong><?= h((string)$fw['name']) ?></strong></td>
          <td><?= $result['ok'] ? '<span class="badge good">Available</span>' : '<span class="badge bad">Unavailable</span>' ?></td>
          <td><?= $result['ok'] ? h($result['url'] !== '' ? $result['url'] : 'Not configured') : h($result['error']) ?></td>
          <td><a class="button secondary" href="<?= h($native) ?>" target="_blank" rel="noopener noreferrer">Open</a></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</section>


<section class="card" id="geoip-policy">
  <h2>GeoIP aliases &amp; firewall blocking rules</h2>
  <p class="muted">Inspect the actual alias definitions and firewall rules for a selected OPNsense.
    GeoIP country selections are not the same as an active blocking rule.</p>
  <div class="actions" style="display:flex;align-items:end;gap:12px;flex-wrap:wrap">
    <label for="geoip-policy-firewall">OPNsense
      <select id="geoip-policy-firewall">
        <?php foreach ($firewalls as $fw): ?>
        <option value="<?= (int)$fw['id'] ?>"><?= h((string)$fw['name']) ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <button type="button" id="geoip-policy-refresh" class="button secondary">Refresh aliases &amp; rules</button>
  </div>
  <div id="geoip-policy-result" role="status" aria-live="polite">Select a firewall and refresh.</div>
  <div id="geoip-policy-detail" hidden>
    <h3>GeoIP / Block / Allow / Exception aliases</h3>
    <p class="muted">Included: aliases of type GeoIP, plus aliases whose names mention GeoIP, block, allow, exception or whitelist/blacklist.
       The name does not establish an allow/block policy; only referencing rules can do that.</p>
    <div class="table-scroll"><table class="management-table">
      <thead><tr><th>Alias</th><th>Type</th><th>Enabled</th><th>Configured content / countries</th><th>Edit</th></tr></thead>
      <tbody id="geoip-policy-aliases"></tbody>
    </table></div>
    <h3>Firewall rules referencing these aliases</h3>
    <div class="table-scroll"><table class="management-table">
      <thead><tr><th>Source</th><th>Rule / description</th><th>Action</th><th>Enabled</th><th>Interface / direction</th><th>Order / protocol</th><th>Source → Destination</th><th>Matched aliases</th></tr></thead>
      <tbody id="geoip-policy-rules"></tbody>
    </table></div>
    <p class="muted">Rules shown are configured references from the filter API (including legacy rules), or from legacy XML if API results are unavailable.
       Rule ordering, applied ruleset, implicit rules, state table and actual packet filtering are <strong>not</strong> verified here.</p>
  </div>
</section>

<script>
(function(){
  'use strict';
  const form=document.getElementById('geoip-form');
  const select=document.getElementById('geoip-firewall');
  const result=document.getElementById('geoip-action-result');
  const buttons=[document.getElementById('geoip-save'),document.getElementById('geoip-update')];
  const allIds=<?= json_encode(array_map(static fn(array $fw): int => (int)$fw['id'], $firewalls)) ?>;
  function esc(v){const n=document.createElement('div');n.textContent=String(v??'');return n.innerHTML;}
  function ids(){return form.querySelector('input[name="scope"]:checked').value==='all'?allIds:[Number(select.value)];}
  form.querySelectorAll('input[name="scope"]').forEach(r=>r.addEventListener('change',()=>{select.disabled=form.querySelector('input[name="scope"]:checked').value==='all';}));
  async function run(action){
    const targetIds=ids();
    if(!targetIds.length)return;
    const label=action==='save'?'save this GeoIP URL':'start the GeoIP update';
    if(!confirm('Really '+label+' on '+targetIds.length+' firewall(s)?'))return;
    buttons.forEach(b=>b.disabled=true);
    result.innerHTML='<div class="alert">Working…</div>';
    try{
      const body=new FormData();
      body.set('csrf',form.elements.csrf.value);
      body.set('action',action);
      body.set('url',document.getElementById('geoip-url').value.trim());
      targetIds.forEach(id=>body.append('firewall_ids[]',String(id)));
      const response=await fetch('/geoip_settings_action.php',{method:'POST',credentials:'same-origin',body});
      const raw=await response.text(); let data;
      try{data=JSON.parse(raw);}catch(e){throw new Error(raw.slice(0,700));}
      if(!response.ok||data.ok!==true)throw new Error(data.error||'GeoIP action failed.');
      const failed=(data.results||[]).filter(x=>!x.ok);
      const ok=(data.results||[]).filter(x=>x.ok);
      result.innerHTML=(ok.length?'<div class="alert goodbox">'+esc(ok.map(x=>x.name+': '+x.message).join(' | '))+'</div>':'')+
        (failed.length?'<div class="alert error">'+esc(failed.map(x=>x.name+': '+x.message).join(' | '))+'</div>':'');
      if(action==='save'&&!failed.length)setTimeout(()=>location.reload(),800);
    }catch(e){result.innerHTML='<div class="alert error">'+esc(e.message)+'</div>';}
    finally{buttons.forEach(b=>b.disabled=false);}
  }
  document.getElementById('geoip-save').addEventListener('click',()=>run('save'));
  document.getElementById('geoip-update').addEventListener('click',()=>run('update'));
  const policySelect=document.getElementById('geoip-policy-firewall');
  const policyRefresh=document.getElementById('geoip-policy-refresh');
  const policyResult=document.getElementById('geoip-policy-result');
  const policyDetail=document.getElementById('geoip-policy-detail');
  const policyAliases=document.getElementById('geoip-policy-aliases');
  const policyRules=document.getElementById('geoip-policy-rules');
  async function refreshPolicy(){
    const firewallId=Number(policySelect.value);
    if(!firewallId)return;
    policyRefresh.disabled=true;
    policyDetail.hidden=true;
    policyResult.innerHTML='<div class="alert">Loading GeoIP aliases and referencing firewall rules…</div>';
    try{
      const response=await fetch('/geoip_policy_data.php?'+new URLSearchParams({firewall_id:String(firewallId)}),{
        credentials:'same-origin',cache:'no-store'
      });
      const data=await response.json();
      if(!response.ok || data.ok!==true)throw new Error(data.error||'Unable to load GeoIP policy.');
      const aliases=Array.isArray(data.aliases)?data.aliases:[];
      const rules=Array.isArray(data.rules)?data.rules:[];
      const warnings=Array.isArray(data.warnings)?data.warnings:[];
      policyAliases.innerHTML=aliases.length?aliases.map(a=>{
        const href='/alias_edit.php?'+new URLSearchParams({source_firewall_id:String(firewallId),name:String(a.name)});
        const content=String(a.content||'');
        return '<tr><td><strong>'+esc(a.name)+'</strong><br><small>'+esc(a.description)+'</small></td>'+
          '<td>'+esc(a.type)+'</td><td>'+esc(a.enabled)+'</td>'+
          '<td><details><summary>'+esc(content?content.split(/\r?\n/).filter(Boolean).length+' configured items':'No configured items')+
          '</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">'+esc(content||'(empty)')+'</pre></details></td>'+
          '<td><a class="button secondary" href="'+esc(href)+'">Edit alias</a></td></tr>';
      }).join(''):'<tr><td colspan="5">No matching GeoIP/policy aliases found.</td></tr>';
      policyRules.innerHTML=rules.length?rules.map(r=>
        '<tr><td>'+esc(r.origin)+'</td><td>'+esc(r.description)+'</td>'+
        '<td>'+esc(r.action)+'</td><td>'+esc(r.enabled)+'</td>'+
        '<td>'+esc(r.interface)+' / '+esc(r.direction)+'</td>'+
        '<td>'+esc(r.sequence||'—')+' / '+esc(r.protocol||'—')+'</td>'+
        '<td>'+esc(String(r.source_not)==='1'?'NOT ':'')+esc(r.source)+
        ' → '+esc(String(r.destination_not)==='1'?'NOT ':'')+esc(r.destination)+'</td>'+
        '<td>'+esc([...(r.matched_source||[]),...(r.matched_destination||[])].join(', '))+'</td></tr>'
      ).join(''):'<tr><td colspan="8">No matching rules found in the sources successfully queried.</td></tr>';
      policyResult.innerHTML=
        '<div class="alert">'+esc(data.firewall)+': '+aliases.length+' aliases; '+rules.length+' referencing rules.</div>'+
        (warnings.length?'<div class="alert error">'+esc(warnings.join(' | '))+
          ' — Rule inventory is incomplete; absence of a rule cannot be concluded.</div>':'');
      policyDetail.hidden=false;
    }catch(e){
      policyResult.innerHTML='<div class="alert error">'+esc(e.message)+'</div>';
    }finally{policyRefresh.disabled=false;}
  }
  policyRefresh.addEventListener('click',refreshPolicy);
  policySelect.addEventListener('change',refreshPolicy);
  if(policySelect.options.length)refreshPolicy();

})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
