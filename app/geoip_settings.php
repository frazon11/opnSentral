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
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
