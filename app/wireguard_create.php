<?php
require_once __DIR__ . '/inc/config.php';
require_login();
$firewalls = db()->query('SELECT id,name,base_url FROM firewalls ORDER BY name')->fetchAll();
require __DIR__ . '/inc/header.php';
?>
<div class="page-title">
  <div><h1>Create WireGuard site-to-site tunnel</h1><p>Create a dedicated reciprocal tunnel and managed firewall rules on two OPNsense systems.</p></div>
  <a class="button secondary" href="/wireguard_overview.php">Back to overview</a>
</div>
<div class="alert warningbox"><strong>Experimental wizard.</strong> Confirm every network, endpoint, port and interface key. Automatic backups are created first.</div>
<div id="create-error" class="alert error hidden"></div><div id="create-success" class="alert goodbox hidden"></div>
<form id="wg-create-form" class="form-card wg-create-form">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<section class="wizard-section"><h2>Sites</h2><div class="field-grid">
<label>Site A<select name="site_a_id" required><option value="">Select firewall</option><?php foreach($firewalls as $f):?><option value="<?= (int)$f['id']?>"><?=h((string)$f['name'])?></option><?php endforeach;?></select></label>
<label>Site B<select name="site_b_id" required><option value="">Select firewall</option><?php foreach($firewalls as $f):?><option value="<?= (int)$f['id']?>"><?=h((string)$f['name'])?></option><?php endforeach;?></select></label>
</div></section>
<section class="wizard-section"><h2>Networks and endpoints</h2><div class="field-grid">
<label>Site A LAN network<input name="site_a_lan" placeholder="192.168.177.0/24" required></label>
<label>Site B LAN network<input name="site_b_lan" placeholder="192.168.1.0/24" required></label>
<label>Site A tunnel address<input name="site_a_tunnel" placeholder="10.177.20.1/30" required></label>
<label>Site B tunnel address<input name="site_b_tunnel" placeholder="10.177.20.2/30" required></label>
<label>Site A public endpoint<input name="site_a_endpoint" placeholder="site-a.example.com" required></label>
<label>Site B public endpoint<input name="site_b_endpoint" placeholder="site-b.example.com" required></label>
<label>Site A UDP port<input name="site_a_port" type="number" min="1" max="65535" value="51820" required></label>
<label>Site B UDP port<input name="site_b_port" type="number" min="1" max="65535" value="51820" required></label>
</div></section>
<section class="wizard-section"><h2>Names and interfaces</h2><div class="field-grid">
<label>Site A instance name<input name="site_a_name" placeholder="S2S_SiteB" required></label>
<label>Site B instance name<input name="site_b_name" placeholder="S2S_SiteA" required></label>
<label>Site A WAN interface key<input name="site_a_wan_interface" value="wan" required></label>
<label>Site B WAN interface key<input name="site_b_wan_interface" value="wan" required></label>
<label>Site A LAN interface key<input name="site_a_lan_interface" value="lan" required></label>
<label>Site B LAN interface key<input name="site_b_lan_interface" value="lan" required></label>
<label>WireGuard group/interface key<input name="wireguard_interface" value="wireguard" required></label>
<label>Persistent keepalive<input name="keepalive" type="number" min="0" max="65535" value="25"></label>
</div></section>
<section class="wizard-section"><h2>Firewall rules</h2>
<label class="checkbox"><input type="checkbox" name="create_wan_rules" value="1" checked>Create WAN UDP rules</label>
<label class="checkbox"><input type="checkbox" name="create_traffic_rules" value="1" checked>Create LAN and WireGuard traffic rules</label>
<p class="muted">Rules use category <strong>WireGuard</strong> and descriptions containing <strong>managed by opnCentral [unique ID]</strong>.</p>
</section>
<div class="actions"><button id="create-button" type="submit">Create tunnel on both sites</button><a class="button secondary" href="/wireguard_overview.php">Cancel</a></div>
</form>
<script>
(function(){
 const form=document.getElementById('wg-create-form'),button=document.getElementById('create-button'),errorBox=document.getElementById('create-error'),successBox=document.getElementById('create-success');
 form.addEventListener('submit',async e=>{e.preventDefault();errorBox.classList.add('hidden');successBox.classList.add('hidden');const data=new FormData(form);if(data.get('site_a_id')===data.get('site_b_id')){errorBox.textContent='Select two different firewalls.';errorBox.classList.remove('hidden');return;}if(!confirm('Create this managed WireGuard tunnel on both OPNsense systems?\n\nAutomatic backups will be created first.'))return;button.disabled=true;button.textContent='Creating and verifying…';try{const response=await fetch('/wireguard_create_action.php',{method:'POST',credentials:'same-origin',cache:'no-store',body:new URLSearchParams(data)});const raw=await response.text();let result;try{result=JSON.parse(raw)}catch(_){throw new Error('Invalid server response: '+raw.slice(0,500))}if(!response.ok||result.ok!==true)throw new Error(result.error||'Tunnel creation failed.');successBox.textContent='Tunnel '+result.tunnel_id+' created: '+result.site_a+' ↔ '+result.site_b+'. '+result.message;successBox.classList.remove('hidden');}catch(err){errorBox.textContent=err.message;errorBox.classList.remove('hidden');}finally{button.disabled=false;button.textContent='Create tunnel on both sites';window.scrollTo({top:0,behavior:'smooth'});}});
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
