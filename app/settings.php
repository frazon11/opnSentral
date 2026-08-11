<?php
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/managed_category.php';
require_login();
require __DIR__ . '/inc/header.php';
?>
<style>
.settings-sections{display:grid;gap:26px}
.settings-group{display:grid;gap:12px}
.settings-group-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;padding:0 2px 8px;border-bottom:1px solid var(--border)}
.settings-group-heading h2{margin:0;font-size:1.15rem}
.settings-group-heading p{margin:0;color:var(--muted);font-size:.9rem}
.settings-group-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;align-items:start}
.settings-group-grid.interface-grid{grid-template-columns:repeat(3,minmax(0,1fr))}
.settings-group-grid>.wide{grid-column:1/-1}
.settings-group .card{height:100%}
#presentation-settings{display:flex;flex-direction:column}
#presentation-settings .button{align-self:flex-start;margin-top:auto}
.telemetry-status-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
@media(max-width:1200px){.settings-group-grid.interface-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:850px){.settings-group-grid,.settings-group-grid.interface-grid,.telemetry-status-grid{grid-template-columns:1fr}.settings-group-grid>.wide{grid-column:auto}.settings-group-heading{align-items:flex-start;flex-direction:column;gap:3px}}
</style>

<div class="page-title">
    <div>
        <h1><?= h(t('settings.title')) ?></h1>
        <p><?= h(t('settings.subtitle')) ?></p>
    </div>
</div>

<div class="settings-sections">
    <section class="settings-group" aria-labelledby="settings-interface-heading">
        <div class="settings-group-heading">
            <h2 id="settings-interface-heading">Interface</h2>
            <p>Appearance, language and presentation-safe display.</p>
        </div>

        <div class="settings-group-grid interface-grid">
            <section class="card">
                <h2><?= h(t('language')) ?></h2>
                <p class="muted"><?= h(t('settings.language_help')) ?></p>
                <label>
                    <?= h(t('language')) ?>
                    <select id="settings-language">
                        <?php foreach (supported_languages() as $code => $label): ?>
                            <option value="<?= h($code) ?>" <?= current_language()===$code?'selected':'' ?>><?= h($label) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
            </section>

            <section class="card">
                <h2><?= h(t('settings.theme')) ?></h2>
                <p class="muted"><?= h(t('settings.theme_help')) ?></p>
                <label>
                    <?= h(t('settings.theme')) ?>
                    <select id="settings-theme">
                        <option value="light"><?= h(t('settings.theme_light')) ?></option>
                        <option value="dark"><?= h(t('settings.theme_dark')) ?></option>
                    </select>
                </label>
                <div class="theme-preview">
                    <div class="theme-preview-sidebar"></div>
                    <div class="theme-preview-content"><span></span><span></span><span></span></div>
                </div>
            </section>

            <section class="card" id="presentation-settings" data-presentation-exempt="true">
                <h2>Presentation mode</h2>
                <p class="muted">Replace visible firewall names, addresses, domains and email addresses with presentation-safe values.</p>
                <button type="button" id="presentation-mode-button" class="button secondary" aria-pressed="false">Enable presentation mode</button>
                <span id="presentation-mode-state" class="presentation-mode-state" hidden>Presentation mode active</span>
            </section>
        </div>
    </section>

    <section class="settings-group" aria-labelledby="settings-opnsense-heading">
        <div class="settings-group-heading">
            <h2 id="settings-opnsense-heading">OPNsense</h2>
            <p>Defaults controlling how managed firewalls are handled.</p>
        </div>

        <div class="settings-group-grid" id="opnsense-settings-grid">
            <section class="card" id="managed-category-settings">
                <h2>Managed category</h2>
                <p class="muted">Before opnSentral changes a firewall, it verifies that this persistent category exists. Managed aliases are assigned to it.</p>

                <?php if (isset($_GET['managed_category_saved'])): ?>
                    <div class="alert goodbox">Managed category settings saved.</div>
                <?php endif; ?>
                <?php if (!empty($_GET['managed_category_error'])): ?>
                    <div class="alert error"><?= h((string) $_GET['managed_category_error']) ?></div>
                <?php endif; ?>

                <form method="post" action="/managed_category_settings_action.php">
                    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                    <label>
                        Category name
                        <input type="text" name="managed_category_name" maxlength="255" required value="<?= h(managed_category_name()) ?>">
                    </label>
                    <label>
                        Category color
                        <input type="text" name="managed_category_color" maxlength="7" required value="<?= h(managed_category_color()) ?>" placeholder="F0AD4E">
                    </label>
                    <p class="muted">Default: <strong>managed by opnSentral</strong>. Existing categories are not renamed automatically.</p>
                    <button type="submit" class="remote-change-control">Save managed category</button>
                </form>
            </section>
        </div>
    </section>

    <section class="settings-group" aria-labelledby="settings-application-heading">
        <div class="settings-group-heading">
            <h2 id="settings-application-heading">Application</h2>
            <p>Updates and notification configuration.</p>
        </div>

        <div class="settings-group-grid">
            <section class="card" id="update-settings-card">
                <div class="card-head">
                    <div>
                        <h2>Updates</h2>
                        <p class="muted">Check GitHub for new published opnSentral releases.</p>
                    </div>
                    <button type="button" class="button secondary" id="update-check-now">Check now</button>
                </div>

                <label class="checkbox">
                    <input type="checkbox" id="automatic-update-check" checked>
                    Check GitHub automatically every 24 hours
                </label>

                <div class="update-status-grid">
                    <div><strong>Installed version</strong><span id="installed-version">Loading…</span></div>
                    <div><strong>Latest version</strong><span id="latest-version">Loading…</span></div>
                    <div><strong>Last checked</strong><span id="last-update-check">Loading…</span></div>
                    <div><strong>Status</strong><span id="update-check-status">Loading…</span></div>
                </div>

                <div id="update-check-message" class="card-message"></div>
                <a id="release-link" class="button secondary hidden" target="_blank" rel="noopener noreferrer">View release</a>
                <p class="muted update-privacy-note">This reads public release information from GitHub. No installation ID, firewall details, credentials, networks or VPN data are sent.</p>
            </section>

            <section class="card" id="notification-settings-card">
                <h2><?= h(t('menu.notifications')) ?></h2>
                <p class="muted"><?= h(t('settings.notifications_help')) ?></p>
                <a class="button secondary" href="/notifications.php"><?= h(t('settings.open_notifications')) ?></a>
            </section>
        </div>
    </section>

    <section class="settings-group" aria-labelledby="settings-data-heading">
        <div class="settings-group-heading">
            <h2 id="settings-data-heading">Data &amp; privacy</h2>
            <p>Anonymous statistics and opnSentral backup/restore.</p>
        </div>

        <div class="settings-group-grid">
            <section class="card" id="telemetry-settings-card">
                <div class="card-head">
                    <div>
                        <h2>Anonymous installation statistics</h2>
                        <p class="muted">Optionally report that this opnSentral installation is active.</p>
                    </div>
                    <button type="button" class="button secondary" id="telemetry-send-now">Send now</button>
                </div>

                <label class="checkbox">
                    <input type="checkbox" id="telemetry-enabled">
                    Share anonymous installation statistics once every 24 hours
                </label>

                <div class="telemetry-status-grid">
                    <div><strong>Last sent</strong><span id="telemetry-last-sent">Never</span></div>
                    <div><strong>Status</strong><span id="telemetry-status">Loading…</span></div>
                </div>

                <div id="telemetry-message" class="card-message"></div>
                <p class="muted">Sent: random anonymous installation hash, opnSentral version, CPU architecture and platform “docker”.</p>
                <p class="muted">Never sent: firewall names or addresses, API credentials, usernames, LAN networks, VPN configuration, email addresses or the APP_KEY.</p>
            </section>

            <section class="card" id="self-backup-settings">
                <h2>Backup &amp; Restore</h2>
                <p class="muted">Back up opnSentral's database, application state and optionally all stored OPNsense configuration backups.</p>

                <div class="backup-restore-grid">
                    <div class="settings-subpanel">
                        <h3>Create backup</h3>
                        <form method="post" action="/self_backup_download.php">
                            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                            <label class="checkbox">
                                <input type="checkbox" name="include_stored_backups" value="1" checked>
                                Include stored OPNsense configuration backups
                            </label>
                            <p class="alert warningbox"><strong>APP_KEY is not included.</strong> Preserve the exact APP_KEY. Encrypted firewall credentials cannot be restored with a different key.</p>
                            <button type="submit" class="remote-change-control backup-download-control">Download backup now</button>
                        </form>
                    </div>

                    <div class="settings-subpanel">
                        <h3>Restore</h3>
                        <form id="self-restore-form" enctype="multipart/form-data">
                            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                            <label>
                                opnSentral backup ZIP
                                <input type="file" name="backup_file" accept=".zip,application/zip" required>
                            </label>
                            <label class="checkbox">
                                <input type="checkbox" id="restore-confirmation" required>
                                I understand that current opnSentral data will be replaced
                            </label>
                            <p class="muted">The archive is verified first and a persistent safety backup is created before replacing data.</p>
                            <button type="submit" class="danger" id="restore-button">Validate and restore</button>
                        </form>
                        <div id="restore-result" class="alert hidden"></div>
                    </div>
                </div>
            </section>
        </div>
    </section>
</div>

<script>
(function(){
    const language=document.getElementById('settings-language');
    const theme=document.getElementById('settings-theme');

    language?.addEventListener('change',function(){const url=new URL(window.location.href);url.searchParams.set('lang',this.value);window.location.href=url.toString();});
    const currentTheme=document.documentElement.dataset.theme==='dark'?'dark':'light';
    theme.value=currentTheme;
    theme?.addEventListener('change',function(){window.opnSentralSetTheme(this.value);});

    const automatic=document.getElementById('automatic-update-check');
    const checkNow=document.getElementById('update-check-now');
    const latest=document.getElementById('latest-version');
    const lastChecked=document.getElementById('last-update-check');
    const status=document.getElementById('update-check-status');
    const message=document.getElementById('update-check-message');
    const releaseLink=document.getElementById('release-link');

    function formatDate(value){if(!value)return'Never';const date=new Date(value);return Number.isNaN(date.getTime())?value:date.toLocaleString();}
    function renderUpdate(result){
        const state=result.state||{};
        document.getElementById('installed-version').textContent=result.installed_version?'v'+result.installed_version:'Unknown';
        automatic.checked=state.enabled!==false;
        latest.textContent=state.latest_version?'v'+state.latest_version:'Unknown';
        lastChecked.textContent=state.last_checked?formatDate(state.last_checked):(state.last_attempt?'No successful check; last attempt '+formatDate(state.last_attempt):'Never');
        releaseLink.classList.add('hidden');releaseLink.removeAttribute('href');
        if(state.error){status.innerHTML='<span class="badge bad">Check failed</span>';message.textContent=state.error;return;}
        if(!state.latest_version){status.innerHTML='<span class="badge neutral">Not checked</span>';message.textContent='No release information is cached yet.';return;}
        if(state.comparison==='behind'){status.innerHTML='<span class="badge warning">Update available</span>';message.textContent='A newer published opnSentral release is available.';}
        else if(state.comparison==='ahead'){status.innerHTML='<span class="badge neutral">Ahead of latest release</span>';message.textContent='This installation is newer than the latest published GitHub release.';}
        else if(state.comparison==='equal'){status.innerHTML='<span class="badge good">Up to date</span>';message.textContent='This installation matches the latest published GitHub release.';}
        else{status.innerHTML='<span class="badge neutral">Unknown</span>';message.textContent='The installed and published versions could not be compared.';}
        if(state.release_url){releaseLink.href=state.release_url;releaseLink.classList.remove('hidden');}
    }
    async function loadUpdate(force){
        checkNow.disabled=true;if(force)checkNow.textContent='Checking…';
        try{const response=await fetch('/update_check.php'+(force?'?force=1':''),{credentials:'same-origin',cache:'no-store'});const result=await response.json();if(!response.ok||result.ok!==true)throw new Error(result.error||'Update check failed.');renderUpdate(result);}
        catch(error){status.innerHTML='<span class="badge bad">Check failed</span>';message.textContent=error.message;}
        finally{checkNow.disabled=false;checkNow.textContent='Check now';}
    }
    automatic?.addEventListener('change',async function(){
        const body=new URLSearchParams();body.set('csrf',<?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>);body.set('enabled',this.checked?'1':'0');
        try{const response=await fetch('/update_settings_action.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});const result=await response.json();if(!response.ok||result.ok!==true)throw new Error(result.error||'Could not save setting.');}
        catch(error){this.checked=!this.checked;alert(error.message);}
    });
    checkNow?.addEventListener('click',()=>loadUpdate(true));loadUpdate(false);

    const telemetryEnabled=document.getElementById('telemetry-enabled');
    const telemetrySendNow=document.getElementById('telemetry-send-now');
    const telemetryLastSent=document.getElementById('telemetry-last-sent');
    const telemetryStatus=document.getElementById('telemetry-status');
    const telemetryMessage=document.getElementById('telemetry-message');

    function renderTelemetry(result){
        const state=result.state||{};
        telemetryEnabled.checked=state.enabled===true;
        telemetryLastSent.textContent=state.last_sent?formatDate(state.last_sent):'Never';
        telemetrySendNow.disabled=!state.enabled;
        if(!state.enabled){telemetryStatus.innerHTML='<span class="badge neutral">Disabled</span>';telemetryMessage.textContent='Anonymous installation statistics are disabled.';}
        else if(!result.configured){telemetryStatus.innerHTML='<span class="badge bad">Not configured</span>';telemetryMessage.textContent='Telemetry receiver is not configured.';}
        else if(state.last_status==='sent'){telemetryStatus.innerHTML='<span class="badge good">Sent</span>';telemetryMessage.textContent='The anonymous active-installation check was accepted.';}
        else if(state.last_error){telemetryStatus.innerHTML='<span class="badge bad">Failed</span>';telemetryMessage.textContent=state.last_error;}
        else{telemetryStatus.innerHTML='<span class="badge neutral">Waiting</span>';telemetryMessage.textContent='The next anonymous check will run in the background.';}
    }
    async function loadTelemetry(force){
        telemetrySendNow.disabled=true;if(force)telemetrySendNow.textContent='Sending…';
        try{const response=await fetch('/telemetry_status.php'+(force?'?force=1':''),{credentials:'same-origin',cache:'no-store'});const result=await response.json();if(!response.ok||result.ok!==true)throw new Error(result.error||'Could not load telemetry status.');renderTelemetry(result);}
        catch(error){telemetryStatus.innerHTML='<span class="badge bad">Failed</span>';telemetryMessage.textContent=error.message;}
        finally{telemetrySendNow.textContent='Send now';if(telemetryEnabled.checked)telemetrySendNow.disabled=false;}
    }
    telemetryEnabled?.addEventListener('change',async function(){
        const requested=this.checked;const body=new URLSearchParams();body.set('csrf',<?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>);body.set('enabled',requested?'1':'0');
        try{const response=await fetch('/telemetry_settings_action.php',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});const result=await response.json();if(!response.ok||result.ok!==true)throw new Error(result.error||'Could not save telemetry setting.');await loadTelemetry(false);}
        catch(error){this.checked=!requested;alert(error.message);}
    });
    telemetrySendNow?.addEventListener('click',()=>loadTelemetry(true));loadTelemetry(false);

    const restoreForm=document.getElementById('self-restore-form');
    const restoreButton=document.getElementById('restore-button');
    const restoreResult=document.getElementById('restore-result');
    restoreForm?.addEventListener('submit',async function(event){
        event.preventDefault();if(!document.getElementById('restore-confirmation').checked)return;
        const file=this.elements.backup_file.files[0];if(!file){alert('Select an opnSentral backup ZIP.');return;}
        if(!confirm('Restore this opnSentral backup now?\n\nCurrent application data will be replaced. A safety backup is created first. The container must be restarted after the restore.'))return;
        restoreButton.disabled=true;restoreButton.textContent='Validating and restoring…';restoreResult.className='alert';restoreResult.textContent='Uploading and validating the archive…';
        try{const response=await fetch('/self_restore.php',{method:'POST',credentials:'same-origin',cache:'no-store',body:new FormData(this)});const raw=await response.text();let result;try{result=JSON.parse(raw);}catch(error){throw new Error('Server returned invalid JSON: '+raw.replace(/\s+/g,' ').trim().slice(0,500));}if(!response.ok||result.ok!==true)throw new Error(result.error||'Restore failed.');restoreResult.className='alert goodbox';restoreResult.innerHTML='<strong>Restore completed.</strong><br>Safety backup: '+escapeHtml(result.safety_backup)+'<br>Restored archive version: '+escapeHtml(result.restored_version)+'<br><br><strong>Restart or recreate the opnSentral container now.</strong>';restoreForm.reset();}
        catch(error){restoreResult.className='alert error';restoreResult.textContent=error.message;}
        finally{restoreButton.disabled=false;restoreButton.textContent='Validate and restore';}
    });
    function escapeHtml(value){const node=document.createElement('div');node.textContent=String(value??'');return node.innerHTML;}
})();
</script>
<?php require __DIR__ . '/inc/footer.php'; ?>
