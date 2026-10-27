<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/system_access_management.php';
require_login();

$firewalls=db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$states=[];
foreach($firewalls as $firewall) $states[(int)$firewall['id']]=access_management_state($firewall);
$message=$_SESSION['system_access_message']??null;
unset($_SESSION['system_access_message']);

require __DIR__ . '/inc/header.php';
?>
<style>
.access-tabs{display:flex;gap:8px;flex-wrap:wrap}.access-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:14px}
.access-form{display:grid;gap:12px}.access-form label{display:grid;gap:5px}.access-form select[multiple]{min-height:112px}
.access-source{font-size:.76rem;color:var(--muted)}
</style>
<div class="page-title">
  <div><h1>System → Access → Settings</h1><p>View and edit OPNsense shell and authentication settings on each managed firewall.</p></div>
  <div class="access-tabs">
    <a class="button secondary" href="/system_access_users.php">Users</a>
    <a class="button secondary" href="/system_access_groups.php">Groups</a>
    <a class="button" href="/system_access_settings.php">Settings</a>
    <a class="button secondary" href="/system_access_servers.php">Servers</a>
  </div>
</div>
<?php if(is_array($message)): ?><div class="alert <?= !empty($message['ok'])?'goodbox':'error' ?>"><strong>System Access</strong><div><?= h((string)($message['text']??'')) ?></div></div><?php endif; ?>
<div class="access-grid">
<?php foreach($firewalls as $firewall): $fid=(int)$firewall['id']; $state=$states[$fid]; $settings=$state['settings']; $groups=$state['groups']; $servers=$state['servers']; ?>
  <div class="card management-card">
    <div class="management-card-header">
      <div><h2><?= h((string)$firewall['name']) ?></h2><div class="access-source"><?= h((string)$state['source']) ?></div></div>
      <?php if($state['writable']): ?><span class="badge good">Editable</span><?php else: ?><span class="badge warning">Read only</span><?php endif; ?>
    </div>
    <?php if(!$state['ok']): ?>
      <div class="alert error"><?= h((string)$state['error']) ?></div>
    <?php else: ?>
      <?php if(!$state['writable'] && $state['error']!==''): ?><div class="alert warningbox"><strong>Read-only fallback.</strong><div><?= h((string)$state['error']) ?></div></div><?php endif; ?>
      <form method="post" action="/system_access_settings_action.php" class="access-form">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="firewall_id" value="<?= $fid ?>">
        <label>Inactivity timeout
          <input type="number" min="1" name="autologout" value="<?= h((string)($settings['autologout']??'')) ?>" placeholder="Minutes">
          <small class="muted">Minutes. Empty keeps the OPNsense default/no automatic shell logout.</small>
        </label>
        <label>Authentication servers
          <select name="authmode[]" multiple>
            <?php $selectedAuth=is_array($settings['authmode']??null)?$settings['authmode']:[]; foreach($servers as $server): $name=trim((string)($server['name']??'')); if($name==='') continue; ?>
              <option value="<?= h($name) ?>" <?= in_array($name,$selectedAuth,true)?'selected':'' ?>><?= h($name) ?></option>
            <?php endforeach; ?>
          </select>
          <small class="muted">One or more servers. Empty means OPNsense default: Local Database.</small>
        </label>
        <label>Sudo
          <select name="sudo_allow_wheel">
            <?php $sudo=(string)($settings['sudo_allow_wheel']??''); ?>
            <option value="" <?= $sudo===''?'selected':'' ?>>Disallow</option>
            <option value="1" <?= $sudo==='1'?'selected':'' ?>>Ask password</option>
            <option value="2" <?= $sudo==='2'?'selected':'' ?>>No password</option>
          </select>
        </label>
        <label>Additional sudo group
          <select name="sudo_allow_group">
            <option value="">wheel only</option>
            <?php $sudoGroup=(string)($settings['sudo_allow_group']??''); foreach($groups as $group): ?>
              <option value="<?= h((string)$group) ?>" <?= $sudoGroup===(string)$group?'selected':'' ?>>wheel, <?= h((string)$group) ?></option>
            <?php endforeach; ?>
          </select>
        </label>
        <label>User OTP seed
          <select name="user_allow_gen_token[]" multiple>
            <?php $otpGroups=is_array($settings['user_allow_gen_token']??null)?$settings['user_allow_gen_token']:[]; foreach($groups as $group): ?>
              <option value="<?= h((string)$group) ?>" <?= in_array((string)$group,$otpGroups,true)?'selected':'' ?>><?= h((string)$group) ?></option>
            <?php endforeach; ?>
          </select>
          <small class="muted">Groups whose users may generate their own OTP seed.</small>
        </label>
        <div><button class="button" type="submit" <?= !$state['writable']?'disabled':'' ?>>Save settings</button></div>
      </form>
    <?php endif; ?>
  </div>
<?php endforeach; ?>
</div>
<?php require __DIR__ . '/inc/footer.php'; ?>
