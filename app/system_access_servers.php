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
.access-tabs{display:flex;gap:8px;flex-wrap:wrap}.server-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:14px}
.server-list{width:100%;border-collapse:collapse}.server-list th,.server-list td{padding:9px;border-bottom:1px solid var(--border);vertical-align:top}.server-list th{text-align:left}
.server-actions{display:flex;gap:6px;flex-wrap:wrap}.access-source{font-size:.76rem;color:var(--muted)}
</style>
<div class="page-title">
  <div><h1>System → Access → Servers</h1><p>View and manage OPNsense authentication servers used by WebGUI and other authentication services.</p></div>
  <div class="access-tabs">
    <a class="button secondary" href="/system_access_users.php">Users</a>
    <a class="button secondary" href="/system_access_groups.php">Groups</a>
    <a class="button secondary" href="/system_access_settings.php">Settings</a>
    <a class="button" href="/system_access_servers.php">Servers</a>
  </div>
</div>
<?php if(is_array($message)): ?><div class="alert <?= !empty($message['ok'])?'goodbox':'error' ?>"><strong>Authentication servers</strong><div><?= h((string)($message['text']??'')) ?></div></div><?php endif; ?>
<div class="server-grid">
<?php foreach($firewalls as $firewall): $fid=(int)$firewall['id']; $state=$states[$fid]; ?>
  <div class="card management-card">
    <div class="management-card-header">
      <div><h2><?= h((string)$firewall['name']) ?></h2><div class="access-source"><?= h((string)$state['source']) ?></div></div>
      <div class="server-actions"><?php if($state['writable']): ?><a class="button" href="/system_access_server_edit.php?firewall_id=<?= $fid ?>">Add server</a><?php else: ?><span class="badge warning">Read only</span><?php endif; ?></div>
    </div>
    <?php if(!$state['ok']): ?><div class="alert error"><?= h((string)$state['error']) ?></div>
    <?php else: ?>
      <?php if(!$state['writable'] && $state['error']!==''): ?>
        <div class="alert warningbox">
          <div><?= h((string)$state['error']) ?></div>
          <form method="post" action="/system_access_support_action.php" style="margin-top:8px">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <input type="hidden" name="firewall_id" value="<?= $fid ?>">
            <button class="button" type="submit">Install / update editing support</button>
          </form>
        </div>
      <?php endif; ?>
      <table class="server-list">
        <thead><tr><th>Name</th><th>Type</th><th>Target</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach($state['servers'] as $server): if(!is_array($server)) continue; $builtin=!empty($server['builtin']); ?>
          <tr>
            <td><strong><?= h((string)($server['name']??'Unnamed')) ?></strong><?php if($builtin): ?> <span class="badge neutral">Built in</span><?php endif; ?></td>
            <td><?= h((string)($server['type']??'unknown')) ?></td>
            <td><?php
              $type=(string)($server['type']??'');
              if(in_array($type,['ldap','ldap-totp','radius'],true)) echo h((string)($server['host']??'—'));
              else echo '—';
            ?></td>
            <td>
              <?php if(!$builtin && $state['writable']): ?>
                <div class="server-actions">
                  <a class="button secondary" href="/system_access_server_edit.php?firewall_id=<?= $fid ?>&amp;index=<?= (int)($server['index']??-1) ?>">Edit</a>
                  <form method="post" action="/system_access_server_action.php" style="display:inline" onsubmit="return confirm('Delete authentication server <?= h((string)($server['name']??'')) ?>?')">
                    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="firewall_id" value="<?= $fid ?>">
                    <input type="hidden" name="index" value="<?= (int)($server['index']??-1) ?>">
                    <button class="button danger" type="submit">Delete</button>
                  </form>
                </div>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>
<?php endforeach; ?>
</div>
<?php require __DIR__ . '/inc/footer.php'; ?>
