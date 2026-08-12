<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/system_access_inventory.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$fleet = access_load_fleet_inventory($firewalls);
$userNames = [];
foreach ($fleet as $entry) {
    foreach (array_keys($entry['users'] ?? []) as $name) $userNames[$name] = true;
}
$userNames = array_keys($userNames);
natcasesort($userNames);

require __DIR__ . '/inc/header.php';
?>
<style>
.access-toolbar{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.access-tabs{display:flex;gap:8px}.access-tabs a{min-width:90px;text-align:center}
.access-table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.access-table{border-collapse:separate;border-spacing:0;min-width:max(980px,100%);width:100%}
.access-table th,.access-table td{padding:10px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:top}
.access-table th:last-child,.access-table td:last-child{border-right:0}.access-table tr:last-child td{border-bottom:0}
.access-table thead th{position:sticky;top:0;z-index:3;background:var(--table-head);text-align:center}
.access-table .object-col{position:sticky;left:0;z-index:2;min-width:210px;background:var(--card);text-align:left}.access-table thead .object-col{z-index:4;background:var(--table-head)}
.access-firewall{min-width:190px;text-align:center}.access-cell{min-width:190px;font-size:.86rem}.access-cell small{display:block;margin-top:3px;color:var(--muted)}
.access-tags{display:flex;gap:4px;flex-wrap:wrap;margin-top:5px}.access-tag{display:inline-block;padding:2px 6px;border-radius:999px;background:rgba(127,127,127,.14);font-size:.72rem}
</style>
<div class="page-title">
    <div><h1>System → Access → Users</h1><p>Compare local OPNsense users across all managed firewalls.</p></div>
    <div class="access-tabs"><a class="button" href="/system_access_users.php">Users</a><a class="button secondary" href="/system_access_groups.php">Groups</a></div>
</div>
<div class="alert warningbox"><strong>Read-only inventory.</strong> Password hashes and OTP seeds are never displayed. This first Access release is for comparison and verification before central account writes are enabled.</div>
<div class="access-toolbar"><strong><?= count($userNames) ?> unique user<?= count($userNames) === 1 ? '' : 's' ?> across <?= count($firewalls) ?> managed firewall<?= count($firewalls) === 1 ? '' : 's' ?></strong><button type="button" class="button secondary" onclick="window.location.reload()">Refresh</button></div>
<div class="access-table-wrap"><table class="access-table"><thead><tr><th class="object-col">User</th><?php foreach ($fleet as $entry): ?><th class="access-firewall"><?= h((string) $entry['firewall']['name']) ?><?php if (!$entry['ok']): ?><br><span class="badge bad">Read failed</span><?php endif; ?></th><?php endforeach; ?></tr></thead><tbody>
<?php if (!$userNames): ?><tr><td colspan="<?= count($fleet)+1 ?>">No local users found.</td></tr><?php endif; ?>
<?php foreach ($userNames as $name): ?><tr><td class="object-col"><strong><?= h($name) ?></strong></td><?php foreach ($fleet as $entry): $user=$entry['users'][$name]??null; ?><td class="access-cell"><?php if (!$entry['ok']): ?><span class="muted">Unavailable</span><?php elseif (!is_array($user)): ?><span class="badge neutral">Missing</span><?php else: ?><span class="badge good">Present</span><?php if ($user['disabled']): ?> <span class="badge bad">Disabled</span><?php endif; ?><small><?= h((string)($user['description'] ?: 'No description')) ?></small><?php if ($user['uid']!==''): ?><small>UID <?= h((string)$user['uid']) ?></small><?php endif; ?><small><?= $user['has_password'] ? 'Password configured' : 'No local password' ?><?= $user['otp'] ? ' · OTP configured' : '' ?></small><?php if ($user['groups']): ?><div class="access-tags"><?php foreach ($user['groups'] as $group): ?><span class="access-tag">group: <?= h($group) ?></span><?php endforeach; ?></div><?php endif; ?><?php if ($user['privileges']): ?><div class="access-tags"><?php foreach ($user['privileges'] as $priv): ?><span class="access-tag"><?= h($priv) ?></span><?php endforeach; ?></div><?php endif; ?><?php endif; ?></td><?php endforeach; ?></tr><?php endforeach; ?>
</tbody></table></div>
<?php require __DIR__ . '/inc/footer.php'; ?>
