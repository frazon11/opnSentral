<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$id = (int) ($_GET['firewall_id'] ?? 0);
$firewall = $id > 0 ? firewall_by_id($id) : null;
$error = '';
$servers = [];
$bridgeReady = false;
$bridgeError = '';
$result = $_SESSION['system_access_result'] ?? null;
unset($_SESSION['system_access_result']);

function access_servers_text(SimpleXMLElement $node, string $name): string
{
    return isset($node->{$name}) ? trim((string) $node->{$name}) : '';
}

function access_servers_bool(SimpleXMLElement $node, string $name): bool
{
    return isset($node->{$name}) && trim((string) $node->{$name}) !== '' && trim((string) $node->{$name}) !== '0';
}

function access_servers_label(string $type): string
{
    return match ($type) {
        'local' => 'Local Database',
        'totp' => 'Local + Timebased One Time Password',
        'ldap' => 'LDAP',
        'ldap-totp' => 'LDAP + Timebased One Time Password',
        'radius' => 'RADIUS',
        default => $type !== '' ? $type : 'Unknown',
    };
}

if ($firewall !== null) {
    try {
        $raw = opn_download($firewall, 'core/backup/download/this');
        $xml = simplexml_load_string($raw, SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        if (!$xml instanceof SimpleXMLElement) {
            throw new RuntimeException('Could not parse OPNsense configuration XML.');
        }

        $webgui = $xml->system->webgui;
        $servers[] = [
            'index' => 'local',
            'name' => 'Local Database',
            'type' => 'local',
            'host' => 'OPNsense',
            'enable_password_policy_constraints' => access_servers_bool($webgui, 'enable_password_policy_constraints'),
            'password_policy_duration' => access_servers_text($webgui, 'password_policy_duration'),
            'password_policy_length' => access_servers_text($webgui, 'password_policy_length'),
            'password_policy_complexity' => access_servers_bool($webgui, 'password_policy_complexity'),
            'password_policy_compliance' => access_servers_bool($webgui, 'password_policy_compliance'),
        ];

        $idx = 0;
        foreach ($xml->system->authserver as $node) {
            $item = [
                'index' => (string) $idx,
                'name' => access_servers_text($node, 'name'),
                'type' => access_servers_text($node, 'type'),
                'host' => access_servers_text($node, 'host'),
            ];
            foreach ($node->children() as $key => $value) {
                if (in_array((string)$key, ['ldap_bindpw','radius_secret'], true)) {
                    $item['has_' . (string)$key] = trim((string)$value) !== '';
                } else {
                    $item[(string)$key] = trim((string)$value);
                }
            }
            $servers[] = $item;
            $idx++;
        }

        try {
            $snapshot = opn_raw_request($firewall, 'opnsentralagent/access/snapshot', 'GET', null, 10);
            $bridgeReady = ($snapshot['status'] ?? '') === 'ok';
            if (!$bridgeReady) {
                $bridgeError = 'System Access API bridge is not available on this firewall.';
            }
        } catch (Throwable $exception) {
            $bridgeError = $exception->getMessage();
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

$editIndex = isset($_GET['edit']) ? trim((string) $_GET['edit']) : '';
$editServer = null;
foreach ($servers as $server) {
    if ((string) $server['index'] === $editIndex) {
        $editServer = $server;
        break;
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.access-tabs{display:flex;gap:8px;flex-wrap:wrap}
.access-server-toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.access-server-toolbar select{min-width:280px}
.access-server-table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.access-server-table{width:100%;border-collapse:collapse}
.access-server-table th,.access-server-table td{padding:10px 12px;border-bottom:1px solid var(--border);text-align:left;vertical-align:middle}
.access-server-table th{background:var(--table-head)}
.access-server-table tr:last-child td{border-bottom:0}
.access-server-form{display:grid;grid-template-columns:repeat(2,minmax(220px,1fr));gap:12px}
.access-server-form label{display:flex;flex-direction:column;gap:5px}
.access-server-form .wide{grid-column:1/-1}
.access-server-check{display:flex!important;flex-direction:row!important;align-items:center;gap:8px!important}
.access-server-actions{grid-column:1/-1;display:flex;gap:8px;align-items:center}
@media(max-width:800px){.access-server-form{grid-template-columns:1fr}}
</style>

<div class="page-title">
    <div>
        <h1>System → Access → Servers</h1>
        <p>View and edit authentication servers on one managed OPNsense firewall.</p>
    </div>
    <div class="access-tabs">
        <a class="button secondary" href="/system_access_users.php">Users</a>
        <a class="button secondary" href="/system_access_groups.php">Groups</a>
        <a class="button" href="/system_access_servers.php<?= $id ? '?firewall_id=' . $id : '' ?>">Servers</a>
    </div>
</div>

<?php if (is_array($result)): ?>
<div class="alert <?= !empty($result['ok']) ? 'goodbox' : 'error' ?>">
    <?= h((string) ($result['message'] ?? '')) ?>
</div>
<?php endif; ?>

<div class="access-server-toolbar">
    <form method="get" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <label for="firewall_id"><strong>OPNsense</strong></label>
        <select id="firewall_id" name="firewall_id" onchange="this.form.submit()">
            <option value="">Select firewall</option>
            <?php foreach ($firewalls as $item): ?>
                <option value="<?= (int)$item['id'] ?>" <?= $id === (int)$item['id'] ? 'selected' : '' ?>><?= h((string)$item['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </form>
    <?php if ($firewall !== null): ?>
        <?php if ($bridgeReady): ?>
            <span class="badge good">Write bridge available</span>
        <?php else: ?>
            <span class="badge warning">Read-only</span>
        <?php endif; ?>
    <?php endif; ?>
</div>

<?php if ($error !== ''): ?>
    <div class="alert error"><?= h($error) ?></div>
<?php elseif ($firewall === null): ?>
    <div class="empty">Select an OPNsense firewall.</div>
<?php else: ?>
    <?php if (!$bridgeReady): ?>
        <div class="alert warningbox">
            <strong>Read-only on this firewall.</strong>
            Current values are read through the OPNsense backup API. Editing is enabled only when the opnSentral System Access API bridge is installed on this firewall.
            <?php if ($bridgeError !== ''): ?><div class="muted" style="margin-top:5px"><?= h($bridgeError) ?></div><?php endif; ?>
        </div>
    <?php endif; ?>

    <div class="access-server-table-wrap">
        <table class="access-server-table">
            <thead><tr><th>Server Name</th><th>Type</th><th>Host Name</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach ($servers as $server): ?>
                <tr>
                    <td><strong><?= h((string)$server['name']) ?></strong></td>
                    <td><?= h(access_servers_label((string)$server['type'])) ?></td>
                    <td><?= h((string)(($server['host'] ?? '') !== '' ? $server['host'] : '—')) ?></td>
                    <td>
                        <?php if ($bridgeReady): ?>
                            <a class="button secondary" href="/system_access_servers.php?firewall_id=<?= $id ?>&amp;edit=<?= rawurlencode((string)$server['index']) ?>">Edit</a>
                        <?php else: ?>
                            <button class="button secondary" disabled>Edit</button>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <?php if (is_array($editServer) && $bridgeReady): $type=(string)$editServer['type']; ?>
        <div class="card management-card" style="margin-top:14px">
            <div class="management-card-header">
                <div>
                    <h2>Edit <?= h((string)$editServer['name']) ?></h2>
                    <div class="management-summary"><?= h(access_servers_label($type)) ?></div>
                </div>
            </div>
            <form method="post" action="/system_access_settings_action.php" class="access-server-form">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                <input type="hidden" name="action" value="set_server">
                <input type="hidden" name="firewall_id" value="<?= $id ?>">
                <input type="hidden" name="server_index" value="<?= h((string)$editServer['index']) ?>">

                <?php if ($type === 'local'): ?>
                    <label class="access-server-check wide"><input type="checkbox" name="enable_password_policy_constraints" value="1" <?= !empty($editServer['enable_password_policy_constraints']) ? 'checked' : '' ?>> Enable password policy constraints</label>
                    <label>Password duration
                        <input type="number" min="1" name="password_policy_duration" value="<?= h((string)($editServer['password_policy_duration'] ?? '')) ?>">
                    </label>
                    <label>Minimum password length
                        <input type="number" min="1" name="password_policy_length" value="<?= h((string)($editServer['password_policy_length'] ?? '')) ?>">
                    </label>
                    <label class="access-server-check"><input type="checkbox" name="password_policy_complexity" value="1" <?= !empty($editServer['password_policy_complexity']) ? 'checked' : '' ?>> Enforce password complexity</label>
                    <label class="access-server-check"><input type="checkbox" name="password_policy_compliance" value="1" <?= !empty($editServer['password_policy_compliance']) ? 'checked' : '' ?>> Require SHA-512 password hashing</label>
                <?php else: ?>
                    <label>Descriptive name
                        <input type="text" name="name" required value="<?= h((string)($editServer['name'] ?? '')) ?>">
                    </label>

                    <?php if ($type === 'totp' || $type === 'ldap-totp'): ?>
                        <label>Token length
                            <select name="otpLength">
                                <option value="6" <?= (string)($editServer['otpLength'] ?? '6') === '6' ? 'selected' : '' ?>>6</option>
                                <option value="8" <?= (string)($editServer['otpLength'] ?? '') === '8' ? 'selected' : '' ?>>8</option>
                            </select>
                        </label>
                        <label>Time window
                            <input type="number" min="1" name="timeWindow" placeholder="30" value="<?= h((string)($editServer['timeWindow'] ?? '')) ?>">
                        </label>
                        <label>Grace period
                            <input type="number" min="0" name="graceperiod" placeholder="10" value="<?= h((string)($editServer['graceperiod'] ?? '')) ?>">
                        </label>
                        <label class="access-server-check"><input type="checkbox" name="passwordFirst" value="1" <?= !empty($editServer['passwordFirst']) ? 'checked' : '' ?>> Reverse token order (password first)</label>
                    <?php endif; ?>

                    <?php if ($type === 'ldap' || $type === 'ldap-totp'): ?>
                        <label>Hostname or IP address<input type="text" name="host" required value="<?= h((string)($editServer['host'] ?? '')) ?>"></label>
                        <label>Port<input type="number" min="1" max="65535" name="ldap_port" required value="<?= h((string)($editServer['ldap_port'] ?? '')) ?>"></label>
                        <label>Transport
                            <select name="ldap_urltype">
                                <?php foreach (['TCP - Standard','StartTLS','SSL - Encrypted'] as $value): ?><option value="<?= h($value) ?>" <?= (string)($editServer['ldap_urltype'] ?? '') === $value ? 'selected' : '' ?>><?= h($value) ?></option><?php endforeach; ?>
                            </select>
                        </label>
                        <label>Protocol version
                            <select name="ldap_protver"><option value="3" <?= (string)($editServer['ldap_protver'] ?? '3') === '3' ? 'selected' : '' ?>>3</option><option value="2" <?= (string)($editServer['ldap_protver'] ?? '') === '2' ? 'selected' : '' ?>>2</option></select>
                        </label>
                        <label>Search scope
                            <select name="ldap_scope"><option value="subtree" <?= (string)($editServer['ldap_scope'] ?? '') === 'subtree' ? 'selected' : '' ?>>Entire Subtree</option><option value="one" <?= (string)($editServer['ldap_scope'] ?? '') === 'one' ? 'selected' : '' ?>>One Level</option></select>
                        </label>
                        <label>Base DN<input type="text" name="ldap_basedn" required value="<?= h((string)($editServer['ldap_basedn'] ?? '')) ?>"></label>
                        <label>Authentication containers<input type="text" name="ldap_authcn" required value="<?= h((string)($editServer['ldap_authcn'] ?? '')) ?>"></label>
                        <label>User naming attribute<input type="text" name="ldap_attr_user" required value="<?= h((string)($editServer['ldap_attr_user'] ?? '')) ?>"></label>
                        <label class="wide">Extended query<input type="text" name="ldap_extended_query" value="<?= h((string)($editServer['ldap_extended_query'] ?? '')) ?>"></label>
                        <label>Bind user DN<input type="text" name="ldap_binddn" value="<?= h((string)($editServer['ldap_binddn'] ?? '')) ?>"></label>
                        <label>Bind password<input type="password" autocomplete="new-password" name="ldap_bindpw" placeholder="<?= !empty($editServer['has_ldap_bindpw']) ? 'Stored — leave blank to keep' : 'Not configured' ?>"></label>
                        <label>Group member attribute<input type="text" name="ldap_attr_memberof" value="<?= h((string)($editServer['ldap_attr_memberof'] ?? '')) ?>"></label>
                        <label>MemberOf groups<input type="text" name="ldap_sync_memberof_groups" value="<?= h((string)($editServer['ldap_sync_memberof_groups'] ?? '')) ?>"></label>
                        <label>Default groups<input type="text" name="ldap_sync_default_groups" value="<?= h((string)($editServer['ldap_sync_default_groups'] ?? '')) ?>"></label>
                        <label class="access-server-check"><input type="checkbox" name="ldap_read_properties" value="1" <?= !empty($editServer['ldap_read_properties']) ? 'checked' : '' ?>> Read properties</label>
                        <label class="access-server-check"><input type="checkbox" name="ldap_sync_memberof" value="1" <?= !empty($editServer['ldap_sync_memberof']) ? 'checked' : '' ?>> Synchronize groups</label>
                        <label class="access-server-check"><input type="checkbox" name="ldap_sync_memberof_constraint" value="1" <?= !empty($editServer['ldap_sync_memberof_constraint']) ? 'checked' : '' ?>> Constraint groups</label>
                        <label class="access-server-check"><input type="checkbox" name="ldap_sync_create_local_users" value="1" <?= !empty($editServer['ldap_sync_create_local_users']) ? 'checked' : '' ?>> Automatic user creation</label>
                    <?php elseif ($type === 'radius'): ?>
                        <label>Hostname or IP address<input type="text" name="host" required value="<?= h((string)($editServer['host'] ?? '')) ?>"></label>
                        <label>Authentication port<input type="number" min="1" max="65535" name="radius_auth_port" required value="<?= h((string)($editServer['radius_auth_port'] ?? '1812')) ?>"></label>
                        <label>Accounting port<input type="number" min="1" max="65535" name="radius_acct_port" value="<?= h((string)($editServer['radius_acct_port'] ?? '')) ?>"></label>
                        <label>Authentication timeout<input type="number" min="1" name="radius_timeout" value="<?= h((string)($editServer['radius_timeout'] ?? '5')) ?>"></label>
                        <label>Called Station ID<input type="text" name="radius_stationid" value="<?= h((string)($editServer['radius_stationid'] ?? '')) ?>"></label>
                        <label>Shared secret<input type="password" autocomplete="new-password" name="radius_secret" placeholder="<?= !empty($editServer['has_radius_secret']) ? 'Stored — leave blank to keep' : 'Not configured' ?>"></label>
                        <label>MemberOf groups<input type="text" name="sync_memberof_groups" value="<?= h((string)($editServer['sync_memberof_groups'] ?? '')) ?>"></label>
                        <label>Default groups<input type="text" name="sync_default_groups" value="<?= h((string)($editServer['sync_default_groups'] ?? '')) ?>"></label>
                        <label class="access-server-check"><input type="checkbox" name="sync_memberof" value="1" <?= !empty($editServer['sync_memberof']) ? 'checked' : '' ?>> Synchronize groups</label>
                        <label class="access-server-check"><input type="checkbox" name="sync_create_local_users" value="1" <?= !empty($editServer['sync_create_local_users']) ? 'checked' : '' ?>> Automatic user creation</label>
                    <?php endif; ?>
                <?php endif; ?>

                <div class="access-server-actions">
                    <button class="button" type="submit">Save settings</button>
                    <a class="button secondary" href="/system_access_servers.php?firewall_id=<?= $id ?>">Cancel</a>
                </div>
            </form>
        </div>
    <?php endif; ?>
<?php endif; ?>

<?php require __DIR__ . '/inc/footer.php'; ?>
