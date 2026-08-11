<?php
declare(strict_types=1);
require_once __DIR__.'/inc/config.php';
require_login();
$firewalls=db()->query('SELECT id,name FROM firewalls ORDER BY name')->fetchAll();
$agents=db()->query('SELECT a.*,f.name AS firewall_name FROM agents a LEFT JOIN firewalls f ON f.id=a.firewall_id ORDER BY COALESCE(f.name,a.name,a.agent_id)')->fetchAll();
$credentials=$_SESSION['new_agent_credentials']??null;
unset($_SESSION['new_agent_credentials']);
require __DIR__.'/inc/header.php';
?>
<div class="page-title management-page-title">
    <div>
        <h1>Agents</h1>
        <p>Registered read-only OPNsense reporting agents.</p>
    </div>
    <div class="management-toolbar">
        <button type="button" class="button secondary" onclick="window.location.reload()">
            Refresh
        </button>
    </div>
</div>

<?php if($credentials): ?>
<div class="alert warning">
    <strong>Save these credentials now. The secret is shown only once.</strong>
    <pre>AGENT_ID=<?=h($credentials['agent_id']) . "\n"?>AGENT_SECRET=<?=h($credentials['secret'])?></pre>
</div>
<?php endif; ?>

<div class="management-overview-bar">
    <div>
        <strong>Agent overview</strong>
        <div class="management-summary">
            <?=count($agents)?> registered agent<?=count($agents)===1?'':'s'?>
        </div>
    </div>
</div>

<div class="card management-card">
    <div class="management-card-header">
        <div>
            <h2>Registered agents</h2>
            <div class="management-summary">
                Read-only status reporters linked to managed firewalls.
            </div>
        </div>
    </div>

    <div class="table-scroll management-table-wrap">
        <table class="management-table">
            <thead>
                <tr>
                    <th>Firewall</th>
                    <th>Agent</th>
                    <th>Last seen</th>
                    <th>OPNsense</th>
                    <th>Services</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php if(!$agents): ?>
                <tr><td colspan="7">No agents registered.</td></tr>
            <?php endif; ?>

            <?php foreach($agents as $agent):
                $payload=json_decode((string)$agent['last_payload'],true);
                $services=is_array($payload['services']??null)?$payload['services']:[];
                $last=$agent['last_seen_at']?(strtotime($agent['last_seen_at'])?:0):0;
                $fresh=$last>0&&time()-$last<150;
            ?>
                <tr>
                    <td><?=h((string)($agent['firewall_name']??$agent['name']??'Unassigned'))?></td>
                    <td>
                        <code><?=h(substr($agent['agent_id'],0,12))?>…</code>
                        <br><small><?=h($agent['last_hostname'])?></small>
                    </td>
                    <td><?=h($agent['last_seen_at']?:'Never')?></td>
                    <td><?=h($agent['last_opnsense_version']?:'—')?></td>
                    <td><?=count($services)?></td>
                    <td>
                        <span class="badge <?=$fresh&&$agent['enabled']?'good':'bad'?>">
                            <?=$agent['enabled']?($fresh?'Online':'Stale'):'Disabled'?>
                        </span>
                    </td>
                    <td>
                        <form method="post" action="/agents_action.php" class="management-row-actions">
                            <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
                            <input type="hidden" name="id" value="<?=(int)$agent['id']?>">
                            <button class="button secondary" name="action" value="toggle">
                                <?=$agent['enabled']?'Disable':'Enable'?>
                            </button>
                            <button
                                class="button danger"
                                name="action"
                                value="delete"
                                onclick="return confirm('Delete this agent?')"
                            >
                                Delete
                            </button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="management-secondary-grid">
    <div class="card management-card">
        <div class="management-card-header">
            <div>
                <h2>Register agent</h2>
                <div class="management-summary">
                    Create credentials for a new reporting agent.
                </div>
            </div>
        </div>

        <form method="post" action="/agents_action.php" class="management-form-grid">
            <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
            <input type="hidden" name="action" value="create">

            <label>
                Firewall
                <select name="firewall_id">
                    <option value="0">Unassigned</option>
                    <?php foreach($firewalls as $fw): ?>
                        <option value="<?=(int)$fw['id']?>"><?=h($fw['name'])?></option>
                    <?php endforeach; ?>
                </select>
            </label>

            <label>
                Label
                <input name="name" placeholder="Optional">
            </label>

            <div class="management-form-action">
                <button class="button" type="submit">Create credentials</button>
            </div>
        </form>
    </div>

    <div class="card management-card">
        <div class="management-card-header">
            <div>
                <h2>Minimal agent installation</h2>
                <div class="management-summary">
                    Configure the agent and test its first report.
                </div>
            </div>
        </div>

        <p>Create:</p>
        <pre>/usr/local/etc/opncentral-agent.conf</pre>
        <pre>{
  "server_url": "https://YOUR-OPNCENTRAL/api/agent_report.php",
  "agent_id": "PASTE_AGENT_ID",
  "agent_secret": "PASTE_AGENT_SECRET",
  "verify_tls": true
}</pre>
        <p>Test with <code>configctl opncentralagent report</code>.</p>
    </div>
</div>

<?php require __DIR__.'/inc/footer.php'; ?>
