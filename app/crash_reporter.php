<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/agent_deployment.php';

require_login();

$firewallId = (int)($_GET['firewall_id'] ?? $_POST['firewall_id'] ?? 0);
$firewall = firewall_by_id($firewallId);

$agentStmt = db()->prepare(
    'SELECT * FROM agents WHERE firewall_id = ? AND enabled = 1 ORDER BY id DESC LIMIT 1'
);
$agentStmt->execute([$firewallId]);
$agent = $agentStmt->fetch() ?: null;

function crash_reporter_latest_job(int $agentId): ?array
{
    $statement = db()->prepare(
        'SELECT * FROM agent_jobs WHERE agent_id = ? AND job_type = ? ORDER BY id DESC LIMIT 1'
    );
    $statement->execute([$agentId, 'crash_reporter']);
    $row = $statement->fetch();
    return $row ?: null;
}

function crash_reporter_queue(array $agent, string $action, array $extra = []): int
{
    if ((int)($agent['enabled'] ?? 0) !== 1) {
        throw new RuntimeException('Agent is disabled.');
    }
    $lastSeen = !empty($agent['last_seen_at']) ? (strtotime((string)$agent['last_seen_at']) ?: 0) : 0;
    if ($lastSeen <= 0 || (time() - $lastSeen) >= 300) {
        throw new RuntimeException('Agent is stale/offline. Crash Reporter requires a live agent.');
    }
    if (version_compare((string)($agent['last_version'] ?? '0.0.0'), '0.1.16', '<')) {
        throw new RuntimeException('Crash Reporter requires opnSentral agent 0.1.16 or newer.');
    }
    if (!in_array($action, ['inspect', 'dismiss', 'submit'], true)) {
        throw new RuntimeException('Invalid Crash Reporter action.');
    }

    $pending = db()->prepare(
        'SELECT id FROM agent_jobs WHERE agent_id = ? AND job_type = ? AND status IN (?, ?) ORDER BY id DESC LIMIT 1'
    );
    $pending->execute([(int)$agent['id'], 'crash_reporter', 'queued', 'running']);
    $existing = $pending->fetchColumn();
    if ($existing !== false) {
        throw new RuntimeException('Crash Reporter job #' . (int)$existing . ' is already queued or running. Wait for it to finish before starting another action.');
    }

    $payload = array_merge(['action' => $action], $extra);
    $statement = db()->prepare(
        'INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at) VALUES(?, ?, ?, ?, ?)'
    );
    agent_execute_with_retry($statement, [
        (int)$agent['id'],
        'crash_reporter',
        json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
        'queued',
        gmdate('c'),
    ]);
    return (int)db()->lastInsertId();
}

$error = '';
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    try {
        if (!$agent) {
            throw new RuntimeException('No enabled opnSentral agent is linked to this firewall.');
        }
        $action = trim((string)($_POST['action'] ?? ''));
        if ($action === 'refresh') {
            crash_reporter_queue($agent, 'inspect');
            $message = 'Crash report refresh queued.';
        } elseif ($action === 'dismiss') {
            crash_reporter_queue($agent, 'dismiss');
            $message = 'Dismiss queued.';
        } elseif ($action === 'submit') {
            $email = trim((string)($_POST['email'] ?? ''));
            $description = trim((string)($_POST['description'] ?? ''));
            if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
                throw new RuntimeException('Enter a valid email address or leave it blank.');
            }
            if (mb_strlen($email) > 254) throw new RuntimeException('Email address is too long.');
            if (mb_strlen($description) > 4000) throw new RuntimeException('Problem description may contain at most 4000 characters.');
            crash_reporter_queue($agent, 'submit', ['email' => $email, 'description' => $description]);
            $message = 'Crash report submission queued.';
        } else {
            throw new RuntimeException('Unknown Crash Reporter action.');
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

$job = $agent ? crash_reporter_latest_job((int)$agent['id']) : null;

if ($_SERVER['REQUEST_METHOD'] !== 'POST' && $agent && version_compare((string)($agent['last_version'] ?? '0.0.0'), '0.1.16', '>=') && $job === null) {
    try {
        crash_reporter_queue($agent, 'inspect');
        $job = crash_reporter_latest_job((int)$agent['id']);
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

$result = null;
if ($job && (string)$job['status'] === 'completed') {
    $decoded = json_decode((string)$job['result_json'], true);
    if (is_array($decoded)) $result = $decoded;
}

require __DIR__ . '/inc/header.php';
?>
<style>
.crash-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(310px,.34fr);gap:16px;align-items:start}
.crash-report-card{padding:0;overflow:hidden}.crash-report-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px;border-bottom:1px solid #343943}.crash-report-head h2{margin:0}.crash-report-body{padding:16px}.crash-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.crash-section{margin-top:12px;border:1px solid #343943;border-radius:6px;overflow:hidden}.crash-section summary{padding:10px 12px;font-weight:700;cursor:pointer;background:#10131a}.crash-section pre{margin:0;border-radius:0;max-height:420px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}.crash-form label{display:block;font-weight:700;margin:12px 0 6px}.crash-form input,.crash-form textarea{width:100%;box-sizing:border-box}.crash-form textarea{min-height:120px}.crash-danger{background:#8c2929}.crash-meta{display:grid;gap:8px}.crash-meta-row{padding:10px;border:1px solid #343943;border-radius:5px}.crash-wait{padding:16px}.crash-status-good{color:#70d58d}.crash-status-bad{color:#ff7676}@media(max-width:900px){.crash-grid{grid-template-columns:1fr}}
</style>

<div class="page-title">
    <div>
        <h1>Crash Reporter</h1>
        <p><?= h((string)$firewall['name']) ?> · <?= h((string)$firewall['base_url']) ?></p>
    </div>
    <a class="button secondary" href="/firewall_view.php?id=<?= $firewallId ?>#system-notifications">Back to firewall</a>
</div>

<?php if ($message): ?><div class="alert goodbox"><?= h($message) ?></div><?php endif; ?>
<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<?php if (!$agent): ?>
<div class="alert error">No enabled opnSentral agent is linked to this firewall. Crash report details and actions are intentionally performed by the local agent, not through the legacy OPNsense WebGUI.</div>
<?php elseif (version_compare((string)($agent['last_version'] ?? '0.0.0'), '0.1.16', '<')): ?>
<div class="alert error">This firewall is running agent <?= h((string)($agent['last_version'] ?? 'unknown')) ?>. Crash Reporter requires agent 0.1.16 or newer. Update the agent first.</div>
<?php else: ?>
<div class="crash-grid">
    <section class="card crash-report-card">
        <div class="crash-report-head">
            <h2>Report contents</h2>
            <form method="post">
                <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
                <input type="hidden" name="firewall_id" value="<?= $firewallId ?>">
                <button type="submit" name="action" value="refresh" class="secondary">Refresh report</button>
            </form>
        </div>
        <div class="crash-report-body">
            <?php if (!$job): ?>
                <div class="crash-wait">No Crash Reporter job has been run yet.</div>
            <?php elseif (in_array((string)$job['status'], ['queued','running'], true)): ?>
                <div class="crash-wait">Waiting for the local agent… Job #<?= (int)$job['id'] ?> is <?= h((string)$job['status']) ?>. This page refreshes automatically.</div>
                <meta http-equiv="refresh" content="5">
            <?php elseif ((string)$job['status'] === 'failed'): ?>
                <div class="alert error">Agent job #<?= (int)$job['id'] ?> failed: <?= h((string)$job['error']) ?></div>
            <?php elseif (is_array($result)): ?>
                <?php if (($result['has_report'] ?? false) === true): ?>
                    <p class="crash-status-bad"><strong>Pending crash report detected.</strong></p>
                    <?php foreach (($result['sections'] ?? []) as $section): if (!is_array($section)) continue; ?>
                        <details class="crash-section" <?= (($section['title'] ?? '') === 'PHP Errors') ? 'open' : '' ?>>
                            <summary><?= h((string)($section['title'] ?? 'Report section')) ?><?= !empty($section['truncated']) ? ' · truncated' : '' ?></summary>
                            <pre><?= h((string)($section['content'] ?? '')) ?></pre>
                        </details>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p class="crash-status-good"><strong>No pending crash report.</strong></p>
                    <?php if (!empty($result['message'])): ?><p><?= h((string)$result['message']) ?></p><?php endif; ?>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </section>

    <aside class="card">
        <h2>Actions</h2>
        <div class="crash-meta">
            <div class="crash-meta-row"><strong>Agent</strong><br><?= h((string)$agent['last_version']) ?></div>
            <?php if ($job): ?><div class="crash-meta-row"><strong>Last job</strong><br>#<?= (int)$job['id'] ?> · <?= h((string)$job['status']) ?><?php if (!empty($job['finished_at'])): ?><br><span class="muted"><?= h((string)$job['finished_at']) ?> UTC</span><?php endif; ?></div><?php endif; ?>
        </div>

        <?php if (is_array($result) && ($result['has_report'] ?? false) === true && !in_array((string)($job['status'] ?? ''), ['queued','running'], true)): ?>
        <form method="post" class="crash-form" style="margin-top:16px" onsubmit="return confirm('Submit this crash report to the OPNsense developers?');">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <input type="hidden" name="firewall_id" value="<?= $firewallId ?>">
            <label>Email (optional)</label>
            <input type="email" name="email" maxlength="254" autocomplete="email">
            <label>Problem description (optional)</label>
            <textarea name="description" maxlength="4000" placeholder="Short problem description or steps to reproduce"></textarea>
            <div class="crash-actions" style="margin-top:12px">
                <button type="submit" name="action" value="submit">Submit report</button>
            </div>
        </form>
        <form method="post" style="margin-top:10px" onsubmit="return confirm('Dismiss and delete the pending crash report from this OPNsense?');">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <input type="hidden" name="firewall_id" value="<?= $firewallId ?>">
            <button type="submit" name="action" value="dismiss" class="crash-danger">Dismiss report</button>
        </form>
        <?php endif; ?>
    </aside>
</div>
<?php endif; ?>

<?php require __DIR__ . '/inc/footer.php'; ?>
