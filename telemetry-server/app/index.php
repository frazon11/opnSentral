<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_dashboard_login();
cleanup_old_installations();

$pdo = telemetry_db();
$now = time();
$serverVersion = env_value('TELEMETRY_SERVER_VERSION', 'unknown');

function count_since(PDO $pdo, int $seconds): int
{
    $threshold = gmdate('c', time() - $seconds);
    $statement = $pdo->prepare(
        'SELECT COUNT(*) FROM installations WHERE last_seen >= :threshold'
    );
    $statement->execute(['threshold' => $threshold]);
    return (int) $statement->fetchColumn();
}

$total = (int) $pdo->query(
    'SELECT COUNT(*) FROM installations'
)->fetchColumn();

$active24h = count_since($pdo, 86400);
$active7d = count_since($pdo, 7 * 86400);
$active30d = count_since($pdo, 30 * 86400);

$versions = $pdo->query(
    'SELECT version, COUNT(*) AS installations
     FROM installations
     WHERE last_seen >= "' . gmdate('c', $now - 30 * 86400) . '"
     GROUP BY version
     ORDER BY installations DESC, version DESC'
)->fetchAll();

$architectures = $pdo->query(
    'SELECT architecture, COUNT(*) AS installations
     FROM installations
     WHERE last_seen >= "' . gmdate('c', $now - 30 * 86400) . '"
     GROUP BY architecture
     ORDER BY installations DESC, architecture'
)->fetchAll();

$recent = $pdo->query(
    'SELECT
        substr(installation_hash, 1, 12) AS anonymous_id,
        first_seen,
        last_seen,
        version,
        architecture,
        platform,
        checks
     FROM installations
     ORDER BY last_seen DESC
     LIMIT 200'
)->fetchAll();

function h(string $value): string
{
    return htmlspecialchars(
        $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>opnSentral Telemetry</title>
<style>
:root{font-family:Inter,system-ui,Segoe UI,sans-serif;color:#e7edf1;background:#151a1e}
*{box-sizing:border-box}body{margin:0;background:#151a1e;color:#e7edf1}
main{max-width:1500px;margin:auto;padding:28px}
h1{margin:0}.muted{color:#9eabb4}.page-head{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px}.server-version{font-size:.95rem;color:#9eabb4}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
.card{background:#222a30;border:1px solid #3b4750;padding:18px;border-radius:4px}
.metric{font-size:2rem;font-weight:750;margin-top:8px}
.columns{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
table{width:100%;border-collapse:collapse;background:#222a30;margin-top:14px}
th,td{border:1px solid #3b4750;padding:9px;text-align:left}
th{background:#2c363e}.badge{display:inline-block;padding:3px 8px;background:#264e35;color:#bce8c8}
@media(max-width:900px){.grid,.columns{grid-template-columns:1fr 1fr}}
@media(max-width:600px){.grid,.columns{grid-template-columns:1fr}main{padding:14px}}
</style>
</head>
<body>
<main>
    <div class="page-head">
        <h1>opnSentral Telemetry</h1>
        <span class="server-version">v<?= h($serverVersion) ?></span>
    </div>
    <p class="muted">
        Anonymous active-installation statistics. No raw installation ID,
        firewall data or client IP address is displayed or stored by the application.
    </p>

    <div class="grid">
        <div class="card"><strong>Known installations</strong><div class="metric"><?= $total ?></div></div>
        <div class="card"><strong>Active 24 hours</strong><div class="metric"><?= $active24h ?></div></div>
        <div class="card"><strong>Active 7 days</strong><div class="metric"><?= $active7d ?></div></div>
        <div class="card"><strong>Active 30 days</strong><div class="metric"><?= $active30d ?></div></div>
    </div>

    <div class="columns">
        <section class="card">
            <h2>Versions active in 30 days</h2>
            <?php if (!$versions): ?><p class="muted">No data yet.</p><?php endif; ?>
            <?php foreach ($versions as $row): ?>
                <p><span class="badge"><?= h((string)$row['installations']) ?></span>
                <?= h((string)$row['version']) ?></p>
            <?php endforeach; ?>
        </section>

        <section class="card">
            <h2>Architectures active in 30 days</h2>
            <?php if (!$architectures): ?><p class="muted">No data yet.</p><?php endif; ?>
            <?php foreach ($architectures as $row): ?>
                <p><span class="badge"><?= h((string)$row['installations']) ?></span>
                <?= h((string)$row['architecture']) ?></p>
            <?php endforeach; ?>
        </section>
    </div>

    <h2>Recent installations</h2>
    <div style="overflow:auto">
        <table>
            <thead>
                <tr>
                    <th>Anonymous ID prefix</th>
                    <th>Version</th>
                    <th>Architecture</th>
                    <th>Platform</th>
                    <th>First seen UTC</th>
                    <th>Last seen UTC</th>
                    <th>Checks</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recent as $row): ?>
                    <tr>
                        <td><?= h((string)$row['anonymous_id']) ?>…</td>
                        <td><?= h((string)$row['version']) ?></td>
                        <td><?= h((string)$row['architecture']) ?></td>
                        <td><?= h((string)$row['platform']) ?></td>
                        <td><?= h((string)$row['first_seen']) ?></td>
                        <td><?= h((string)$row['last_seen']) ?></td>
                        <td><?= h((string)$row['checks']) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</main>
</body>
</html>
