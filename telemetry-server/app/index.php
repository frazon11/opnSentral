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

function project_stats_request(string $url, array $headers = []): array
{
    $curl = curl_init($url);
    if ($curl === false) {
        return ['ok' => false, 'error' => 'Unable to initialize HTTP client.'];
    }

    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => array_merge(
            ['Accept: application/json', 'User-Agent: opnSentral-telemetry-project-stats'],
            $headers
        ),
    ]);

    $body = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $error = curl_error($curl);
    unset($curl);

    if (!is_string($body) || $body === '') {
        return [
            'ok' => false,
            'status' => $status,
            'error' => $error !== '' ? $error : 'Empty response.',
        ];
    }

    $decoded = json_decode($body, true);
    if (!is_array($decoded)) {
        return ['ok' => false, 'status' => $status, 'error' => 'Invalid JSON response.'];
    }

    if ($status < 200 || $status >= 300) {
        return [
            'ok' => false,
            'status' => $status,
            'error' => (string) ($decoded['message'] ?? ('HTTP ' . $status)),
        ];
    }

    return ['ok' => true, 'status' => $status, 'data' => $decoded];
}

function load_project_stats(): array
{
    $dockerRepository = env_value('DOCKER_HUB_REPOSITORY', 'frazon11/opnsentral');
    $githubRepository = env_value('GITHUB_TRAFFIC_REPOSITORY', 'frazon11/opnSentral');
    $githubToken = trim(env_value('GITHUB_TRAFFIC_TOKEN'));

    $result = [
        'docker_pulls' => null,
        'github_views' => null,
        'github_unique_views' => null,
        'github_clones' => null,
        'github_unique_clones' => null,
        'message' => '',
    ];

    $dockerParts = explode('/', $dockerRepository, 2);
    if (count($dockerParts) === 2 && $dockerParts[0] !== '' && $dockerParts[1] !== '') {
        $dockerResponse = project_stats_request(
            'https://hub.docker.com/v2/repositories/'
            . rawurlencode($dockerParts[0]) . '/'
            . rawurlencode($dockerParts[1]) . '/'
        );

        if ($dockerResponse['ok'] === true) {
            $result['docker_pulls'] = isset($dockerResponse['data']['pull_count'])
                ? (int) $dockerResponse['data']['pull_count']
                : null;
        } else {
            $result['message'] = 'Docker Hub statistics unavailable: '
                . (string) ($dockerResponse['error'] ?? 'request failed');
        }
    } else {
        $result['message'] = 'Docker Hub statistics unavailable: invalid repository setting.';
    }

    if ($githubToken === '') {
        $githubMessage = 'GitHub traffic is not configured. Set GITHUB_TRAFFIC_TOKEN to enable views and clone statistics.';
        $result['message'] = $result['message'] !== ''
            ? $result['message'] . ' ' . $githubMessage
            : $githubMessage;
        return $result;
    }

    if (!str_contains($githubRepository, '/')) {
        $result['message'] = 'GitHub traffic unavailable: invalid repository setting.';
        return $result;
    }

    [$owner, $repo] = explode('/', $githubRepository, 2);
    $headers = [
        'Authorization: Bearer ' . $githubToken,
        'Accept: application/vnd.github+json',
        'X-GitHub-Api-Version: 2022-11-28',
    ];
    $base = 'https://api.github.com/repos/'
        . rawurlencode($owner) . '/'
        . rawurlencode($repo) . '/traffic/';

    $viewsResponse = project_stats_request($base . 'views?per=day', $headers);
    $clonesResponse = project_stats_request($base . 'clones?per=day', $headers);

    if ($viewsResponse['ok'] === true) {
        $result['github_views'] = (int) ($viewsResponse['data']['count'] ?? 0);
        $result['github_unique_views'] = (int) ($viewsResponse['data']['uniques'] ?? 0);
    }

    if ($clonesResponse['ok'] === true) {
        $result['github_clones'] = (int) ($clonesResponse['data']['count'] ?? 0);
        $result['github_unique_clones'] = (int) ($clonesResponse['data']['uniques'] ?? 0);
    }

    $errors = [];
    if ($viewsResponse['ok'] !== true) {
        $errors[] = 'views: ' . (string) ($viewsResponse['error'] ?? 'request failed');
    }
    if ($clonesResponse['ok'] !== true) {
        $errors[] = 'clones: ' . (string) ($clonesResponse['error'] ?? 'request failed');
    }
    if ($errors !== []) {
        $githubMessage = 'GitHub traffic unavailable: ' . implode('; ', $errors);
        $result['message'] = $result['message'] !== ''
            ? $result['message'] . ' ' . $githubMessage
            : $githubMessage;
    }

    return $result;
}

$total = (int) $pdo->query('SELECT COUNT(*) FROM installations')->fetchColumn();
$active24h = count_since($pdo, 86400);
$active7d = count_since($pdo, 7 * 86400);
$active30d = count_since($pdo, 30 * 86400);
$projectStats = load_project_stats();

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
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function stat_value(?int $value): string
{
    return $value === null ? '—' : number_format($value, 0, '.', ',');
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
.project-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}
.card{background:#222a30;border:1px solid #3b4750;padding:18px;border-radius:4px}
.metric{font-size:2rem;font-weight:750;margin-top:8px}.project-metric{font-size:1.55rem;font-weight:750;margin-top:8px}
.columns{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
.section{margin-top:18px}.section h2{margin-bottom:10px}.note{margin-top:10px;font-size:.85rem;color:#9eabb4}
table{width:100%;border-collapse:collapse;background:#222a30;margin-top:14px}
th,td{border:1px solid #3b4750;padding:9px;text-align:left}
th{background:#2c363e}.badge{display:inline-block;padding:3px 8px;background:#264e35;color:#bce8c8}
@media(max-width:1100px){.project-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:900px){.grid,.columns{grid-template-columns:1fr 1fr}}
@media(max-width:600px){.grid,.columns,.project-grid{grid-template-columns:1fr}main{padding:14px}}
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

    <section class="section">
        <h2>Project statistics</h2>
        <div class="project-grid">
            <div class="card"><strong>Docker Hub pulls</strong><div class="project-metric"><?= h(stat_value($projectStats['docker_pulls'])) ?></div><div class="muted">Lifetime repository pulls</div></div>
            <div class="card"><strong>GitHub views</strong><div class="project-metric"><?= h(stat_value($projectStats['github_views'])) ?></div><div class="muted">Last 14 days</div></div>
            <div class="card"><strong>Unique visitors</strong><div class="project-metric"><?= h(stat_value($projectStats['github_unique_views'])) ?></div><div class="muted">Last 14 days</div></div>
            <div class="card"><strong>GitHub clones</strong><div class="project-metric"><?= h(stat_value($projectStats['github_clones'])) ?></div><div class="muted">Last 14 days</div></div>
            <div class="card"><strong>Unique cloners</strong><div class="project-metric"><?= h(stat_value($projectStats['github_unique_clones'])) ?></div><div class="muted">Last 14 days</div></div>
        </div>
        <?php if ($projectStats['message'] !== ''): ?>
            <div class="note"><?= h((string) $projectStats['message']) ?></div>
        <?php endif; ?>
    </section>

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
