<?php
declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$results = [];

foreach ($firewalls as $firewall) {
    try {
        $settings = opn_raw_request(
            $firewall,
            'firewall/alias/get_geo_i_p',
            'GET',
            null,
            20
        );

        $results[] = [
            'firewall' => $firewall,
            'ok' => true,
            'settings' => $settings,
            'error' => null,
        ];
    } catch (Throwable $exception) {
        $results[] = [
            'firewall' => $firewall,
            'ok' => false,
            'settings' => [],
            'error' => $exception->getMessage(),
        ];
    }
}

function geoip_flatten(mixed $value, string $prefix = ''): array
{
    $rows = [];

    if (!is_array($value)) {
        $rows[] = [$prefix !== '' ? $prefix : 'Value', (string) $value];
        return $rows;
    }

    foreach ($value as $key => $child) {
        $label = $prefix === '' ? (string) $key : $prefix . ' / ' . $key;
        if (is_array($child)) {
            $rows = array_merge($rows, geoip_flatten($child, $label));
        } else {
            $rows[] = [$label, (string) $child];
        }
    }

    return $rows;
}

require __DIR__ . '/inc/header.php';
?>

<div class="page-title management-page-title">
    <div>
        <h1>GeoIP Settings</h1>
        <p>Review the GeoIP database configuration on every managed OPNsense.</p>
    </div>
    <a class="button secondary" href="/alias_overview.php">Back to aliases</a>
</div>

<div class="management-overview-bar">
    <div>
        <strong>GeoIP overview</strong>
        <div class="management-summary">
            <?= count($firewalls) ?> firewall(s) ·
            <?= count(array_filter($results, static fn(array $row): bool => $row['ok'])) ?> reachable
        </div>
    </div>
</div>

<div class="vpn-summary-list">
<?php if (!$results): ?>
    <section class="card vpn-summary-card">
        <p class="muted">No firewalls configured.</p>
    </section>
<?php endif; ?>

<?php foreach ($results as $result): ?>
    <?php
        $firewall = $result['firewall'];
        $baseUrl = rtrim((string) $firewall['base_url'], '/');
        $nativeUrl = $baseUrl . '/ui/firewall/alias/geoip';
        $rows = $result['ok'] ? geoip_flatten($result['settings']) : [];
    ?>
    <section class="card vpn-summary-card vpn-summary-expanded">
        <div class="vpn-summary-main">
            <div class="vpn-summary-identity">
                <h2><?= h((string) $firewall['name']) ?></h2>
                <a class="muted" href="<?= h($baseUrl) ?>" target="_blank" rel="noopener noreferrer">
                    <?= h($baseUrl) ?>
                </a>
            </div>

            <div class="vpn-summary-metric">
                <span class="vpn-summary-label">Status</span>
                <?php if ($result['ok']): ?>
                    <span class="badge good">Available</span>
                <?php else: ?>
                    <span class="badge bad">Unavailable</span>
                <?php endif; ?>
            </div>

            <div class="vpn-summary-actions">
                <a class="button" href="<?= h($nativeUrl) ?>" target="_blank" rel="noopener noreferrer">
                    Open GeoIP settings
                </a>
            </div>
        </div>

        <div class="vpn-details-panel">
            <?php if (!$result['ok']): ?>
                <div class="alert error"><?= h((string) $result['error']) ?></div>
            <?php elseif (!$rows): ?>
                <p class="muted">OPNsense returned no GeoIP configuration values.</p>
            <?php else: ?>
                <div class="table-scroll management-table-wrap">
                    <table class="management-table">
                        <thead>
                            <tr><th>Setting</th><th>Value</th></tr>
                        </thead>
                        <tbody>
                        <?php foreach ($rows as [$label, $value]): ?>
                            <tr>
                                <td><strong><?= h($label) ?></strong></td>
                                <td><?= h($value !== '' ? $value : '—') ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </section>
<?php endforeach; ?>
</div>

<?php require __DIR__ . '/inc/footer.php'; ?>
