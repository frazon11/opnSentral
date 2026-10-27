<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$requests = [];
foreach ($firewalls as $firewall) {
    $requests[(int)$firewall['id']] = [
        'firewall' => $firewall,
        'path' => 'core/backup/download/this',
        'timeout' => 60,
    ];
}
$downloads = opn_downloads_parallel($requests);
$inventory = [];
foreach ($firewalls as $firewall) {
    $id = (int)$firewall['id'];
    $entry = ['firewall' => $firewall, 'servers' => [], 'error' => ''];
    try {
        $download = $downloads[$id] ?? ['ok' => false, 'error' => 'No response'];
        if (empty($download['ok'])) {
            throw new RuntimeException((string)($download['error'] ?? 'Could not read configuration'));
        }
        $raw = ltrim((string)$download['value']);
        $xml = simplexml_load_string($raw, SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        if (!$xml instanceof SimpleXMLElement || strcasecmp($xml->getName(), 'opnsense') !== 0) {
            throw new RuntimeException('Invalid OPNsense configuration XML');
        }
        $nodes = $xml->xpath('/opnsense/system/authserver');
        if (!is_array($nodes)) throw new RuntimeException('Could not query authentication servers');
        foreach ($nodes as $node) {
            if (!$node instanceof SimpleXMLElement) continue;
            $type = trim((string)($node->type ?? ''));
            $entry['servers'][] = [
                'name' => trim((string)($node->name ?? '')),
                'type' => $type,
                'host' => trim((string)($node->host ?? '')),
                'port' => $type === 'radius'
                    ? trim((string)($node->radius_auth_port ?? ''))
                    : trim((string)($node->ldap_port ?? '')),
                'refid' => trim((string)($node->refid ?? '')),
            ];
        }
        // Only show configured entries actually present in this firewall's XML.
        // The built-in local database is not assumed to be an authserver node.
    } catch (Throwable $e) {
        $entry['error'] = $e->getMessage();
    }
    $inventory[] = $entry;
}

require __DIR__ . '/inc/header.php';
?>
<div class="page-title">
  <div>
    <h1>System → Access → Servers</h1>
    <p>Authentication servers configured on each managed OPNsense firewall.</p>
  </div>
</div>
<div class="alert warningbox">
  Read-only inventory. Editing is not enabled: the existing administration write endpoint
  is disabled following a confirmed remote lockout. Authentication-server credentials
  and shared secrets are intentionally not displayed.
</div>
<?php foreach ($inventory as $entry): ?>
  <h2><?= h((string)$entry['firewall']['name']) ?></h2>
  <?php if ($entry['error'] !== ''): ?>
    <div class="alert warningbox"><?= h($entry['error']) ?></div>
  <?php else: ?>
    <div style="overflow-x:auto">
      <table>
        <thead><tr><th>Name</th><th>Type</th><th>Host</th><th>Authentication port</th><th>Ref ID</th></tr></thead>
        <tbody>
        <?php if ($entry['servers'] === []): ?>
          <tr><td colspan="5">No explicit authentication-server entries found in the configuration.</td></tr>
        <?php endif; ?>
        <?php foreach ($entry['servers'] as $server): ?>
          <tr>
            <td><?= h($server['name']) ?></td>
            <td><?= h($server['type']) ?></td>
            <td><?= h($server['host']) ?></td>
            <td><?= h($server['port']) ?></td>
            <td><?= h($server['refid']) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  <?php endif; ?>
<?php endforeach; ?>
<?php require __DIR__ . '/inc/footer.php'; ?>
