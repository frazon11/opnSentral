<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/plugin_features.php';
require_login();

$firewalls = db()
    ->query('SELECT id,name,base_url FROM firewalls ORDER BY name')
    ->fetchAll();
$installedIds = plugin_feature_installed_firewall_ids('os-acme-client');
$installedLookup = array_fill_keys($installedIds, true);
$columns = [];

function acme_scalar(mixed $value): string
{
    if ($value === null) return '';
    if (is_string($value) || is_int($value) || is_float($value)) return trim((string) $value);
    if (is_bool($value)) return $value ? '1' : '0';
    if (!is_array($value)) return '';

    foreach (['selected','value','name','id','uuid'] as $key) {
        if (array_key_exists($key, $value) && !is_array($value[$key]) && !is_object($value[$key])) {
            $text = trim((string) $value[$key]);
            if ($text !== '') return $text;
        }
    }

    foreach ($value as $key => $item) {
        if (!is_array($item)) continue;
        if (!acme_bool($item['selected'] ?? false)) continue;
        if (isset($item['value']) && !is_array($item['value']) && !is_object($item['value'])) {
            $text = trim((string) $item['value']);
            if ($text !== '') return $text;
        }
        if (is_string($key) && $key !== '') return $key;
    }

    foreach ($value as $item) {
        if (is_array($item) || is_object($item)) continue;
        $text = trim((string) $item);
        if ($text !== '') return $text;
    }

    return '';
}

function acme_bool(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    if (is_array($value)) $value = acme_scalar($value);
    return in_array(strtolower(trim((string) $value)), ['1','true','yes','on','enabled','selected'], true);
}

function acme_setting(array $column, string $key, string $fallback = '—'): string
{
    $value = acme_scalar($column['settings'][$key] ?? '');
    return $value !== '' ? $value : $fallback;
}

function acme_list_text(mixed $value, string $fallback = '—'): string
{
    if ($value === null || $value === '') return $fallback;
    if (!is_array($value)) {
        $text = trim((string) $value);
        return $text !== '' ? $text : $fallback;
    }

    $values = [];
    foreach ($value as $key => $item) {
        if (is_array($item)) {
            if (array_key_exists('selected', $item) && !acme_bool($item['selected'])) continue;
            $candidate = acme_scalar($item);
            if ($candidate !== '') $values[] = $candidate;
            elseif (is_string($key) && $key !== '') $values[] = $key;
            continue;
        }
        $text = trim((string) $item);
        if ($text !== '') $values[] = $text;
    }
    $values = array_values(array_unique($values));
    return $values !== [] ? implode(', ', $values) : $fallback;
}

function acme_timestamp(mixed $value, string $fallback = 'Never / unknown'): string
{
    $raw = acme_scalar($value);
    if ($raw === '' || !ctype_digit($raw) || (int) $raw <= 0) return $fallback;
    return gmdate('Y-m-d H:i:s', (int) $raw) . ' UTC';
}

function acme_status_label(array $certificate): string
{
    $raw = acme_scalar($certificate['statusCode'] ?? '');
    if ($raw === '') {
        return acme_scalar($certificate['lastUpdate'] ?? '') !== '' ? 'OK' : 'Unknown';
    }
    return match ((int) $raw) {
        100 => 'Unknown',
        200 => 'OK',
        250 => 'Certificate revoked',
        300 => 'Configuration error',
        400 => 'Validation failed',
        500 => 'Internal error',
        default => 'Unknown (' . $raw . ')',
    };
}

function acme_response_item(array $response, string $key): array
{
    if (is_array($response[$key] ?? null)) return $response[$key];
    if (is_array($response['acmeclient'][$key] ?? null)) return $response['acmeclient'][$key];
    foreach ($response as $item) {
        if (!is_array($item)) continue;
        if (is_array($item[$key] ?? null)) return $item[$key];
    }
    return [];
}

function acme_relation_uuid(mixed $value): string
{
    if (is_string($value) && preg_match('/^[A-Fa-f0-9-]{8,64}$/', $value)) {
        return $value;
    }
    if (!is_array($value)) return '';

    foreach ($value as $key => $item) {
        if (!is_string($key) || !preg_match('/^[A-Fa-f0-9-]{8,64}$/', $key)) continue;
        if (!is_array($item) || acme_bool($item['selected'] ?? false)) return $key;
    }

    foreach (['uuid','id'] as $key) {
        $candidate = trim((string) ($value[$key] ?? ''));
        if (preg_match('/^[A-Fa-f0-9-]{8,64}$/', $candidate)) return $candidate;
    }
    return '';
}

function acme_validation_label(array $validation): string
{
    return match (acme_scalar($validation['method'] ?? '')) {
        'http01' => 'HTTP-01',
        'dns01' => 'DNS-01',
        'tlsalpn01' => 'TLS-ALPN-01',
        default => 'Unavailable',
    };
}

function acme_http_validation_state(array $validation): string
{
    if ($validation === []) return 'Unavailable';
    if (acme_scalar($validation['method'] ?? '') !== 'http01') {
        return 'Not used (' . acme_validation_label($validation) . ')';
    }
    if (acme_scalar($validation['http_service'] ?? 'opnsense') !== 'opnsense') {
        return 'Not used (HAProxy)';
    }
    return acme_bool($validation['http_opn_autodiscovery'] ?? false) ? 'Enabled' : 'Disabled';
}

function acme_http_interface_text(array $validation): string
{
    if ($validation === []) return 'Unavailable';
    if (acme_scalar($validation['method'] ?? '') !== 'http01') {
        return 'Not used (' . acme_validation_label($validation) . ')';
    }
    if (acme_scalar($validation['http_service'] ?? 'opnsense') !== 'opnsense') {
        return 'Not used (HAProxy)';
    }
    $interface = acme_scalar($validation['http_opn_interface'] ?? '');
    return $interface !== '' ? $interface : 'Not explicitly set';
}

function acme_http_ip_text(array $validation): string
{
    if ($validation === []) return 'Unavailable';
    if (acme_scalar($validation['method'] ?? '') !== 'http01') {
        return 'Not used (' . acme_validation_label($validation) . ')';
    }
    if (acme_scalar($validation['http_service'] ?? 'opnsense') !== 'opnsense') {
        return 'Not used (HAProxy)';
    }
    $ips = acme_list_text($validation['http_opn_ipaddresses'] ?? '', '');
    if ($ips !== '') return $ips;
    if (acme_bool($validation['http_opn_autodiscovery'] ?? false)) return 'Auto-discovered';
    return 'None configured';
}

foreach ($firewalls as $firewallRow) {
    $id = (int) $firewallRow['id'];
    if (!isset($installedLookup[$id])) continue;

    $column = [
        'id' => $id,
        'name' => (string) $firewallRow['name'],
        'base_url' => rtrim((string) $firewallRow['base_url'], '/'),
        'ok' => false,
        'error' => null,
        'settings' => [],
        'certificates' => [],
        'certificate_details' => [],
    ];

    try {
        $firewall = firewall_by_id($id);
        $settingsResponse = opn_request($firewall, 'acmeclient/settings/get', 'GET', [], 25);
        $settings = is_array($settingsResponse['acmeclient']['settings'] ?? null)
            ? $settingsResponse['acmeclient']['settings']
            : [];
        if ($settings === []) {
            throw new RuntimeException('Unexpected ACME settings response.');
        }

        $certResponse = opn_request(
            $firewall,
            'acmeclient/certificates/search',
            'POST',
            ['current' => 1, 'rowCount' => 500, 'searchPhrase' => ''],
            25
        );

        $validationSearch = opn_request(
            $firewall,
            'acmeclient/validations/search',
            'POST',
            ['current' => 1, 'rowCount' => 500, 'searchPhrase' => ''],
            25
        );
        $validationRows = is_array($validationSearch['rows'] ?? null) ? $validationSearch['rows'] : [];
        $validationByUuid = [];
        $validationByName = [];
        foreach ($validationRows as $validationRow) {
            $validationRowUuid = acme_scalar($validationRow['uuid'] ?? '');
            $validationRowName = acme_scalar($validationRow['name'] ?? '');
            if ($validationRowUuid !== '') $validationByUuid[$validationRowUuid] = $validationRow;
            if ($validationRowName !== '') $validationByName[strtolower($validationRowName)] = $validationRowUuid;
        }

        $column['settings'] = $settings;
        $column['certificates'] = is_array($certResponse['rows'] ?? null) ? $certResponse['rows'] : [];

        foreach ($column['certificates'] as $certificate) {
            $uuid = acme_scalar($certificate['uuid'] ?? '');
            if ($uuid === '') continue;

            $detail = [
                'certificate' => $certificate,
                'validation' => [],
            ];

            try {
                $certificateResponse = opn_request(
                    $firewall,
                    'acmeclient/certificates/get/' . rawurlencode($uuid),
                    'GET',
                    [],
                    20
                );
                $certificateConfig = acme_response_item($certificateResponse, 'certificate');
                if ($certificateConfig !== []) {
                    $detail['certificate'] = array_merge($certificate, $certificateConfig);
                }

                $validationRelation = $certificateConfig['validationMethod'] ?? '';
                $validationUuid = acme_relation_uuid($validationRelation);
                if ($validationUuid === '') {
                    $validationName = strtolower(acme_scalar($validationRelation));
                    if ($validationName !== '' && isset($validationByName[$validationName])) {
                        $validationUuid = $validationByName[$validationName];
                    }
                }
                if ($validationUuid !== '') {
                    $validationResponse = opn_request(
                        $firewall,
                        'acmeclient/validations/get/' . rawurlencode($validationUuid),
                        'GET',
                        [],
                        20
                    );
                    $detail['validation'] = acme_response_item($validationResponse, 'validation');
                    if ($detail['validation'] === [] && isset($validationByUuid[$validationUuid])) {
                        $detail['validation'] = $validationByUuid[$validationUuid];
                    }
                }
            } catch (Throwable $ignored) {
                // Keep the certificate overview usable if one optional detail call fails.
            }

            $column['certificate_details'][$uuid] = $detail;
        }

        $column['ok'] = true;
    } catch (Throwable $exception) {
        $column['error'] = $exception->getMessage();
    }

    $columns[] = $column;
}

require __DIR__ . '/inc/header.php';
?>

<style>
.acme-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.acme-matrix{border-collapse:separate;border-spacing:0;min-width:max(980px,100%);width:100%}
.acme-matrix th,.acme-matrix td{padding:10px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:top}
.acme-matrix th:last-child,.acme-matrix td:last-child{border-right:0}.acme-matrix tr:last-child td{border-bottom:0}
.acme-matrix thead th{position:sticky;top:0;z-index:3;background:var(--table-head);text-align:center;min-width:210px}
.acme-matrix .setting-col{position:sticky;left:0;z-index:2;background:var(--card);min-width:210px;font-weight:700}
.acme-matrix thead .setting-col{z-index:4;background:var(--table-head);text-align:left}
.acme-fw small{display:block;margin-top:3px;color:var(--muted);font-weight:400}.acme-cert{padding:7px 0;border-bottom:1px solid var(--border)}.acme-cert:last-child{border-bottom:0}.acme-cert small{display:block;color:var(--muted);margin-top:3px}.acme-error{color:#b3261e}.acme-cert-row{padding:5px 0;border-bottom:1px solid var(--border)}.acme-cert-row:last-child{border-bottom:0}.acme-run-result{margin-bottom:12px}
</style>

<div class="page-title">
    <div>
        <h1>Services → ACME Client</h1>
        <p>Fleet overview for OPNsense firewalls with <code>os-acme-client</code> installed.</p>
    </div>
</div>

<?php if ($columns === []): ?>
    <div class="alert warningbox"><strong>ACME Client is not installed on any managed firewall.</strong></div>
<?php else: ?>
<div class="acme-wrap">
<table class="acme-matrix">
    <thead>
        <tr>
            <th class="setting-col">Setting</th>
            <?php foreach ($columns as $column): ?>
                <th class="acme-fw">
                    <strong><?= h($column['name']) ?></strong>
                    <small><?= h($column['base_url']) ?></small>
                </th>
            <?php endforeach; ?>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td class="setting-col">Plugin</td>
            <?php foreach ($columns as $column): ?><td><span class="badge good">os-acme-client</span></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Status</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if ($column['ok']): ?>
                        <span class="badge <?= acme_bool($column['settings']['enabled'] ?? false) ? 'good' : 'neutral' ?>"><?= acme_bool($column['settings']['enabled'] ?? false) ? 'Enabled' : 'Disabled' ?></span>
                    <?php else: ?>
                        <span class="badge bad">Read failed</span><div class="acme-error"><?= h((string) $column['error']) ?></div>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Auto renewal</td>
            <?php foreach ($columns as $column): ?><td><?= $column['ok'] ? (acme_bool($column['settings']['autoRenewal'] ?? false) ? 'Enabled' : 'Disabled') : '—' ?></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Environment</td>
            <?php foreach ($columns as $column): ?><td><?= $column['ok'] ? h(acme_setting($column, 'environment')) : '—' ?></td><?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">IP Auto-Discovery</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if (!$column['ok']): ?>—
                    <?php elseif ($column['certificate_details'] === []): ?><span class="muted">No certificates</span>
                    <?php else: ?>
                        <?php
                            $values = [];
                            foreach ($column['certificate_details'] as $detail) {
                                $name = acme_scalar($detail['certificate']['name'] ?? '') ?: 'Certificate';
                                $values[$name] = acme_http_validation_state($detail['validation']);
                            }
                            $unique = array_values(array_unique(array_values($values)));
                        ?>
                        <?php if (count($unique) === 1): ?><?= h($unique[0]) ?>
                        <?php else: foreach ($values as $name => $value): ?>
                            <div class="acme-cert-row"><strong><?= h($name) ?></strong><br><?= h($value) ?></div>
                        <?php endforeach; endif; ?>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">HTTP-01 interface</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if (!$column['ok']): ?>—
                    <?php elseif ($column['certificate_details'] === []): ?><span class="muted">No certificates</span>
                    <?php else: ?>
                        <?php
                            $values = [];
                            foreach ($column['certificate_details'] as $detail) {
                                $name = acme_scalar($detail['certificate']['name'] ?? '') ?: 'Certificate';
                                $values[$name] = acme_http_interface_text($detail['validation']);
                            }
                            $unique = array_values(array_unique(array_values($values)));
                        ?>
                        <?php if (count($unique) === 1): ?><?= h($unique[0]) ?>
                        <?php else: foreach ($values as $name => $value): ?>
                            <div class="acme-cert-row"><strong><?= h($name) ?></strong><br><?= h($value) ?></div>
                        <?php endforeach; endif; ?>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">HTTP-01 IP addresses</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if (!$column['ok']): ?>—
                    <?php elseif ($column['certificate_details'] === []): ?><span class="muted">No certificates</span>
                    <?php else: ?>
                        <?php
                            $values = [];
                            foreach ($column['certificate_details'] as $detail) {
                                $name = acme_scalar($detail['certificate']['name'] ?? '') ?: 'Certificate';
                                $values[$name] = acme_http_ip_text($detail['validation']);
                            }
                            $unique = array_values(array_unique(array_values($values)));
                        ?>
                        <?php if (count($unique) === 1): ?><?= h($unique[0]) ?>
                        <?php else: foreach ($values as $name => $value): ?>
                            <div class="acme-cert-row"><strong><?= h($name) ?></strong><br><?= h($value) ?></div>
                        <?php endforeach; endif; ?>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Last ACME status</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if (!$column['ok']): ?>—
                    <?php elseif ($column['certificate_details'] === []): ?><span class="muted">No certificates</span>
                    <?php else: ?>
                        <?php foreach ($column['certificate_details'] as $detail): ?>
                            <?php $cert = $detail['certificate']; ?>
                            <div class="acme-cert-row">
                                <strong><?= h(acme_scalar($cert['name'] ?? '') ?: 'Certificate') ?></strong><br>
                                <?= h(acme_status_label($cert)) ?>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Last ACME run</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if (!$column['ok']): ?>—
                    <?php elseif ($column['certificate_details'] === []): ?><span class="muted">No certificates</span>
                    <?php else: ?>
                        <?php foreach ($column['certificate_details'] as $detail): ?>
                            <?php $cert = $detail['certificate']; ?>
                            <div class="acme-cert-row">
                                <strong><?= h(acme_scalar($cert['name'] ?? '') ?: 'Certificate') ?></strong><br>
                                <?= h(acme_timestamp($cert['statusLastUpdate'] ?? ($cert['lastUpdate'] ?? ''))) ?>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Run ACME</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if (!$column['ok']): ?>—
                    <?php elseif ($column['certificate_details'] === []): ?><span class="muted">No certificates</span>
                    <?php else: ?>
                        <?php foreach ($column['certificate_details'] as $uuid => $detail): ?>
                            <?php $cert = $detail['certificate']; ?>
                            <div class="acme-cert-row">
                                <strong><?= h(acme_scalar($cert['name'] ?? '') ?: 'Certificate') ?></strong><br>
                                <button
                                    type="button"
                                    class="button secondary acme-run"
                                    data-firewall-id="<?= (int) $column['id'] ?>"
                                    data-certificate-uuid="<?= h((string) $uuid) ?>"
                                    data-certificate-name="<?= h(acme_scalar($cert['name'] ?? '') ?: 'certificate') ?>"
                                >Issue / renew now</button>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Certificates</td>
            <?php foreach ($columns as $column): ?>
                <td>
                    <?php if (!$column['ok']): ?>—
                    <?php elseif ($column['certificates'] === []): ?><span class="muted">No certificates</span>
                    <?php else: ?>
                        <?php foreach ($column['certificates'] as $certificate): ?>
                            <?php
                                $certificateName = acme_scalar($certificate['name'] ?? '');
                                $certificateName = $certificateName !== '' ? $certificateName : 'Unnamed certificate';
                                $lastUpdate = acme_timestamp($certificate['lastUpdate'] ?? '');
                            ?>
                            <div class="acme-cert">
                                <strong><?= h($certificateName) ?></strong>
                                <small><?= acme_bool($certificate['enabled'] ?? false) ? 'Enabled' : 'Disabled' ?> · Last update: <?= h($lastUpdate) ?></small>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </td>
            <?php endforeach; ?>
        </tr>
        <tr>
            <td class="setting-col">Edit</td>
            <?php foreach ($columns as $column): ?>
                <td><a class="button secondary" href="<?= h($column['base_url'] . '/ui/acmeclient') ?>" target="_blank" rel="noopener noreferrer">Open ACME settings</a></td>
            <?php endforeach; ?>
        </tr>
    </tbody>
</table>
</div>
<?php endif; ?>

<div id="acme-run-result" class="alert hidden acme-run-result"></div>
<script>
(function(){
    const result = document.getElementById('acme-run-result');
    document.querySelectorAll('.acme-run').forEach(function(button){
        button.addEventListener('click', async function(){
            const name = button.dataset.certificateName || 'certificate';
            if(!confirm('Issue or renew ' + name + ' now?\n\nA pre-change backup will be created first.')) return;

            const original = button.textContent;
            button.disabled = true;
            button.textContent = 'Running…';
            result.className = 'alert warningbox acme-run-result';
            result.textContent = 'Running ACME for ' + name + '…';

            const form = new URLSearchParams({
                csrf: <?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>,
                firewall_id: button.dataset.firewallId || '',
                certificate_uuid: button.dataset.certificateUuid || ''
            });

            try{
                const response = await fetch('/acme_action.php',{
                    method:'POST',
                    credentials:'same-origin',
                    cache:'no-store',
                    headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},
                    body:form
                });
                const raw = await response.text();
                let data;
                try{data=JSON.parse(raw);}catch(error){throw new Error('Invalid server response: '+raw.slice(0,500));}
                if(!response.ok || data.ok !== true) throw new Error(data.error || 'ACME run failed.');
                result.className = 'alert goodbox acme-run-result';
                result.textContent = data.message || 'ACME run completed.';
                window.setTimeout(()=>window.location.reload(),1500);
            }catch(error){
                result.className = 'alert error acme-run-result';
                result.textContent = error.message;
                button.disabled = false;
                button.textContent = original;
            }
        });
    });
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
