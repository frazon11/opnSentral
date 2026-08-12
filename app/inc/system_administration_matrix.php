<?php

declare(strict_types=1);

function administration_matrix_settings(): array
{
    return [
        'disablehttpredirect' => [
            'label' => 'Disable HTTP redirect rule',
            'section' => 'Web GUI',
            'path' => '/opnsense/system/webgui/disablehttpredirect',
            'help' => 'Checked means OPNsense will not create the automatic HTTP/HTTPS redirect rule. Useful when another service must own port 80.',
        ],
        'ssl-hsts' => [
            'label' => 'HTTP Strict Transport Security',
            'section' => 'Web GUI',
            'path' => '/opnsense/system/webgui/ssl-hsts',
            'help' => 'Enable HSTS for the OPNsense WebGUI.',
        ],
        'httpaccesslog' => [
            'label' => 'Access log',
            'section' => 'Web GUI',
            'path' => '/opnsense/system/webgui/httpaccesslog',
            'help' => 'Log WebGUI access requests.',
        ],
        'nodnsrebindcheck' => [
            'label' => 'Disable DNS rebind check',
            'section' => 'Web GUI',
            'path' => '/opnsense/system/webgui/nodnsrebindcheck',
            'help' => 'Checked disables the WebGUI DNS rebinding protection.',
        ],
        'nohttpreferercheck' => [
            'label' => 'Disable HTTP_REFERER enforcement',
            'section' => 'Web GUI',
            'path' => '/opnsense/system/webgui/nohttpreferercheck',
            'help' => 'Checked disables the WebGUI HTTP_REFERER origin check.',
        ],
        'quietlogin' => [
            'label' => 'Quiet login',
            'section' => 'Web GUI',
            'path' => '/opnsense/system/webgui/quietlogin',
            'help' => 'Suppress successful login messages in the WebGUI.',
        ],
    ];
}

function administration_matrix_xml_bool(SimpleXMLElement $xml, string $path): bool
{
    $nodes = $xml->xpath($path);
    return is_array($nodes) && isset($nodes[0]);
}

function administration_matrix_read_firewall(array $firewall): array
{
    $rawXml = opn_download($firewall, 'core/backup/download/this');
    libxml_use_internal_errors(true);
    $xml = simplexml_load_string(
        $rawXml,
        SimpleXMLElement::class,
        LIBXML_NONET | LIBXML_NOCDATA
    );

    if (!$xml instanceof SimpleXMLElement) {
        throw new RuntimeException('Could not parse OPNsense configuration XML.');
    }

    $values = [];
    foreach (administration_matrix_settings() as $key => $definition) {
        $values[$key] = administration_matrix_xml_bool($xml, (string) $definition['path']);
    }

    return $values;
}
