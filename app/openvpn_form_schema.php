<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('html_errors', '0');
ob_start();

require_once __DIR__ . '/inc/config.php';
require_login();

if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $path = __DIR__ .
        '/resources/opnsense/OpenVPN/forms/dialogInstance.xml';

    if (!is_file($path)) {
        throw new RuntimeException(
            'Bundled OPNsense OpenVPN form definition is missing.'
        );
    }

    libxml_use_internal_errors(true);
    $xml = simplexml_load_file($path);

    if (!$xml instanceof SimpleXMLElement) {
        $messages = array_map(
            static fn(LibXMLError $error): string =>
                trim($error->message),
            libxml_get_errors()
        );

        throw new RuntimeException(
            'Could not parse bundled OPNsense form: ' .
            implode(' | ', $messages)
        );
    }

    $schema = [];

    foreach ($xml->field as $field) {
        $type = trim((string) $field->type);
        $label = trim((string) $field->label);

        if ($type === 'header') {
            $schema[] = [
                'header' => $label,
            ];
            continue;
        }

        $id = trim((string) $field->id);

        if (!str_starts_with($id, 'instance.')) {
            continue;
        }

        $schema[] = [
            'key' => substr($id, strlen('instance.')),
            'label' => $label,
            'type' => $type,
            'advanced' =>
                strtolower(trim((string) $field->advanced)) === 'true',
            'style' => trim((string) $field->style),
        ];
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => true,
            'source' =>
                'OPNsense/OpenVPN/forms/dialogInstance.xml',
            'schema' => $schema,
        ],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE |
        JSON_THROW_ON_ERROR
    );
} catch (Throwable $exception) {
    http_response_code(500);

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => false,
            'error' => $exception->getMessage(),
        ],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE
    );
}
