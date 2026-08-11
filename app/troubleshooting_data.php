<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('html_errors', '0');
ob_start();

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';

require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function troubleshooting_node_name(SimpleXMLElement $node): string
{
    return $node->getName();
}

function troubleshooting_is_sensitive(string $path): bool
{
    $lower = strtolower($path);
    $tokens = [
        'password',
        'passwd',
        'secret',
        'privatekey',
        'private-key',
        'apikey',
        'api-key',
        'token',
        'pre-shared-key',
        'psk',
    ];

    foreach ($tokens as $token) {
        if (str_contains($lower, $token)) {
            return true;
        }
    }

    return false;
}

function troubleshooting_mask(string $path, string $value): string
{
    if ($value === '') {
        return '';
    }

    return troubleshooting_is_sensitive($path)
        ? '••••••••'
        : $value;
}

function troubleshooting_path_identity_value(
    SimpleXMLElement $node
): ?string {
    foreach (['name', 'descr', 'description'] as $field) {
        if (!isset($node->{$field})) {
            continue;
        }

        $value = trim((string) $node->{$field});

        if ($value !== '') {
            return $value;
        }
    }

    return null;
}

function troubleshooting_name_identity_allowed(
    string $parentPath,
    string $childName
): bool {
    $context = strtolower($parentPath . '/' . $childName);

    return
        str_contains($context, '/aliases') ||
        str_contains($context, '/alias') ||
        str_contains($context, '/categories') ||
        str_contains($context, '/category');
}

function troubleshooting_identity_token(string $value): string
{
    $value = preg_replace('/\s+/', ' ', trim($value)) ?? trim($value);

    return str_replace(
        ['\\', '[', ']', '/', '='],
        ['\\\\', '\\[', '\\]', '\\/', '\\='],
        $value
    );
}

function troubleshooting_flatten(
    SimpleXMLElement $node,
    string $path = ''
): array {
    $rows = [];
    $name = troubleshooting_node_name($node);
    $base = $path === '' ? $name : $path . '/' . $name;

    $attributes = [];

    foreach ($node->attributes() as $key => $value) {
        $attributes[(string) $key] = (string) $value;
    }

    ksort($attributes, SORT_NATURAL | SORT_FLAG_CASE);

    foreach ($attributes as $key => $value) {
        $attributePath = $base . '/@' . $key;
        $rows[$attributePath] = troubleshooting_mask(
            $attributePath,
            trim($value)
        );
    }

    $children = $node->children();

    if (count($children) === 0) {
        $rows[$base] = troubleshooting_mask(
            $base,
            trim((string) $node)
        );

        return $rows;
    }

    $nameCounts = [];
    foreach ($children as $child) {
        $childName = troubleshooting_node_name($child);
        $nameCounts[$childName] = ($nameCounts[$childName] ?? 0) + 1;
    }

    $indexes = [];
    $identityOccurrences = [];

    foreach ($children as $child) {
        $childName = troubleshooting_node_name($child);
        $indexes[$childName] = ($indexes[$childName] ?? 0) + 1;
        $suffix = '';

        if ($nameCounts[$childName] > 1) {
            $identity = troubleshooting_path_identity_value($child);

            if (
                $identity !== null &&
                troubleshooting_name_identity_allowed(
                    $base,
                    $childName
                )
            ) {
                $identityKey =
                    strtolower($childName . ':' . $identity);
                $identityOccurrences[$identityKey] =
                    ($identityOccurrences[$identityKey] ?? 0) + 1;

                $suffix =
                    '[name=' .
                    troubleshooting_identity_token($identity) .
                    ']';

                if ($identityOccurrences[$identityKey] > 1) {
                    $suffix .=
                        '[duplicate=' .
                        $identityOccurrences[$identityKey] .
                        ']';
                }
            } else {
                $suffix = '[' . $indexes[$childName] . ']';
            }
        }

        $childRows = troubleshooting_flatten(
            $child,
            $base . $suffix
        );

        foreach ($childRows as $key => $value) {
            $rows[$key] = $value;
        }
    }

    return $rows;
}

try {
    $leftId = (int) ($_GET['left_id'] ?? 0);
    $rightId = (int) ($_GET['right_id'] ?? 0);

    if ($leftId < 1 || $rightId < 1) {
        throw new RuntimeException('Select two OPNsense firewalls.');
    }

    if ($leftId === $rightId) {
        throw new RuntimeException('Select two different OPNsense firewalls.');
    }

    $left = firewall_by_id($leftId);
    $right = firewall_by_id($rightId);

    $requests = [
        'left' => [
            'firewall' => $left,
            'path' => 'core/backup/download/this',
            'timeout' => 60,
        ],
        'right' => [
            'firewall' => $right,
            'path' => 'core/backup/download/this',
            'timeout' => 60,
        ],
    ];

    $responses = opn_downloads_parallel($requests);

    foreach (['left', 'right'] as $side) {
        if (($responses[$side]['ok'] ?? false) !== true) {
            throw new RuntimeException(
                ucfirst($side) . ' firewall: ' .
                (string) (
                    $responses[$side]['error'] ??
                    'configuration download failed'
                )
            );
        }
    }

    $leftXml = simplexml_load_string(
        (string) $responses['left']['value'],
        SimpleXMLElement::class,
        LIBXML_NONET | LIBXML_NOCDATA
    );
    $rightXml = simplexml_load_string(
        (string) $responses['right']['value'],
        SimpleXMLElement::class,
        LIBXML_NONET | LIBXML_NOCDATA
    );

    if (
        !$leftXml instanceof SimpleXMLElement ||
        !$rightXml instanceof SimpleXMLElement
    ) {
        throw new RuntimeException(
            'Could not parse one or both OPNsense configurations.'
        );
    }

    $leftRows = troubleshooting_flatten($leftXml);
    $rightRows = troubleshooting_flatten($rightXml);

    $paths = array_values(
        array_unique(
            array_merge(
                array_keys($leftRows),
                array_keys($rightRows)
            )
        )
    );

    natcasesort($paths);
    $paths = array_values($paths);

    $rows = [];
    $different = 0;
    $same = 0;
    $missingLeft = 0;
    $missingRight = 0;

    foreach ($paths as $path) {
        $leftExists = array_key_exists($path, $leftRows);
        $rightExists = array_key_exists($path, $rightRows);
        $leftValue = $leftExists ? (string) $leftRows[$path] : null;
        $rightValue = $rightExists ? (string) $rightRows[$path] : null;

        $isDifferent =
            !$leftExists ||
            !$rightExists ||
            !hash_equals(
                (string) $leftValue,
                (string) $rightValue
            );

        if ($isDifferent) {
            $different++;
        } else {
            $same++;
        }

        if (!$leftExists) {
            $missingLeft++;
        }

        if (!$rightExists) {
            $missingRight++;
        }

        $rows[] = [
            'path' => $path,
            'left_exists' => $leftExists,
            'right_exists' => $rightExists,
            'left' => $leftValue,
            'right' => $rightValue,
            'different' => $isDifferent,
        ];
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => true,
            'left' => [
                'id' => (int) $left['id'],
                'name' => (string) $left['name'],
                'base_url' => (string) $left['base_url'],
                'setting_count' => count($leftRows),
            ],
            'right' => [
                'id' => (int) $right['id'],
                'name' => (string) $right['name'],
                'base_url' => (string) $right['base_url'],
                'setting_count' => count($rightRows),
            ],
            'summary' => [
                'total' => count($rows),
                'same' => $same,
                'different' => $different,
                'missing_left' => $missingLeft,
                'missing_right' => $missingRight,
            ],
            'rows' => $rows,
        ],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE |
        JSON_THROW_ON_ERROR
    );
} catch (Throwable $exception) {
    http_response_code(400);

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => false,
            'error' => $exception->getMessage(),
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
