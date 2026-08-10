<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';

require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function project_stats_request(string $url, array $headers = []): array
{
    $curl = curl_init($url);
    if ($curl === false) {
        return ['ok' => false, 'error' => 'Unable to initialize HTTP client.'];
    }

    $defaultHeaders = [
        'Accept: application/json',
        'User-Agent: opnSentral-project-stats',
    ];

    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => array_merge($defaultHeaders, $headers),
    ]);

    $body = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $error = curl_error($curl);
    curl_close($curl);

    if (!is_string($body) || $body === '') {
        return [
            'ok' => false,
            'status' => $status,
            'error' => $error !== '' ? $error : 'Empty response.',
        ];
    }

    $decoded = json_decode($body, true);
    if (!is_array($decoded)) {
        return [
            'ok' => false,
            'status' => $status,
            'error' => 'Invalid JSON response.',
        ];
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

$dockerRepository = envv('DOCKER_HUB_REPOSITORY', 'frazon11/opnsentral');
$githubRepository = envv('GITHUB_TRAFFIC_REPOSITORY', 'frazon11/opnSentral');
$githubToken = trim(envv('GITHUB_TRAFFIC_TOKEN', ''));

$result = [
    'ok' => true,
    'docker_hub' => [
        'repository' => $dockerRepository,
        'pulls' => null,
        'error' => null,
    ],
    'github' => [
        'repository' => $githubRepository,
        'configured' => $githubToken !== '',
        'views' => null,
        'clones' => null,
        'error' => null,
    ],
];

$dockerResponse = project_stats_request(
    'https://hub.docker.com/v2/repositories/' . rawurlencode(explode('/', $dockerRepository, 2)[0] ?? '') . '/' . rawurlencode(explode('/', $dockerRepository, 2)[1] ?? '') . '/'
);

if ($dockerResponse['ok'] === true) {
    $result['docker_hub']['pulls'] = isset($dockerResponse['data']['pull_count'])
        ? (int) $dockerResponse['data']['pull_count']
        : null;
} else {
    $result['docker_hub']['error'] = (string) ($dockerResponse['error'] ?? 'Docker Hub request failed.');
}

if ($githubToken !== '' && str_contains($githubRepository, '/')) {
    [$owner, $repo] = explode('/', $githubRepository, 2);
    $githubHeaders = [
        'Authorization: Bearer ' . $githubToken,
        'Accept: application/vnd.github+json',
        'X-GitHub-Api-Version: 2022-11-28',
    ];

    $base = 'https://api.github.com/repos/' . rawurlencode($owner) . '/' . rawurlencode($repo) . '/traffic/';
    $viewsResponse = project_stats_request($base . 'views?per=day', $githubHeaders);
    $clonesResponse = project_stats_request($base . 'clones?per=day', $githubHeaders);

    if ($viewsResponse['ok'] === true) {
        $result['github']['views'] = [
            'count' => (int) ($viewsResponse['data']['count'] ?? 0),
            'uniques' => (int) ($viewsResponse['data']['uniques'] ?? 0),
        ];
    }

    if ($clonesResponse['ok'] === true) {
        $result['github']['clones'] = [
            'count' => (int) ($clonesResponse['data']['count'] ?? 0),
            'uniques' => (int) ($clonesResponse['data']['uniques'] ?? 0),
        ];
    }

    if ($viewsResponse['ok'] !== true || $clonesResponse['ok'] !== true) {
        $errors = [];
        if ($viewsResponse['ok'] !== true) {
            $errors[] = 'views: ' . (string) ($viewsResponse['error'] ?? 'request failed');
        }
        if ($clonesResponse['ok'] !== true) {
            $errors[] = 'clones: ' . (string) ($clonesResponse['error'] ?? 'request failed');
        }
        $result['github']['error'] = implode('; ', $errors);
    }
}

echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
