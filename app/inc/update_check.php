<?php

declare(strict_types=1);

const OPNSENTRAL_VERSION = '0.6.21.42';
const OPNSENTRAL_GITHUB_REPOSITORY = 'frazon11/opnSentral';
const OPNSENTRAL_UPDATE_INTERVAL = 86400;

function update_check_path(): string
{
    return DATA_DIR . '/update-check.json';
}

function update_check_defaults(): array
{
    return [
        'enabled' => true,
        'last_attempt' => null,
        'last_checked' => null,
        'latest_version' => null,
        'latest_tag' => null,
        'release_name' => null,
        'release_url' => null,
        'published_at' => null,
        'update_available' => false,
        'comparison' => 'unknown',
        'error' => null,
    ];
}

function update_check_normalize_version(string $version): string
{
    $version = trim($version);
    return preg_replace('/^[vV]/', '', $version) ?? $version;
}

function update_check_compare(array $state): array
{
    $latest = update_check_normalize_version((string) ($state['latest_version'] ?? ''));
    if ($latest === '') {
        $state['comparison'] = 'unknown';
        $state['update_available'] = false;
    } elseif (version_compare($latest, OPNSENTRAL_VERSION, '>')) {
        $state['comparison'] = 'behind';
        $state['update_available'] = true;
    } elseif (version_compare($latest, OPNSENTRAL_VERSION, '<')) {
        $state['comparison'] = 'ahead';
        $state['update_available'] = false;
    } else {
        $state['comparison'] = 'equal';
        $state['update_available'] = false;
    }
    return $state;
}

function update_check_load(): array
{
    $defaults = update_check_defaults();
    $path = update_check_path();
    if (!is_file($path)) return $defaults;
    $decoded = json_decode((string) file_get_contents($path), true);
    $state = is_array($decoded) ? array_replace($defaults, $decoded) : $defaults;
    return update_check_compare($state);
}

function update_check_save(array $state): void
{
    if (!is_dir(DATA_DIR) && !mkdir(DATA_DIR, 0770, true) && !is_dir(DATA_DIR)) {
        throw new RuntimeException('Could not create the data directory.');
    }
    $json = json_encode(array_replace(update_check_defaults(), $state), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    if (file_put_contents(update_check_path(), $json, LOCK_EX) === false) {
        throw new RuntimeException('Could not store update-check state.');
    }
}

function update_check_is_stale(array $state): bool
{
    $lastSuccess = trim((string) ($state['last_checked'] ?? ''));
    if ($lastSuccess !== '') {
        $timestamp = strtotime($lastSuccess);
        if ($timestamp !== false && (time() - $timestamp) < OPNSENTRAL_UPDATE_INTERVAL) return false;
    }
    $lastAttempt = trim((string) ($state['last_attempt'] ?? ''));
    if ($lastAttempt !== '') {
        $timestamp = strtotime($lastAttempt);
        if ($timestamp !== false && (time() - $timestamp) < 900) return false;
    }
    return true;
}

function update_check_run(bool $force = false): array
{
    $state = update_check_load();
    if (($state['enabled'] ?? true) !== true && !$force) return $state;
    if (!$force && !update_check_is_stale($state)) return update_check_compare($state);

    $url = 'https://api.github.com/repos/' . OPNSENTRAL_GITHUB_REPOSITORY . '/releases/latest';
    $curl = curl_init($url);
    if ($curl === false) throw new RuntimeException('Could not initialize the GitHub request.');
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => 12,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => [
            'Accept: application/vnd.github+json',
            'X-GitHub-Api-Version: 2022-11-28',
            'User-Agent: opnSentral/' . OPNSENTRAL_VERSION,
        ],
    ]);
    $body = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $curlError = curl_error($curl);

    unset($curl);

    $state['last_attempt'] = gmdate('c');
    if ($body === false || $curlError !== '') {
        $state['error'] = 'GitHub request failed: ' . ($curlError ?: 'unknown error');
        update_check_save($state);
        return $state;
    }
    if ($status !== 200) {
        $state['error'] = 'GitHub returned HTTP ' . $status . '.';
        update_check_save($state);
        return $state;
    }
    $release = json_decode($body, true);
    if (!is_array($release)) {
        $state['error'] = 'GitHub returned invalid JSON.';
        update_check_save($state);
        return $state;
    }
    $tag = trim((string) ($release['tag_name'] ?? ''));
    $latest = update_check_normalize_version($tag);
    if ($latest === '' || !preg_match('/^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/', $latest)) {
        $state['error'] = 'The latest GitHub release has an unsupported version tag.';
        update_check_save($state);
        return $state;
    }
    $state['last_checked'] = gmdate('c');
    $state['latest_version'] = $latest;
    $state['latest_tag'] = $tag;
    $state['release_name'] = trim((string) ($release['name'] ?? $tag));
    $state['release_url'] = filter_var((string) ($release['html_url'] ?? ''), FILTER_VALIDATE_URL) ?: null;
    $state['published_at'] = trim((string) ($release['published_at'] ?? '')) ?: null;
    $state['error'] = null;
    $state = update_check_compare($state);
    update_check_save($state);
    return $state;
}
