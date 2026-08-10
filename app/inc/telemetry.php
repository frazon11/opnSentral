<?php

declare(strict_types=1);

const TELEMETRY_INTERVAL = 86400;
const TELEMETRY_FAILURE_RETRY = 3600;

function telemetry_state_path(): string
{
    return DATA_DIR . '/telemetry.json';
}

function telemetry_default_state(): array
{
    return [
        'enabled' => false,
        'installation_secret' => null,
        'last_attempt' => null,
        'last_sent' => null,
        'last_status' => null,
        'last_error' => null,
    ];
}

function telemetry_load_state(): array
{
    $defaults = telemetry_default_state();
    $path = telemetry_state_path();

    if (!is_file($path)) {
        return $defaults;
    }

    $decoded = json_decode((string) file_get_contents($path), true);
    return is_array($decoded)
        ? array_replace($defaults, $decoded)
        : $defaults;
}

function telemetry_save_state(array $state): void
{
    if (!is_dir(DATA_DIR) && !mkdir(DATA_DIR, 0770, true) && !is_dir(DATA_DIR)) {
        throw new RuntimeException('Could not create telemetry data directory.');
    }

    $json = json_encode(
        array_replace(telemetry_default_state(), $state),
        JSON_PRETTY_PRINT |
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE |
        JSON_THROW_ON_ERROR
    );

    if (file_put_contents(telemetry_state_path(), $json, LOCK_EX) === false) {
        throw new RuntimeException('Could not store telemetry settings.');
    }

    @chmod(telemetry_state_path(), 0660);
}

function telemetry_installation_secret(array &$state): string
{
    $secret = trim((string) ($state['installation_secret'] ?? ''));

    if (!preg_match('/^[a-f0-9]{64}$/', $secret)) {
        $secret = bin2hex(random_bytes(32));
        $state['installation_secret'] = $secret;
        telemetry_save_state($state);
    }

    return $secret;
}

function telemetry_installation_hash(array &$state): string
{
    return hash(
        'sha256',
        'opnsentral-installation-v1:' . telemetry_installation_secret($state)
    );
}

function telemetry_endpoint(): string
{
    return trim(envv('TELEMETRY_URL', ''));
}

function telemetry_is_due(array $state): bool
{
    if (($state['enabled'] ?? false) !== true) {
        return false;
    }

    $lastSent = trim((string) ($state['last_sent'] ?? ''));
    if ($lastSent !== '') {
        $timestamp = strtotime($lastSent);
        if (
            $timestamp !== false &&
            (time() - $timestamp) < TELEMETRY_INTERVAL
        ) {
            return false;
        }
    }

    $lastAttempt = trim((string) ($state['last_attempt'] ?? ''));
    if ($lastAttempt !== '') {
        $timestamp = strtotime($lastAttempt);
        if (
            $timestamp !== false &&
            (time() - $timestamp) < TELEMETRY_FAILURE_RETRY
        ) {
            return false;
        }
    }

    return true;
}

function telemetry_payload(array &$state): array
{
    return [
        'installation_hash' => telemetry_installation_hash($state),
        'version' => defined('OPNSENTRAL_VERSION')
            ? OPNSENTRAL_VERSION
            : 'unknown',
        'architecture' => php_uname('m') ?: 'unknown',
        'platform' => 'docker',
    ];
}

function telemetry_send(bool $force = false): array
{
    $state = telemetry_load_state();

    if (($state['enabled'] ?? false) !== true) {
        $state['last_status'] = 'disabled';
        return $state;
    }

    if (!$force && !telemetry_is_due($state)) {
        return $state;
    }

    $endpoint = telemetry_endpoint();
    if ($endpoint === '') {
        $state['last_attempt'] = gmdate('c');
        $state['last_status'] = 'not_configured';
        $state['last_error'] =
            'TELEMETRY_URL is not configured for this container.';
        telemetry_save_state($state);
        return $state;
    }

    if (
        filter_var($endpoint, FILTER_VALIDATE_URL) === false ||
        !str_starts_with(strtolower($endpoint), 'https://')
    ) {
        $state['last_attempt'] = gmdate('c');
        $state['last_status'] = 'invalid_endpoint';
        $state['last_error'] =
            'TELEMETRY_URL must be a valid HTTPS URL.';
        telemetry_save_state($state);
        return $state;
    }

    $payload = telemetry_payload($state);
    $body = json_encode(
        $payload,
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE |
        JSON_THROW_ON_ERROR
    );

    $headers = [
        'Accept: application/json',
        'Content-Type: application/json',
        'User-Agent: opnSentral/' . $payload['version'],
    ];

    $token = trim(envv('TELEMETRY_WRITE_TOKEN', ''));
    if ($token !== '') {
        $headers[] = 'Authorization: Bearer ' . $token;
    }

    $curl = curl_init($endpoint);
    if ($curl === false) {
        throw new RuntimeException('Could not initialize telemetry request.');
    }

    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_HTTPHEADER => $headers,
    ]);

    $responseBody = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $error = curl_error($curl);
    curl_close($curl);

    $state['last_attempt'] = gmdate('c');

    if ($responseBody === false || $error !== '') {
        $state['last_status'] = 'failed';
        $state['last_error'] = 'Telemetry request failed: ' .
            ($error !== '' ? $error : 'unknown error');
        telemetry_save_state($state);
        return $state;
    }

    if ($status < 200 || $status >= 300) {
        $state['last_status'] = 'failed';
        $state['last_error'] = 'Telemetry endpoint returned HTTP ' . $status . '.';
        telemetry_save_state($state);
        return $state;
    }

    $decoded = json_decode($responseBody, true);
    if (!is_array($decoded) || ($decoded['ok'] ?? false) !== true) {
        $state['last_status'] = 'failed';
        $state['last_error'] =
            'Telemetry endpoint returned an invalid response.';
        telemetry_save_state($state);
        return $state;
    }

    $state['last_sent'] = gmdate('c');
    $state['last_status'] = 'sent';
    $state['last_error'] = null;
    telemetry_save_state($state);

    return $state;
}
