<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

/** Local, single-administrator MFA. No external TOTP or QR service is used. */
function mfa_store(): PDO
{
    $pdo = db();
    $pdo->exec('CREATE TABLE IF NOT EXISTS administrator_mfa (
        id INTEGER PRIMARY KEY CHECK(id=1),
        secret_enc TEXT NOT NULL DEFAULT "",
        recovery_hashes TEXT NOT NULL DEFAULT "[]",
        last_counter INTEGER NOT NULL DEFAULT -1,
        generation TEXT NOT NULL DEFAULT "",
        failure_count INTEGER NOT NULL DEFAULT 0,
        blocked_until INTEGER NOT NULL DEFAULT 0
    )');
    $pdo->exec('INSERT OR IGNORE INTO administrator_mfa(id) VALUES(1)');
    return $pdo;
}

function mfa_state(): array
{
    $state = mfa_store()->query('SELECT * FROM administrator_mfa WHERE id=1')->fetch();
    if (!is_array($state)) throw new RuntimeException('MFA state unavailable.');
    return $state;
}

function mfa_enabled(): bool
{
    return (string)mfa_state()['secret_enc'] !== '';
}

function mfa_base32_encode(string $binary): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = 0;
    $buffer = 0;
    $out = '';
    foreach (unpack('C*', $binary) as $byte) {
        $buffer = ($buffer << 8) | $byte;
        $bits += 8;
        while ($bits >= 5) {
            $bits -= 5;
            $out .= $alphabet[($buffer >> $bits) & 31];
            $buffer &= (1 << $bits) - 1;
        }
    }
    if ($bits) $out .= $alphabet[($buffer << (5 - $bits)) & 31];
    return $out;
}

function mfa_base32_decode(string $encoded): string
{
    $encoded = strtoupper(preg_replace('/[\s=-]/', '', $encoded) ?? '');
    if ($encoded === '' || preg_match('/[^A-Z2-7]/', $encoded)) {
        throw new InvalidArgumentException('Invalid TOTP secret.');
    }
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = 0;
    $buffer = 0;
    $out = '';
    foreach (str_split($encoded) as $letter) {
        $buffer = ($buffer << 5) | strpos($alphabet, $letter);
        $bits += 5;
        if ($bits >= 8) {
            $bits -= 8;
            $out .= chr(($buffer >> $bits) & 255);
            $buffer &= (1 << $bits) - 1;
        }
    }
    return $out;
}

function mfa_totp(string $secret, int $counter, int $digits = 6): string
{
    if ($counter < 0) throw new InvalidArgumentException('Invalid TOTP counter.');
    $key = mfa_base32_decode($secret);
    $message = pack('N2', ($counter >> 32) & 0xffffffff, $counter & 0xffffffff);
    $mac = hash_hmac('sha1', $message, $key, true);
    $offset = ord($mac[19]) & 15;
    $integer = ((ord($mac[$offset]) & 127) << 24)
        | (ord($mac[$offset+1]) << 16)
        | (ord($mac[$offset+2]) << 8)
        | ord($mac[$offset+3]);
    return str_pad((string)($integer % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}

function mfa_counter_for_code(string $secret, string $code, int $now, int $lastCounter = -1): ?int
{
    if (!preg_match('/^\d{6}$/D', $code)) return null;
    $counter = intdiv($now, 30);
    for ($delta = -1; $delta <= 1; $delta++) {
        $candidate = $counter + $delta;
        if ($candidate <= $lastCounter || $candidate < 0) continue;
        if (hash_equals(mfa_totp($secret, $candidate), $code)) return $candidate;
    }
    return null;
}

function mfa_recovery_codes(): array
{
    $codes = [];
    for ($i=0; $i<10; $i++) {
        $raw = strtoupper(bin2hex(random_bytes(10)));
        $codes[] = implode('-', str_split($raw, 5));
    }
    return $codes;
}

function mfa_recovery_normalize(string $code): string
{
    return strtoupper(preg_replace('/[\s-]/', '', $code) ?? '');
}

function mfa_recovery_hash(string $code): string
{
    return hash('sha256', mfa_recovery_normalize($code));
}

function mfa_enable_with_code(string $secret, string $code, string $password): array
{
    if (!hash_equals(envv('ADMIN_PASSWORD'), $password) || $password === '') {
        throw new RuntimeException('Administrator password incorrect.');
    }
    if (mfa_counter_for_code($secret, $code, time()) === null) {
        throw new RuntimeException('Incorrect verification code.');
    }
    $codes = mfa_recovery_codes();
    $hashes = array_map('mfa_recovery_hash', $codes);
    $pdo = mfa_store();
    $pdo->beginTransaction();
    try {
        $state = $pdo->query('SELECT secret_enc FROM administrator_mfa WHERE id=1')->fetch();
        if (!is_array($state) || (string)$state['secret_enc'] !== '') {
            throw new RuntimeException('MFA is already enabled.');
        }
        $generation = bin2hex(random_bytes(16));
        $stmt = $pdo->prepare('UPDATE administrator_mfa SET secret_enc=?, recovery_hashes=?,
            last_counter=-1, generation=?, failure_count=0, blocked_until=0 WHERE id=1');
        $stmt->execute([encrypt_value($secret), json_encode($hashes, JSON_THROW_ON_ERROR), $generation]);
        $pdo->commit();
        return ['codes' => $codes, 'generation' => $generation];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
}

/** Login MFA verification with replay protection and one-time recovery codes. */
function mfa_verify_login_code(string $provided): bool
{
    $pdo = mfa_store();
    $pdo->exec('BEGIN IMMEDIATE');
    try {
        $state = $pdo->query('SELECT * FROM administrator_mfa WHERE id=1')->fetch();
        if (!is_array($state) || (string)$state['secret_enc'] === '') {
            $pdo->rollBack();
            return false;
        }
        $now = time();
        if ((int)$state['blocked_until'] > $now) {
            $pdo->commit();
            return false;
        }
        $secret = decrypt_value((string)$state['secret_enc']);
        $counter = mfa_counter_for_code($secret, trim($provided), $now, (int)$state['last_counter']);
        $hashes = json_decode((string)$state['recovery_hashes'], true);
        if (!is_array($hashes)) throw new RuntimeException('Recovery code data invalid.');
        $recoveryIndex = null;
        $normalized = mfa_recovery_normalize($provided);
        if ($counter === null && preg_match('/^[A-F0-9]{20}$/D', $normalized)) {
            $hash = mfa_recovery_hash($provided);
            foreach ($hashes as $index => $stored) {
                if (is_string($stored) && hash_equals($stored, $hash)) {
                    $recoveryIndex = $index;
                    break;
                }
            }
        }
        if ($counter === null && $recoveryIndex === null) {
            $failures = (int)$state['failure_count'] + 1;
            $lockUntil = $failures >= 8 ? $now + 300 : 0;
            $update = $pdo->prepare('UPDATE administrator_mfa SET failure_count=?, blocked_until=? WHERE id=1');
            $update->execute([$failures >= 8 ? 0 : $failures, $lockUntil]);
            $pdo->commit();
            return false;
        }
        if ($recoveryIndex !== null) {
            unset($hashes[$recoveryIndex]);
            $update = $pdo->prepare('UPDATE administrator_mfa SET recovery_hashes=?,
                failure_count=0,blocked_until=0 WHERE id=1');
            $update->execute([json_encode(array_values($hashes), JSON_THROW_ON_ERROR)]);
        } else {
            $update = $pdo->prepare('UPDATE administrator_mfa SET last_counter=?,
                failure_count=0,blocked_until=0 WHERE id=1');
            $update->execute([$counter]);
        }
        $pdo->commit();
        return true;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
}

function mfa_disable(string $password, string $code): bool
{
    if ($password === '' || !hash_equals(envv('ADMIN_PASSWORD'), $password)) return false;
    if (!mfa_verify_login_code($code)) return false;
    $pdo = mfa_store();
    // Rotate session generation on disabling MFA so previously authenticated
    // API-key and password sessions cannot become valid again.
    $stmt = $pdo->prepare('UPDATE administrator_mfa SET secret_enc="", recovery_hashes="[]",
        last_counter=-1, generation=?, failure_count=0, blocked_until=0 WHERE id=1');
    $stmt->execute([bin2hex(random_bytes(16))]);
    return true;
}

function mfa_session_satisfied(): bool
{
    $state = mfa_state();
    $generation = (string)$state['generation'];
    // Blank generation preserves existing sessions on installations that
    // have never activated MFA. After enrollment, all sessions are epoch-bound.
    if ($generation !== '' && !hash_equals($generation, (string)($_SESSION['mfa_generation'] ?? ''))) {
        return false;
    }
    if ((string)$state['secret_enc'] === '') return true;
    return ($_SESSION['mfa_verified'] ?? false) === true && $generation !== '';
}
