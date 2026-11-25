<?php
declare(strict_types=1);

/* Run only in an isolated test container. This deliberately uses
   /var/www/data/central.sqlite and must never run against a live deployment. */
require_once dirname(__DIR__) . '/app/inc/config.php';
require_once dirname(__DIR__) . '/app/inc/mfa.php';

putenv('APP_KEY=' . str_repeat('ab', 32));
putenv('ADMIN_PASSWORD=ci-only-mfa-password');

function mfa_assert(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException('MFA test failed: ' . $message);
}

$binary = '12345678901234567890';
$secret = mfa_base32_encode($binary);
mfa_assert(mfa_base32_decode($secret) === $binary, 'base32 round trip');
foreach ([59 => '94287082', 1111111109 => '07081804',
    1111111111 => '14050471', 1234567890 => '89005924',
    2000000000 => '69279037', 20000000000 => '65353130'] as $timestamp => $expected) {
    mfa_assert(mfa_totp($secret, intdiv((int)$timestamp, 30), 8) === $expected,
        'RFC 6238 vector for ' . $timestamp);
}
mfa_assert(mfa_counter_for_code($secret, '287082', 59) === 1, 'six digit TOTP accepted');
mfa_assert(mfa_counter_for_code($secret, '287082', 59, 1) === null, 'replayed counter rejected');

mfa_assert(!mfa_enabled(), 'new installations default to MFA disabled');
mfa_assert(mfa_session_satisfied(), 'disabled MFA requires no second factor');
$enrollSecret = mfa_base32_encode(random_bytes(20));
$otp = mfa_totp($enrollSecret, intdiv(time(), 30));
$result = mfa_enable_with_code($enrollSecret, $otp, 'ci-only-mfa-password');
mfa_assert(mfa_enabled(), 'MFA enabled only after valid code and password');
mfa_assert(count($result['codes']) === 10, 'ten recovery codes generated');

start_session_secure();
$_SESSION['auth'] = true;
$_SESSION['mfa_verified'] = false;
mfa_assert(!logged_in(), 'old sessions rejected after MFA enrollment');
$_SESSION['mfa_verified'] = true;
$_SESSION['mfa_generation'] = 'wrong';
mfa_assert(!logged_in(), 'wrong generation rejected');
$_SESSION['mfa_generation'] = $result['generation'];
mfa_assert(logged_in(), 'valid MFA session accepted');

mfa_assert(mfa_verify_login_code($otp), 'valid login OTP accepted');
mfa_assert(!mfa_verify_login_code($otp), 'replay of same OTP rejected');
mfa_assert(mfa_verify_login_code($result['codes'][0]), 'recovery code accepted');
mfa_assert(!mfa_verify_login_code($result['codes'][0]), 'recovery code cannot be reused');
mfa_assert(!mfa_disable('incorrect', $result['codes'][1]), 'incorrect password cannot disable MFA');
mfa_assert(mfa_enabled(), 'MFA remains enabled after bad password');
mfa_assert(mfa_disable('ci-only-mfa-password', $result['codes'][1]), 'password + recovery can disable');
mfa_assert(!mfa_enabled(), 'MFA disabled successfully');

fwrite(STDOUT, "MFA RFC6238, enrollment, session enforcement, replay, recovery, and disable tests passed.\n");
