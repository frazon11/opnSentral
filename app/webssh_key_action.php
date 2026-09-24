<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/webssh.php';
require_login();
require_csrf();

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        throw new RuntimeException('POST required.');
    }

    $firewallId = filter_var($_POST['firewall_id'] ?? null, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1],
    ]);
    if ($firewallId === false) throw new RuntimeException('Invalid firewall id.');

    $action = trim((string) ($_POST['action'] ?? ''));
    if (!in_array($action, ['generate_deploy', 'deploy_existing'], true)) {
        throw new RuntimeException('Invalid WebSSH key action.');
    }

    $statement = db()->prepare('SELECT * FROM firewalls WHERE id = ? LIMIT 1');
    $statement->execute([(int) $firewallId]);
    $firewall = $statement->fetch();
    if (!is_array($firewall)) throw new RuntimeException('Firewall not found.');

    $username = trim((string) ($firewall['ssh_username'] ?? ''));
    if ($username === '') {
        throw new RuntimeException('Configure the WebSSH SSH username first.');
    }

    if ($action === 'generate_deploy') {
        // Fail before changing stored authentication if the remote agent cannot
        // accept the narrow Authorized Key job yet.
        webssh_public_key_deploy_agent($firewall);
        $pair = webssh_generate_rsa_keypair(3072, 'opnSentral-' . (string) ($firewall['name'] ?? 'firewall'));
        $privateKeyEnc = encrypt_value((string) $pair['private_key']);
        $statement = db()->prepare(
            'UPDATE firewalls SET ssh_auth_method=?,ssh_password_enc=?,ssh_private_key_enc=?,updated_at=? WHERE id=?'
        );
        $statement->execute(['key', '', $privateKeyEnc, gmdate('c'), (int) $firewallId]);
        $firewall['ssh_auth_method'] = 'key';
        $firewall['ssh_password_enc'] = '';
        $firewall['ssh_private_key_enc'] = $privateKeyEnc;
        $publicKey = (string) $pair['public_key'];
        $jobId = webssh_queue_public_key_deploy($firewall, $publicKey);
        $_SESSION['webssh_key_result'] = [
            'ok' => true,
            'message' => 'Generated a 3072-bit RSA keypair, stored the private key encrypted, and queued public-key deployment as agent job #' . $jobId . '. Existing authorized_keys entries will be preserved.',
        ];
    } else {
        if ((string) ($firewall['ssh_auth_method'] ?? '') !== 'key' || trim((string) ($firewall['ssh_private_key_enc'] ?? '')) === '') {
            throw new RuntimeException('No stored private key is configured for this firewall.');
        }
        $privateKey = decrypt_value((string) $firewall['ssh_private_key_enc']);
        $publicKey = webssh_rsa_public_key_from_private($privateKey, 'opnSentral-' . (string) ($firewall['name'] ?? 'firewall'));
        $jobId = webssh_queue_public_key_deploy($firewall, $publicKey);
        $_SESSION['webssh_key_result'] = [
            'ok' => true,
            'message' => 'Queued public-key deployment as agent job #' . $jobId . '. Existing authorized_keys entries will be preserved.',
        ];
    }
} catch (Throwable $exception) {
    $_SESSION['webssh_key_result'] = [
        'ok' => false,
        'message' => $exception->getMessage(),
    ];
}

header('Location: /webssh.php');
exit;
