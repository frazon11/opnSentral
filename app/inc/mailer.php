<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/notification_settings.php';

function smtp_config(): array
{
    $settings = notification_settings();
    return [
        'host' => $settings['smtp_host'],
        'port' => $settings['smtp_port'],
        'security' => $settings['smtp_security'],
        'username' => $settings['smtp_username'],
        'password' => $settings['smtp_password'],
        'from' => $settings['smtp_from'],
        'from_name' => $settings['smtp_from_name'],
        'to' => array_values(array_filter(array_map('trim', explode(',', $settings['notify_to'])))),
    ];
}

function smtp_is_configured(): bool
{
    $config = smtp_config();
    return $config['host'] !== '' && $config['from'] !== '' && $config['to'] !== [];
}

function smtp_read_response($socket, array $expected): string
{
    $response = '';
    while (($line = fgets($socket, 4096)) !== false) {
        $response .= $line;
        if (strlen($line) >= 4 && $line[3] === ' ') {
            break;
        }
    }

    $code = (int) substr($response, 0, 3);
    if (!in_array($code, $expected, true)) {
        throw new RuntimeException('SMTP error ' . $code . ': ' . trim($response));
    }

    return $response;
}

function smtp_command($socket, string $command, array $expected): string
{
    if (fwrite($socket, $command . "\r\n") === false) {
        throw new RuntimeException('Could not write to the SMTP server.');
    }
    return smtp_read_response($socket, $expected);
}

function smtp_header_value(string $value): string
{
    return '=?UTF-8?B?' . base64_encode($value) . '?=';
}

function smtp_send(string $subject, string $body): void
{
    $config = smtp_config();
    if (!smtp_is_configured()) {
        throw new RuntimeException('SMTP is not fully configured.');
    }

    $transport = $config['security'] === 'ssl' ? 'ssl://' : '';
    $socket = @stream_socket_client(
        $transport . $config['host'] . ':' . $config['port'],
        $errorNumber,
        $errorMessage,
        15,
        STREAM_CLIENT_CONNECT
    );
    if (!is_resource($socket)) {
        throw new RuntimeException('SMTP connection failed: ' . $errorMessage . ' (' . $errorNumber . ')');
    }

    stream_set_timeout($socket, 15);

    try {
        smtp_read_response($socket, [220]);
        $hostname = gethostname() ?: 'opncentral';
        smtp_command($socket, 'EHLO ' . $hostname, [250]);

        if ($config['security'] === 'tls') {
            smtp_command($socket, 'STARTTLS', [220]);
            if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                throw new RuntimeException('Could not enable SMTP TLS encryption.');
            }
            smtp_command($socket, 'EHLO ' . $hostname, [250]);
        }

        if ($config['username'] !== '') {
            smtp_command($socket, 'AUTH LOGIN', [334]);
            smtp_command($socket, base64_encode($config['username']), [334]);
            smtp_command($socket, base64_encode($config['password']), [235]);
        }

        smtp_command($socket, 'MAIL FROM:<' . $config['from'] . '>', [250]);
        foreach ($config['to'] as $recipient) {
            smtp_command($socket, 'RCPT TO:<' . $recipient . '>', [250, 251]);
        }
        smtp_command($socket, 'DATA', [354]);

        $headers = [
            'Date: ' . date(DATE_RFC2822),
            'From: ' . smtp_header_value($config['from_name']) . ' <' . $config['from'] . '>',
            'To: ' . implode(', ', $config['to']),
            'Subject: ' . smtp_header_value($subject),
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
            'X-Mailer: opnCentral',
        ];

        $normalizedBody = preg_replace("~\r?\n~", "\r\n", $body) ?? $body;
        $normalizedBody = preg_replace('/(?m)^\./', '..', $normalizedBody) ?? $normalizedBody;
        $message = implode("\r\n", $headers) . "\r\n\r\n" . $normalizedBody . "\r\n.";
        smtp_command($socket, $message, [250]);
        smtp_command($socket, 'QUIT', [221]);
    } finally {
        fclose($socket);
    }
}
