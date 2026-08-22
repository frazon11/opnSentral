<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();
require_csrf();

http_response_code(409);
exit('Full System Access user writes are disabled for safety. Use System → Access → Add SSH Key to add one key to one existing user on one firewall.');
