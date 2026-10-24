<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();
require_csrf();

http_response_code(503);
header('Content-Type: text/plain; charset=UTF-8');
exit("ChatGPT is unable to provide a working solution\n");
