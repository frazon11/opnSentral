<?php http_response_code(200);header('Content-Type:text/plain');if (!class_exists('ZipArchive')) {
    http_response_code(500);
    echo 'zip extension unavailable';
    exit;
}

echo 'ok';