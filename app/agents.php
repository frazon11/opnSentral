<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();

require __DIR__ . '/inc/header.php';
?>
<div class="page-title management-page-title">
    <div>
        <h1>Agents</h1>
        <p>Agent management is disabled.</p>
    </div>
</div>

<div class="alert warningbox" data-presentation-exempt="true">
    <strong>Disabled</strong>
    <p>ChatGPT is unable to provide a working solution</p>
</div>

<?php require __DIR__ . '/inc/footer.php'; ?>
