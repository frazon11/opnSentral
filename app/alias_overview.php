<?php
declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/managed_category.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/alias_central.php';

require_login();
central_alias_init();

$message = '';
$error = '';

$aliases = db()
    ->query('SELECT * FROM central_aliases ORDER BY name')
    ->fetchAll();
$firewalls = db()
    ->query('SELECT * FROM firewalls ORDER BY name')
    ->fetchAll();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    try {
        foreach ($aliases as $alias) {
            foreach ($firewalls as $firewall) {
                $status = 'unknown';
                $info = 'Not checked';

                try {
                    $categoryUuid =
                        central_alias_category_uuid($firewall);

                    if ($categoryUuid === null) {
                        $status = 'category missing';
                        $info = 'Managed category "' . managed_category_name() . '" is missing.';
                    } else {
                        $remote = central_alias_find(
                            $firewall,
                            (string) $alias['name']
                        );

                        if ($remote === null) {
                            $status = 'missing';
                            $info = 'Alias does not exist.';
                        } elseif (
                            !central_alias_has_category(
                                $remote,
                                $categoryUuid
                            )
                        ) {
                            $status = 'unmanaged';
                            $info =
                                'Alias exists but is not assigned to ' .
                                'the managed category "' . managed_category_name() . '".';
                        } else {
                            $sameType =
                                (string) ($remote['type'] ?? '') ===
                                (string) $alias['type'];
                            $sameEnabled =
                                (int) ($remote['enabled'] ?? 0) ===
                                (int) $alias['enabled'];
                            $sameContent =
                                central_alias_lines(
                                    (string) (
                                        $remote['content'] ?? ''
                                    )
                                ) ===
                                central_alias_lines(
                                    (string) $alias['content']
                                );

                            if (
                                $sameType &&
                                $sameEnabled &&
                                $sameContent
                            ) {
                                $status = 'synchronized';
                                $info = 'Remote definition matches.';
                            } else {
                                $status = 'different';
                                $info =
                                    'Type, enabled state or content ' .
                                    'differs.';
                            }
                        }
                    }
                } catch (Throwable $exception) {
                    $status = 'unreachable';
                    $info = $exception->getMessage();
                }

                central_alias_target_status(
                    (int) $alias['id'],
                    (int) $firewall['id'],
                    $status,
                    $info
                );
            }
        }

        $message = 'Alias synchronization check completed.';
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>

<div class="page-title management-page-title">
    <div>
        <h1><?= h(t('aliases.distributed')) ?></h1>
        <p>
            Complete alias inventory from every managed OPNsense.
        </p>
    </div>

    <div class="management-toolbar">
        <form method="post">
            <input
                type="hidden"
                name="csrf"
                value="<?= h(csrf_token()) ?>"
            >
            <button name="action" value="check">
                <?= h(t('aliases.check_sync')) ?>
            </button>
        </form>

        <button
            type="button"
            class="button secondary"
            id="alias-inventory-refresh"
        >
            Refresh
        </button>

        <a class="button" href="/aliases.php">
            Add alias
        </a>
    </div>
</div>

<?php if ($message): ?>
    <div class="alert goodbox"><?= h($message) ?></div>
<?php endif; ?>

<?php if ($error): ?>
    <div class="alert error"><?= h($error) ?></div>
<?php endif; ?>

<div class="management-overview-bar">
    <div>
        <strong>Alias overview</strong>
        <div id="alias-inventory-summary" class="management-summary">
            Loading all aliases…
        </div>
    </div>
</div>

<div id="alias-inventory-error" class="alert error hidden"></div>

<div id="alias-inventory-list" class="vpn-summary-list">
    <section class="card vpn-summary-card">
        <p class="muted">Loading…</p>
    </section>
</div>

<script src="/assets/inventory-overview.js?v=06111"></script>
<script>
window.opnCentralInventoryOverview({
    type: 'aliases',
    label: 'Aliases',
    addUrl: '/aliases.php',
    listId: 'alias-inventory-list',
    summaryId: 'alias-inventory-summary',
    errorId: 'alias-inventory-error',
    refreshId: 'alias-inventory-refresh'
});
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
