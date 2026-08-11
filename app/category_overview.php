<?php
declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/managed_category.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/category_central.php';

require_login();
central_category_init();

$message = '';
$error = '';

$categories = db()
    ->query('SELECT * FROM central_categories ORDER BY name')
    ->fetchAll();
$firewalls = db()
    ->query('SELECT * FROM firewalls ORDER BY name')
    ->fetchAll();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    try {
        foreach ($categories as $category) {
            foreach ($firewalls as $firewall) {
                $status = 'unknown';
                $info = 'Not checked';

                try {
                    $remote = central_category_search(
                        $firewall,
                        (string) $category['name']
                    );

                    if ($remote === null) {
                        $status = 'missing';
                        $info = 'Category does not exist.';
                    } else {
                        $remoteColor = strtolower(
                            (string) ($remote['color'] ?? '')
                        );
                        $localColor = strtolower(
                            (string) $category['color']
                        );
                        $remoteAutomatic = (int) (
                            $remote['auto'] ??
                            $remote['automatic'] ??
                            0
                        );

                        if (
                            $remoteColor === $localColor &&
                            $remoteAutomatic ===
                                (int) $category['automatic']
                        ) {
                            $status = 'synchronized';
                            $info = 'Remote definition matches.';
                        } else {
                            $status = 'different';
                            $info =
                                'Color or automatic setting differs.';
                        }
                    }
                } catch (Throwable $exception) {
                    $status = 'unreachable';
                    $info = $exception->getMessage();
                }

                central_category_target_status(
                    (int) $category['id'],
                    (int) $firewall['id'],
                    $status,
                    $info
                );
            }
        }

        $message = 'Category synchronization check completed.';
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>

<div class="page-title management-page-title">
    <div>
        <h1><?= h(t('categories.distributed')) ?></h1>
        <p>
            Complete category inventory from every managed OPNsense.
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
            id="category-inventory-refresh"
        >
            Refresh
        </button>

        <a class="button" href="/categories.php">
            Add category
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
        <strong>Category overview</strong>
        <div id="category-inventory-summary" class="management-summary">
            Loading all categories…
        </div>
    </div>
</div>

<div id="category-inventory-error" class="alert error hidden"></div>

<div id="category-inventory-list" class="vpn-summary-list">
    <section class="card vpn-summary-card">
        <p class="muted">Loading…</p>
    </section>
</div>

<script src="/assets/inventory-overview.js?v=06111"></script>
<script>
window.opnCentralInventoryOverview({
    type: 'categories',
    label: 'Categories',
    addUrl: '/categories.php',
    listId: 'category-inventory-list',
    summaryId: 'category-inventory-summary',
    errorId: 'category-inventory-error',
    refreshId: 'category-inventory-refresh'
});
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
