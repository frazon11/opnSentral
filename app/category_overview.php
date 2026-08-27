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

$categories = db()->query('SELECT * FROM central_categories ORDER BY name')->fetchAll();
$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();

    try {
        foreach ($categories as $category) {
            foreach ($firewalls as $firewall) {
                $status = 'unknown';
                $info = 'Not checked';

                try {
                    $remote = central_category_search($firewall, (string) $category['name']);

                    if ($remote === null) {
                        $status = 'missing';
                        $info = 'Category does not exist.';
                    } else {
                        $remoteColor = strtolower((string) ($remote['color'] ?? ''));
                        $localColor = strtolower((string) $category['color']);
                        $remoteAutomatic = (int) ($remote['auto'] ?? $remote['automatic'] ?? 0);

                        if ($remoteColor === $localColor && $remoteAutomatic === (int) $category['automatic']) {
                            $status = 'synchronized';
                            $info = 'Remote definition matches.';
                        } else {
                            $status = 'different';
                            $info = 'Color or automatic setting differs.';
                        }
                    }
                } catch (Throwable $exception) {
                    $status = 'unreachable';
                    $info = $exception->getMessage();
                }

                central_category_target_status((int) $category['id'], (int) $firewall['id'], $status, $info);
            }
        }

        $message = 'Category synchronization check completed.';
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

require __DIR__ . '/inc/header.php';
?>
<style>
.category-overview-filter{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.category-overview-filter label{font-weight:700}
.category-overview-filter select{min-width:220px;width:auto}
.category-filter-empty{padding:14px 12px;color:var(--muted);font-style:italic;text-align:center}
.category-matrix-card{padding:0;overflow:hidden}
.category-matrix-scroll{overflow:auto;max-width:100%}
.category-matrix-table{min-width:max-content;margin:0}
.category-matrix-table th,.category-matrix-table td{vertical-align:top}
.category-matrix-corner,.category-matrix-name{position:sticky;left:0;z-index:3;background:var(--card-bg,#fff);min-width:240px;max-width:340px}
.category-matrix-corner{z-index:5}
.category-matrix-table thead th{position:sticky;top:0;z-index:4;background:var(--card-bg,#fff)}
.category-matrix-table thead .category-matrix-corner{left:0;z-index:6}
.category-matrix-name strong{display:block}
.category-matrix-type{display:inline-block;margin-top:4px;color:var(--muted);font-weight:400;font-size:.9em}
.category-matrix-row-action{margin-top:8px}
.category-matrix-row-action .button{padding:4px 8px;font-size:.84em}
.category-matrix-firewall{min-width:170px;max-width:230px}
.category-matrix-firewall strong{display:block}
.category-matrix-firewall-url{display:block;margin-top:3px;font-size:.86em;white-space:normal;word-break:break-all;font-weight:400}
.category-matrix-cell{min-width:150px;text-align:center}
.category-matrix-cell-status,.category-matrix-cell-meta{margin-bottom:6px}
.category-matrix-missing{vertical-align:middle!important}
.category-matrix-rename{padding:3px 7px;font-size:.82em}
@media (max-width:900px){
    .category-matrix-corner,.category-matrix-name{min-width:190px;max-width:230px}
    .category-matrix-firewall{min-width:150px}
}
</style>

<div class="page-title management-page-title">
    <div>
        <h1><?= h(t('categories.distributed')) ?></h1>
        <p>Complete category inventory from every managed OPNsense.</p>
    </div>

    <div class="management-toolbar">
        <form method="post">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <button name="action" value="check"><?= h(t('aliases.check_sync')) ?></button>
        </form>
        <button type="button" class="button secondary" id="category-inventory-refresh">Refresh</button>
        <a class="button" href="/categories.php">Add category</a>
    </div>
</div>

<?php if ($message): ?><div class="alert goodbox"><?= h($message) ?></div><?php endif; ?>
<?php if ($error): ?><div class="alert error"><?= h($error) ?></div><?php endif; ?>

<div class="management-overview-bar">
    <div>
        <strong>Category overview</strong>
        <div id="category-inventory-summary" class="management-summary">Loading all categories…</div>
    </div>
    <div class="category-overview-filter">
        <label for="category-management-filter">Show</label>
        <select id="category-management-filter">
            <option value="all">All categories</option>
            <option value="managed">opnSentral managed categories</option>
            <option value="unmanaged">Unmanaged categories</option>
        </select>
    </div>
</div>

<div id="category-inventory-error" class="alert error hidden"></div>
<div id="category-inventory-list"><section class="card"><p class="muted">Loading…</p></section></div>

<script src="/assets/category-overview-matrix.js?v=062118"></script>
<script>
window.opnSentralCategoryOverviewMatrix({
    listId: 'category-inventory-list',
    summaryId: 'category-inventory-summary',
    errorId: 'category-inventory-error',
    refreshId: 'category-inventory-refresh',
    filterId: 'category-management-filter'
});
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
