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
                    $categoryUuid = central_alias_category_uuid($firewall);

                    if ($categoryUuid === null) {
                        $status = 'category missing';
                        $info = 'Managed category "' . managed_category_name() . '" is missing.';
                    } else {
                        $remote = central_alias_find($firewall, (string) $alias['name']);

                        if ($remote === null) {
                            $status = 'missing';
                            $info = 'Alias does not exist.';
                        } elseif (!central_alias_has_category($remote, $categoryUuid)) {
                            $status = 'unmanaged';
                            $info = 'Alias exists but is not assigned to the managed category "' . managed_category_name() . '".';
                        } else {
                            $sameType = (string) ($remote['type'] ?? '') === (string) $alias['type'];
                            $sameEnabled = (int) ($remote['enabled'] ?? 0) === (int) $alias['enabled'];
                            $sameContent = central_alias_lines((string) ($remote['content'] ?? '')) === central_alias_lines((string) $alias['content']);

                            if ($sameType && $sameEnabled && $sameContent) {
                                $status = 'synchronized';
                                $info = 'Remote definition matches.';
                            } else {
                                $status = 'different';
                                $info = 'Type, enabled state or content differs.';
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
<style>
.alias-overview-filter{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.alias-overview-filter label{font-weight:700}
.alias-overview-filter select{min-width:220px;width:auto}
.alias-filter-empty{padding:14px 12px;color:var(--muted);font-style:italic;text-align:center}
.alias-matrix-card{padding:0;overflow:hidden}
.alias-matrix-scroll{overflow:auto;max-width:100%}
.alias-matrix-table{min-width:max-content;margin:0}
.alias-matrix-table th,.alias-matrix-table td{vertical-align:top}
.alias-matrix-corner,.alias-matrix-name{position:sticky;left:0;z-index:3;background:var(--card-bg,#fff);min-width:240px;max-width:340px}
.alias-matrix-corner{z-index:5}
.alias-matrix-table thead th{position:sticky;top:0;z-index:4;background:var(--card-bg,#fff)}
.alias-matrix-table thead .alias-matrix-corner{left:0;z-index:6}
.alias-matrix-name strong{display:block}
.alias-matrix-name small{display:block;margin-top:4px;color:var(--muted);font-weight:400;white-space:normal}
.alias-matrix-type{display:inline-block;margin-top:4px;color:var(--muted);font-weight:400;font-size:.9em}
.alias-matrix-row-action{margin-top:8px}
.alias-matrix-row-action .button{padding:4px 8px;font-size:.84em}
.alias-matrix-firewall{min-width:170px;max-width:230px}
.alias-matrix-firewall strong{display:block}
.alias-matrix-firewall-url{display:block;margin-top:3px;font-size:.86em;white-space:normal;word-break:break-all;font-weight:400}
.alias-matrix-cell{min-width:150px;text-align:center}
.alias-matrix-cell-status,.alias-matrix-cell-meta{margin-bottom:6px}
.alias-matrix-missing{vertical-align:middle!important}
.alias-matrix-rename{padding:3px 7px;font-size:.82em}
@media (max-width:900px){
    .alias-matrix-corner,.alias-matrix-name{min-width:190px;max-width:230px}
    .alias-matrix-firewall{min-width:150px}
}
</style>

<div class="page-title management-page-title">
    <div>
        <h1><?= h(t('aliases.distributed')) ?></h1>
        <p>Complete alias inventory from every managed OPNsense.</p>
    </div>

    <div class="management-toolbar">
        <form method="post">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <button name="action" value="check"><?= h(t('aliases.check_sync')) ?></button>
        </form>

        <button type="button" class="button secondary" id="alias-inventory-refresh">Refresh</button>
        <a class="button" href="/aliases.php">Add alias</a>
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
        <div id="alias-inventory-summary" class="management-summary">Loading all aliases…</div>
    </div>
    <div class="alias-overview-filter">
        <label for="alias-management-filter">Show</label>
        <select id="alias-management-filter">
            <option value="all">All aliases</option>
            <option value="managed">opnSentral managed aliases</option>
            <option value="unmanaged">Unmanaged aliases</option>
        </select>
    </div>
</div>

<div id="alias-inventory-error" class="alert error hidden"></div>

<div id="alias-inventory-list">
    <section class="card"><p class="muted">Loading…</p></section>
</div>

<script src="/assets/alias-overview-matrix.js?v=062118"></script>
<script>
window.opnSentralAliasOverviewMatrix({
    listId: 'alias-inventory-list',
    summaryId: 'alias-inventory-summary',
    errorId: 'alias-inventory-error',
    refreshId: 'alias-inventory-refresh',
    filterId: 'alias-management-filter'
});
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
