<?php
declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';

require_login();

$firewalls = db()->query(
    'SELECT id,name,base_url FROM firewalls ORDER BY name'
)->fetchAll();

require __DIR__ . '/inc/header.php';
?>

<style>
.troubleshooting-toolbar{
    display:grid;
    grid-template-columns:minmax(250px,1fr) auto minmax(250px,1fr) auto;
    gap:12px;
    align-items:end;
    margin-bottom:14px
}
.troubleshooting-toolbar label{
    margin:0
}
.troubleshooting-toolbar select{
    margin-top:5px
}
.troubleshooting-toolbar .compare-separator{
    align-self:center;
    padding-top:22px;
    font-size:1.4rem;
    font-weight:800;
    color:var(--muted)
}
.troubleshooting-filterbar{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:14px;
    flex-wrap:wrap;
    padding:12px 14px;
    margin-bottom:14px;
    border:1px solid var(--border);
    background:var(--panel)
}
.troubleshooting-filters{
    display:flex;
    align-items:center;
    gap:12px;
    flex-wrap:wrap
}
.troubleshooting-filters label{
    margin:0;
    display:flex;
    align-items:center;
    gap:6px
}
.troubleshooting-filters input[type=radio]{
    width:auto;
    margin:0
}
.troubleshooting-search{
    width:min(430px,100%)
}
.troubleshooting-search input{
    margin:0
}
.compare-summary{
    display:grid;
    grid-template-columns:repeat(5,minmax(120px,1fr));
    gap:8px;
    margin-bottom:14px
}
.compare-summary>div{
    padding:10px 12px;
    border:1px solid var(--border);
    background:var(--panel)
}
.compare-summary strong,
.compare-summary span{
    display:block
}
.compare-summary strong{
    font-size:.76rem;
    color:var(--muted);
    margin-bottom:3px
}
.compare-table-wrap{
    overflow:auto;
    border:1px solid var(--border);
    background:var(--panel)
}
.compare-table{
    width:100%;
    min-width:1100px;
    border-collapse:collapse
}
.compare-table th,
.compare-table td{
    padding:9px 10px;
    border-bottom:1px solid var(--border);
    border-right:1px solid var(--border);
    vertical-align:top;
    text-align:left
}
.compare-table th:last-child,
.compare-table td:last-child{
    border-right:0
}
.compare-table th{
    position:sticky;
    top:0;
    z-index:2;
    background:var(--table-head);
    color:var(--muted);
    font-size:.78rem;
    text-transform:uppercase;
    letter-spacing:.035em
}
.compare-table tr.is-different{
    background:rgba(202,91,43,.08)
}
.compare-table tr.is-same{
    opacity:.82
}
.compare-path{
    min-width:360px;
    max-width:520px;
    font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
    overflow-wrap:anywhere
}
.compare-value{
    min-width:300px;
    max-width:520px;
    font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
    white-space:pre-wrap;
    overflow-wrap:anywhere
}
.compare-missing{
    color:#a63a32;
    font-style:italic
}
.compare-difference-badge{
    display:inline-block;
    padding:3px 7px;
    border-radius:3px;
    font-size:.74rem;
    font-weight:700
}
.compare-difference-badge.changed{
    background:#f6dddd;
    color:#942b2b
}
.compare-difference-badge.same{
    background:#d9f0df;
    color:#21723a
}
.compare-empty{
    padding:30px;
    text-align:center;
    color:var(--muted)
}
@media(max-width:900px){
    .troubleshooting-toolbar{
        grid-template-columns:1fr
    }
    .troubleshooting-toolbar .compare-separator{
        display:none
    }
    .compare-summary{
        grid-template-columns:repeat(2,minmax(0,1fr))
    }
}
</style>

<div class="page-title">
    <div>
        <h1>Troubleshooting</h1>
        <p>
            Compare all configuration settings from two managed OPNsense
            firewalls. Aliases and categories are matched by name instead
            of their internal IDs or list positions.
        </p>
    </div>
</div>

<section class="card">
    <div class="troubleshooting-toolbar">
        <label>
            Left OPNsense
            <select id="left-firewall">
                <option value="">Select firewall</option>
                <?php foreach ($firewalls as $firewall): ?>
                    <option value="<?= (int) $firewall['id'] ?>">
                        <?= h((string) $firewall['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </label>

        <div class="compare-separator">⇄</div>

        <label>
            Right OPNsense
            <select id="right-firewall">
                <option value="">Select firewall</option>
                <?php foreach ($firewalls as $firewall): ?>
                    <option value="<?= (int) $firewall['id'] ?>">
                        <?= h((string) $firewall['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </label>

        <button type="button" id="compare-button">
            Compare
        </button>
    </div>
</section>

<div id="compare-error" class="alert error hidden"></div>
<div id="compare-loading" class="alert goodbox hidden">
    Loading and comparing both OPNsense configurations…
</div>

<section id="compare-results" class="hidden">
    <div class="troubleshooting-filterbar">
        <div class="troubleshooting-filters">
            <strong>Show:</strong>

            <label>
                <input
                    type="radio"
                    name="comparison-filter"
                    value="all"
                    checked
                >
                All settings
            </label>

            <label>
                <input
                    type="radio"
                    name="comparison-filter"
                    value="different"
                >
                Different settings only
            </label>
        </div>

        <div class="troubleshooting-search">
            <input
                type="search"
                id="compare-search"
                placeholder="Filter setting path or value"
            >
        </div>
    </div>

    <div class="compare-summary">
        <div>
            <strong>Total settings</strong>
            <span id="summary-total">0</span>
        </div>
        <div>
            <strong>Same</strong>
            <span id="summary-same">0</span>
        </div>
        <div>
            <strong>Different</strong>
            <span id="summary-different">0</span>
        </div>
        <div>
            <strong>Missing left</strong>
            <span id="summary-missing-left">0</span>
        </div>
        <div>
            <strong>Missing right</strong>
            <span id="summary-missing-right">0</span>
        </div>
    </div>

    <div class="compare-table-wrap">
        <table class="compare-table">
            <thead>
                <tr>
                    <th>Setting path</th>
                    <th id="left-heading">Left OPNsense</th>
                    <th id="right-heading">Right OPNsense</th>
                    <th>Result</th>
                </tr>
            </thead>
            <tbody id="compare-body"></tbody>
        </table>

        <div id="compare-empty" class="compare-empty hidden">
            No settings match the selected filter.
        </div>
    </div>
</section>

<script>
(function(){
    const leftSelect = document.getElementById('left-firewall');
    const rightSelect = document.getElementById('right-firewall');
    const compareButton = document.getElementById('compare-button');
    const errorBox = document.getElementById('compare-error');
    const loadingBox = document.getElementById('compare-loading');
    const results = document.getElementById('compare-results');
    const body = document.getElementById('compare-body');
    const empty = document.getElementById('compare-empty');
    const search = document.getElementById('compare-search');

    let comparisonRows = [];
    let comparisonData = null;

    function escapeHtml(value){
        const div = document.createElement('div');
        div.textContent = String(value ?? '');
        return div.innerHTML;
    }

    function visibleFilter(){
        return document.querySelector(
            'input[name="comparison-filter"]:checked'
        )?.value || 'all';
    }

    function render(){
        const filter = visibleFilter();
        const query = String(search.value || '').trim().toLowerCase();

        const rows = comparisonRows.filter(row => {
            if(filter === 'different' && !row.different){
                return false;
            }

            if(query === ''){
                return true;
            }

            const haystack = [
                row.path,
                row.left,
                row.right
            ].map(value => String(value ?? '').toLowerCase()).join(' ');

            return haystack.includes(query);
        });

        body.innerHTML = rows.map(row => {
            const left = row.left_exists
                ? escapeHtml(row.left ?? '')
                : '<span class="compare-missing">Missing</span>';
            const right = row.right_exists
                ? escapeHtml(row.right ?? '')
                : '<span class="compare-missing">Missing</span>';

            return `
                <tr class="${row.different
                    ? 'is-different'
                    : 'is-same'}">
                    <td class="compare-path">
                        ${escapeHtml(row.path)}
                    </td>
                    <td class="compare-value">${left}</td>
                    <td class="compare-value">${right}</td>
                    <td>
                        <span class="compare-difference-badge ${
                            row.different ? 'changed' : 'same'
                        }">
                            ${row.different ? 'Different' : 'Same'}
                        </span>
                    </td>
                </tr>
            `;
        }).join('');

        empty.classList.toggle('hidden', rows.length !== 0);
    }

    async function compare(){
        errorBox.classList.add('hidden');
        results.classList.add('hidden');

        const leftId = Number(leftSelect.value);
        const rightId = Number(rightSelect.value);

        if(!leftId || !rightId){
            errorBox.textContent = 'Select two OPNsense firewalls.';
            errorBox.classList.remove('hidden');
            return;
        }

        if(leftId === rightId){
            errorBox.textContent =
                'Select two different OPNsense firewalls.';
            errorBox.classList.remove('hidden');
            return;
        }

        compareButton.disabled = true;
        loadingBox.classList.remove('hidden');

        try{
            const response = await fetch(
                '/troubleshooting_data.php?' +
                new URLSearchParams({
                    left_id:String(leftId),
                    right_id:String(rightId)
                }),
                {
                    credentials:'same-origin',
                    cache:'no-store'
                }
            );

            const raw = await response.text();
            let data;

            try{
                data = JSON.parse(raw);
            }catch(error){
                throw new Error(
                    'Invalid server response: ' +
                    raw.replace(/\s+/g, ' ').slice(0, 500)
                );
            }

            if(!response.ok || data.ok !== true){
                throw new Error(data.error || 'Comparison failed.');
            }

            comparisonData = data;
            comparisonRows = Array.isArray(data.rows)
                ? data.rows
                : [];

            document.getElementById('left-heading').textContent =
                data.left.name + ' (' +
                data.left.setting_count + ' settings)';
            document.getElementById('right-heading').textContent =
                data.right.name + ' (' +
                data.right.setting_count + ' settings)';

            document.getElementById('summary-total').textContent =
                data.summary.total;
            document.getElementById('summary-same').textContent =
                data.summary.same;
            document.getElementById('summary-different').textContent =
                data.summary.different;
            document.getElementById(
                'summary-missing-left'
            ).textContent = data.summary.missing_left;
            document.getElementById(
                'summary-missing-right'
            ).textContent = data.summary.missing_right;

            results.classList.remove('hidden');
            render();
        }catch(error){
            errorBox.textContent = error.message;
            errorBox.classList.remove('hidden');
        }finally{
            compareButton.disabled = false;
            loadingBox.classList.add('hidden');
        }
    }

    compareButton.addEventListener('click', compare);

    document.querySelectorAll(
        'input[name="comparison-filter"]'
    ).forEach(radio => {
        radio.addEventListener('change', render);
    });

    search.addEventListener('input', render);
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
