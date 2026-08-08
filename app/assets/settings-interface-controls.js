(function(){
    'use strict';

    const presentationStack = document.querySelector('.presentation-mode-stack');
    const lockStack = document.querySelector('.configuration-lock-stack');
    const topbarRight = document.querySelector('.topbar-right');

    if(location.pathname !== '/settings.php'){
        if(presentationStack) presentationStack.hidden = true;
        if(lockStack) lockStack.hidden = true;
        if(topbarRight && !topbarRight.querySelector(':scope > :not([hidden])')){
            topbarRight.hidden = true;
        }
        return;
    }

    const grid = document.querySelector('.settings-grid');
    if(!grid || (!presentationStack && !lockStack)) return;

    const card = document.createElement('section');
    card.className = 'card wide';
    card.id = 'interface-access-settings';
    card.innerHTML = `
        <h2>Interface &amp; access</h2>
        <p class="muted">Control configuration write access and presentation mode.</p>
        <div class="backup-restore-grid">
            <div class="settings-subpanel" id="configuration-access-settings">
                <h3>Configuration access</h3>
                <p class="muted">
                    Lock opnSentral in read-only mode or unlock remote configuration changes for this login session.
                </p>
                <div class="settings-control-mount" id="configuration-lock-mount"></div>
            </div>
            <div class="settings-subpanel" id="presentation-settings">
                <h3>Presentation mode</h3>
                <p class="muted">
                    Replace visible names, addresses and domains with presentation-safe values.
                </p>
                <div class="settings-control-mount" id="presentation-mode-mount"></div>
            </div>
        </div>`;

    const firstWideCard = grid.querySelector('.card.wide');
    if(firstWideCard) firstWideCard.before(card);
    else grid.appendChild(card);

    if(lockStack){
        lockStack.hidden = false;
        document.getElementById('configuration-lock-mount')?.appendChild(lockStack);
    }

    if(presentationStack){
        presentationStack.hidden = false;
        document.getElementById('presentation-mode-mount')?.appendChild(presentationStack);
    }

    if(topbarRight && topbarRight.children.length === 0){
        topbarRight.hidden = true;
    }
})();
