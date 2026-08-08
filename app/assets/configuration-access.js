(function(){
    'use strict';

    function init(){
        window.opnCentralConfigurationUnlocked =
            document.body.classList.contains('configuration-unlocked');

        const lockButton = document.getElementById('configuration-lock-button');
        const unlockDialog = document.getElementById('configuration-unlock-dialog');
        const unlockPassword = document.getElementById('configuration-unlock-password');
        const unlockError = document.getElementById('configuration-unlock-error');

        function markRemoteChangeControls(){
            const locked = !window.opnCentralConfigurationUnlocked;
            const currentPath = window.location.pathname;
            const mutatingPages = new Set([
                '/aliases.php',
                '/categories.php',
                '/wireguard_create.php',
                '/openvpn_roadwarrior_create.php'
            ]);

            const selectors = [
                '[data-action]:not([data-action="firmware_check"])',
                '.wg-state-action',
                '.vpn-state-action',
                '.plugin-action',
                '.remote-change-control'
            ];

            if(mutatingPages.has(currentPath)){
                selectors.push(
                    'form button[type="submit"]',
                    'form input[type="submit"]'
                );
            }

            document.querySelectorAll(selectors.join(',')).forEach(element => {
                if(element.id === 'configuration-lock-button') return;
                element.classList.add('remote-change-control');
                element.dataset.configurationLocked = locked ? '1' : '0';
                element.setAttribute('aria-disabled', locked ? 'true' : 'false');
                element.title = locked
                    ? 'Unlock configuration changes in Settings first.'
                    : '';
            });

            const changeLinks = [
                'a[href="/wireguard_create.php"]',
                'a[href="/openvpn_roadwarrior_create.php"]',
                'a[href="/aliases.php"]',
                'a[href^="/aliases.php?"]',
                'a[href="/categories.php"]',
                'a[href^="/categories.php?"]',
                'a[href^="/backup_download.php"]',
                'a[href^="/backup_zip_download.php"]',
                'form[action="/self_backup_download.php"] button[type="submit"]',
                '.backup-download-control'
            ];

            document.querySelectorAll(changeLinks.join(',')).forEach(link => {
                link.classList.add('remote-change-control');
                link.dataset.configurationLocked = locked ? '1' : '0';
                link.setAttribute('aria-disabled', locked ? 'true' : 'false');
                link.title = locked
                    ? 'Unlock configuration changes in Settings first.'
                    : '';
            });
        }

        document.addEventListener('click', function(event){
            const target = event.target.closest(
                '.remote-change-control[data-configuration-locked="1"]'
            );

            if(!target) return;

            event.preventDefault();
            event.stopImmediatePropagation();
            window.location.href = '/settings.php#interface-access-settings';
        }, true);

        async function submitConfigurationLock(action, password = ''){
            const form = new URLSearchParams({
                csrf: String(window.opnSentralCsrf || ''),
                action,
                password
            });

            const response = await fetch('/configuration_lock.php', {
                method:'POST',
                credentials:'same-origin',
                cache:'no-store',
                headers:{
                    'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'
                },
                body:form
            });

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
                throw new Error(data.error || 'Lock action failed.');
            }

            window.location.reload();
        }

        lockButton?.addEventListener('click', async function(){
            const unlocked = lockButton.dataset.unlocked === '1';

            if(unlocked){
                lockButton.disabled = true;
                try{
                    await submitConfigurationLock('lock');
                }catch(error){
                    alert(error.message);
                    lockButton.disabled = false;
                }
                return;
            }

            unlockError?.classList.add('hidden');
            if(unlockError) unlockError.textContent = '';
            if(unlockPassword) unlockPassword.value = '';
            if(unlockDialog) unlockDialog.hidden = false;
            window.setTimeout(() => unlockPassword?.focus(), 0);
        });

        document.getElementById('configuration-unlock-cancel')?.addEventListener('click', function(){
            if(unlockDialog) unlockDialog.hidden = true;
        });

        document.getElementById('configuration-unlock-submit')?.addEventListener('click', async function(){
            const submit = this;
            submit.disabled = true;
            unlockError?.classList.add('hidden');

            try{
                await submitConfigurationLock(
                    'unlock',
                    unlockPassword?.value || ''
                );
            }catch(error){
                if(unlockError){
                    unlockError.textContent = error.message;
                    unlockError.classList.remove('hidden');
                }
                submit.disabled = false;
                unlockPassword?.focus();
                unlockPassword?.select();
            }
        });

        unlockPassword?.addEventListener('keydown', function(event){
            if(event.key === 'Enter'){
                event.preventDefault();
                document.getElementById('configuration-unlock-submit')?.click();
            }
            if(event.key === 'Escape' && unlockDialog){
                unlockDialog.hidden = true;
            }
        });

        markRemoteChangeControls();

        if(document.body.classList.contains('app-shell')){
            const observer = new MutationObserver(markRemoteChangeControls);
            observer.observe(document.body, {childList:true, subtree:true});
        }
    }

    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', init, {once:true});
    }else{
        init();
    }
})();
