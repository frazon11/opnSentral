<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/webssh.php';
require_login();

$firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
$rows = [];
foreach ($firewalls as $firewall) {
    try {
        $target = webssh_target_from_firewall($firewall);
        $rows[] = [
            'firewall' => $firewall,
            'target' => $target,
            'auto_auth' => webssh_credentials_configured($firewall),
            'error' => '',
        ];
    } catch (Throwable $exception) {
        $rows[] = ['firewall' => $firewall, 'target' => null, 'error' => $exception->getMessage()];
    }
}

require __DIR__ . '/inc/header.php';
?>
<link rel="stylesheet" href="/assets/vendor/xterm/xterm.css">
<style>
.webssh-table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.webssh-table{width:100%;border-collapse:separate;border-spacing:0;min-width:720px}
.webssh-table th,.webssh-table td{padding:11px 12px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);vertical-align:middle;text-align:left}
.webssh-table th:last-child,.webssh-table td:last-child{border-right:0}.webssh-table tr:last-child td{border-bottom:0}.webssh-table thead th{background:var(--table-head)}
.webssh-terminal-card{margin-top:18px;display:none}.webssh-terminal-card.is-open{display:block}
.webssh-terminal-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px}
.webssh-terminal-actions{display:flex;gap:8px;flex-wrap:wrap}
.webssh-auth{display:grid;grid-template-columns:minmax(160px,1fr) minmax(180px,1fr) minmax(260px,2fr) auto;gap:10px;align-items:end;margin-bottom:12px}
.webssh-auth label{margin:0}.webssh-auth textarea{min-height:80px;resize:vertical;font-family:monospace;font-size:.84rem}
.webssh-auth .webssh-key-field{display:none}.webssh-auth.use-key .webssh-password-field{display:none}.webssh-auth.use-key .webssh-key-field{display:block}
#webssh-terminal{height:520px;background:#000;border-radius:8px;padding:8px;overflow:hidden}
.webssh-status{margin:8px 0 10px;min-height:24px}.webssh-status.good{color:#2aa84a}.webssh-status.bad{color:#d74747}.webssh-status.warning{color:#cc8a00}
.webssh-security-note{margin-top:12px;font-size:.9rem;opacity:.85}
@media(max-width:900px){.webssh-auth{grid-template-columns:1fr 1fr}.webssh-auth .webssh-key-field{grid-column:1/-1}}
@media(max-width:620px){.webssh-auth{grid-template-columns:1fr}.webssh-auth .webssh-key-field{grid-column:auto}#webssh-terminal{height:430px}}
</style>

<div class="page-title">
    <div>
        <h1>opnSentral → Tools → WebSSH</h1>
        <p>Open an interactive SSH terminal to a configured OPNsense firewall without exposing an SSH proxy to arbitrary hosts.</p>
    </div>
    <a class="button secondary" href="/ssh_access.php">Managed SSH Access</a>
</div>

<div class="alert warningbox">
    WebSSH can connect only to firewalls already configured in opnSentral. Stored WebSSH credentials are encrypted with APP_KEY and passed to the internal SSH bridge only inside a short-lived encrypted token; they are never exposed to browser JavaScript in plaintext. Host keys use trust-on-first-use and are pinned for later sessions.
</div>

<div class="webssh-table-wrap">
<table class="webssh-table">
<thead><tr><th>Firewall</th><th>SSH target</th><th>Port</th><th>Authentication</th><th>Action</th></tr></thead>
<tbody>
<?php foreach ($rows as $entry):
    $firewall = $entry['firewall'];
    $target = $entry['target'];
?>
<tr>
    <td><strong><?= h((string) $firewall['name']) ?></strong><div class="muted"><?= h((string) $firewall['base_url']) ?></div></td>
    <?php if (is_array($target)): ?>
        <td><?= h((string) $target['host']) ?></td>
        <td><?= (int) $target['port'] ?></td>
        <td><?= !empty($entry['auto_auth']) ? '<span class="badge good">Stored</span>' : '<span class="badge warning">Manual</span>' ?></td>
        <td>
            <button type="button" class="button webssh-open"
                data-id="<?= (int) $firewall['id'] ?>"
                data-name="<?= h((string) $firewall['name']) ?>"
                data-host="<?= h((string) $target['host']) ?>"
                data-port="<?= (int) $target['port'] ?>"
                data-auto="<?= !empty($entry['auto_auth']) ? '1' : '0' ?>">Open terminal</button>
            <?php if (empty($entry['auto_auth'])): ?>
                <a class="button secondary" href="/firewall_edit.php?id=<?= (int) $firewall['id'] ?>">Configure login</a>
            <?php endif; ?>
        </td>
    <?php else: ?>
        <td colspan="3"><span class="badge bad">Unavailable</span> <?= h((string) $entry['error']) ?></td>
        <td>—</td>
    <?php endif; ?>
</tr>
<?php endforeach; ?>
<?php if (!$rows): ?><tr><td colspan="5" class="muted">No firewalls configured.</td></tr><?php endif; ?>
</tbody>
</table>
</div>

<section class="card webssh-terminal-card" id="webssh-card">
    <div class="webssh-terminal-head">
        <div><h2 style="margin:0" id="webssh-title">WebSSH</h2><div class="muted" id="webssh-target"></div></div>
        <div class="webssh-terminal-actions">
            <button type="button" class="button secondary" id="webssh-reconnect" disabled>Reconnect</button>
            <button type="button" class="button secondary" id="webssh-close">Close</button>
        </div>
    </div>

    <div class="webssh-auth" id="webssh-auth" style="display:none">
        <label>Username<input id="webssh-username" value="root" autocomplete="username"></label>
        <label>Authentication<select id="webssh-auth-method"><option value="password">Password</option><option value="key">Private key</option></select></label>
        <label class="webssh-password-field">Password<input type="password" id="webssh-password" autocomplete="new-password"></label>
        <label class="webssh-key-field">Private key<textarea id="webssh-private-key" autocomplete="off" spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label>
        <button type="button" class="button" id="webssh-connect">Connect</button>
    </div>

    <div class="webssh-status" id="webssh-status">Select a firewall to connect.</div>
    <div id="webssh-terminal"></div>
    <div class="webssh-security-note">The SSH target is server-signed by opnSentral. Stored credentials remain encrypted while crossing the browser and are decrypted only by the loopback-only WebSSH bridge. A changed SSH host key is rejected.</div>
</section>

<script src="/assets/vendor/xterm/xterm.js"></script>
<script src="/assets/vendor/xterm/xterm-addon-fit.js"></script>
<script>
(function(){
    const card=document.getElementById('webssh-card');
    const title=document.getElementById('webssh-title');
    const targetLabel=document.getElementById('webssh-target');
    const auth=document.getElementById('webssh-auth');
    const method=document.getElementById('webssh-auth-method');
    const username=document.getElementById('webssh-username');
    const password=document.getElementById('webssh-password');
    const privateKey=document.getElementById('webssh-private-key');
    const connectButton=document.getElementById('webssh-connect');
    const reconnectButton=document.getElementById('webssh-reconnect');
    const closeButton=document.getElementById('webssh-close');
    const status=document.getElementById('webssh-status');
    const csrf=<?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>;

    let selected=null;
    let socket=null;
    let terminal=null;
    let fitAddon=null;
    let inputDisposable=null;
    let resizeObserver=null;

    function setStatus(text,kind=''){
        status.textContent=text;
        status.className='webssh-status'+(kind?' '+kind:'');
    }

    function ensureTerminal(){
        if(terminal)return;
        if(typeof Terminal!=='function' || typeof FitAddon==='undefined'){
            setStatus('WebSSH terminal assets are unavailable.','bad');
            return;
        }
        terminal=new Terminal({
            cursorBlink:true,
            convertEol:false,
            scrollback:5000,
            fontFamily:'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
            fontSize:14,
            theme:{background:'#000000'}
        });
        fitAddon=new FitAddon.FitAddon();
        terminal.loadAddon(fitAddon);
        terminal.open(document.getElementById('webssh-terminal'));
        fitAddon.fit();
        inputDisposable=terminal.onData(data=>{
            if(socket&&socket.readyState===WebSocket.OPEN){
                socket.send(JSON.stringify({type:'input',data:data}));
            }
        });
        resizeObserver=new ResizeObserver(()=>{
            if(!fitAddon||!terminal)return;
            try{fitAddon.fit();}catch(_){return;}
            if(socket&&socket.readyState===WebSocket.OPEN){
                socket.send(JSON.stringify({type:'resize',cols:terminal.cols,rows:terminal.rows}));
            }
        });
        resizeObserver.observe(document.getElementById('webssh-terminal'));
    }

    function disconnect(){
        if(socket){
            try{if(socket.readyState===WebSocket.OPEN)socket.send(JSON.stringify({type:'disconnect'}));}catch(_){}
            try{socket.close();}catch(_){}
            socket=null;
        }
        reconnectButton.disabled=!selected;
        connectButton.disabled=false;
    }

    async function getToken(firewallId){
        const body=new URLSearchParams();
        body.set('csrf',csrf);
        body.set('firewall_id',String(firewallId));
        const response=await fetch('/webssh_token.php',{
            method:'POST',credentials:'same-origin',cache:'no-store',
            headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},
            body:body.toString()
        });
        const data=await response.json();
        if(!response.ok||data?.ok!==true)throw new Error(data?.error||('HTTP '+response.status));
        return data;
    }

    async function connect(){
        if(!selected)return;

        disconnect();
        ensureTerminal();
        if(!terminal)return;
        terminal.clear();
        terminal.write('\x1b[90mRequesting signed target for '+selected.name+'…\x1b[0m\r\n');
        connectButton.disabled=true;
        reconnectButton.disabled=true;
        setStatus('Preparing secure WebSSH connection…','warning');

        try{
            const tokenData=await getToken(selected.id);
            let user='';
            let useKey=false;
            let pass='';
            let key='';

            if(tokenData.auto_auth===true){
                auth.style.display='none';
                setStatus('Connecting with stored SSH credentials…','warning');
            }else{
                auth.style.display='grid';
                user=username.value.trim();
                useKey=method.value==='key';
                pass=password.value;
                key=privateKey.value;
                if(!user){setStatus('No stored WebSSH login is configured. Enter the SSH username.','bad');username.focus();connectButton.disabled=false;reconnectButton.disabled=false;return;}
                if(useKey&&!key.trim()){setStatus('Paste the SSH private key.','bad');privateKey.focus();connectButton.disabled=false;reconnectButton.disabled=false;return;}
                if(!useKey&&!pass){setStatus('Enter the SSH password.','bad');password.focus();connectButton.disabled=false;reconnectButton.disabled=false;return;}
            }

            const scheme=location.protocol==='https:'?'wss:':'ws:';
            socket=new WebSocket(scheme+'//'+location.host+'/webssh/socket');

            socket.addEventListener('open',()=>{
                try{fitAddon.fit();}catch(_){}
                socket.send(JSON.stringify({
                    type:'connect',
                    token:tokenData.token,
                    username:user,
                    password:useKey?'':pass,
                    private_key:useKey?key:'',
                    cols:terminal.cols,
                    rows:terminal.rows
                }));
                password.value='';
                privateKey.value='';
            });

            socket.addEventListener('message',event=>{
                let message;
                try{message=JSON.parse(event.data);}catch(_){return;}
                if(message.type==='data'){
                    terminal.write(String(message.data||''));
                }else if(message.type==='error'){
                    setStatus(String(message.message||'WebSSH error.'),'bad');
                    terminal.write('\r\n\x1b[31m'+String(message.message||'WebSSH error.')+'\x1b[0m\r\n');
                    connectButton.disabled=false;
                    reconnectButton.disabled=false;
                }else if(message.type==='hostkey'){
                    setStatus(String(message.message||'SSH host key verified.'),message.state==='learned'?'warning':'good');
                }else if(message.type==='status'){
                    const state=String(message.state||'');
                    if(state==='connected'){
                        setStatus(String(message.message||'Connected.'),'good');
                        connectButton.disabled=true;
                        reconnectButton.disabled=false;
                        terminal.focus();
                    }else if(state==='connecting'){
                        setStatus(String(message.message||'Connecting…'),'warning');
                    }else if(state==='closed'){
                        setStatus(String(message.message||'Connection closed.'),'warning');
                        connectButton.disabled=false;
                        reconnectButton.disabled=false;
                    }
                }
            });

            socket.addEventListener('close',()=>{
                connectButton.disabled=false;
                reconnectButton.disabled=false;
                socket=null;
            });
            socket.addEventListener('error',()=>{
                setStatus('Could not reach the internal WebSSH service.','bad');
                connectButton.disabled=false;
                reconnectButton.disabled=false;
            });
        }catch(error){
            setStatus(error.message||'Could not start WebSSH.','bad');
            connectButton.disabled=false;
            reconnectButton.disabled=false;
        }
    }

    method.addEventListener('change',()=>auth.classList.toggle('use-key',method.value==='key'));
    connectButton.addEventListener('click',connect);
    reconnectButton.addEventListener('click',connect);
    closeButton.addEventListener('click',()=>{
        disconnect();
        card.classList.remove('is-open');
        if(terminal)terminal.clear();
    });

    document.querySelectorAll('.webssh-open').forEach(button=>button.addEventListener('click',()=>{
        disconnect();
        selected={id:Number(button.dataset.id),name:button.dataset.name,host:button.dataset.host,port:Number(button.dataset.port||22),auto:button.dataset.auto==='1'};
        title.textContent='WebSSH · '+selected.name;
        targetLabel.textContent=selected.host+':'+selected.port;
        card.classList.add('is-open');
        reconnectButton.disabled=false;
        auth.style.display=selected.auto?'none':'grid';
        ensureTerminal();
        if(terminal){terminal.clear();terminal.write('\x1b[90mOpening '+selected.name+' ('+selected.host+':'+selected.port+')…\x1b[0m\r\n');}
        setStatus(selected.auto?'Connecting automatically…':'No stored login configured. Enter SSH credentials.','warning');
        card.scrollIntoView({behavior:'smooth',block:'start'});
        connect();
    }));

    window.addEventListener('beforeunload',disconnect);
})();
</script>

<?php require __DIR__ . '/inc/footer.php'; ?>
