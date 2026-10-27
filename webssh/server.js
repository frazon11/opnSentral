'use strict';

const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { Client } = require('ssh2');

const LISTEN_HOST = '127.0.0.1';
const LISTEN_PORT = 3001;
const MAX_SESSIONS = 8;
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const KNOWN_HOSTS_FILE = '/var/www/data/webssh-known-hosts.json';

let activeSessions = 0;

function appKey() {
  const raw = String(process.env.APP_KEY || '').trim();
  if (!/^[a-f0-9]{64}$/i.test(raw)) throw new Error('APP_KEY must be 64 hex characters.');
  return Buffer.from(raw, 'hex');
}

function decryptCredentialBlob(blob) {
  const raw = Buffer.from(String(blob || ''), 'base64');
  if (raw.length < 29) throw new Error('Invalid WebSSH credential blob.');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', appKey(), iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  const credentials = JSON.parse(plaintext);
  const username = String(credentials.username || '').trim();
  const authMethod = String(credentials.auth_method || 'password');
  const password = String(credentials.password || '');
  const privateKey = String(credentials.private_key || '');
  if (!username || username.length > 128) throw new Error('Stored SSH username is invalid.');
  if (authMethod === 'key') {
    if (!privateKey || privateKey.length > 131072) throw new Error('Stored SSH private key is invalid.');
  } else if (!password || password.length > 4096) {
    throw new Error('Stored SSH password is invalid.');
  }
  return { username, authMethod: authMethod === 'key' ? 'key' : 'password', password, privateKey };
}

function timingSafeHexEqual(a, b) {
  if (!/^[a-f0-9]{64}$/i.test(a) || !/^[a-f0-9]{64}$/i.test(b)) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

function decodeToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 2) throw new Error('Invalid WebSSH token.');
  const [payloadEncoded, signature] = parts;
  const expected = crypto.createHmac('sha256', appKey()).update(payloadEncoded).digest('hex');
  if (!timingSafeHexEqual(signature, expected)) throw new Error('Invalid WebSSH token signature.');

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf8'));
  } catch (_) {
    throw new Error('Invalid WebSSH token payload.');
  }

  const now = Math.floor(Date.now() / 1000);
  const expires = Number(payload.exp || 0);
  if (!Number.isFinite(expires) || expires < now || expires > now + 180) {
    throw new Error('Expired WebSSH token. Refresh the page and try again.');
  }

  const host = String(payload.host || '').trim();
  const port = Number(payload.port || 22);
  const firewallId = Number(payload.firewall_id || 0);
  const firewallName = String(payload.firewall_name || '').trim();
  const credentialBlob = String(payload.credential_blob || '');
  const scope = String(payload.scope || 'terminal');
  const serverUrl = String(payload.server_url || '').trim();
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535 || !Number.isInteger(firewallId) || firewallId < 1) {
    throw new Error('Incomplete WebSSH target token.');
  }

  return { host, port, firewallId, firewallName, credentialBlob, scope, serverUrl };
}

function readKnownHosts() {
  try {
    const decoded = JSON.parse(fs.readFileSync(KNOWN_HOSTS_FILE, 'utf8'));
    return decoded && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : {};
  } catch (_) {
    return {};
  }
}

function saveKnownHosts(data) {
  const temp = KNOWN_HOSTS_FILE + '.tmp-' + process.pid;
  fs.writeFileSync(temp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(temp, KNOWN_HOSTS_FILE);
}

function fingerprintLabel(hashHex) {
  try {
    return 'SHA256:' + Buffer.from(hashHex, 'hex').toString('base64').replace(/=+$/g, '');
  } catch (_) {
    return hashHex;
  }
}

function send(ws, payload) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(payload));
}

function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

function maintenanceConnectOptions(target, credentials) {
  const knownKey = target.host + ':' + target.port;
  const options = {
    host: target.host,
    port: target.port,
    username: credentials.username,
    readyTimeout: 15000,
    keepaliveInterval: 15000,
    keepaliveCountMax: 3,
    hostHash: 'sha256',
    hostVerifier: (hash) => {
      const value = String(hash || '').toLowerCase();
      const current = readKnownHosts();
      const remembered = String(current[knownKey] || '').toLowerCase();
      if (remembered) return remembered === value;
      current[knownKey] = value;
      saveKnownHosts(current);
      return true;
    },
  };
  if (credentials.authMethod === 'key') options.privateKey = credentials.privateKey;
  else options.password = credentials.password;
  return options;
}

let activeMaintenance = 0;

const server = http.createServer((req, res) => {
  const isAgentRepair = req.method === 'POST' && req.url === '/maintenance/agent-repair';
  const isAccessControllerInstall = req.method === 'POST' && req.url === '/maintenance/access-controller-install';
  if (!isAgentRepair && !isAccessControllerInstall) {
    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: false, error: 'Not found' }));
    return;
  }
  if (activeMaintenance >= 2) {
    res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: false, error: 'Too many maintenance operations are already running.' }));
    return;
  }

  let raw = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => {
    raw += chunk;
    if (Buffer.byteLength(raw, 'utf8') > 65536) req.destroy();
  });
  req.on('end', () => {
    activeMaintenance += 1;
    let replied = false;
    let ssh = null;
    let timer = null;
    const finish = (status, payload) => {
      if (replied) return;
      replied = true;
      if (timer) clearTimeout(timer);
      if (ssh) { try { ssh.end(); } catch (_) {} }
      activeMaintenance = Math.max(0, activeMaintenance - 1);
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(payload));
    };

    try {
      const body = JSON.parse(raw || '{}');
      const target = decodeToken(body.token);
      const expectedScope = isAccessControllerInstall ? 'access_controller_install' : 'agent_repair';
      if (target.scope !== expectedScope) throw new Error('Invalid maintenance token scope.');
      if (!target.credentialBlob) throw new Error('Stored SSH credentials are not configured.');

      let maintenanceUrl;
      try { maintenanceUrl = new URL(target.serverUrl); } catch (_) { throw new Error('Invalid opnSentral maintenance URL.'); }
      if (maintenanceUrl.protocol !== 'https:' || !maintenanceUrl.hostname || maintenanceUrl.username || maintenanceUrl.password || target.serverUrl.length > 2048) {
        throw new Error('Maintenance requires a public HTTPS opnSentral URL.');
      }

      const serverUrl = target.serverUrl.replace(/\/+$/, '');
      const credentials = decryptCredentialBlob(target.credentialBlob);
      const accessControllerTarget = '/usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/AccessController.php';
      const command = isAccessControllerInstall
        ? [
            'set -eu',
            '[ "$(id -u)" -eq 0 ]',
            'tmp=$(mktemp /tmp/opnsentral-access.XXXXXX)',
            'trap \'rm -f "$tmp"\' EXIT INT TERM',
            'fetch -q -o "$tmp" ' + shellQuote(serverUrl + '/agent/plugin_file.php?file=access_controller'),
            '/usr/local/bin/php -l "$tmp" >/dev/null',
            'mkdir -p ' + shellQuote('/usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api'),
            'install -m 0644 "$tmp" ' + shellQuote(accessControllerTarget),
            '/usr/local/bin/php -l ' + shellQuote(accessControllerTarget) + ' >/dev/null',
          ].join('; ')
        : 'fetch -q -o - ' + shellQuote(serverUrl + '/agent/install-plugin.sh') + ' | sh -s -- ' + shellQuote(serverUrl);
      ssh = new Client();
      let stdout = '';
      let stderr = '';
      const maintenanceLabel = isAccessControllerInstall ? 'System Access support installation' : 'SSH agent repair';
      timer = setTimeout(() => finish(504, { ok: false, error: maintenanceLabel + ' timed out.' }), 75000);

      ssh.on('ready', () => {
        ssh.exec(command, (error, stream) => {
          if (error) return finish(502, { ok: false, error: 'Could not start remote ' + maintenanceLabel + ': ' + error.message });
          stream.on('data', (data) => { if (stdout.length < 65536) stdout += data.toString('utf8'); });
          stream.stderr.on('data', (data) => { if (stderr.length < 65536) stderr += data.toString('utf8'); });
          stream.on('close', (code) => {
            const exitCode = Number.isInteger(code) ? code : 1;
            if (exitCode !== 0) {
              return finish(502, { ok: false, error: 'Remote installer exited with code ' + exitCode + (stderr.trim() ? ': ' + stderr.trim().slice(-1000) : '') });
            }
            finish(200, {
              ok: true,
              message: isAccessControllerInstall
                ? 'System Access editing support installed successfully.'
                : 'Remote agent repair completed successfully.',
              output: stdout.trim().slice(-4000),
            });
          });
        });
      });
      ssh.on('error', (error) => finish(502, { ok: false, error: 'SSH connection failed: ' + error.message }));
      ssh.connect(maintenanceConnectOptions(target, credentials));
    } catch (error) {
      finish(400, { ok: false, error: error.message || 'Invalid agent repair request.' });
    }
  });
});

const wss = new WebSocketServer({
  server,
  maxPayload: 1024 * 1024,
  perMessageDeflate: false,
});

wss.on('connection', (ws) => {
  if (activeSessions >= MAX_SESSIONS) {
    send(ws, { type: 'error', message: 'Maximum number of WebSSH sessions reached.' });
    ws.close(1013, 'Server busy');
    return;
  }

  activeSessions += 1;
  let counted = true;
  let ssh = null;
  let shell = null;
  let connected = false;
  let idleTimer = null;
  let target = null;
  let firstSeenFingerprint = null;
  let hostMismatch = false;

  const release = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = null;
    if (shell) {
      try { shell.end(); } catch (_) {}
      shell = null;
    }
    if (ssh) {
      try { ssh.end(); } catch (_) {}
      ssh = null;
    }
    if (counted) {
      activeSessions = Math.max(0, activeSessions - 1);
      counted = false;
    }
  };

  const bumpIdle = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      send(ws, { type: 'status', state: 'closed', message: 'Session closed after 30 minutes of inactivity.' });
      try { ws.close(1000, 'Idle timeout'); } catch (_) {}
      release();
    }, IDLE_TIMEOUT_MS);
  };

  send(ws, { type: 'status', state: 'ready', message: 'WebSSH bridge ready.' });

  ws.on('message', (raw) => {
    let message;
    try {
      message = JSON.parse(raw.toString('utf8'));
    } catch (_) {
      send(ws, { type: 'error', message: 'Invalid WebSSH message.' });
      return;
    }

    if (message.type === 'connect') {
      if (connected || ssh) {
        send(ws, { type: 'error', message: 'This WebSSH socket is already in use.' });
        return;
      }

      let username = '';
      let password = '';
      let privateKey = '';
      try {
        target = decodeToken(message.token);
        if (target.credentialBlob) {
          const stored = decryptCredentialBlob(target.credentialBlob);
          username = stored.username;
          password = stored.authMethod === 'password' ? stored.password : '';
          privateKey = stored.authMethod === 'key' ? stored.privateKey : '';
        } else {
          username = String(message.username || '').trim();
          password = String(message.password || '');
          privateKey = String(message.private_key || '');
          if (!username || username.length > 128) throw new Error('A valid SSH username is required.');
          if (!password && !privateKey) throw new Error('No stored WebSSH credentials are configured. Enter an SSH password or private key.');
          if (password.length > 4096 || privateKey.length > 131072) throw new Error('SSH credential input is too large.');
        }
      } catch (error) {
        send(ws, { type: 'error', message: error.message || 'Invalid WebSSH connection request.' });
        return;
      }

      const cols = Math.max(20, Math.min(400, Number(message.cols || 100)));
      const rows = Math.max(5, Math.min(200, Number(message.rows || 30)));
      const knownKey = target.host + ':' + target.port;
      const knownHosts = readKnownHosts();

      ssh = new Client();
      send(ws, { type: 'status', state: 'connecting', message: 'Connecting to ' + target.firewallName + '…' });

      ssh.on('ready', () => {
        connected = true;
        if (firstSeenFingerprint) {
          send(ws, {
            type: 'hostkey',
            state: 'learned',
            message: 'Host key learned for ' + knownKey + ': ' + fingerprintLabel(firstSeenFingerprint),
          });
        } else if (knownHosts[knownKey]) {
          send(ws, {
            type: 'hostkey',
            state: 'verified',
            message: 'Host key verified: ' + fingerprintLabel(String(knownHosts[knownKey])),
          });
        }

        ssh.shell({ term: 'xterm-256color', cols, rows }, (error, stream) => {
          if (error) {
            send(ws, { type: 'error', message: 'Could not open SSH shell: ' + error.message });
            try { ws.close(1011, 'Shell failed'); } catch (_) {}
            return;
          }

          shell = stream;
          send(ws, { type: 'status', state: 'connected', message: 'Connected to ' + target.firewallName + '.' });
          bumpIdle();

          stream.on('data', (data) => {
            bumpIdle();
            send(ws, { type: 'data', data: data.toString('utf8') });
          });
          stream.stderr.on('data', (data) => {
            bumpIdle();
            send(ws, { type: 'data', data: data.toString('utf8') });
          });
          stream.on('close', () => {
            send(ws, { type: 'status', state: 'closed', message: 'SSH session closed.' });
            try { ws.close(1000, 'SSH session closed'); } catch (_) {}
          });
        });
      });

      ssh.on('error', (error) => {
        const prefix = hostMismatch ? 'SSH host key verification failed. ' : 'SSH connection failed. ';
        send(ws, { type: 'error', message: prefix + (error.message || 'Unknown SSH error.') });
      });
      ssh.on('close', () => {
        if (ws.readyState === ws.OPEN) {
          send(ws, { type: 'status', state: 'closed', message: 'SSH connection closed.' });
        }
      });

      const connectOptions = {
        host: target.host,
        port: target.port,
        username,
        readyTimeout: 15000,
        keepaliveInterval: 15000,
        keepaliveCountMax: 3,
        hostHash: 'sha256',
        hostVerifier: (hash) => {
          const value = String(hash || '').toLowerCase();
          const current = readKnownHosts();
          const remembered = String(current[knownKey] || '').toLowerCase();
          if (remembered) {
            if (remembered === value) return true;
            hostMismatch = true;
            return false;
          }
          current[knownKey] = value;
          try {
            saveKnownHosts(current);
            firstSeenFingerprint = value;
            return true;
          } catch (_) {
            return false;
          }
        },
      };

      if (privateKey) connectOptions.privateKey = privateKey;
      else connectOptions.password = password;

      // Do not retain credentials after handing them to ssh2.
      password = '';
      privateKey = '';

      try {
        ssh.connect(connectOptions);
      } catch (error) {
        send(ws, { type: 'error', message: 'Could not start SSH connection: ' + error.message });
      }
      return;
    }

    if (message.type === 'input') {
      if (!shell) return;
      const data = String(message.data || '');
      if (Buffer.byteLength(data, 'utf8') > 65536) return;
      bumpIdle();
      shell.write(data);
      return;
    }

    if (message.type === 'resize') {
      if (!shell) return;
      const cols = Math.max(20, Math.min(400, Number(message.cols || 100)));
      const rows = Math.max(5, Math.min(200, Number(message.rows || 30)));
      try { shell.setWindow(rows, cols, 0, 0); } catch (_) {}
      return;
    }

    if (message.type === 'disconnect') {
      send(ws, { type: 'status', state: 'closed', message: 'Disconnected.' });
      try { ws.close(1000, 'Disconnected'); } catch (_) {}
    }
  });

  ws.on('close', release);
  ws.on('error', release);
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log('opnSentral WebSSH bridge listening on ' + LISTEN_HOST + ':' + LISTEN_PORT);
});
