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
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535 || !Number.isInteger(firewallId) || firewallId < 1) {
    throw new Error('Incomplete WebSSH target token.');
  }

  return { host, port, firewallId, firewallName, credentialBlob };
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

const server = http.createServer((req, res) => {
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found\n');
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
