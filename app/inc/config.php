<?php
declare(strict_types=1);
const DATA_DIR = '/var/www/data';
const BACKUP_DIR = '/var/www/backups';
function envv(string $n, ?string $d=null): string { $v=getenv($n); return ($v===false||$v==='')?(string)$d:$v; }
function app_name(): string { return envv('APP_NAME','OPNsense Central Lite'); }
function db(): PDO {
 static $p=null; if($p instanceof PDO)return $p;
 if(!is_dir(DATA_DIR))mkdir(DATA_DIR,0770,true);
 $p=new PDO('sqlite:'.DATA_DIR.'/central.sqlite');
 $p->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
 $p->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE,PDO::FETCH_ASSOC);
 $p->setAttribute(PDO::ATTR_TIMEOUT,10);
 $p->exec('PRAGMA busy_timeout=10000');
 $p->exec('PRAGMA journal_mode=WAL');
 $p->exec('CREATE TABLE IF NOT EXISTS firewalls (
 id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,base_url TEXT NOT NULL,
 api_key_enc TEXT NOT NULL,api_secret_enc TEXT NOT NULL,verify_tls INTEGER NOT NULL DEFAULT 1,
 notes TEXT NOT NULL DEFAULT "",created_at TEXT NOT NULL,updated_at TEXT NOT NULL)');
 $p->exec('CREATE TABLE IF NOT EXISTS alert_states (state_key TEXT PRIMARY KEY,state_value TEXT NOT NULL,failure_count INTEGER NOT NULL DEFAULT 0,details TEXT NOT NULL DEFAULT "",updated_at TEXT NOT NULL)');
 $p->exec('CREATE TABLE IF NOT EXISTS alert_log (id INTEGER PRIMARY KEY AUTOINCREMENT,state_key TEXT NOT NULL,event_type TEXT NOT NULL,subject TEXT NOT NULL,message TEXT NOT NULL,sent_ok INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT "",created_at TEXT NOT NULL)');
 $p->exec('CREATE TABLE IF NOT EXISTS backups (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 firewall_id INTEGER NOT NULL,
 firewall_name TEXT NOT NULL,
 filename TEXT NOT NULL,
 backup_type TEXT NOT NULL DEFAULT "manual",
 reason TEXT NOT NULL DEFAULT "",
 byte_size INTEGER NOT NULL DEFAULT 0,
 sha256 TEXT NOT NULL DEFAULT "",
 created_by TEXT NOT NULL DEFAULT "",
 created_at TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT "ok",
 error TEXT NOT NULL DEFAULT ""
 )');
 $p->exec('CREATE INDEX IF NOT EXISTS idx_backups_firewall_created ON backups(firewall_id,created_at DESC)');
 $p->exec('CREATE TABLE IF NOT EXISTS agents (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 firewall_id INTEGER,
 agent_id TEXT NOT NULL UNIQUE,
 secret_enc TEXT NOT NULL,
 name TEXT NOT NULL DEFAULT "",
 enabled INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 last_seen_at TEXT,
 last_remote_ip TEXT NOT NULL DEFAULT "",
 last_version TEXT NOT NULL DEFAULT "",
 last_hostname TEXT NOT NULL DEFAULT "",
 last_opnsense_version TEXT NOT NULL DEFAULT "",
 last_payload TEXT NOT NULL DEFAULT ""
 )');
 $p->exec('CREATE INDEX IF NOT EXISTS idx_agents_firewall ON agents(firewall_id)');
 $p->exec('CREATE TABLE IF NOT EXISTS agent_nonces (
 agent_id TEXT NOT NULL,
 nonce TEXT NOT NULL,
 seen_at INTEGER NOT NULL,
 PRIMARY KEY(agent_id,nonce)
 )');
 $p->exec('CREATE INDEX IF NOT EXISTS idx_agent_nonces_seen ON agent_nonces(seen_at)');
 $p->exec('CREATE TABLE IF NOT EXISTS agent_registration_tokens (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 firewall_id INTEGER,
 token_hash TEXT NOT NULL UNIQUE,
 token_prefix TEXT NOT NULL,
 label TEXT NOT NULL DEFAULT "",
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 used_at TEXT
 )');
 $p->exec('CREATE INDEX IF NOT EXISTS idx_agent_registration_tokens_expires ON agent_registration_tokens(expires_at)');
 $p->exec('CREATE TABLE IF NOT EXISTS agent_jobs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 agent_id INTEGER NOT NULL,
 job_type TEXT NOT NULL,
 payload_json TEXT NOT NULL DEFAULT "{}",
 status TEXT NOT NULL DEFAULT "queued",
 result_json TEXT NOT NULL DEFAULT "null",
 error TEXT NOT NULL DEFAULT "",
 created_at TEXT NOT NULL,
 picked_at TEXT,
 finished_at TEXT
 )');
 $p->exec('CREATE INDEX IF NOT EXISTS idx_agent_jobs_agent_status ON agent_jobs(agent_id,status,id)');
 $p->exec('CREATE TABLE IF NOT EXISTS plugin_jobs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 firewall_id INTEGER NOT NULL,
 firewall_name TEXT NOT NULL,
 package_name TEXT NOT NULL,
 operation TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT "requested",
 message_uuid TEXT NOT NULL DEFAULT "",
 backup_id INTEGER,
 response_json TEXT NOT NULL DEFAULT "",
 error TEXT NOT NULL DEFAULT "",
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
 )');
 $p->exec('CREATE INDEX IF NOT EXISTS idx_plugin_jobs_created ON plugin_jobs(created_at DESC)');
 return $p;
}
function crypto_key(): string {
 $h=envv('APP_KEY'); if(!preg_match('/^[a-f0-9]{64}$/i',$h))throw new RuntimeException('APP_KEY must be 64 hex characters.');
 $k=hex2bin($h); if($k===false)throw new RuntimeException('Invalid APP_KEY.'); return $k;
}
function encrypt_value(string $v): string {
 $iv=random_bytes(12);$tag='';$c=openssl_encrypt($v,'aes-256-gcm',crypto_key(),OPENSSL_RAW_DATA,$iv,$tag);
 if($c===false)throw new RuntimeException('Encryption failed.'); return base64_encode($iv.$tag.$c);
}
function decrypt_value(string $v): string {
 $r=base64_decode($v,true); if($r===false||strlen($r)<29)throw new RuntimeException('Invalid encrypted value.');
 $p=openssl_decrypt(substr($r,28),'aes-256-gcm',crypto_key(),OPENSSL_RAW_DATA,substr($r,0,12),substr($r,12,16));
 if($p===false)throw new RuntimeException('Decryption failed; APP_KEY may have changed.'); return $p;
}
function start_session_secure(): void {
 if(session_status()===PHP_SESSION_ACTIVE)return;
 session_name('opncentral');
 session_set_cookie_params(['httponly'=>true,'secure'=>filter_var(envv('SESSION_SECURE','false'),FILTER_VALIDATE_BOOL),'samesite'=>'Strict','path'=>'/']);
 session_start();
}
function csrf_token(): string { start_session_secure(); if(empty($_SESSION['csrf']))$_SESSION['csrf']=bin2hex(random_bytes(24)); return $_SESSION['csrf']; }
function require_csrf(): void { start_session_secure();$v=(string)($_POST['csrf']??'');if(!hash_equals((string)($_SESSION['csrf']??''),$v)){http_response_code(400);exit('Invalid CSRF token');}}
function verify_csrf(): void { require_csrf(); }
function logged_in(): bool { start_session_secure(); return ($_SESSION['auth']??false)===true; }
function require_login(): void { if(!logged_in()){header('Location: /login.php');exit;}}

// 0.6.21+: configuration changes are available to authenticated users without
// a separate read-only/unlock state. These compatibility helpers remain so
// existing action handlers do not need special-case migrations.
function configuration_unlocked(): bool
{
    return true;
}

function unlock_configuration(string $password): bool
{
    return true;
}

function lock_configuration(): void
{
}

function require_configuration_unlocked(bool $json = true): void
{
}

function h(string $v): string { return htmlspecialchars($v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function normalize_url(string $u): string {$u=rtrim(trim($u),'/');if(!preg_match('#^https?://#i',$u))$u='https://'.$u;if(filter_var($u,FILTER_VALIDATE_URL)===false)throw new InvalidArgumentException('Invalid URL.');return $u;}

require_once __DIR__ . '/i18n.php';
