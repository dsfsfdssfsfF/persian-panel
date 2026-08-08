'use strict';

const express      = require('express');
const session      = require('express-session');
const compression  = require('compression');
const morgan       = require('morgan');
const path         = require('path');
const cron         = require('node-cron');
const Database     = require('better-sqlite3');
const bcrypt       = require('bcryptjs');
const rateLimit    = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { v4: uuidv4 } = require('uuid');
const fs           = require('fs');
const { execSync, exec } = require('child_process');
const xrayApi      = require('./xray-api');

const app  = express();
const PORT = parseInt(process.env.PORT) || 3000;
const PANEL_PATH = '/' + (process.env.PANEL_PATH || 'panel')
  .replace(/^\//, '').replace(/\/$/, '');

// ══════════════════════════════════
// DOMAIN
// ══════════════════════════════════
function getDomain(req) {
  return process.env.CF_DOMAIN
    || process.env.RAILWAY_PUBLIC_DOMAIN
    || req?.get('host')?.split(':')[0]
    || 'localhost';
}

// ══════════════════════════════════
// DATABASE
// ══════════════════════════════════
let dbPath = './persian.db';
try {
  if (!fs.existsSync('/data')) fs.mkdirSync('/data', { recursive: true });
  dbPath = '/data/persian.db';
} catch (_) {}

let db;
try { db = new Database(dbPath); }
catch (_) { db = new Database('./persian.db'); }

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');

// ══════════════════════════════════
// INIT DB
// ══════════════════════════════════
function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS panel_users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      role       TEXT DEFAULT 'admin',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS inbounds (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      tag             TEXT UNIQUE NOT NULL,
      remark          TEXT NOT NULL,
      protocol        TEXT NOT NULL,
      port            INTEGER NOT NULL,
      network         TEXT NOT NULL,
      security        TEXT DEFAULT 'none',
      tls_sni         TEXT DEFAULT '',
      ws_path         TEXT DEFAULT '/ws',
      grpc_service    TEXT DEFAULT 'grpc',
      reality_pbk     TEXT DEFAULT '',
      reality_sid     TEXT DEFAULT '',
      header_type     TEXT DEFAULT 'none',
      xhttp_mode      TEXT DEFAULT 'auto',
      enabled         INTEGER DEFAULT 1,
      up_mbytes       INTEGER DEFAULT 0,
      down_mbytes     INTEGER DEFAULT 0,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS clients (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      inbound_id      INTEGER NOT NULL,
      name            TEXT NOT NULL,
      uuid            TEXT NOT NULL,
      email           TEXT DEFAULT '',
      traffic_limit   INTEGER DEFAULT 0,
      traffic_used    INTEGER DEFAULT 0,
      expire_date     TEXT DEFAULT NULL,
      max_connections INTEGER DEFAULT 0,
      enabled         INTEGER DEFAULT 1,
      sub_token       TEXT UNIQUE NOT NULL,
      note            TEXT DEFAULT '',
      up_bytes        INTEGER DEFAULT 0,
      down_bytes      INTEGER DEFAULT 0,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_clients_sub      ON clients(sub_token);
    CREATE INDEX IF NOT EXISTS idx_clients_enabled  ON clients(enabled);
    CREATE INDEX IF NOT EXISTS idx_clients_uuid     ON clients(uuid);
    CREATE INDEX IF NOT EXISTS idx_clients_inbound  ON clients(inbound_id);
  `);

  if (!db.prepare('SELECT id FROM panel_users WHERE username=?').get('admin')) {
    db.prepare('INSERT INTO panel_users (username,password,role) VALUES (?,?,?)')
      .run('admin', bcrypt.hashSync('admin', 12), 'superadmin');
    console.log('✅ Admin: admin / admin');
  }

  const defaults = {
    panel_name : 'Persian Panel',
    theme      : 'dark',
    cf_domain  : process.env.CF_DOMAIN || ''
  };
  for (const [k, v] of Object.entries(defaults)) {
    if (!db.prepare('SELECT key FROM settings WHERE key=?').get(k))
      db.prepare('INSERT INTO settings (key,value) VALUES (?,?)').run(k, v);
  }

  console.log('✅ DB ready:', dbPath);
}

const G = k => { const r = db.prepare('SELECT value FROM settings WHERE key=?').get(k); return r ? r.value : ''; };
const S = (k, v) => db.prepare('INSERT OR REPLACE INTO settings (key,value,updated_at) VALUES (?,?,CURRENT_TIMESTAMP)').run(k, String(v));

// ══════════════════════════════════
// XRAY CONFIG BUILDER
// ══════════════════════════════════
function buildXrayConfig() {
  const inbounds = db.prepare('SELECT * FROM inbounds WHERE enabled=1').all();
  const allClients = db.prepare('SELECT c.*, i.tag as inbound_tag FROM clients c JOIN inbounds i ON c.inbound_id=i.id WHERE c.enabled=1').all();

  const xrayInbounds = [
    // API inbound - همیشه باشه
    {
      tag     : 'api',
      port    : 10085,
      listen  : '127.0.0.1',
      protocol: 'dokodemo-door',
      settings: { address: '127.0.0.1' },
      streamSettings: { network: 'tcp' }
    }
  ];

  // ساخت inbound های دینامیک
  for (const ib of inbounds) {
    const clients = allClients.filter(c => c.inbound_id === ib.id);

    const streamSettings = buildStreamSettings(ib);
    const settings       = buildProtocolSettings(ib, clients);

    xrayInbounds.push({
      tag     : ib.tag,
      port    : ib.port,
      listen  : '0.0.0.0',
      protocol: ib.protocol,
      settings,
      streamSettings,
      sniffing: {
        enabled     : true,
        destOverride: ['http', 'tls', 'quic']
      }
    });
  }

  return {
    log: { loglevel: 'warning', access: 'none', error: '/var/log/xray-error.log' },
    api: { tag: 'api', services: ['HandlerService', 'StatsService', 'LoggerService'] },
    stats: {},
    policy: {
      levels: { '0': { statsUserUplink: true, statsUserDownlink: true } },
      system: {
        statsInboundUplink  : true,
        statsInboundDownlink: true,
        statsOutboundUplink : true,
        statsOutboundDownlink: true
      }
    },
    inbounds : xrayInbounds,
    outbounds: [
      { protocol: 'freedom',   tag: 'direct', settings: { domainStrategy: 'UseIPv4' } },
      { protocol: 'blackhole', tag: 'block',  settings: {} }
    ],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { type: 'field', inboundTag: ['api'], outboundTag: 'api' },
        { type: 'field', ip: ['geoip:private'], outboundTag: 'block' }
      ]
    }
  };
}

function buildStreamSettings(ib) {
  const ss = { network: ib.network };

  if (ib.security === 'tls') {
    ss.security = 'tls';
    ss.tlsSettings = {
      serverName : ib.tls_sni || '',
      alpn       : ['h2', 'http/1.1'],
      allowInsecure: false
    };
  } else if (ib.security === 'reality') {
    ss.security = 'reality';
    ss.realitySettings = {
      dest         : 'www.google.com:443',
      xver         : 0,
      serverNames  : [ib.tls_sni || 'www.google.com'],
      privateKey   : ib.reality_pbk || '',
      shortIds     : [ib.reality_sid || '']
    };
  } else {
    ss.security = 'none';
  }

  switch (ib.network) {
    case 'ws':
      ss.wsSettings = { path: ib.ws_path || '/ws', headers: {} };
      break;
    case 'grpc':
      ss.grpcSettings = { serviceName: ib.grpc_service || 'grpc', multiMode: false };
      break;
    case 'httpupgrade':
      ss.httpupgradeSettings = { path: ib.ws_path || '/', host: ib.tls_sni || '' };
      break;
    case 'xhttp':
      ss.xhttpSettings = { path: ib.ws_path || '/', host: ib.tls_sni || '', mode: ib.xhttp_mode || 'auto' };
      break;
    case 'tcp':
      if (ib.header_type === 'http') {
        ss.tcpSettings = { header: { type: 'http', request: { method: 'GET', path: [ib.ws_path || '/'] } } };
      } else {
        ss.tcpSettings = { header: { type: 'none' } };
      }
      break;
  }
  return ss;
}

function buildProtocolSettings(ib, clients) {
  const xClients = clients.map(c => {
    const base = { id: c.uuid, email: c.email || c.name };
    if (ib.protocol === 'vless') {
      base.flow = ib.security === 'reality' ? 'xtls-rprx-vision' : '';
    }
    if (ib.protocol === 'trojan') {
      return { password: c.uuid, email: c.email || c.name };
    }
    return base;
  });

  switch (ib.protocol) {
    case 'vless':
      return { clients: xClients, decryption: 'none' };
    case 'vmess':
      return { clients: xClients.map(c => ({ ...c, alterId: 0 })) };
    case 'trojan':
      return { clients: xClients };
    case 'shadowsocks':
      return {
        method  : 'chacha20-ietf-poly1305',
        password: clients[0]?.uuid || uuidv4(),
        network : 'tcp,udp'
      };
    default:
      return { clients: xClients };
  }
}

// ══════════════════════════════════
// XRAY SYNC (با hot reload)
// ══════════════════════════════════
let xraySyncing = false;
async function syncXray() {
  if (xraySyncing) return;
  xraySyncing = true;
  try {
    const config = buildXrayConfig();
    fs.writeFileSync('/etc/xray/config.json', JSON.stringify(config, null, 2));

    // hot reload با SIGUSR1 (بدون قطع اتصال‌های موجود)
    try {
      execSync('kill -SIGUSR1 $(cat /var/run/xray.pid 2>/dev/null) 2>/dev/null || supervisorctl restart xray 2>/dev/null || true');
    } catch (_) {}

    const total = db.prepare('SELECT COUNT(*) c FROM clients WHERE enabled=1').get().c;
    console.log(`[xray] synced — ${config.inbounds.length - 1} inbounds, ${total} clients`);
  } catch (e) {
    console.error('[xray] sync error:', e.message);
  } finally {
    xraySyncing = false;
  }
}

// ══════════════════════════════════
// TRAFFIC SYNC از Xray Stats API
// ══════════════════════════════════
async function syncTraffic() {
  try {
    const allTraffic = await xrayApi.getAllUsersTraffic(true); // reset=true
    const keys = Object.keys(allTraffic);
    if (!keys.length) return;

    const updateStmt = db.prepare('UPDATE clients SET traffic_used=traffic_used+?, up_bytes=up_bytes+?, down_bytes=down_bytes+? WHERE email=? AND enabled=1');
    const bulkUpdate = db.transaction(() => {
      for (const email of keys) {
        const t = allTraffic[email];
        if (t.total > 0) {
          updateStmt.run(t.total, t.up, t.down, email);
        }
      }
    });
    bulkUpdate();

    // غیرفعال کردن کاربرانی که ترافیک تموم شده
    const now = new Date().toISOString();
    db.prepare('UPDATE clients SET enabled=0 WHERE traffic_limit>0 AND traffic_used>=traffic_limit AND enabled=1').run();
    db.prepare('UPDATE clients SET enabled=0 WHERE expire_date IS NOT NULL AND expire_date<? AND enabled=1').run(now);

    console.log(`[traffic] synced ${keys.length} users`);
  } catch (e) {
    console.error('[traffic] sync error:', e.message);
  }
}

// ══════════════════════════════════
// LINK GENERATOR
// ══════════════════════════════════
function makeLink(client, ib, req) {
  const domain = getDomain(req);
  const port   = ib.security === 'none' ? String(ib.port) : '443';
  const name   = encodeURIComponent(`${client.name} | PersianPanel`);

  switch (ib.protocol) {
    case 'vless':  return makeVlessLink(client, ib, domain, port, name);
    case 'vmess':  return makeVmessLink(client, ib, domain, port, name);
    case 'trojan': return makeTrojanLink(client, ib, domain, port, name);
    default:       return '';
  }
}

function makeVlessLink(client, ib, domain, port, name) {
  const q = new URLSearchParams();
  q.set('type',       ib.network);
  q.set('security',   ib.security || 'none');
  q.set('encryption', 'none');

  if (ib.security === 'tls' || ib.security === 'reality') {
    q.set('sni', ib.tls_sni || domain);
    q.set('fp',  'chrome');
    if (ib.security === 'reality') {
      q.set('pbk', ib.reality_pbk || '');
      q.set('sid', ib.reality_sid || '');
      q.set('flow', 'xtls-rprx-vision');
    } else {
      q.set('alpn', 'h2,http/1.1');
    }
  }

  applyNetworkParams(q, ib, domain);
  return `vless://${client.uuid}@${domain}:${port}?${q.toString()}#${name}`;
}

function makeVmessLink(client, ib, domain, port, name) {
  const obj = {
    v: '2', ps: decodeURIComponent(name),
    add: domain, port: String(port),
    id: client.uuid, aid: '0', scy: 'auto',
    net: ib.network, type: 'none',
    host: ib.tls_sni || domain, path: ib.ws_path || '/',
    tls: ib.security === 'tls' ? 'tls' : '',
    sni: ib.tls_sni || domain, alpn: '',
    fp: ib.security === 'tls' ? 'chrome' : ''
  };
  if (ib.network === 'grpc') { obj.path = ib.grpc_service || 'grpc'; obj.type = 'gun'; }
  if (ib.network === 'tcp' && ib.header_type === 'http') obj.type = 'http';
  return `vmess://${Buffer.from(JSON.stringify(obj)).toString('base64')}`;
}

function makeTrojanLink(client, ib, domain, port, name) {
  const q = new URLSearchParams();
  q.set('type',     ib.network);
  q.set('security', ib.security !== 'none' ? ib.security : 'tls');
  q.set('sni',      ib.tls_sni || domain);
  q.set('fp',       'chrome');
  q.set('alpn',     'h2,http/1.1');
  applyNetworkParams(q, ib, domain);
  return `trojan://${client.uuid}@${domain}:${port}?${q.toString()}#${name}`;
}

function applyNetworkParams(q, ib, domain) {
  switch (ib.network) {
    case 'ws':
      q.set('path', ib.ws_path || '/');
      q.set('host', ib.tls_sni || domain);
      break;
    case 'grpc':
      q.set('serviceName', ib.grpc_service || 'grpc');
      q.set('mode', 'gun');
      break;
    case 'httpupgrade':
      q.set('path', ib.ws_path || '/');
      q.set('host', ib.tls_sni || domain);
      break;
    case 'xhttp':
      q.set('path', ib.ws_path || '/');
      q.set('host', ib.tls_sni || domain);
      q.set('mode', ib.xhttp_mode || 'auto');
      break;
    case 'tcp':
      if (ib.header_type === 'http') {
        q.set('headerType', 'http');
        q.set('path', ib.ws_path || '/');
      }
      break;
  }
}

// ══════════════════════════════════
// EXPRESS
// ══════════════════════════════════
app.set('trust proxy', 1);
app.use(compression());
app.use(morgan('tiny'));

// WS Proxy برای همه inbound های WS
const wsProxy = createProxyMiddleware({
  target      : 'http://127.0.0.1:10086',
  changeOrigin: true,
  ws          : true,
  logLevel    : 'silent',
  router      : (req) => {
    // پیدا کردن inbound مناسب بر اساس path
    const wsInbounds = db.prepare("SELECT * FROM inbounds WHERE network='ws' AND enabled=1").all();
    for (const ib of wsInbounds) {
      if (req.url.startsWith(ib.ws_path)) {
        return `http://127.0.0.1:${ib.port}`;
      }
    }
    return 'http://127.0.0.1:10086';
  },
  on: {
    error: (err) => console.error('[proxy]', err.message)
  }
});

// Dynamic WS routing
app.use((req, res, next) => {
  const wsInbounds = db.prepare("SELECT * FROM inbounds WHERE network='ws' AND enabled=1").all();
  for (const ib of wsInbounds) {
    if (req.url.startsWith(ib.ws_path) && req.headers.upgrade === 'websocket') {
      return wsProxy(req, res, next);
    }
  }
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret           : process.env.SESSION_SECRET || uuidv4(),
  resave           : false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { success: false, message: 'تلاش بیش از حد' } });
const apiLimiter   = rateLimit({ windowMs: 60*1000, max: 300 });
app.use('/api/', apiLimiter);

const auth = (req, res, next) => {
  if (req.session?.uid) return next();
  res.status(401).json({ success: false, message: 'Unauthorized' });
};

// ══════════════════════════════════
// HEALTH
// ══════════════════════════════════
app.get('/health', (_, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// ══════════════════════════════════
// AUTH
// ══════════════════════════════════
app.get('/api/auth/me', (req, res) => {
  if (!req.session?.uid) return res.status(401).json({ success: false });
  res.json({ success: true, user: { id: req.session.uid, username: req.session.uname, role: req.session.role } });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username?.trim() || !password) return res.status(400).json({ success: false, message: 'اطلاعات ناقص' });
    const user = db.prepare('SELECT * FROM panel_users WHERE username=?').get(username.trim());
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ success: false, message: 'نام کاربری یا رمز اشتباه' });
    req.session.uid = user.id; req.session.uname = user.username; req.session.role = user.role;
    res.json({ success: true, user: { id: user.id, username: user.username } });
  } catch (e) { res.status(500).json({ success: false, message: 'خطای سرور' }); }
});

app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ success: true })));

app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword, newUsername } = req.body;
    const user = db.prepare('SELECT * FROM panel_users WHERE id=?').get(req.session.uid);
    if (!user || !(await bcrypt.compare(currentPassword, user.password)))
      return res.status(401).json({ success: false, message: 'رمز فعلی اشتباه' });
    const upd = [], prm = [];
    if (newPassword?.length >= 4)        { upd.push('password=?'); prm.push(await bcrypt.hash(newPassword, 12)); }
    if (newUsername?.trim().length >= 2) { upd.push('username=?'); prm.push(newUsername.trim()); }
    if (!upd.length) return res.json({ success: false, message: 'چیزی تغییر نکرد' });
    prm.push(req.session.uid);
    db.prepare(`UPDATE panel_users SET ${upd.join(',')} WHERE id=?`).run(...prm);
    if (newUsername) req.session.uname = newUsername.trim();
    res.json({ success: true, message: 'تغییر یافت ✅' });
  } catch (e) { res.status(500).json({ success: false, message: 'خطای سرور' }); }
});

// ══════════════════════════════════
// SETTINGS
// ══════════════════════════════════
app.get('/api/settings', auth, (_, res) => {
  res.json({ success: true, data: {
    panel_name: G('panel_name') || 'Persian Panel',
    cf_domain : G('cf_domain') || '',
    theme     : G('theme') || 'dark'
  }});
});

app.post('/api/settings', auth, (req, res) => {
  const { panel_name, cf_domain, theme } = req.body;
  if (panel_name !== undefined) S('panel_name', panel_name.trim());
  if (cf_domain  !== undefined) S('cf_domain',  cf_domain.trim());
  if (theme      !== undefined) S('theme',       theme);
  res.json({ success: true, message: 'ذخیره شد ✅' });
});

app.get('/api/server-info', auth, (req, res) => {
  const domain = getDomain(req);
  res.json({ success: true, data: {
    domain,
    uptime    : process.uptime(),
    memory    : process.memoryUsage(),
    node      : process.version,
    env       : process.env.RAILWAY_ENVIRONMENT || 'local',
    panel_path: PANEL_PATH
  }});
});

// ══════════════════════════════════
// STATS
// ══════════════════════════════════
app.get('/api/stats', auth, (_, res) => {
  try {
    const now = new Date().toISOString();
    const inbounds = db.prepare('SELECT * FROM inbounds').all();
    const totalTraffic = inbounds.reduce((sum, ib) => sum + (ib.up_mbytes || 0) + (ib.down_mbytes || 0), 0);
    res.json({ success: true, data: {
      total        : db.prepare('SELECT COUNT(*) c FROM clients').get().c,
      active       : db.prepare('SELECT COUNT(*) c FROM clients WHERE enabled=1 AND (expire_date IS NULL OR expire_date>?)').get(now).c,
      expired      : db.prepare('SELECT COUNT(*) c FROM clients WHERE expire_date IS NOT NULL AND expire_date<=?').get(now).c,
      disabled     : db.prepare('SELECT COUNT(*) c FROM clients WHERE enabled=0').get().c,
      total_inbounds: db.prepare('SELECT COUNT(*) c FROM inbounds').get().c,
      total_traffic: db.prepare('SELECT COALESCE(SUM(traffic_used),0) t FROM clients').get().t
    }});
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════
// INBOUNDS
// ══════════════════════════════════
app.get('/api/inbounds', auth, (_, res) => {
  try {
    const inbounds = db.prepare(`
      SELECT i.*, COUNT(c.id) as client_count
      FROM inbounds i
      LEFT JOIN clients c ON i.id=c.inbound_id AND c.enabled=1
      GROUP BY i.id
      ORDER BY i.created_at DESC
    `).all();
    res.json({ success: true, data: inbounds });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/inbounds', auth, (req, res) => {
  try {
    const { remark, protocol, port, network, security, tls_sni, ws_path, grpc_service, reality_pbk, reality_sid, header_type, xhttp_mode } = req.body;
    if (!protocol || !port || !network) return res.status(400).json({ success: false, message: 'پروتکل، پورت و شبکه الزامی است' });
    const portN = parseInt(port);
    if (isNaN(portN) || portN < 1 || portN > 65535) return res.status(400).json({ success: false, message: 'پورت نامعتبر' });
    if (db.prepare('SELECT id FROM inbounds WHERE port=?').get(portN)) return res.status(400).json({ success: false, message: `پورت ${portN} قبلاً استفاده شده` });

    const tag = `ib_${Date.now()}`;
    const r = db.prepare(`
      INSERT INTO inbounds (tag, remark, protocol, port, network, security, tls_sni, ws_path, grpc_service, reality_pbk, reality_sid, header_type, xhttp_mode)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(
      tag,
      remark || `${protocol.toUpperCase()}-${network.toUpperCase()}-${portN}`,
      protocol, portN, network,
      security || 'none',
      tls_sni || '',
      ws_path || '/ws',
      grpc_service || 'grpc',
      reality_pbk || '',
      reality_sid || '',
      header_type || 'none',
      xhttp_mode || 'auto'
    );
    syncXray();
    res.json({ success: true, message: 'Inbound ایجاد شد ✅', data: db.prepare('SELECT * FROM inbounds WHERE id=?').get(r.lastInsertRowid) });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/inbounds/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(id);
    if (!ib) return res.status(404).json({ success: false, message: 'یافت نشد' });
    const { remark, protocol, port, network, security, tls_sni, ws_path, grpc_service, reality_pbk, reality_sid, header_type, xhttp_mode, enabled } = req.body;
    db.prepare(`
      UPDATE inbounds SET remark=?, protocol=?, port=?, network=?, security=?, tls_sni=?,
      ws_path=?, grpc_service=?, reality_pbk=?, reality_sid=?, header_type=?, xhttp_mode=?, enabled=? WHERE id=?
    `).run(
      remark        ?? ib.remark,
      protocol      ?? ib.protocol,
      port          ? parseInt(port) : ib.port,
      network       ?? ib.network,
      security      ?? ib.security,
      tls_sni       ?? ib.tls_sni,
      ws_path       ?? ib.ws_path,
      grpc_service  ?? ib.grpc_service,
      reality_pbk   ?? ib.reality_pbk,
      reality_sid   ?? ib.reality_sid,
      header_type   ?? ib.header_type,
      xhttp_mode    ?? ib.xhttp_mode,
      enabled !== undefined ? (enabled ? 1 : 0) : ib.enabled,
      id
    );
    syncXray();
    res.json({ success: true, message: 'آپدیت شد ✅', data: db.prepare('SELECT * FROM inbounds WHERE id=?').get(id) });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.delete('/api/inbounds/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!db.prepare('SELECT id FROM inbounds WHERE id=?').get(id)) return res.status(404).json({ success: false, message: 'یافت نشد' });
    db.prepare('DELETE FROM inbounds WHERE id=?').run(id);
    syncXray();
    res.json({ success: true, message: 'حذف شد' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════
// CLIENTS
// ══════════════════════════════════
app.get('/api/clients', auth, (req, res) => {
  try {
    const { search, inbound_id } = req.query;
    let q = `
      SELECT c.*, i.remark as inbound_remark, i.protocol as i_protocol,
             i.network as i_network, i.port as i_port, i.security as i_security,
             i.ws_path, i.tls_sni, i.grpc_service
      FROM clients c
      JOIN inbounds i ON c.inbound_id=i.id
      WHERE 1=1
    `;
    const params = [];
    if (inbound_id) { q += ' AND c.inbound_id=?'; params.push(parseInt(inbound_id)); }
    if (search)     { q += ' AND (c.name LIKE ? OR c.email LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    q += ' ORDER BY c.created_at DESC LIMIT 500';
    const now = new Date();
    res.json({ success: true, data: db.prepare(q).all(...params).map(c => ({
      ...c,
      is_expired  : c.expire_date ? new Date(c.expire_date) < now : false,
      over_traffic: c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit
    }))});
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/clients', auth, (req, res) => {
  try {
    const { inbound_id, name, email, traffic_limit_gb, expire_days, max_connections, note, custom_uuid } = req.body;
    if (!inbound_id || !name?.trim()) return res.status(400).json({ success: false, message: 'Inbound و نام الزامی است' });
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=? AND enabled=1').get(parseInt(inbound_id));
    if (!ib) return res.status(404).json({ success: false, message: 'Inbound یافت نشد' });

    const uuidRx = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const uuid   = (custom_uuid?.trim() && uuidRx.test(custom_uuid.trim())) ? custom_uuid.trim() : uuidv4();
    if (db.prepare('SELECT id FROM clients WHERE uuid=?').get(uuid))
      return res.status(400).json({ success: false, message: 'این UUID قبلاً استفاده شده' });

    const sub    = uuidv4().replace(/-/g,'') + uuidv4().replace(/-/g,'');
    const tBytes = traffic_limit_gb ? Math.floor(parseFloat(traffic_limit_gb) * 1073741824) : 0;
    let expDate  = null;
    if (expire_days && parseInt(expire_days) > 0) {
      const d = new Date(); d.setDate(d.getDate() + parseInt(expire_days)); expDate = d.toISOString();
    }
    const mail = email?.trim() || `${name.trim().toLowerCase().replace(/[^a-z0-9]/g,'.')}.${Date.now()}@persian.panel`;

    const r = db.prepare(`
      INSERT INTO clients (inbound_id, name, uuid, email, traffic_limit, traffic_used, expire_date, max_connections, enabled, sub_token, note)
      VALUES (?,?,?,?,?,0,?,?,1,?,?)
    `).run(parseInt(inbound_id), name.trim(), uuid, mail, tBytes, expDate, parseInt(max_connections)||0, sub, note?.trim()||'');

    syncXray();
    res.json({ success: true, message: 'کاربر ایجاد شد ✅', data: db.prepare('SELECT * FROM clients WHERE id=?').get(r.lastInsertRowid) });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/clients/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const c  = db.prepare('SELECT * FROM clients WHERE id=?').get(id);
    if (!c) return res.status(404).json({ success: false, message: 'یافت نشد' });
    const { name, email, traffic_limit_gb, expire_days, max_connections, enabled, reset_traffic, note } = req.body;
    const tBytes = traffic_limit_gb !== undefined ? Math.floor(parseFloat(traffic_limit_gb) * 1073741824) : c.traffic_limit;
    let expDate = c.expire_date;
    if (expire_days !== undefined) {
      if (!expire_days || parseInt(expire_days) <= 0) { expDate = null; }
      else { const d = new Date(); d.setDate(d.getDate() + parseInt(expire_days)); expDate = d.toISOString(); }
    }
    db.prepare(`
      UPDATE clients SET name=?, email=?, traffic_limit=?, traffic_used=?, expire_date=?, max_connections=?, enabled=?, note=? WHERE id=?
    `).run(name??c.name, email??c.email, tBytes, reset_traffic?0:c.traffic_used, expDate,
      max_connections!==undefined?parseInt(max_connections):c.max_connections,
      enabled!==undefined?(enabled?1:0):c.enabled, note!==undefined?note.trim():c.note, id);
    syncXray();
    res.json({ success: true, message: 'آپدیت شد ✅', data: db.prepare('SELECT * FROM clients WHERE id=?').get(id) });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.delete('/api/clients/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!db.prepare('SELECT id FROM clients WHERE id=?').get(id)) return res.status(404).json({ success: false, message: 'یافت نشد' });
    db.prepare('DELETE FROM clients WHERE id=?').run(id);
    syncXray();
    res.json({ success: true, message: 'کاربر حذف شد' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/clients/:id/reset-traffic', auth, (req, res) => {
  try {
    db.prepare('UPDATE clients SET traffic_used=0, up_bytes=0, down_bytes=0 WHERE id=?').run(parseInt(req.params.id));
    res.json({ success: true, message: 'ترافیک ری‌ست شد ✅' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/clients/:id/config', auth, (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE id=?').get(parseInt(req.params.id));
    if (!c) return res.status(404).json({ success: false, message: 'یافت نشد' });
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(c.inbound_id);
    if (!ib) return res.status(404).json({ success: false, message: 'Inbound یافت نشد' });
    const link   = makeLink(c, ib, req);
    const subUrl = `${req.protocol}://${req.get('host')}/sub/${c.sub_token}`;
    res.json({ success: true, data: { link, subUrl, uuid: c.uuid, protocol: ib.protocol, network: ib.network } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════
// SUBSCRIPTION
// ══════════════════════════════════
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');

app.get('/sub/:token', (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(req.params.token);
    if (!c || !c.enabled) return res.status(404).send('Not Found');
    if (c.expire_date && new Date(c.expire_date) < new Date()) return res.status(403).send('Expired');
    if (c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit) return res.status(403).send('Traffic Exceeded');
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=? AND enabled=1').get(c.inbound_id);
    if (!ib) return res.status(404).send('Not Found');
    const link = makeLink(c, ib, req);
    if (!link) return res.status(500).send('Config Error');
    const exp = c.expire_date ? Math.floor(new Date(c.expire_date).getTime()/1000) : 0;
    res.setHeader('Content-Type',            'text/plain; charset=utf-8');
    res.setHeader('Subscription-Userinfo',   `upload=${c.up_bytes||0}; download=${c.down_bytes||0}; total=${c.traffic_limit||0}; expire=${exp}`);
    res.setHeader('Profile-Title',           Buffer.from(`PersianPanel-${c.name}`).toString('base64'));
    res.setHeader('Profile-Update-Interval', '12');
    res.setHeader('Support-Url',             `${req.protocol}://${req.get('host')}/sub/info/${c.sub_token}`);
    res.send(Buffer.from(link).toString('base64'));
  } catch (e) { res.status(500).send('Error'); }
});

app.get('/sub/info/:token', (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(req.params.token);
    if (!c) return res.status(404).send('Not Found');
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(c.inbound_id);
    if (!ib) return res.status(404).send('Not Found');

    const now    = new Date();
    const isExp  = c.expire_date && new Date(c.expire_date) < now;
    const isTraf = c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit;
    const ok     = !isExp && !isTraf && !!c.enabled;
    const link   = makeLink(c, ib, req);
    const subUrl = `${req.protocol}://${req.get('host')}/sub/${c.sub_token}`;
    const tU     = (c.traffic_used / 1073741824).toFixed(2);
    const tT     = c.traffic_limit > 0 ? (c.traffic_limit / 1073741824).toFixed(0) : '∞';
    const pct    = c.traffic_limit > 0 ? Math.min(100,(c.traffic_used/c.traffic_limit)*100) : 0;
    const dL     = c.expire_date ? Math.max(0,Math.ceil((new Date(c.expire_date)-now)/86400000)) : null;
    const expStr = c.expire_date ? new Date(c.expire_date).toLocaleDateString('fa-IR',{year:'numeric',month:'long',day:'numeric'}) : 'نامحدود';
    const pColor = pct>90?'#ef4444':pct>70?'#f59e0b':'#10b981';
    const qrUrl  = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&color=a78bfa&bgcolor=040410&data=${encodeURIComponent(link)}`;

    res.setHeader('Content-Type','text/html; charset=utf-8');
    res.send(`<!DOCTYPE html>
<html lang="fa" dir="rtl"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>اشتراک ${esc(c.name)}</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Vazirmatn',sans-serif;background:#040410;color:#f1f5f9;min-height:100vh;padding:20px 16px;
  background-image:radial-gradient(ellipse at 20% 20%,rgba(124,58,237,.12) 0%,transparent 50%),radial-gradient(ellipse at 80% 80%,rgba(96,165,250,.08) 0%,transparent 50%)}
.wrap{max-width:500px;margin:0 auto}
.hdr{text-align:center;padding:40px 0 28px}
.logo{display:inline-flex;align-items:center;justify-content:center;width:88px;height:88px;border-radius:28px;
  background:linear-gradient(135deg,rgba(124,58,237,.25),rgba(59,130,246,.15));border:1px solid rgba(124,58,237,.3);
  font-size:44px;margin-bottom:18px;animation:glow 3s ease-in-out infinite}
@keyframes glow{0%,100%{box-shadow:0 0 40px rgba(124,58,237,.3)}50%{box-shadow:0 0 70px rgba(124,58,237,.6)}}
.htitle{font-size:28px;font-weight:900;background:linear-gradient(135deg,#fff,#a78bfa,#60a5fa);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}
.hsub{color:#475569;font-size:13px}
.card{background:rgba(255,255,255,.04);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.07);
  border-radius:22px;padding:22px;margin-bottom:14px;transition:.3s}
.card:hover{border-color:rgba(124,58,237,.25)}
.clbl{font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:1.5px;font-weight:700;margin-bottom:14px}
.ur{display:flex;align-items:center;justify-content:space-between;gap:12px}
.un{font-size:22px;font-weight:800}
.sb{display:inline-flex;align-items:center;gap:5px;padding:7px 16px;border-radius:20px;font-size:13px;font-weight:700}
.sg{background:rgba(16,185,129,.12);color:#10b981;border:1px solid rgba(16,185,129,.2)}
.sr{background:rgba(239,68,68,.12);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.sy{background:rgba(245,158,11,.12);color:#f59e0b;border:1px solid rgba(245,158,11,.2)}
.so{background:rgba(100,116,139,.12);color:#94a3b8;border:1px solid rgba(100,116,139,.2)}
.ue{color:#475569;font-size:13px;margin-top:6px}
.al{background:rgba(239,68,68,.07);border:1px solid rgba(239,68,237,.15);border-radius:12px;padding:12px 16px;font-size:13px;color:#fca5a5;margin-top:14px}
.ib-info{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}
.ib-badge{background:rgba(124,58,237,.12);color:#a78bfa;border:1px solid rgba(124,58,237,.2);padding:4px 10px;border-radius:8px;font-size:12px;font-weight:600}
.sg2{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.st{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:16px;text-align:center;transition:.3s}
.st:hover{border-color:rgba(124,58,237,.25);transform:translateY(-2px)}
.si{font-size:22px;margin-bottom:8px}
.sv{font-size:22px;font-weight:800;line-height:1}
.cg{color:#10b981}.cb{color:#60a5fa}.cy{color:#f59e0b}.cr{color:#ef4444}.cp{color:#a78bfa}.cpk{color:#ec4899}
.sl{font-size:11px;color:#475569;margin-top:4px}
.pw{margin-top:16px;padding-top:16px;border-top:1px solid rgba(255,255,255,.06)}
.ph{display:flex;justify-content:space-between;font-size:12px;color:#94a3b8;margin-bottom:8px}
.pb{background:rgba(255,255,255,.07);border-radius:6px;height:8px;overflow:hidden}
.pf{height:100%;border-radius:6px;transition:width 1s ease}
.pi{text-align:center;font-size:12px;color:#475569;margin-top:6px}
.er{display:flex;justify-content:space-between;align-items:center;padding-top:14px;margin-top:14px;border-top:1px solid rgba(255,255,255,.06);font-size:13px}
.el{color:#475569}.ev{font-weight:700}
.ca{position:relative;margin:10px 0}
.cb2{background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:12px 56px 12px 14px;font-family:monospace;font-size:11px;color:#94a3b8;word-break:break-all;direction:ltr;text-align:left;line-height:1.7}
.cpb{position:absolute;top:50%;right:10px;transform:translateY(-50%);background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;border:none;border-radius:8px;padding:7px 12px;cursor:pointer;font-size:12px;font-family:inherit;font-weight:600;transition:.3s;white-space:nowrap}
.cpb:hover{opacity:.85;transform:translateY(-50%) scale(1.05)}
.cpb.copied{background:linear-gradient(135deg,#10b981,#059669)}
.br{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.btn{flex:1;padding:13px 16px;border:none;border-radius:14px;cursor:pointer;font-size:14px;font-weight:700;font-family:inherit;display:flex;align-items:center;justify-content:center;gap:6px;min-width:120px;text-decoration:none;transition:.3s}
.btn:hover{transform:translateY(-3px);box-shadow:0 10px 30px rgba(0,0,0,.3)}
.btnp{background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;box-shadow:0 4px 16px rgba(124,58,237,.3)}
.btnb{background:linear-gradient(135deg,#2563eb,#1d4ed8);color:#fff}
.qs{display:none;margin-top:16px;text-align:center}
.qs.show{display:block;animation:fu .3s ease}
@keyframes fu{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.qf{display:inline-block;background:rgba(167,139,250,.05);border:2px solid rgba(124,58,237,.2);border-radius:22px;padding:20px}
.qf img{border-radius:14px;display:block}
.qh{font-size:12px;color:#475569;margin-top:10px}
.step{display:flex;align-items:flex-start;gap:12px;margin-bottom:12px}
.step:last-child{margin-bottom:0}
.sn{width:28px;height:28px;flex-shrink:0;background:rgba(124,58,237,.15);color:#a78bfa;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700}
.sn.ok{background:rgba(16,185,129,.15);color:#10b981}
.st2{font-size:13px;color:#94a3b8;line-height:1.8;padding-top:3px}
.st2 strong{color:#f1f5f9}
.ft{text-align:center;padding:32px 0 12px;color:#334155;font-size:12px}
.fb{display:inline-flex;align-items:center;gap:6px;background:rgba(124,58,237,.08);border:1px solid rgba(124,58,237,.15);border-radius:20px;padding:7px 18px;color:#a78bfa;font-weight:600;margin-top:10px}
</style></head><body>
<div class="wrap">
  <div class="hdr">
    <div class="logo">🔮</div>
    <div class="htitle">Persian Panel</div>
    <div class="hsub">اطلاعات اشتراک VPN شما</div>
  </div>
  <div class="card">
    <div class="ur">
      <div class="un">${esc(c.name)}</div>
      <span class="sb ${ok?'sg':isExp?'sr':isTraf?'sy':'so'}">${ok?'🟢 فعال':isExp?'🔴 منقضی':isTraf?'🟡 تمام':'⚫ غیرفعال'}</span>
    </div>
    <div class="ue">${esc(c.email)}</div>
    <div class="ib-info">
      <span class="ib-badge">${ib.protocol.toUpperCase()}</span>
      <span class="ib-badge">${ib.network.toUpperCase()}</span>
      <span class="ib-badge">${ib.security.toUpperCase()}</span>
      <span class="ib-badge">${esc(ib.remark)}</span>
    </div>
    ${!ok?`<div class="al">⚠️ ${isExp?'اشتراک منقضی — برای تمدید اقدام کنید':isTraf?'ترافیک تمام شده است':'اشتراک غیرفعال است'}</div>`:''}
  </div>
  <div class="card">
    <div class="clbl">📊 آمار مصرف</div>
    <div class="sg2">
      <div class="st"><div class="si">📦</div><div class="sv ${pct>90?'cr':pct>70?'cy':'cg'}">${tU}</div><div class="sl">GB مصرف</div></div>
      <div class="st"><div class="si">🗄️</div><div class="sv cb">${tT}</div><div class="sl">GB کل</div></div>
      <div class="st"><div class="si">📅</div><div class="sv ${dL!==null&&dL<3?'cr':dL!==null&&dL<7?'cy':'cp'}">${dL!==null?dL:'∞'}</div><div class="sl">روز مانده</div></div>
      <div class="st"><div class="si">🔗</div><div class="sv cpk">${c.max_connections||'∞'}</div><div class="sl">حداکثر اتصال</div></div>
    </div>
    ${c.traffic_limit>0?`<div class="pw"><div class="ph"><span>ترافیک</span><span>${pct.toFixed(1)}%</span></div><div class="pb"><div class="pf" id="pf" style="width:0%;background:${pColor}"></div></div><div class="pi">${tU} از ${tT} گیگابایت</div></div>`:''}
    <div class="er"><span class="el">📅 انقضا</span><span class="ev">${expStr}</span></div>
  </div>
  <div class="card">
    <div class="clbl">🔗 لینک ساب‌اسکریپشن</div>
    <div class="ca"><div class="cb2">${esc(subUrl)}</div><button class="cpb" onclick="cp('${esc(subUrl)}',this)">📋 کپی</button></div>
    <div style="font-size:12px;color:#475569;margin-top:10px;line-height:2">توی <strong style="color:#a78bfa">Hiddify</strong>، <strong style="color:#a78bfa">v2rayNG</strong> یا <strong style="color:#a78bfa">Streisand</strong> وارد کنید</div>
  </div>
  <div class="card">
    <div class="clbl">⚙️ کانفیگ ${ib.protocol.toUpperCase()}+${ib.network.toUpperCase()}</div>
    <div class="ca"><div class="cb2">${esc(link)}</div><button class="cpb" onclick="cp('${link.replace(/\\/g,'\\\\').replace(/'/g,"\\'")}',this)">📋 کپی</button></div>
    <div class="br">
      <button class="btn btnp" onclick="cp('${link.replace(/\\/g,'\\\\').replace(/'/g,"\\'")}',this)">📋 کپی کانفیگ</button>
      <button class="btn btnb" id="qb" onclick="tqr()">📱 QR کد</button>
    </div>
    <div class="qs" id="qs"><div class="qf"><img src="${qrUrl}" width="220" height="220" alt="QR"/><div class="qh">با اپ اسکن کنید</div></div></div>
  </div>
  <div class="card">
    <div class="clbl">📱 راهنمای اتصال</div>
    <div class="step"><div class="sn">۱</div><div class="st2">اپ <strong>Hiddify</strong> یا <strong>v2rayNG</strong> رو دانلود کنید</div></div>
    <div class="step"><div class="sn">۲</div><div class="st2">روی <strong>افزودن سرور</strong> کلیک کنید</div></div>
    <div class="step"><div class="sn">۳</div><div class="st2"><strong>لینک ساب</strong> رو paste یا <strong>QR</strong> رو اسکن کنید</div></div>
    <div class="step"><div class="sn ok">✓</div><div class="st2">وصل شوید و از اینترنت آزاد لذت ببرید 🎉</div></div>
  </div>
  <div class="ft"><div>رمزنگاری شده و محفوظ 🔒</div><div class="fb">🔮 Persian Panel</div></div>
</div>
<script>
function cp(t,btn){navigator.clipboard.writeText(t).catch(()=>{const x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove()});
if(btn&&btn.classList.contains('cpb')){const o=btn.innerHTML;btn.innerHTML='✅ کپی شد!';btn.classList.add('copied');setTimeout(()=>{btn.innerHTML=o;btn.classList.remove('copied')},2000)}
else if(btn){const o=btn.innerHTML;btn.innerHTML='✅ کپی شد!';setTimeout(()=>btn.innerHTML=o,2000)}}
function tqr(){const s=document.getElementById('qs');const b=document.getElementById('qb');if(s.classList.contains('show')){s.classList.remove('show');b.innerHTML='📱 QR کد'}else{s.classList.add('show');b.innerHTML='❌ بستن QR'}}
window.addEventListener('load',()=>{const pf=document.getElementById('pf');if(pf)setTimeout(()=>pf.style.width='${pct.toFixed(1)}%',400)});
</script></body></html>`);
  } catch (e) { res.status(500).send('<h2>Error</h2>'); }
});

// ══════════════════════════════════
// STATIC + SPA
// ══════════════════════════════════
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/sub/'))
    return res.status(404).json({ success: false, message: 'Not Found' });
  if (req.path === PANEL_PATH || req.path.startsWith(PANEL_PATH + '/'))
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  if (req.path === '/') return res.redirect(301, PANEL_PATH);
  res.status(404).send('Not Found');
});

// ══════════════════════════════════
// CRON JOBS
// ══════════════════════════════════

// هر ۵ دقیقه ترافیک sync
cron.schedule('*/5 * * * *', () => syncTraffic());

// هر ساعت expire check
cron.schedule('0 * * * *', () => {
  try {
    const now = new Date().toISOString();
    const r1  = db.prepare('UPDATE clients SET enabled=0 WHERE expire_date IS NOT NULL AND expire_date<? AND enabled=1').run(now);
    const r2  = db.prepare('UPDATE clients SET enabled=0 WHERE traffic_limit>0 AND traffic_used>=traffic_limit AND enabled=1').run();
    if (r1.changes || r2.changes) { console.log(`[cron] ${r1.changes} expired, ${r2.changes} over-traffic`); syncXray(); }
  } catch (e) { console.error('[cron]', e.message); }
});

// ══════════════════════════════════
// START
// ══════════════════════════════════
initDB();
setTimeout(syncXray, 5000);
setTimeout(syncTraffic, 15000);

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
🔮 Persian Panel v4.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 ${process.env.RAILWAY_PUBLIC_DOMAIN || `localhost:${PORT}`}
📁 Panel : ${PANEL_PATH}
🚀 Port  : ${PORT}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
});

server.on('upgrade', (req, socket, head) => {
  try { wsProxy.upgrade(req, socket, head); } catch (_) {}
});
