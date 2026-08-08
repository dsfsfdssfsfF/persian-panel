'use strict';
require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const compression  = require('compression');
const morgan       = require('morgan');
const path         = require('path');
const cron         = require('node-cron');
const Database     = require('better-sqlite3');
const bcrypt       = require('bcryptjs');
const rateLimit    = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const fs           = require('fs');

const app  = express();
const PORT = parseInt(process.env.PORT) || 3000;

// ════════════════════════════════════════════
// PANEL PATH (مخفی کردن آدرس پنل)
// ════════════════════════════════════════════
const PANEL_PATH = (process.env.PANEL_PATH || '/panel').replace(/\/$/, '');

// ════════════════════════════════════════════
// DATABASE
// ════════════════════════════════════════════
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

// ════════════════════════════════════════════
// INIT DB
// ════════════════════════════════════════════
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
      protocol        TEXT NOT NULL,
      port            INTEGER NOT NULL,
      network         TEXT NOT NULL,
      security        TEXT DEFAULT 'none',
      external_proxy  TEXT DEFAULT '',
      path            TEXT DEFAULT '/',
      host            TEXT DEFAULT '',
      service_name    TEXT DEFAULT 'grpc',
      header_type     TEXT DEFAULT 'none',
      xhttp_mode      TEXT DEFAULT 'auto',
      tls_sni         TEXT DEFAULT '',
      stream_settings TEXT DEFAULT '{}',
      enabled         INTEGER DEFAULT 1,
      remark          TEXT DEFAULT '',
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
      external_proxy  TEXT DEFAULT '',
      enabled         INTEGER DEFAULT 1,
      sub_token       TEXT UNIQUE NOT NULL,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_clients_sub_token  ON clients(sub_token);
    CREATE INDEX IF NOT EXISTS idx_clients_inbound_id ON clients(inbound_id);
    CREATE INDEX IF NOT EXISTS idx_clients_enabled    ON clients(enabled);
  `);

  // ادمین پیش‌فرض
  if (!db.prepare('SELECT id FROM panel_users WHERE username=?').get('admin')) {
    db.prepare('INSERT INTO panel_users (username,password,role) VALUES (?,?,?)')
      .run('admin', bcrypt.hashSync('admin', 12), 'superadmin');
    console.log('✅ Default admin: admin / admin  ← رمز رو عوض کن!');
  }

  // تنظیمات پیش‌فرض
  const railDomain = process.env.RAILWAY_PUBLIC_DOMAIN || '';
  const defaults = {
    panel_name   : 'Persian Panel',
    panel_domain : railDomain || 'localhost',
    theme        : 'dark',
    tcp_proxy    : ''
  };

  for (const [k, v] of Object.entries(defaults)) {
    if (!db.prepare('SELECT key FROM settings WHERE key=?').get(k))
      db.prepare('INSERT INTO settings (key,value) VALUES (?,?)').run(k, v);
  }

  if (railDomain)
    db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)')
      .run('panel_domain', railDomain);

  console.log('✅ DB ready:', dbPath);
  console.log(`🔮 Panel path: ${PANEL_PATH}`);
}

// ════════════════════════════════════════════
// SETTINGS HELPERS
// ════════════════════════════════════════════
const G = k => { const r = db.prepare('SELECT value FROM settings WHERE key=?').get(k); return r ? r.value : ''; };
const S = (k, v) => db.prepare('INSERT OR REPLACE INTO settings (key,value,updated_at) VALUES (?,?,CURRENT_TIMESTAMP)').run(k, String(v));

// ════════════════════════════════════════════
// CONFIG GENERATOR — قلب پنل
// ════════════════════════════════════════════

/**
 * آدرس و پورت واقعی کلاینت رو حساب میکنه
 * اولویت: external_proxy کلاینت > external_proxy inbound > tcp_proxy سراسری > دامنه پنل
 */
function resolveAddr(client, ib) {
  const domain = G('panel_domain') || 'localhost';
  const proxy  = client.external_proxy || ib.external_proxy || G('tcp_proxy') || '';

  if (proxy && proxy.trim()) {
    const parts = proxy.trim().split(':');
    // فرمت: host:port
    if (parts.length >= 2) {
      const addr = parts.slice(0, -1).join(':').trim();
      const port = parseInt(parts[parts.length - 1]);
      if (addr && !isNaN(port) && port > 0) return { addr, port };
    }
    // فقط host بدون پورت
    const addr = parts[0].trim();
    if (addr) return { addr, port: ib.port };
  }

  return { addr: domain, port: ib.port };
}

/**
 * لینک VLESS
 */
function makeVlessLink(client, ib, addr, port) {
  const net = ib.network;
  const sec = ib.security || 'none';
  const pr  = ib.path    || '/';
  const ho  = ib.host    || '';
  const sn  = ib.service_name || 'grpc';
  const xm  = ib.xhttp_mode  || 'auto';
  const sni = ib.tls_sni || addr;
  const nm  = encodeURIComponent(`${client.name} | PersianPanel`);

  const q = new URLSearchParams();
  q.set('type', net);
  q.set('encryption', 'none');

  if (sec === 'tls') {
    q.set('security', 'tls');
    q.set('sni', sni);
    q.set('alpn', 'h2,http/1.1');
    q.set('fp', 'chrome');
  } else if (sec === 'reality') {
    q.set('security', 'reality');
    q.set('sni', sni);
    q.set('fp', 'chrome');
  } else {
    q.set('security', 'none');
  }

  switch (net) {
    case 'ws':
      q.set('path', pr || '/');
      if (ho) q.set('host', ho);
      break;
    case 'grpc':
      q.set('serviceName', sn);
      q.set('mode', 'gun');
      break;
    case 'httpupgrade':
      q.set('path', pr || '/');
      if (ho) q.set('host', ho);
      break;
    case 'xhttp':
      q.set('path', pr || '/');
      if (ho) q.set('host', ho);
      q.set('mode', xm);
      break;
    case 'tcp':
      if (ib.header_type === 'http') {
        q.set('headerType', 'http');
        q.set('path', pr || '/');
        if (ho) q.set('host', ho);
      }
      break;
  }

  return `vless://${client.uuid}@${addr}:${port}?${q.toString()}#${nm}`;
}

/**
 * لینک VMess
 */
function makeVmessLink(client, ib, addr, port) {
  const net = ib.network;
  const sec = ib.security || 'none';
  const pr  = ib.path    || '/';
  const ho  = ib.host    || '';
  const sn  = ib.service_name || 'grpc';
  const sni = ib.tls_sni || addr;

  const obj = {
    v   : '2',
    ps  : `${client.name} | PersianPanel`,
    add : addr,
    port: String(port),
    id  : client.uuid,
    aid : '0',
    scy : 'auto',
    net,
    type: 'none',
    host: ho,
    path: pr,
    tls : sec === 'tls' ? 'tls' : '',
    sni : sec === 'tls' ? sni   : '',
    alpn: sec === 'tls' ? 'h2,http/1.1' : '',
    fp  : sec === 'tls' ? 'chrome' : ''
  };

  if (net === 'grpc') {
    obj.path = sn;
    obj.type = 'gun';
    obj.host = '';
  } else if (net === 'tcp' && ib.header_type === 'http') {
    obj.type = 'http';
  }

  return `vmess://${Buffer.from(JSON.stringify(obj)).toString('base64')}`;
}

/**
 * لینک Trojan
 */
function makeTrojanLink(client, ib, addr, port) {
  const net = ib.network;
  const pr  = ib.path    || '/';
  const ho  = ib.host    || '';
  const sn  = ib.service_name || 'grpc';
  const sni = ib.tls_sni || addr;
  const nm  = encodeURIComponent(`${client.name} | PersianPanel`);

  const q = new URLSearchParams();
  q.set('type',     net);
  q.set('security', 'tls');
  q.set('sni',      sni);
  q.set('alpn',     'h2,http/1.1');
  q.set('fp',       'chrome');

  switch (net) {
    case 'ws':
      q.set('path', pr || '/');
      if (ho) q.set('host', ho);
      break;
    case 'grpc':
      q.set('serviceName', sn);
      q.set('mode', 'gun');
      break;
    case 'httpupgrade':
      q.set('path', pr || '/');
      if (ho) q.set('host', ho);
      break;
    case 'xhttp':
      q.set('path', pr || '/');
      if (ho) q.set('host', ho);
      break;
  }

  return `trojan://${client.uuid}@${addr}:${port}?${q.toString()}#${nm}`;
}

/**
 * تولید لینک اصلی
 */
function makeLink(client, ib) {
  const { addr, port } = resolveAddr(client, ib);

  switch (ib.protocol) {
    case 'vless'  : return makeVlessLink (client, ib, addr, port);
    case 'vmess'  : return makeVmessLink (client, ib, addr, port);
    case 'trojan' : return makeTrojanLink(client, ib, addr, port);
    default       : return '';
  }
}

/**
 * لیست کانفیگ‌های یک کلاینت
 */
function getConfigs(client, ib) {
  const link = makeLink(client, ib);
  if (!link) return [];
  return [{
    type   : ib.protocol,
    network: ib.network,
    name   : `${client.name} | ${ib.network.toUpperCase()}`,
    link
  }];
}

// ════════════════════════════════════════════
// EXPRESS SETUP
// ════════════════════════════════════════════
app.set('trust proxy', 1);
app.use(compression());
app.use(morgan('tiny'));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Session
app.use(session({
  secret           : process.env.SESSION_SECRET || uuidv4(),
  resave           : false,
  saveUninitialized: false,
  cookie: {
    secure  : process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge  : 7 * 24 * 60 * 60 * 1000
  }
}));

// ════════════════════════════════════════════
// RATE LIMITERS
// ════════════════════════════════════════════
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max     : 10,
  message : { success: false, message: 'تعداد تلاش بیش از حد — ۱۵ دقیقه صبر کنید' }
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max     : 120,
  message : { success: false, message: 'درخواست‌های زیاد' }
});

app.use('/api/', apiLimiter);

// ════════════════════════════════════════════
// MIDDLEWARES
// ════════════════════════════════════════════
const auth = (req, res, next) => {
  if (req.session?.uid) return next();
  res.status(401).json({ success: false, message: 'Unauthorized' });
};

// Basic Auth (اختیاری)
const BASIC_USER = process.env.BASIC_USER || '';
const BASIC_PASS = process.env.BASIC_PASS || '';

if (BASIC_USER && BASIC_PASS) {
  app.use((req, res, next) => {
    if (req.path.startsWith('/sub/') || req.path === '/health') return next();
    const header = req.headers['authorization'];
    if (!header?.startsWith('Basic ')) {
      res.setHeader('WWW-Authenticate', 'Basic realm="Persian Panel"');
      return res.status(401).send('Authentication required');
    }
    const decoded = Buffer.from(header.split(' ')[1], 'base64').toString();
    const colon   = decoded.indexOf(':');
    const user    = decoded.substring(0, colon);
    const pass    = decoded.substring(colon + 1);
    if (user === BASIC_USER && pass === BASIC_PASS) return next();
    res.setHeader('WWW-Authenticate', 'Basic realm="Persian Panel"');
    res.status(401).send('Invalid credentials');
  });
}

// IP Guard (اختیاری)
const ALLOWED_IPS = (process.env.ALLOWED_IPS || '').split(',').map(s => s.trim()).filter(Boolean);
if (ALLOWED_IPS.length) {
  app.use((req, res, next) => {
    if (req.path.startsWith('/sub/') || req.path === '/health') return next();
    const raw = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip  = raw.toString().split(',')[0].trim();
    if (ALLOWED_IPS.some(a => ip.includes(a))) return next();
    res.status(403).send('Forbidden');
  });
}

// ════════════════════════════════════════════
// HEALTH
// ════════════════════════════════════════════
app.get('/health', (_, res) =>
  res.json({ status: 'ok', uptime: process.uptime() })
);

// ════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════
app.get('/api/auth/me', (req, res) => {
  if (!req.session?.uid) return res.status(401).json({ success: false });
  res.json({
    success: true,
    user: { id: req.session.uid, username: req.session.uname, role: req.session.role }
  });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username?.trim() || !password)
      return res.status(400).json({ success: false, message: 'اطلاعات ناقص' });

    const user = db.prepare('SELECT * FROM panel_users WHERE username=?').get(username.trim());
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ success: false, message: 'نام کاربری یا رمز اشتباه' });

    req.session.uid   = user.id;
    req.session.uname = user.username;
    req.session.role  = user.role;
    res.json({ success: true, user: { id: user.id, username: user.username } });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ success: false, message: 'خطای سرور' });
  }
});

app.post('/api/auth/logout', (req, res) =>
  req.session.destroy(() => res.json({ success: true }))
);

app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword, newUsername } = req.body;
    const user = db.prepare('SELECT * FROM panel_users WHERE id=?').get(req.session.uid);
    if (!user || !(await bcrypt.compare(currentPassword, user.password)))
      return res.status(401).json({ success: false, message: 'رمز فعلی اشتباه' });

    const upd = [], prm = [];
    if (newPassword?.length >= 4) {
      upd.push('password=?');
      prm.push(await bcrypt.hash(newPassword, 12));
    }
    if (newUsername?.trim().length >= 2) {
      upd.push('username=?');
      prm.push(newUsername.trim());
    }
    if (!upd.length) return res.json({ success: false, message: 'چیزی تغییر نکرد' });

    prm.push(req.session.uid);
    db.prepare(`UPDATE panel_users SET ${upd.join(',')} WHERE id=?`).run(...prm);
    if (newUsername) req.session.uname = newUsername.trim();
    res.json({ success: true, message: 'تغییر یافت ✅' });
  } catch (e) {
    res.status(500).json({ success: false, message: 'خطای سرور' });
  }
});

// ════════════════════════════════════════════
// SETTINGS ROUTES
// ════════════════════════════════════════════
app.get('/api/settings', auth, (_, res) => {
  const keys = ['panel_name', 'panel_domain', 'tcp_proxy', 'theme'];
  const data = {};
  keys.forEach(k => data[k] = G(k));
  res.json({ success: true, data });
});

app.post('/api/settings', auth, (req, res) => {
  const { panel_domain, tcp_proxy, theme, panel_name } = req.body;
  if (panel_domain !== undefined) S('panel_domain', panel_domain.trim());
  if (tcp_proxy    !== undefined) S('tcp_proxy',    tcp_proxy.trim());
  if (theme        !== undefined) S('theme',         theme);
  if (panel_name   !== undefined) S('panel_name',    panel_name.trim());
  res.json({ success: true, message: 'ذخیره شد ✅' });
});

app.get('/api/server-info', auth, (req, res) => {
  const domain = process.env.RAILWAY_PUBLIC_DOMAIN || req.get('host') || `localhost:${PORT}`;
  res.json({
    success: true,
    data: {
      domain,
      uptime    : process.uptime(),
      memory    : process.memoryUsage(),
      node      : process.version,
      env       : process.env.RAILWAY_ENVIRONMENT || 'local',
      panel_path: PANEL_PATH
    }
  });
});

// ════════════════════════════════════════════
// INBOUNDS ROUTES
// ════════════════════════════════════════════
app.get('/api/inbounds', auth, (_, res) => {
  try {
    res.json({
      success: true,
      data: db.prepare(`
        SELECT i.*, COUNT(c.id) client_count
        FROM inbounds i
        LEFT JOIN clients c ON i.id = c.inbound_id AND c.enabled = 1
        GROUP BY i.id
        ORDER BY i.created_at DESC
      `).all()
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/inbounds', auth, (req, res) => {
  try {
    const {
      protocol, port, network, security, remark,
      path: p, host, serviceName, headerType,
      xhttpMode, tlsSni, externalProxy
    } = req.body;

    if (!protocol || !port || !network)
      return res.status(400).json({ success: false, message: 'پروتکل، پورت و شبکه الزامی است' });

    const portN = parseInt(port);
    if (isNaN(portN) || portN < 1 || portN > 65535)
      return res.status(400).json({ success: false, message: 'پورت نامعتبر است' });

    if (db.prepare('SELECT id FROM inbounds WHERE port=?').get(portN))
      return res.status(400).json({ success: false, message: `پورت ${portN} قبلاً استفاده شده` });

    const tag = `ib_${Date.now()}`;

    db.prepare(`
      INSERT INTO inbounds
        (tag, protocol, port, network, security, external_proxy, path, host,
         service_name, header_type, xhttp_mode, tls_sni, stream_settings, remark)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(
      tag, protocol, portN, network,
      security      || 'none',
      externalProxy || '',
      p             || '/',
      host          || '',
      serviceName   || 'grpc',
      headerType    || 'none',
      xhttpMode     || 'auto',
      tlsSni        || '',
      '{}',
      remark        || `${protocol.toUpperCase()}-${network.toUpperCase()}-${portN}`
    );

    res.json({
      success: true,
      message: 'Inbound ایجاد شد ✅',
      data   : db.prepare('SELECT * FROM inbounds WHERE tag=?').get(tag)
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.put('/api/inbounds/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(id);
    if (!ib) return res.status(404).json({ success: false, message: 'یافت نشد' });

    const {
      protocol, port, network, security, remark, enabled,
      path: p, host, serviceName, headerType, xhttpMode, tlsSni, externalProxy
    } = req.body;

    db.prepare(`
      UPDATE inbounds SET
        protocol=?, port=?, network=?, security=?, external_proxy=?,
        path=?, host=?, service_name=?, header_type=?, xhttp_mode=?,
        tls_sni=?, remark=?, enabled=?
      WHERE id=?
    `).run(
      protocol      ?? ib.protocol,
      port          ? parseInt(port) : ib.port,
      network       ?? ib.network,
      security      ?? ib.security,
      externalProxy ?? ib.external_proxy,
      p             ?? ib.path,
      host          ?? ib.host,
      serviceName   ?? ib.service_name,
      headerType    ?? ib.header_type,
      xhttpMode     ?? ib.xhttp_mode,
      tlsSni        ?? ib.tls_sni,
      remark        ?? ib.remark,
      enabled !== undefined ? (enabled ? 1 : 0) : ib.enabled,
      id
    );

    res.json({
      success: true,
      message: 'آپدیت شد ✅',
      data   : db.prepare('SELECT * FROM inbounds WHERE id=?').get(id)
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.delete('/api/inbounds/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!db.prepare('SELECT id FROM inbounds WHERE id=?').get(id))
      return res.status(404).json({ success: false, message: 'یافت نشد' });
    db.prepare('DELETE FROM inbounds WHERE id=?').run(id);
    res.json({ success: true, message: 'حذف شد' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ════════════════════════════════════════════
// CLIENTS ROUTES
// ════════════════════════════════════════════
app.get('/api/clients/stats/overview', auth, (_, res) => {
  try {
    const now = new Date().toISOString();
    res.json({
      success: true,
      data: {
        total         : db.prepare('SELECT COUNT(*) c FROM clients').get().c,
        active        : db.prepare('SELECT COUNT(*) c FROM clients WHERE enabled=1 AND (expire_date IS NULL OR expire_date>?)').get(now).c,
        expired       : db.prepare('SELECT COUNT(*) c FROM clients WHERE expire_date IS NOT NULL AND expire_date<=?').get(now).c,
        total_inbounds: db.prepare('SELECT COUNT(*) c FROM inbounds').get().c,
        total_traffic : db.prepare('SELECT COALESCE(SUM(traffic_used),0) t FROM clients').get().t
      }
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/api/clients', auth, (req, res) => {
  try {
    const { inbound_id, search } = req.query;
    let q = `
      SELECT
        c.*,
        i.protocol   AS i_protocol,
        i.network    AS i_network,
        i.port       AS i_port,
        i.remark     AS inbound_remark,
        i.security   AS i_security,
        i.path       AS i_path,
        i.host       AS i_host,
        i.service_name,
        i.header_type,
        i.xhttp_mode,
        i.tls_sni,
        i.external_proxy AS i_proxy
      FROM clients c
      JOIN inbounds i ON c.inbound_id = i.id
      WHERE 1=1
    `;
    const params = [];
    if (inbound_id) { q += ' AND c.inbound_id=?'; params.push(parseInt(inbound_id)); }
    if (search)     { q += ' AND (c.name LIKE ? OR c.email LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    q += ' ORDER BY c.created_at DESC LIMIT 500';

    const now = new Date();
    const rows = db.prepare(q).all(...params).map(c => ({
      ...c,
      is_expired: c.expire_date ? new Date(c.expire_date) < now : false
    }));

    res.json({ success: true, data: rows });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/clients', auth, (req, res) => {
  try {
    const {
      inbound_id, name, email, traffic_limit_gb,
      expire_days, max_connections, external_proxy, custom_uuid
    } = req.body;

    if (!inbound_id || !name?.trim())
      return res.status(400).json({ success: false, message: 'Inbound و نام الزامی است' });

    const ib = db.prepare('SELECT * FROM inbounds WHERE id=? AND enabled=1').get(parseInt(inbound_id));
    if (!ib) return res.status(404).json({ success: false, message: 'Inbound یافت نشد' });

    // UUID
    const uuidRx = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const uuid   = (custom_uuid?.trim() && uuidRx.test(custom_uuid.trim()))
      ? custom_uuid.trim()
      : uuidv4();

    // چک تکراری بودن UUID
    if (db.prepare('SELECT id FROM clients WHERE uuid=?').get(uuid))
      return res.status(400).json({ success: false, message: 'این UUID قبلاً استفاده شده' });

    const sub      = uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');
    const tBytes   = traffic_limit_gb ? Math.floor(parseFloat(traffic_limit_gb) * 1073741824) : 0;
    const maxConn  = parseInt(max_connections) || 0;

    let expDate = null;
    if (expire_days && parseInt(expire_days) > 0) {
      const d = new Date();
      d.setDate(d.getDate() + parseInt(expire_days));
      expDate = d.toISOString();
    }

    const mail = email?.trim()
      || `${name.trim().toLowerCase().replace(/[^a-z0-9]/g, '.')}.${Date.now()}@persian.panel`;

    const r = db.prepare(`
      INSERT INTO clients
        (inbound_id, name, uuid, email, traffic_limit, traffic_used,
         expire_date, max_connections, external_proxy, enabled, sub_token)
      VALUES (?,?,?,?,?,0,?,?,?,1,?)
    `).run(
      parseInt(inbound_id), name.trim(), uuid, mail,
      tBytes, expDate, maxConn,
      external_proxy?.trim() || '', sub
    );

    res.json({
      success: true,
      message: 'کاربر ایجاد شد ✅',
      data   : db.prepare('SELECT * FROM clients WHERE id=?').get(r.lastInsertRowid)
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.put('/api/clients/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const c  = db.prepare('SELECT * FROM clients WHERE id=?').get(id);
    if (!c) return res.status(404).json({ success: false, message: 'یافت نشد' });

    const {
      name, email, traffic_limit_gb, expire_days,
      max_connections, enabled, external_proxy, reset_traffic
    } = req.body;

    const tBytes = traffic_limit_gb !== undefined
      ? Math.floor(parseFloat(traffic_limit_gb) * 1073741824)
      : c.traffic_limit;

    let expDate = c.expire_date;
    if (expire_days !== undefined) {
      if (!expire_days || parseInt(expire_days) <= 0) {
        expDate = null;
      } else {
        const d = new Date();
        d.setDate(d.getDate() + parseInt(expire_days));
        expDate = d.toISOString();
      }
    }

    db.prepare(`
      UPDATE clients SET
        name=?, email=?, traffic_limit=?, traffic_used=?,
        expire_date=?, max_connections=?, enabled=?, external_proxy=?
      WHERE id=?
    `).run(
      name           ?? c.name,
      email          ?? c.email,
      tBytes,
      reset_traffic  ? 0 : c.traffic_used,
      expDate,
      max_connections !== undefined ? parseInt(max_connections) : c.max_connections,
      enabled !== undefined ? (enabled ? 1 : 0) : c.enabled,
      external_proxy !== undefined ? external_proxy.trim() : c.external_proxy,
      id
    );

    res.json({
      success: true,
      message: 'آپدیت شد ✅',
      data   : db.prepare('SELECT * FROM clients WHERE id=?').get(id)
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.delete('/api/clients/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!db.prepare('SELECT id FROM clients WHERE id=?').get(id))
      return res.status(404).json({ success: false, message: 'یافت نشد' });
    db.prepare('DELETE FROM clients WHERE id=?').run(id);
    res.json({ success: true, message: 'حذف شد' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/clients/:id/reset-traffic', auth, (req, res) => {
  try {
    db.prepare('UPDATE clients SET traffic_used=0 WHERE id=?').run(parseInt(req.params.id));
    res.json({ success: true, message: 'ترافیک ری‌ست شد' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/api/clients/:id/config', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const c  = db.prepare('SELECT * FROM clients WHERE id=?').get(id);
    if (!c) return res.status(404).json({ success: false, message: 'کاربر یافت نشد' });

    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(c.inbound_id);
    if (!ib) return res.status(404).json({ success: false, message: 'Inbound یافت نشد' });

    const configs = getConfigs(c, ib);
    const { addr, port } = resolveAddr(c, ib);

    res.json({
      success: true,
      data: configs,
      meta: { addr, port, protocol: ib.protocol, network: ib.network }
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ════════════════════════════════════════════
// SUBSCRIPTION
// ════════════════════════════════════════════

// اسکیپ HTML
function esc(s) {
  return String(s || '')
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;')
    .replace(/`/g,  '&#x60;');
}

// ساب‌اسکریپشن متنی (برای v2rayNG/Hiddify/...)
app.get('/sub/:token', (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(req.params.token);
    if (!c || !c.enabled)                                          return res.status(404).send('Not Found');
    if (c.expire_date && new Date(c.expire_date) < new Date())     return res.status(403).send('Expired');
    if (c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit) return res.status(403).send('Traffic Exceeded');

    const ib = db.prepare('SELECT * FROM inbounds WHERE id=? AND enabled=1').get(c.inbound_id);
    if (!ib) return res.status(404).send('Not Found');

    const link = makeLink(c, ib);
    if (!link) return res.status(500).send('Config Error');

    const exp = c.expire_date ? Math.floor(new Date(c.expire_date).getTime() / 1000) : 0;

    res.setHeader('Content-Type',             'text/plain; charset=utf-8');
    res.setHeader('Subscription-Userinfo',    `upload=0; download=${c.traffic_used}; total=${c.traffic_limit || 0}; expire=${exp}`);
    res.setHeader('Profile-Title',            Buffer.from(`PersianPanel-${c.name}`).toString('base64'));
    res.setHeader('Profile-Update-Interval',  '12');
    res.setHeader('Support-Url',              `${req.protocol}://${req.get('host')}/sub/html/${c.sub_token}`);
    res.send(Buffer.from(link).toString('base64'));
  } catch (e) {
    console.error('[sub]', e.message);
    res.status(500).send('Error');
  }
});

// صفحه HTML اشتراک کاربر
app.get('/sub/html/:token', (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(req.params.token);
    if (!c) return res.status(404).send('<h2>404 Not Found</h2>');

    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(c.inbound_id);
    if (!ib) return res.status(404).send('<h2>Not Found</h2>');

    const now    = new Date();
    const isExp  = c.expire_date && new Date(c.expire_date) < now;
    const isTraf = c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit;
    const ok     = !isExp && !isTraf && c.enabled;

    const configs = getConfigs(c, ib);
    const subUrl  = `${req.protocol}://${req.get('host')}/sub/${c.sub_token}`;
    const tU      = (c.traffic_used  / 1073741824).toFixed(2);
    const tT      = c.traffic_limit > 0 ? (c.traffic_limit / 1073741824).toFixed(0) : '∞';
    const pct     = c.traffic_limit > 0 ? Math.min(100, (c.traffic_used / c.traffic_limit) * 100) : 0;
    const dL      = c.expire_date
      ? Math.max(0, Math.ceil((new Date(c.expire_date) - now) / 86400000))
      : '∞';

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>اشتراک ${esc(c.name)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:#0f0f1a;color:#e2e8f0;min-height:100vh;padding:20px}
.wrap{max-width:600px;margin:0 auto}
.card{background:#1e1e3a;border:1px solid #2d2d5a;border-radius:16px;padding:24px;margin-bottom:16px}
h1{font-size:20px;margin-bottom:4px}
.sub{color:#94a3b8;font-size:13px}
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:13px;font-weight:600}
.green{background:rgba(16,185,129,.2);color:#10b981}
.red{background:rgba(239,68,68,.2);color:#ef4444}
.yellow{background:rgba(245,158,11,.2);color:#f59e0b}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin:16px 0}
.stat{background:#16213e;border-radius:10px;padding:14px;text-align:center}
.stat-v{font-size:22px;font-weight:700}
.stat-l{font-size:12px;color:#64748b;margin-top:4px}
.progress{background:#16213e;border-radius:4px;height:8px;overflow:hidden;margin:8px 0}
.progress-fill{height:100%;border-radius:4px;transition:.5s}
.box{background:#16213e;border-radius:8px;padding:12px;font-family:monospace;font-size:11px;word-break:break-all;color:#94a3b8;margin:8px 0;position:relative}
.btn{display:inline-block;padding:10px 20px;background:#7c3aed;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;text-decoration:none;margin:4px 0}
.btn-g{background:#10b981}
.warn{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);border-radius:10px;padding:12px;margin:12px 0;color:#f87171;font-size:13px}
label{font-size:14px;color:#94a3b8}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>🔮 ${esc(c.name)}</h1>
    <div class="sub">${esc(c.email)}</div>
    <br/>
    <span class="badge ${ok?'green':isExp?'red':'yellow'}">
      ${ok ? '✅ فعال' : isExp ? '⏰ منقضی' : isTraf ? '📦 ترافیک تمام' : '🚫 غیرفعال'}
    </span>
    ${!ok ? `<div class="warn">⚠️ ${isExp?'اشتراک منقضی — لطفاً تمدید کنید':isTraf?'ترافیک تمام شده':'اشتراک غیرفعال است'}</div>` : ''}
    <div class="stats">
      <div class="stat"><div class="stat-v">${tU}</div><div class="stat-l">GB مصرف</div></div>
      <div class="stat"><div class="stat-v">${tT}</div><div class="stat-l">GB کل</div></div>
      <div class="stat"><div class="stat-v">${dL}</div><div class="stat-l">روز مانده</div></div>
      <div class="stat"><div class="stat-v">${c.max_connections || '∞'}</div><div class="stat-l">حداکثر اتصال</div></div>
    </div>
    ${c.traffic_limit > 0 ? `
    <label>ترافیک — ${pct.toFixed(1)}%</label>
    <div class="progress">
      <div class="progress-fill" style="width:${pct}%;background:${pct>90?'#ef4444':pct>70?'#f59e0b':'#10b981'}"></div>
    </div>` : ''}
  </div>

  <div class="card">
    <h2 style="margin-bottom:12px;font-size:16px">🔗 لینک ساب‌اسکریپشن</h2>
    <div class="box">${esc(subUrl)}</div>
    <button class="btn" onclick="copy('${esc(subUrl)}',this)">📋 کپی لینک ساب</button>
  </div>

  ${configs.map((cfg, i) => `
  <div class="card">
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <span class="badge" style="background:rgba(124,58,237,.2);color:#8b5cf6">${esc(cfg.type.toUpperCase())}</span>
      <span class="badge" style="background:rgba(59,130,246,.2);color:#60a5fa">${esc(cfg.network.toUpperCase())}</span>
    </div>
    <div class="box">${esc(cfg.link.substring(0,100))}...</div>
    <button class="btn" onclick="copy('${cfg.link.replace(/'/g,"\\'")}',this)">📋 کپی کانفیگ</button>
    <button class="btn" style="background:#1d4ed8;margin-right:8px" onclick="showQR('qr${i}','${encodeURIComponent(cfg.link)}')">📱 QR کد</button>
    <div id="qr${i}" style="display:none;margin-top:12px;background:#fff;border-radius:8px;padding:12px;text-align:center"></div>
  </div>`).join('')}
</div>

<script>
function copy(text, btn) {
  navigator.clipboard.writeText(text).catch(()=>{
    const t=document.createElement('textarea');
    t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove();
  });
  const old=btn.textContent;
  btn.textContent='✅ کپی شد!';
  setTimeout(()=>btn.textContent=old,1500);
}
function showQR(id, link) {
  const el=document.getElementById(id);
  if(el.style.display==='none'){
    el.innerHTML='<img src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&data='+link+'" style="border-radius:8px"/>';
    el.style.display='block';
  } else el.style.display='none';
}
</script>
</body>
</html>`);
  } catch (e) {
    console.error('[sub/html]', e.message);
    res.status(500).send('<h2>Error</h2>');
  }
});

// ════════════════════════════════════════════
// STATIC + SPA (با path مخفی)
// ════════════════════════════════════════════
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  // APIها و sub لینک‌ها
  if (req.path.startsWith('/api/') || req.path.startsWith('/sub/'))
    return res.status(404).json({ success: false, message: 'Not Found' });

  // فقط آدرس پنل → SPA
  if (req.path === PANEL_PATH || req.path.startsWith(PANEL_PATH + '/'))
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));

  // ریشه → ریدایرکت به پنل
  if (req.path === '/')
    return res.redirect(301, PANEL_PATH);

  res.status(404).send('Not Found');
});

// ════════════════════════════════════════════
// CRON — هر ساعت
// ════════════════════════════════════════════
cron.schedule('0 * * * *', () => {
  try {
    const now = new Date().toISOString();
    const r1  = db.prepare(`
      UPDATE clients SET enabled=0
      WHERE expire_date IS NOT NULL AND expire_date < ? AND enabled=1
    `).run(now);
    const r2 = db.prepare(`
      UPDATE clients SET enabled=0
      WHERE traffic_limit > 0 AND traffic_used >= traffic_limit AND enabled=1
    `).run();
    if (r1.changes || r2.changes)
      console.log(`[cron] disabled: ${r1.changes} expired, ${r2.changes} over-traffic`);
  } catch (e) {
    console.error('[cron]', e.message);
  }
});

// ════════════════════════════════════════════
// START
// ════════════════════════════════════════════
initDB();
app.listen(PORT, '0.0.0.0', () => {
  const domain = process.env.RAILWAY_PUBLIC_DOMAIN || `localhost:${PORT}`;
  console.log(`
🔮 Persian Panel
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 https://${domain}${PANEL_PATH}
👤 admin / admin
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  `);
});
