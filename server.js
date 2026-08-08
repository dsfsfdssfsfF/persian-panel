'use strict';

const express     = require('express');
const session     = require('express-session');
const compression = require('compression');
const morgan      = require('morgan');
const path        = require('path');
const cron        = require('node-cron');
const Database    = require('better-sqlite3');
const bcrypt      = require('bcryptjs');
const rateLimit   = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { v4: uuidv4 } = require('uuid');
const fs          = require('fs');
const { execSync } = require('child_process');

const app  = express();
const PORT = parseInt(process.env.PORT) || 3000;
const PANEL_PATH = '/' + (process.env.PANEL_PATH || 'panel')
  .replace(/^\//, '').replace(/\/$/, '');

// ══════════════════════════════════
// DOMAIN
// ══════════════════════════════════
function getDomain(req) {
  return process.env.RAILWAY_PUBLIC_DOMAIN
    || process.env.CF_DOMAIN
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
    CREATE TABLE IF NOT EXISTS clients (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      name            TEXT NOT NULL,
      uuid            TEXT UNIQUE NOT NULL,
      email           TEXT DEFAULT '',
      traffic_limit   INTEGER DEFAULT 0,
      traffic_used    INTEGER DEFAULT 0,
      expire_date     TEXT DEFAULT NULL,
      max_connections INTEGER DEFAULT 0,
      enabled         INTEGER DEFAULT 1,
      sub_token       TEXT UNIQUE NOT NULL,
      note            TEXT DEFAULT '',
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_clients_sub     ON clients(sub_token);
    CREATE INDEX IF NOT EXISTS idx_clients_enabled ON clients(enabled);
    CREATE INDEX IF NOT EXISTS idx_clients_uuid    ON clients(uuid);
  `);

  if (!db.prepare('SELECT id FROM panel_users WHERE username=?').get('admin')) {
    db.prepare('INSERT INTO panel_users (username,password,role) VALUES (?,?,?)')
      .run('admin', bcrypt.hashSync('admin', 12), 'superadmin');
    console.log('✅ Admin created: admin / admin');
  }

  const defaults = {
    panel_name : 'Persian Panel',
    ws_path    : '/ws',
    theme      : 'dark'
  };
  for (const [k, v] of Object.entries(defaults)) {
    if (!db.prepare('SELECT key FROM settings WHERE key=?').get(k))
      db.prepare('INSERT INTO settings (key,value) VALUES (?,?)').run(k, v);
  }

  if (process.env.RAILWAY_PUBLIC_DOMAIN) {
    if (!db.prepare('SELECT key FROM settings WHERE key=?').get('panel_domain'))
      db.prepare('INSERT INTO settings (key,value) VALUES (?,?)').run('panel_domain', process.env.RAILWAY_PUBLIC_DOMAIN);
  }

  console.log('✅ DB ready:', dbPath);
  console.log('🔮 Panel:', PANEL_PATH);
}

const G = k => { const r = db.prepare('SELECT value FROM settings WHERE key=?').get(k); return r ? r.value : ''; };
const S = (k, v) => db.prepare('INSERT OR REPLACE INTO settings (key,value,updated_at) VALUES (?,?,CURRENT_TIMESTAMP)').run(k, String(v));

// ══════════════════════════════════
// XRAY SYNC
// ══════════════════════════════════
function syncXray() {
  try {
    const clients = db.prepare('SELECT * FROM clients WHERE enabled=1').all();
    const wsPath  = G('ws_path') || '/ws';

    const config = {
      log: {
        loglevel: 'info',
        access  : '/var/log/supervisor/xray-access.log',
        error   : '/var/log/supervisor/xray-error.log'
      },
      inbounds: [{
        port    : 10086,
        listen  : '127.0.0.1',
        protocol: 'vless',
        settings: {
          clients   : clients.map(c => ({ id: c.uuid, email: c.email || c.name, flow: '' })),
          decryption: 'none'
        },
        streamSettings: {
          network   : 'ws',
          security  : 'none',
          wsSettings: { path: wsPath, headers: {} }
        },
        sniffing: {
          enabled    : true,
          destOverride: ['http', 'tls', 'quic']
        }
      }],
      outbounds: [
        { protocol: 'freedom',   tag: 'direct', settings: { domainStrategy: 'UseIPv4' } },
        { protocol: 'blackhole', tag: 'block',  settings: {} }
      ],
      routing: {
        domainStrategy: 'IPIfNonMatch',
        rules: [
          { type: 'field', ip: ['geoip:private'], outboundTag: 'block' }
        ]
      },
      policy: {
        levels: {
          '0': {
            handshake   : 4,
            connIdle    : 300,
            uplinkOnly  : 2,
            downlinkOnly: 5,
            bufferSize  : 512
          }
        },
        system: {
          statsInboundUplink  : false,
          statsInboundDownlink: false
        }
      }
    };

    fs.writeFileSync('/etc/xray/config.json', JSON.stringify(config, null, 2));

    try { execSync('supervisorctl restart xray 2>/dev/null'); } catch (_) {}

    console.log(`[xray] synced — ${clients.length} clients, path: ${wsPath}`);
  } catch (e) {
    console.error('[xray] sync error:', e.message);
  }
}

// ══════════════════════════════════
// LINK GENERATOR
// ══════════════════════════════════
function makeLink(client, req) {
  const domain = getDomain(req);
  const port   = '443';
  const wsPath = G('ws_path') || '/ws';
  const name   = encodeURIComponent(`${client.name} | PersianPanel`);

  const q = new URLSearchParams();
  q.set('type',       'ws');
  q.set('security',   'tls');
  q.set('path',       wsPath);
  q.set('host',       domain);
  q.set('sni',        domain);
  q.set('fp',         'chrome');
  q.set('alpn',       'h2,http/1.1');
  q.set('encryption', 'none');

  return `vless://${client.uuid}@${domain}:${port}?${q.toString()}#${name}`;
}

// ══════════════════════════════════
// EXPRESS SETUP
// ══════════════════════════════════
app.set('trust proxy', 1);
app.use(compression());
app.use(morgan('tiny'));

// ✅ WebSocket Proxy به Xray
const wsProxy = createProxyMiddleware({
  target      : 'http://127.0.0.1:10086',
  changeOrigin: true,
  ws          : true,
  logLevel    : 'warn',
  on: {
    error: (err, req, res) => {
      console.error('[proxy error]', err.message);
      if (res?.writeHead) { res.writeHead(502); res.end('Bad Gateway'); }
    },
    proxyReqWs: (proxyReq, req) => {
      console.log('[ws] new connection from:', req.socket?.remoteAddress || 'unknown');
    }
  }
});

// ✅ اول WS proxy رو بذار
app.use('/ws', wsProxy);

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

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

// Rate limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max     : 10,
  message : { success: false, message: 'تلاش بیش از حد — ۱۵ دقیقه صبر کنید' }
});
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 200 });
app.use('/api/', apiLimiter);

const auth = (req, res, next) => {
  if (req.session?.uid) return next();
  res.status(401).json({ success: false, message: 'Unauthorized' });
};

// ══════════════════════════════════
// HEALTH
// ══════════════════════════════════
app.get('/health', (_, res) =>
  res.json({ status: 'ok', uptime: process.uptime() })
);

// ══════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════
app.get('/api/auth/me', (req, res) => {
  if (!req.session?.uid) return res.status(401).json({ success: false });
  res.json({ success: true, user: { id: req.session.uid, username: req.session.uname, role: req.session.role } });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username?.trim() || !password)
      return res.status(400).json({ success: false, message: 'اطلاعات ناقص است' });
    const user = db.prepare('SELECT * FROM panel_users WHERE username=?').get(username.trim());
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ success: false, message: 'نام کاربری یا رمز اشتباه است' });
    req.session.uid   = user.id;
    req.session.uname = user.username;
    req.session.role  = user.role;
    res.json({ success: true, user: { id: user.id, username: user.username } });
  } catch (e) {
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
      return res.status(401).json({ success: false, message: 'رمز فعلی اشتباه است' });
    const upd = [], prm = [];
    if (newPassword?.length >= 4)        { upd.push('password=?'); prm.push(await bcrypt.hash(newPassword, 12)); }
    if (newUsername?.trim().length >= 2) { upd.push('username=?'); prm.push(newUsername.trim()); }
    if (!upd.length) return res.json({ success: false, message: 'چیزی تغییر نکرد' });
    prm.push(req.session.uid);
    db.prepare(`UPDATE panel_users SET ${upd.join(',')} WHERE id=?`).run(...prm);
    if (newUsername) req.session.uname = newUsername.trim();
    res.json({ success: true, message: 'با موفقیت تغییر یافت ✅' });
  } catch (e) {
    res.status(500).json({ success: false, message: 'خطای سرور' });
  }
});

// ══════════════════════════════════
// SETTINGS ROUTES
// ══════════════════════════════════
app.get('/api/settings', auth, (_, res) => {
  res.json({
    success: true,
    data: {
      panel_name: G('panel_name') || 'Persian Panel',
      ws_path   : G('ws_path')    || '/ws',
      theme     : G('theme')      || 'dark'
    }
  });
});

app.post('/api/settings', auth, (req, res) => {
  const { panel_name, ws_path, theme } = req.body;
  if (panel_name !== undefined) S('panel_name', panel_name.trim());
  if (ws_path    !== undefined) S('ws_path',    ws_path.trim() || '/ws');
  if (theme      !== undefined) S('theme',       theme);
  syncXray();
  res.json({ success: true, message: 'ذخیره شد ✅' });
});

app.get('/api/server-info', auth, (req, res) => {
  const domain = getDomain(req);
  res.json({
    success: true,
    data: {
      domain,
      port      : '443',
      ws_path   : G('ws_path') || '/ws',
      uptime    : process.uptime(),
      memory    : process.memoryUsage(),
      node      : process.version,
      env       : process.env.RAILWAY_ENVIRONMENT || 'local',
      panel_path: PANEL_PATH
    }
  });
});

// ══════════════════════════════════
// STATS
// ══════════════════════════════════
app.get('/api/stats', auth, (_, res) => {
  try {
    const now = new Date().toISOString();
    res.json({
      success: true,
      data: {
        total        : db.prepare('SELECT COUNT(*) c FROM clients').get().c,
        active       : db.prepare('SELECT COUNT(*) c FROM clients WHERE enabled=1 AND (expire_date IS NULL OR expire_date>?)').get(now).c,
        expired      : db.prepare('SELECT COUNT(*) c FROM clients WHERE expire_date IS NOT NULL AND expire_date<=?').get(now).c,
        disabled     : db.prepare('SELECT COUNT(*) c FROM clients WHERE enabled=0').get().c,
        total_traffic: db.prepare('SELECT COALESCE(SUM(traffic_used),0) t FROM clients').get().t
      }
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ══════════════════════════════════
// CLIENTS ROUTES
// ══════════════════════════════════
app.get('/api/clients', auth, (req, res) => {
  try {
    const { search } = req.query;
    let q = 'SELECT * FROM clients WHERE 1=1';
    const params = [];
    if (search) { q += ' AND (name LIKE ? OR email LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    q += ' ORDER BY created_at DESC LIMIT 500';
    const now = new Date();
    res.json({
      success: true,
      data: db.prepare(q).all(...params).map(c => ({
        ...c,
        is_expired  : c.expire_date ? new Date(c.expire_date) < now : false,
        over_traffic: c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit
      }))
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/clients', auth, (req, res) => {
  try {
    const { name, email, traffic_limit_gb, expire_days, max_connections, note, custom_uuid } = req.body;
    if (!name?.trim())
      return res.status(400).json({ success: false, message: 'نام الزامی است' });

    const uuidRx = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const uuid   = (custom_uuid?.trim() && uuidRx.test(custom_uuid.trim()))
      ? custom_uuid.trim() : uuidv4();

    if (db.prepare('SELECT id FROM clients WHERE uuid=?').get(uuid))
      return res.status(400).json({ success: false, message: 'این UUID قبلاً استفاده شده' });

    const sub    = uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');
    const tBytes = traffic_limit_gb ? Math.floor(parseFloat(traffic_limit_gb) * 1073741824) : 0;
    let expDate  = null;
    if (expire_days && parseInt(expire_days) > 0) {
      const d = new Date();
      d.setDate(d.getDate() + parseInt(expire_days));
      expDate = d.toISOString();
    }
    const mail = email?.trim()
      || `${name.trim().toLowerCase().replace(/[^a-z0-9]/g, '.')}.${Date.now()}@persian.panel`;

    const r = db.prepare(`
      INSERT INTO clients
        (name, uuid, email, traffic_limit, traffic_used, expire_date, max_connections, enabled, sub_token, note)
      VALUES (?,?,?,?,0,?,?,1,?,?)
    `).run(name.trim(), uuid, mail, tBytes, expDate, parseInt(max_connections) || 0, sub, note?.trim() || '');

    syncXray();
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

    const { name, email, traffic_limit_gb, expire_days, max_connections, enabled, reset_traffic, note } = req.body;
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
        expire_date=?, max_connections=?, enabled=?, note=?
      WHERE id=?
    `).run(
      name  ?? c.name,
      email ?? c.email,
      tBytes,
      reset_traffic ? 0 : c.traffic_used,
      expDate,
      max_connections !== undefined ? parseInt(max_connections) : c.max_connections,
      enabled !== undefined ? (enabled ? 1 : 0) : c.enabled,
      note !== undefined ? note.trim() : c.note,
      id
    );

    syncXray();
    res.json({ success: true, message: 'آپدیت شد ✅', data: db.prepare('SELECT * FROM clients WHERE id=?').get(id) });
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
    syncXray();
    res.json({ success: true, message: 'کاربر حذف شد' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/clients/:id/reset-traffic', auth, (req, res) => {
  try {
    db.prepare('UPDATE clients SET traffic_used=0 WHERE id=?').run(parseInt(req.params.id));
    res.json({ success: true, message: 'ترافیک ری‌ست شد ✅' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/api/clients/:id/config', auth, (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE id=?').get(parseInt(req.params.id));
    if (!c) return res.status(404).json({ success: false, message: 'یافت نشد' });
    const link   = makeLink(c, req);
    const subUrl = `${req.protocol}://${req.get('host')}/sub/${c.sub_token}`;
    const domain = getDomain(req);
    res.json({ success: true, data: { link, subUrl, uuid: c.uuid, domain, port: '443' } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ══════════════════════════════════
// SUBSCRIPTION
// ══════════════════════════════════
const esc = s => String(s || '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;')
  .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

app.get('/sub/:token', (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(req.params.token);
    if (!c || !c.enabled)                                          return res.status(404).send('Not Found');
    if (c.expire_date && new Date(c.expire_date) < new Date())     return res.status(403).send('Expired');
    if (c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit) return res.status(403).send('Traffic Exceeded');

    const link = makeLink(c, req);
    const exp  = c.expire_date ? Math.floor(new Date(c.expire_date).getTime() / 1000) : 0;

    res.setHeader('Content-Type',            'text/plain; charset=utf-8');
    res.setHeader('Subscription-Userinfo',   `upload=0; download=${c.traffic_used}; total=${c.traffic_limit || 0}; expire=${exp}`);
    res.setHeader('Profile-Title',           Buffer.from(`PersianPanel-${c.name}`).toString('base64'));
    res.setHeader('Profile-Update-Interval', '12');
    res.setHeader('Support-Url',             `${req.protocol}://${req.get('host')}/sub/info/${c.sub_token}`);
    res.send(Buffer.from(link).toString('base64'));
  } catch (e) {
    console.error('[sub]', e.message);
    res.status(500).send('Error');
  }
});

// ══════════════════════════════════
// SUB INFO PAGE
// ══════════════════════════════════
app.get('/sub/info/:token', (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(req.params.token);
    if (!c) return res.status(404).send('Not Found');

    const now    = new Date();
    const isExp  = c.expire_date && new Date(c.expire_date) < now;
    const isTraf = c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit;
    const ok     = !isExp && !isTraf && !!c.enabled;
    const link   = makeLink(c, req);
    const subUrl = `${req.protocol}://${req.get('host')}/sub/${c.sub_token}`;
    const tU     = (c.traffic_used / 1073741824).toFixed(2);
    const tT     = c.traffic_limit > 0 ? (c.traffic_limit / 1073741824).toFixed(0) : '∞';
    const pct    = c.traffic_limit > 0 ? Math.min(100, (c.traffic_used / c.traffic_limit) * 100) : 0;
    const dL     = c.expire_date ? Math.max(0, Math.ceil((new Date(c.expire_date) - now) / 86400000)) : null;
    const expStr = c.expire_date
      ? new Date(c.expire_date).toLocaleDateString('fa-IR', { year: 'numeric', month: 'long', day: 'numeric' })
      : 'نامحدود';
    const pColor = pct > 90 ? '#ef4444' : pct > 70 ? '#f59e0b' : '#10b981';
    const qrUrl  = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&color=a78bfa&bgcolor=060612&data=${encodeURIComponent(link)}`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>اشتراک ${esc(c.name)}</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{
  font-family:'Vazirmatn',sans-serif;
  background:#060612;color:#f1f5f9;min-height:100vh;padding:20px 16px;
  background-image:
    radial-gradient(ellipse at 20% 20%,rgba(124,58,237,.12) 0%,transparent 50%),
    radial-gradient(ellipse at 80% 80%,rgba(96,165,250,.08) 0%,transparent 50%);
}
.wrap{max-width:500px;margin:0 auto}
.header{text-align:center;padding:40px 0 32px}
.logo{
  display:inline-flex;align-items:center;justify-content:center;
  width:88px;height:88px;border-radius:28px;margin-bottom:20px;
  background:linear-gradient(135deg,rgba(124,58,237,.25),rgba(59,130,246,.15));
  border:1px solid rgba(124,58,237,.3);font-size:44px;
  box-shadow:0 0 40px rgba(124,58,237,.3);
  animation:glow 3s ease-in-out infinite;
}
@keyframes glow{0%,100%{box-shadow:0 0 40px rgba(124,58,237,.3)}50%{box-shadow:0 0 70px rgba(124,58,237,.6)}}
.title{
  font-size:28px;font-weight:900;
  background:linear-gradient(135deg,#fff,#a78bfa,#60a5fa);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  margin-bottom:6px;
}
.sub{color:#475569;font-size:14px}
.card{
  background:rgba(255,255,255,.04);
  backdrop-filter:blur(20px);
  border:1px solid rgba(255,255,255,.07);
  border-radius:22px;padding:24px;margin-bottom:14px;
  transition:.3s;
}
.card:hover{border-color:rgba(124,58,237,.25)}
.clabel{font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:1.5px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:6px}
.user-row{display:flex;align-items:center;justify-content:space-between;gap:12px}
.uname{font-size:22px;font-weight:800}
.sbadge{display:inline-flex;align-items:center;gap:5px;padding:7px 16px;border-radius:20px;font-size:13px;font-weight:700}
.sok{background:rgba(16,185,129,.12);color:#10b981;border:1px solid rgba(16,185,129,.2)}
.sexp{background:rgba(239,68,68,.12);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.straf{background:rgba(245,158,11,.12);color:#f59e0b;border:1px solid rgba(245,158,11,.2)}
.soff{background:rgba(100,116,139,.12);color:#94a3b8;border:1px solid rgba(100,116,139,.2)}
.uemail{color:#475569;font-size:13px;margin-top:6px}
.alert{
  background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.15);
  border-radius:12px;padding:12px 16px;font-size:13px;color:#fca5a5;margin-top:14px;
}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.stat{
  background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);
  border-radius:16px;padding:16px;text-align:center;transition:.3s;
}
.stat:hover{border-color:rgba(124,58,237,.25);transform:translateY(-2px)}
.si{font-size:22px;margin-bottom:8px}
.sv{font-size:22px;font-weight:800;line-height:1}
.cg{color:#10b981}.cb{color:#60a5fa}.cy{color:#f59e0b}.cr{color:#ef4444}.cp{color:#a78bfa}.cpk{color:#ec4899}
.sl{font-size:11px;color:#475569;margin-top:4px}
.prog-w{margin-top:16px;padding-top:16px;border-top:1px solid rgba(255,255,255,.06)}
.prog-h{display:flex;justify-content:space-between;font-size:12px;color:#94a3b8;margin-bottom:8px}
.prog-b{background:rgba(255,255,255,.07);border-radius:6px;height:8px;overflow:hidden}
.prog-f{height:100%;border-radius:6px;transition:width 1s ease}
.prog-i{text-align:center;font-size:12px;color:#475569;margin-top:6px}
.exp-row{display:flex;justify-content:space-between;align-items:center;padding-top:14px;margin-top:14px;border-top:1px solid rgba(255,255,255,.06);font-size:13px}
.exp-l{color:#475569}.exp-v{font-weight:700}
.ca{position:relative;margin:10px 0}
.cb2{
  background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.07);
  border-radius:12px;padding:12px 56px 12px 14px;
  font-family:monospace;font-size:11px;color:#94a3b8;
  word-break:break-all;direction:ltr;text-align:left;line-height:1.7;
}
.cpb{
  position:absolute;top:50%;right:10px;transform:translateY(-50%);
  background:linear-gradient(135deg,#7c3aed,#6d28d9);
  color:#fff;border:none;border-radius:8px;padding:7px 12px;
  cursor:pointer;font-size:12px;font-family:inherit;font-weight:600;
  transition:.3s;white-space:nowrap;
}
.cpb:hover{opacity:.85;transform:translateY(-50%) scale(1.05)}
.cpb.copied{background:linear-gradient(135deg,#10b981,#059669)}
.brow{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.btn{
  flex:1;padding:13px 16px;border:none;border-radius:14px;
  cursor:pointer;font-size:14px;font-weight:700;font-family:inherit;
  display:flex;align-items:center;justify-content:center;gap:6px;
  min-width:120px;text-decoration:none;transition:.3s;
}
.btn:hover{transform:translateY(-3px);box-shadow:0 10px 30px rgba(0,0,0,.3)}
.btnp{background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;box-shadow:0 4px 16px rgba(124,58,237,.3)}
.btnb{background:linear-gradient(135deg,#2563eb,#1d4ed8);color:#fff}
.qr-s{display:none;margin-top:16px;text-align:center}
.qr-s.show{display:block;animation:fadeUp .3s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.qr-f{
  display:inline-block;background:rgba(167,139,250,.05);
  border:2px solid rgba(124,58,237,.2);
  border-radius:22px;padding:20px;
}
.qr-f img{border-radius:14px;display:block}
.qr-h{font-size:12px;color:#475569;margin-top:10px}
.step{display:flex;align-items:flex-start;gap:12px;margin-bottom:12px}
.step:last-child{margin-bottom:0}
.sn{
  width:28px;height:28px;flex-shrink:0;
  background:rgba(124,58,237,.15);color:#a78bfa;
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  font-size:13px;font-weight:700;
}
.sn.ok{background:rgba(16,185,129,.15);color:#10b981}
.st{font-size:13px;color:#94a3b8;line-height:1.8;padding-top:3px}
.st strong{color:#f1f5f9}
.footer{text-align:center;padding:32px 0 12px;color:#334155;font-size:12px}
.fbrand{
  display:inline-flex;align-items:center;gap:6px;
  background:rgba(124,58,237,.08);border:1px solid rgba(124,58,237,.15);
  border-radius:20px;padding:7px 18px;color:#a78bfa;font-weight:600;margin-top:10px;
}
.divider{height:1px;background:rgba(255,255,255,.05);margin:4px 0;position:relative}
.divider::after{content:'';position:absolute;top:0;left:20%;right:20%;height:1px;background:linear-gradient(90deg,transparent,rgba(124,58,237,.3),transparent)}
</style>
</head>
<body>
<div class="wrap">

  <div class="header">
    <div class="logo">🔮</div>
    <div class="title">Persian Panel</div>
    <div class="sub">اطلاعات اشتراک VPN شما</div>
  </div>

  <!-- STATUS -->
  <div class="card">
    <div class="user-row">
      <div class="uname">${esc(c.name)}</div>
      <span class="sbadge ${ok?'sok':isExp?'sexp':isTraf?'straf':'soff'}">
        ${ok?'🟢 فعال':isExp?'🔴 منقضی':isTraf?'🟡 تمام':'⚫ غیرفعال'}
      </span>
    </div>
    <div class="uemail">${esc(c.email)}</div>
    ${!ok?`<div class="alert">⚠️ ${isExp?'اشتراک منقضی — برای تمدید اقدام کنید':isTraf?'ترافیک تمام شده است':'اشتراک غیرفعال است'}</div>`:''}
  </div>

  <!-- STATS -->
  <div class="card">
    <div class="clabel">📊 آمار مصرف</div>
    <div class="stats">
      <div class="stat">
        <div class="si">📦</div>
        <div class="sv ${pct>90?'cr':pct>70?'cy':'cg'}">${tU}</div>
        <div class="sl">GB مصرف شده</div>
      </div>
      <div class="stat">
        <div class="si">🗄️</div>
        <div class="sv cb">${tT}</div>
        <div class="sl">GB کل ترافیک</div>
      </div>
      <div class="stat">
        <div class="si">📅</div>
        <div class="sv ${dL!==null&&dL<3?'cr':dL!==null&&dL<7?'cy':'cp'}">${dL!==null?dL:'∞'}</div>
        <div class="sl">روز مانده</div>
      </div>
      <div class="stat">
        <div class="si">🔗</div>
        <div class="sv cpk">${c.max_connections||'∞'}</div>
        <div class="sl">حداکثر اتصال</div>
      </div>
    </div>
    ${c.traffic_limit>0?`
    <div class="prog-w">
      <div class="prog-h"><span>ترافیک مصرفی</span><span>${pct.toFixed(1)}%</span></div>
      <div class="prog-b"><div class="prog-f" id="pf" style="width:0%;background:${pColor}"></div></div>
      <div class="prog-i">${tU} از ${tT} گیگابایت</div>
    </div>`:''}
    <div class="exp-row">
      <span class="exp-l">📅 تاریخ انقضا</span>
      <span class="exp-v">${expStr}</span>
    </div>
  </div>

  <!-- SUB LINK -->
  <div class="card">
    <div class="clabel">🔗 لینک ساب‌اسکریپشن</div>
    <div class="ca">
      <div class="cb2">${esc(subUrl)}</div>
      <button class="cpb" onclick="cp('${esc(subUrl)}',this)">📋 کپی</button>
    </div>
    <div style="font-size:12px;color:#475569;margin-top:10px;line-height:2">
      این لینک رو توی <strong style="color:#a78bfa">Hiddify</strong>،
      <strong style="color:#a78bfa">v2rayNG</strong> یا
      <strong style="color:#a78bfa">Streisand</strong> وارد کنید
    </div>
  </div>

  <!-- CONFIG -->
  <div class="card">
    <div class="clabel">⚙️ کانفیگ مستقیم VLESS</div>
    <div class="ca">
      <div class="cb2">${esc(link)}</div>
      <button class="cpb" onclick="cp('${link.replace(/\\/g,'\\\\').replace(/'/g,"\\'")}',this)">📋 کپی</button>
    </div>
    <div class="brow">
      <button class="btn btnp" onclick="cp('${link.replace(/\\/g,'\\\\').replace(/'/g,"\\'")}',this)">📋 کپی کانفیگ</button>
      <button class="btn btnb" id="qrBtn" onclick="toggleQR()">📱 QR کد</button>
    </div>
    <div class="qr-s" id="qrSec">
      <div class="qr-f">
        <img src="${qrUrl}" width="220" height="220" alt="QR"/>
        <div class="qr-h">با اپ اسکن کنید</div>
      </div>
    </div>
  </div>

  <!-- HOW TO -->
  <div class="card">
    <div class="clabel">📱 راهنمای اتصال</div>
    <div class="step"><div class="sn">۱</div><div class="st">اپ <strong>Hiddify</strong> یا <strong>v2rayNG</strong> رو دانلود کنید</div></div>
    <div class="step"><div class="sn">۲</div><div class="st">روی <strong>افزودن سرور</strong> یا <strong>+</strong> کلیک کنید</div></div>
    <div class="step"><div class="sn">۳</div><div class="st"><strong>لینک ساب</strong> رو paste کنید یا <strong>QR</strong> رو اسکن کنید</div></div>
    <div class="step"><div class="sn ok">✓</div><div class="st"><strong>اتصال</strong> رو فعال کنید و از اینترنت آزاد لذت ببرید 🎉</div></div>
  </div>

  <div class="footer">
    <div>اطلاعات شما رمزنگاری و محفوظ است 🔒</div>
    <div class="fbrand">🔮 Persian Panel</div>
  </div>
</div>

<script>
function cp(text,btn){
  navigator.clipboard.writeText(text).catch(()=>{
    const t=document.createElement('textarea');t.value=text;
    document.body.appendChild(t);t.select();document.execCommand('copy');t.remove();
  });
  if(btn&&btn.classList.contains('cpb')){
    const old=btn.innerHTML;btn.innerHTML='✅ کپی شد!';btn.classList.add('copied');
    setTimeout(()=>{btn.innerHTML=old;btn.classList.remove('copied')},2000);
  }else if(btn){const old=btn.innerHTML;btn.innerHTML='✅ کپی شد!';setTimeout(()=>btn.innerHTML=old,2000)}
}
function toggleQR(){
  const s=document.getElementById('qrSec');
  const b=document.getElementById('qrBtn');
  if(s.classList.contains('show')){s.classList.remove('show');b.innerHTML='📱 QR کد'}
  else{s.classList.add('show');b.innerHTML='❌ بستن QR'}
}
window.addEventListener('load',()=>{
  const pf=document.getElementById('pf');
  if(pf)setTimeout(()=>pf.style.width='${pct.toFixed(1)}%',400);
});
</script>
</body>
</html>`);
  } catch (e) {
    console.error('[sub/info]', e.message);
    res.status(500).send('<h2>Error</h2>');
  }
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
  if (req.path === '/')
    return res.redirect(301, PANEL_PATH);
  res.status(404).send('Not Found');
});

// ══════════════════════════════════
// CRON
// ══════════════════════════════════
cron.schedule('0 * * * *', () => {
  try {
    const now = new Date().toISOString();
    const r1  = db.prepare('UPDATE clients SET enabled=0 WHERE expire_date IS NOT NULL AND expire_date<? AND enabled=1').run(now);
    const r2  = db.prepare('UPDATE clients SET enabled=0 WHERE traffic_limit>0 AND traffic_used>=traffic_limit AND enabled=1').run();
    if (r1.changes || r2.changes) {
      console.log(`[cron] ${r1.changes} expired, ${r2.changes} over-traffic`);
      syncXray();
    }
  } catch (e) {
    console.error('[cron]', e.message);
  }
});

// ══════════════════════════════════
// START
// ══════════════════════════════════
initDB();

// ✅ صبر کن Xray بالا بیاد بعد sync کن
setTimeout(syncXray, 6000);

// ✅ server رو جدا تعریف کن برای WebSocket upgrade
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
🔮 Persian Panel v3.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 ${process.env.RAILWAY_PUBLIC_DOMAIN || `localhost:${PORT}`}
📁 Panel: ${PANEL_PATH}
🚀 Port: ${PORT}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
});

// ✅ مهم‌ترین خط — WebSocket upgrade رو به Xray پروکسی کن
server.on('upgrade', wsProxy.upgrade);
