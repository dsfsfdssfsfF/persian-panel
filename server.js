require('dotenv').config();
const express = require('express');
const session = require('express-session');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const cron = require('node-cron');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

let dbPath = './persian.db';
try {
  const fs = require('fs');
  if (!fs.existsSync('/data')) fs.mkdirSync('/data', { recursive: true });
  dbPath = '/data/persian.db';
} catch (e) {}

let db;
try { db = new Database(dbPath); } catch (e) { db = new Database('./persian.db'); }
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS panel_users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'admin', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS inbounds (id INTEGER PRIMARY KEY AUTOINCREMENT, tag TEXT UNIQUE NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL, network TEXT NOT NULL, security TEXT DEFAULT 'none', external_proxy TEXT DEFAULT '', path TEXT DEFAULT '/', host TEXT DEFAULT '', service_name TEXT DEFAULT 'grpc', header_type TEXT DEFAULT 'none', xhttp_mode TEXT DEFAULT 'auto', tls_sni TEXT DEFAULT '', stream_settings TEXT DEFAULT '{}', enabled INTEGER DEFAULT 1, remark TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY AUTOINCREMENT, inbound_id INTEGER NOT NULL, name TEXT NOT NULL, uuid TEXT NOT NULL, email TEXT DEFAULT '', traffic_limit INTEGER DEFAULT 0, traffic_used INTEGER DEFAULT 0, expire_date TEXT DEFAULT NULL, max_connections INTEGER DEFAULT 0, external_proxy TEXT DEFAULT '', enabled INTEGER DEFAULT 1, sub_token TEXT UNIQUE NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE);
  `);
  if (!db.prepare('SELECT id FROM panel_users WHERE username=?').get('admin')) {
    db.prepare('INSERT INTO panel_users (username,password,role) VALUES (?,?,?)').run('admin', bcrypt.hashSync('admin', 10), 'superadmin');
    console.log('✅ admin / admin');
  }
  const rd = process.env.RAILWAY_PUBLIC_DOMAIN || '';
  const defs = { panel_name: 'Persian Panel', panel_domain: rd || 'localhost', theme: 'dark', tcp_proxy: '' };
  for (const [k, v] of Object.entries(defs))
    if (!db.prepare('SELECT key FROM settings WHERE key=?').get(k))
      db.prepare('INSERT INTO settings (key,value) VALUES (?,?)').run(k, v);
  if (rd) db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)').run('panel_domain', rd);
  console.log('✅ DB:', dbPath);
}

const G = k => { const r = db.prepare('SELECT value FROM settings WHERE key=?').get(k); return r ? r.value : ''; };
const S = (k, v) => db.prepare('INSERT OR REPLACE INTO settings (key,value,updated_at) VALUES (?,?,CURRENT_TIMESTAMP)').run(k, String(v));

function buildSS(net, sec, p, h, sn, ht, xm, sni) {
  const ss = { network: net, security: sec || 'none' };
  if (sec === 'tls') ss.tlsSettings = { serverName: sni || '', alpn: ['h2', 'http/1.1'], allowInsecure: false };
  if (net === 'tcp') ss.tcpSettings = { header: ht === 'http' ? { type: 'http', request: { version: '1.1', method: 'GET', path: [p || '/'], headers: { Host: [h || ''], 'User-Agent': ['Mozilla/5.0'], Connection: ['keep-alive'] } } } : { type: 'none' } };
  if (net === 'ws') ss.wsSettings = { path: p || '/', headers: h ? { Host: h } : {} };
  if (net === 'grpc') ss.grpcSettings = { serviceName: sn || 'grpc', multiMode: false };
  if (net === 'httpupgrade') ss.httpupgradeSettings = { path: p || '/', host: h || '' };
  if (net === 'xhttp') ss.xhttpSettings = { path: p || '/', host: h || '', mode: xm || 'auto' };
  return ss;
}

function makeLink(client, ib) {
  const domain = G('panel_domain') || 'localhost';
  const proxy = client.external_proxy || ib.external_proxy || G('tcp_proxy') || '';
  let addr = domain, port = ib.port;
  if (proxy && proxy.includes(':')) { const pp = proxy.split(':'); addr = pp[0].trim(); port = parseInt(pp[1]) || ib.port; }
  const net = ib.network, sec = ib.security || 'none', pr = ib.path || '/';
  const ho = ib.host || '', sn = ib.service_name || 'grpc', ht = ib.header_type || 'none';
  const xm = ib.xhttp_mode || 'auto', sni = ib.tls_sni || domain;
  const nm = encodeURIComponent(`${client.name} | PersianPanel`);
  if (ib.protocol === 'vless') {
    const q = new URLSearchParams({ type: net, security: sec });
    if (sec === 'tls') { q.set('sni', sni); q.set('alpn', 'h2,http/1.1'); q.set('fp', 'chrome'); }
    if (net === 'ws') { q.set('path', pr); if (ho) q.set('host', ho); }
    if (net === 'grpc') { q.set('serviceName', sn); q.set('mode', 'gun'); }
    if (net === 'httpupgrade') { q.set('path', pr); if (ho) q.set('host', ho); }
    if (net === 'xhttp') { q.set('path', pr); if (ho) q.set('host', ho); q.set('mode', xm); }
    if (net === 'tcp' && ht === 'http') { q.set('headerType', 'http'); q.set('path', pr); if (ho) q.set('host', ho); }
    return `vless://${client.uuid}@${addr}:${port}?${q.toString()}#${nm}`;
  }
  if (ib.protocol === 'vmess') {
    const obj = { v: '2', ps: `${client.name} | PersianPanel`, add: addr, port: String(port), id: client.uuid, aid: '0', scy: 'auto', net, type: 'none', host: ho, path: pr, tls: sec === 'tls' ? 'tls' : '', sni: sec === 'tls' ? sni : '', alpn: sec === 'tls' ? 'h2,http/1.1' : '', fp: sec === 'tls' ? 'chrome' : '' };
    if (net === 'grpc') { obj.path = sn; obj.type = 'gun'; obj.host = ''; }
    if (net === 'tcp' && ht === 'http') obj.type = 'http';
    return `vmess://${Buffer.from(JSON.stringify(obj)).toString('base64')}`;
  }
  if (ib.protocol === 'trojan') {
    const q = new URLSearchParams({ type: net, security: 'tls', sni, alpn: 'h2,http/1.1', fp: 'chrome' });
    if (net === 'ws') { q.set('path', pr); if (ho) q.set('host', ho); }
    if (net === 'grpc') q.set('serviceName', sn);
    if (net === 'httpupgrade') { q.set('path', pr); if (ho) q.set('host', ho); }
    return `trojan://${client.uuid}@${addr}:${port}?${q.toString()}#${nm}`;
  }
  return '';
}

function getConfigs(c, ib) {
  const lnk = makeLink(c, ib);
  return lnk ? [{ type: ib.protocol, network: ib.network, name: `${c.name} | ${ib.network.toUpperCase()}`, link: lnk }] : [];
}

app.use(compression());
app.use(morgan('tiny'));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'persian2024secret', resave: false, saveUninitialized: false, cookie: { secure: false, httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 } }));
const auth = (req, res, next) => req.session?.uid ? next() : res.status(401).json({ success: false, message: 'Unauthorized' });

app.get('/health', (_, res) => res.json({ status: 'ok', uptime: process.uptime() }));

app.get('/api/auth/me', (req, res) => req.session?.uid ? res.json({ success: true, user: { id: req.session.uid, username: req.session.uname } }) : res.status(401).json({ success: false }));
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM panel_users WHERE username=?').get(username?.trim());
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ success: false, message: 'نام کاربری یا رمز اشتباه' });
    req.session.uid = user.id; req.session.uname = user.username; req.session.role = user.role;
    res.json({ success: true, user: { id: user.id, username: user.username } });
  } catch (e) { res.status(500).json({ success: false, message: 'خطا' }); }
});
app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ success: true })));
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword, newUsername } = req.body;
    const user = db.prepare('SELECT * FROM panel_users WHERE id=?').get(req.session.uid);
    if (!user || !(await bcrypt.compare(currentPassword, user.password))) return res.status(401).json({ success: false, message: 'رمز فعلی اشتباه' });
    const upd = [], prm = [];
    if (newPassword?.length >= 4) { upd.push('password=?'); prm.push(await bcrypt.hash(newPassword, 10)); }
    if (newUsername?.trim().length >= 2) { upd.push('username=?'); prm.push(newUsername.trim()); }
    if (!upd.length) return res.json({ success: false, message: 'چیزی تغییر نکرد' });
    prm.push(req.session.uid);
    db.prepare(`UPDATE panel_users SET ${upd.join(',')} WHERE id=?`).run(...prm);
    if (newUsername) req.session.uname = newUsername.trim();
    res.json({ success: true, message: '✅ تغییر یافت' });
  } catch (e) { res.status(500).json({ success: false, message: 'خطا' }); }
});

app.get('/api/settings', auth, (_, res) => { const d = {}; ['panel_name','panel_domain','tcp_proxy','theme'].forEach(k => d[k] = G(k)); res.json({ success: true, data: d }); });
app.post('/api/settings', auth, (req, res) => { const { panel_domain, tcp_proxy, theme, panel_name } = req.body; if (panel_domain !== undefined) S('panel_domain', panel_domain.trim()); if (tcp_proxy !== undefined) S('tcp_proxy', tcp_proxy.trim()); if (theme !== undefined) S('theme', theme); if (panel_name !== undefined) S('panel_name', panel_name.trim()); res.json({ success: true, message: '✅ ذخیره شد' }); });
app.get('/api/server-info', auth, (req, res) => res.json({ success: true, data: { domain: process.env.RAILWAY_PUBLIC_DOMAIN || req.get('host') || `localhost:${PORT}`, uptime: process.uptime(), memory: process.memoryUsage(), node: process.version, env: process.env.RAILWAY_ENVIRONMENT || 'local' } }));

app.get('/api/inbounds', auth, (_, res) => { try { res.json({ success: true, data: db.prepare('SELECT i.*,COUNT(c.id) client_count FROM inbounds i LEFT JOIN clients c ON i.id=c.inbound_id AND c.enabled=1 GROUP BY i.id ORDER BY i.created_at DESC').all() }); } catch (e) { res.status(500).json({ success: false, message: e.message }); } });
app.post('/api/inbounds', auth, (req, res) => {
  try {
    const { protocol, port, network, security, remark, path, host, serviceName, headerType, xhttpMode, tlsSni, externalProxy } = req.body;
    if (!protocol || !port || !network) return res.status(400).json({ success: false, message: 'پروتکل، پورت و شبکه لازم است' });
    const portN = parseInt(port);
    if (isNaN(portN) || portN < 1 || portN > 65535) return res.status(400).json({ success: false, message: 'پورت نامعتبر' });
    if (db.prepare('SELECT id FROM inbounds WHERE port=?').get(portN)) return res.status(400).json({ success: false, message: `پورت ${portN} قبلاً استفاده شده` });
    const tag = `ib_${Date.now()}`;
    const ss = buildSS(network, security, path, host, serviceName, headerType, xhttpMode, tlsSni);
    db.prepare('INSERT INTO inbounds (tag,protocol,port,network,security,external_proxy,path,host,service_name,header_type,xhttp_mode,tls_sni,stream_settings,remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(tag, protocol, portN, network, security || 'none', externalProxy || '', path || '/', host || '', serviceName || 'grpc', headerType || 'none', xhttpMode || 'auto', tlsSni || '', JSON.stringify(ss), remark || `${protocol.toUpperCase()}-${network.toUpperCase()}-${portN}`);
    res.json({ success: true, message: '✅ ایجاد شد', data: db.prepare('SELECT * FROM inbounds WHERE tag=?').get(tag) });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.put('/api/inbounds/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(id);
    if (!ib) return res.status(404).json({ success: false, message: 'یافت نشد' });
    const { protocol, port, network, security, remark, enabled, path, host, serviceName, headerType, xhttpMode, tlsSni, externalProxy } = req.body;
    const nn = network || ib.network, ns = security ?? ib.security, np = path ?? ib.path, nh = host ?? ib.host;
    const ss = buildSS(nn, ns, np, nh, serviceName || ib.service_name, headerType || ib.header_type, xhttpMode || ib.xhttp_mode, tlsSni ?? ib.tls_sni);
    db.prepare('UPDATE inbounds SET protocol=?,port=?,network=?,security=?,external_proxy=?,path=?,host=?,service_name=?,header_type=?,xhttp_mode=?,tls_sni=?,stream_settings=?,remark=?,enabled=? WHERE id=?').run(protocol || ib.protocol, port ? parseInt(port) : ib.port, nn, ns, externalProxy ?? ib.external_proxy, np, nh, serviceName || ib.service_name, headerType || ib.header_type, xhttpMode || ib.xhttp_mode, tlsSni ?? ib.tls_sni, JSON.stringify(ss), remark || ib.remark, enabled !== undefined ? (enabled ? 1 : 0) : ib.enabled, id);
    res.json({ success: true, message: '✅ آپدیت شد', data: db.prepare('SELECT * FROM inbounds WHERE id=?').get(id) });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.delete('/api/inbounds/:id', auth, (req, res) => { try { const id = parseInt(req.params.id); if (!db.prepare('SELECT id FROM inbounds WHERE id=?').get(id)) return res.status(404).json({ success: false, message: 'یافت نشد' }); db.prepare('DELETE FROM inbounds WHERE id=?').run(id); res.json({ success: true, message: 'حذف شد' }); } catch (e) { res.status(500).json({ success: false, message: e.message }); } });

app.get('/api/clients/stats/overview', auth, (_, res) => { try { const now = new Date().toISOString(); res.json({ success: true, data: { total: db.prepare('SELECT COUNT(*) c FROM clients').get().c, active: db.prepare('SELECT COUNT(*) c FROM clients WHERE enabled=1 AND (expire_date IS NULL OR expire_date>?)').get(now).c, expired: db.prepare('SELECT COUNT(*) c FROM clients WHERE expire_date IS NOT NULL AND expire_date<=?').get(now).c, total_inbounds: db.prepare('SELECT COUNT(*) c FROM inbounds').get().c, total_traffic: db.prepare('SELECT COALESCE(SUM(traffic_used),0) t FROM clients').get().t } }); } catch (e) { res.status(500).json({ success: false, message: e.message }); } });
app.get('/api/clients', auth, (req, res) => { try { const { inbound_id, search } = req.query; let q = 'SELECT c.*,i.protocol i_protocol,i.network i_network,i.port i_port,i.remark inbound_remark,i.external_proxy i_proxy,i.security i_security,i.path i_path,i.host i_host,i.service_name,i.header_type,i.xhttp_mode,i.tls_sni FROM clients c JOIN inbounds i ON c.inbound_id=i.id WHERE 1=1'; const p = []; if (inbound_id) { q += ' AND c.inbound_id=?'; p.push(parseInt(inbound_id)); } if (search) { q += ' AND (c.name LIKE ? OR c.email LIKE ?)'; p.push(`%${search}%`, `%${search}%`); } q += ' ORDER BY c.created_at DESC'; const now = new Date(); res.json({ success: true, data: db.prepare(q).all(...p).map(c => ({ ...c, is_expired: c.expire_date ? new Date(c.expire_date) < now : false })) }); } catch (e) { res.status(500).json({ success: false, message: e.message }); } });
app.post('/api/clients', auth, (req, res) => {
  try {
    const { inbound_id, name, email, traffic_limit_gb, expire_days, max_connections, external_proxy, custom_uuid } = req.body;
    if (!inbound_id || !name) return res.status(400).json({ success: false, message: 'Inbound و نام لازم است' });
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=? AND enabled=1').get(parseInt(inbound_id));
    if (!ib) return res.status(404).json({ success: false, message: 'Inbound یافت نشد' });
    const uuidRx = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const uuid = (custom_uuid && uuidRx.test(custom_uuid.trim())) ? custom_uuid.trim() : uuidv4();
    const sub = uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');
    const tBytes = traffic_limit_gb ? Math.floor(parseFloat(traffic_limit_gb) * 1073741824) : 0;
    let expDate = null;
    if (expire_days && parseInt(expire_days) > 0) { const d = new Date(); d.setDate(d.getDate() + parseInt(expire_days)); expDate = d.toISOString(); }
    const mail = email?.trim() || `${name.trim().toLowerCase().replace(/[^a-z0-9]/g, '.')}.${Date.now()}@persian.panel`;
    const r = db.prepare('INSERT INTO clients (inbound_id,name,uuid,email,traffic_limit,traffic_used,expire_date,max_connections,external_proxy,enabled,sub_token) VALUES (?,?,?,?,?,0,?,?,?,1,?)').run(parseInt(inbound_id), name.trim(), uuid, mail, tBytes, expDate, parseInt(max_connections) || 0, external_proxy?.trim() || '', sub);
    res.json({ success: true, message: '✅ کلاینت ایجاد شد', data: db.prepare('SELECT * FROM clients WHERE id=?').get(r.lastInsertRowid) });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.put('/api/clients/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const c = db.prepare('SELECT * FROM clients WHERE id=?').get(id);
    if (!c) return res.status(404).json({ success: false, message: 'یافت نشد' });
    const { name, email, traffic_limit_gb, expire_days, max_connections, enabled, external_proxy, reset_traffic } = req.body;
    const tBytes = traffic_limit_gb !== undefined ? Math.floor(parseFloat(traffic_limit_gb) * 1073741824) : c.traffic_limit;
    let expDate = c.expire_date;
    if (expire_days !== undefined) { if (!expire_days || parseInt(expire_days) <= 0) expDate = null; else { const d = new Date(); d.setDate(d.getDate() + parseInt(expire_days)); expDate = d.toISOString(); } }
    db.prepare('UPDATE clients SET name=?,email=?,traffic_limit=?,traffic_used=?,expire_date=?,max_connections=?,enabled=?,external_proxy=? WHERE id=?').run(name || c.name, email || c.email, tBytes, reset_traffic ? 0 : c.traffic_used, expDate, max_connections !== undefined ? parseInt(max_connections) : c.max_connections, enabled !== undefined ? (enabled ? 1 : 0) : c.enabled, external_proxy !== undefined ? external_proxy.trim() : c.external_proxy, id);
    res.json({ success: true, message: '✅ آپدیت شد', data: db.prepare('SELECT * FROM clients WHERE id=?').get(id) });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.delete('/api/clients/:id', auth, (req, res) => { try { if (!db.prepare('SELECT id FROM clients WHERE id=?').get(parseInt(req.params.id))) return res.status(404).json({ success: false, message: 'یافت نشد' }); db.prepare('DELETE FROM clients WHERE id=?').run(parseInt(req.params.id)); res.json({ success: true, message: 'حذف شد' }); } catch (e) { res.status(500).json({ success: false, message: e.message }); } });
app.post('/api/clients/:id/reset-traffic', auth, (req, res) => { try { db.prepare('UPDATE clients SET traffic_used=0 WHERE id=?').run(parseInt(req.params.id)); res.json({ success: true, message: '✅ ری‌ست شد' }); } catch (e) { res.status(500).json({ success: false, message: e.message }); } });
app.get('/api/clients/:id/config', auth, (req, res) => { try { const c = db.prepare('SELECT * FROM clients WHERE id=?').get(parseInt(req.params.id)); if (!c) return res.status(404).json({ success: false, message: 'یافت نشد' }); const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(c.inbound_id); if (!ib) return res.status(404).json({ success: false, message: 'Inbound یافت نشد' }); res.json({ success: true, data: getConfigs(c, ib) }); } catch (e) { res.status(500).json({ success: false, message: e.message }); } });

const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

app.get('/sub/:token', (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(req.params.token);
    if (!c || !c.enabled) return res.status(404).send('Not Found');
    if (c.expire_date && new Date(c.expire_date) < new Date()) return res.status(403).send('Expired');
    if (c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit) return res.status(403).send('Traffic Exceeded');
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=? AND enabled=1').get(c.inbound_id);
    if (!ib) return res.status(404).send('Not Found');
    const lnk = makeLink(c, ib);
    if (!lnk) return res.status(500).send('Config Error');
    const exp = c.expire_date ? Math.floor(new Date(c.expire_date).getTime() / 1000) : 0;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Subscription-Userinfo', `upload=0; download=${c.traffic_used}; total=${c.traffic_limit || 0}; expire=${exp}`);
    res.setHeader('Profile-Title', Buffer.from(`PersianPanel-${c.name}`).toString('base64'));
    res.setHeader('Profile-Update-Interval', '12');
    res.send(Buffer.from(lnk).toString('base64'));
  } catch (e) { res.status(500).send('Error'); }
});

app.get('/sub/html/:token', (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(req.params.token);
    if (!c) return res.status(404).send('<h1 style="font-family:sans-serif;text-align:center;margin-top:20vh;color:#7c3aed">404 — یافت نشد</h1>');
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(c.inbound_id);
    if (!ib) return res.status(404).send('<h1>Not Found</h1>');
    const now = new Date();
    const isExp = c.expire_date && new Date(c.expire_date) < now;
    const isTraf = c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit;
    const ok = !isExp && !isTraf && c.enabled;
    const cfgs = getConfigs(c, ib);
    const subUrl = `${req.protocol}://${req.get('host')}/sub/${c.sub_token}`;
    const tU = (c.traffic_used / 1073741824).toFixed(2);
    const tT = c.traffic_limit > 0 ? (c.traffic_limit / 1073741824).toFixed(0) : '∞';
    const pct = c.traffic_limit > 0 ? Math.min(100, (c.traffic_used / c.traffic_limit) * 100) : 0;
    const expD = c.expire_date ? new Date(c.expire_date).toLocaleDateString('fa-IR', { year: 'numeric', month: 'long', day: 'numeric' }) : 'نامحدود';
    const dL = c.expire_date ? Math.max(0, Math.ceil((new Date(c.expire_date) - now) / 86400000)) : '∞';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Persian Panel — ${esc(c.name)}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#08081a,#13082c,#0b1828);min-height:100vh;color:#e0e0ff;padding:14px}.w{max-width:540px;margin:0 auto}.hdr{text-align:center;padding:22px;background:rgba(255,255,255,.04);border:1px solid rgba(120,100,255,.18);border-radius:18px;margin-bottom:13px;backdrop-filter:blur(10px)}.logo{font-size:18px;font-weight:900;background:linear-gradient(135deg,#a78bfa,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}.nm{font-size:19px;font-weight:700;margin:6px 0 2px}.em{font-size:11px;color:#8888aa}.bdg{display:inline-block;padding:3px 14px;border-radius:20px;font-size:11px;font-weight:700;margin-top:8px}.ok{background:rgba(16,185,129,.12);color:#10b981;border:1px solid rgba(16,185,129,.25)}.bad{background:rgba(239,68,68,.12);color:#ef4444;border:1px solid rgba(239,68,68,.25)}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:12px}@media(min-width:400px){.grid{grid-template-columns:repeat(4,1fr)}}.sc{background:rgba(255,255,255,.04);border:1px solid rgba(120,100,255,.15);border-radius:11px;padding:11px;text-align:center}.sv{font-size:19px;font-weight:800;color:#a78bfa}.sl{font-size:10px;color:#8888aa;margin-top:2px}.ps{background:rgba(255,255,255,.04);border:1px solid rgba(120,100,255,.15);border-radius:11px;padding:12px;margin-bottom:12px}.pr{display:flex;justify-content:space-between;font-size:11px;margin-bottom:5px}.pb{background:rgba(255,255,255,.08);border-radius:8px;height:7px;overflow:hidden}.pf{height:100%;border-radius:8px}.sb2{background:rgba(124,58,237,.07);border:1px solid rgba(124,58,237,.2);border-radius:11px;padding:12px;margin-bottom:11px}.sbt{font-size:12px;font-weight:700;color:#a78bfa;margin-bottom:6px}.sbl{font-family:monospace;font-size:10px;word-break:break-all;color:#c4b5fd;background:rgba(0,0,0,.2);border-radius:6px;padding:7px;margin-bottom:7px;line-height:1.5}.cfg{background:rgba(255,255,255,.04);border:1px solid rgba(120,100,255,.15);border-radius:12px;padding:13px;margin-bottom:10px}.cfgh{display:flex;gap:5px;align-items:center;margin-bottom:9px;flex-wrap:wrap}.tp{background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700}.tn{background:rgba(59,130,246,.12);color:#60a5fa;border:1px solid rgba(59,130,246,.25);padding:3px 8px;border-radius:20px;font-size:10px;font-weight:600}.tabs{display:flex;gap:3px;background:rgba(255,255,255,.04);border:1px solid rgba(120,100,255,.12);border-radius:7px;padding:2px;margin-bottom:8px}.tab{flex:1;padding:6px;border-radius:6px;border:none;background:transparent;color:#8888aa;cursor:pointer;font-size:11px;font-weight:700;transition:all .2s;font-family:inherit}.tab.on{background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff}.lnk{background:rgba(0,0,0,.28);border:1px solid rgba(100,100,255,.1);border-radius:7px;padding:8px;font-size:10px;color:#a78bfa;word-break:break-all;font-family:monospace;margin:7px 0;line-height:1.5}.btn{display:flex;align-items:center;justify-content:center;padding:9px;border-radius:8px;border:none;cursor:pointer;font-size:12px;font-weight:700;width:100%;transition:all .2s;font-family:inherit;background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff}.btn:hover{opacity:.88}.brow{display:flex;gap:5px;margin-top:7px}.brow .btn{flex:1}.bs{background:rgba(255,255,255,.06);border:1px solid rgba(120,100,255,.18);color:#e0e0ff}.qrw{text-align:center;padding:6px}.qrw img{border-radius:9px;border:3px solid rgba(167,139,250,.2)}.al{padding:9px 12px;border-radius:8px;margin-bottom:11px;font-size:11px;text-align:center;font-weight:600;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#f87171}.ftr{text-align:center;color:#444466;font-size:10px;margin-top:14px;padding:10px}.tc{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);z-index:999;display:flex;flex-direction:column;gap:4px;align-items:center}.ts{background:rgba(15,15,35,.95);border:1px solid rgba(124,58,237,.3);border-radius:8px;padding:8px 15px;font-size:11px;color:#e0e0ff;backdrop-filter:blur(10px)}</style></head><body><div class="w"><div class="hdr"><div class="logo">🔮 Persian Panel</div><div class="nm">${esc(c.name)}</div><div class="em">${esc(c.email)}</div><div class="bdg ${ok ? 'ok' : 'bad'}">${ok ? '✅ فعال' : isExp ? '⏰ منقضی' : isTraf ? '📦 تمام' : '🚫 غیرفعال'}</div></div>${!ok ? `<div class="al">${isExp ? '⚠️ اشتراک منقضی شده' : isTraf ? '⚠️ ترافیک تمام' : '🚫 غیرفعال'}</div>` : ''}<div class="grid"><div class="sc"><div class="sv">${tU}</div><div class="sl">GB مصرف</div></div><div class="sc"><div class="sv">${tT}</div><div class="sl">GB کل</div></div><div class="sc"><div class="sv">${dL}</div><div class="sl">روز مانده</div></div><div class="sc"><div class="sv">${c.max_connections > 0 ? c.max_connections : '∞'}</div><div class="sl">اتصال</div></div></div>${c.traffic_limit > 0 ? `<div class="ps"><div class="pr"><span>ترافیک</span><span style="color:#a78bfa;font-weight:700">${pct.toFixed(1)}%</span></div><div class="pb"><div class="pf" style="width:${pct}%;background:${pct > 90 ? '#ef4444' : pct > 70 ? '#f59e0b' : '#7c3aed'}"></div></div><div style="font-size:9px;color:#8888aa;text-align:center;margin-top:4px">${tU} از ${tT} GB</div></div>` : ''}<div class="sb2"><div class="sbt">🔗 لینک ساب</div><div class="sbl" id="SURL">${esc(subUrl)}</div><button class="btn" onclick="cp('SURL',this)">📋 کپی لینک ساب</button></div><div style="font-size:13px;font-weight:700;margin:11px 0 8px">📋 کانفیگ‌ها</div>${cfgs.map((cfg, i) => `<div class="cfg"><div class="cfgh"><span class="tp">${esc(cfg.type.toUpperCase())}</span><span class="tn">${esc(cfg.network.toUpperCase())}</span></div><div class="tabs"><button class="tab on" onclick="sw(${i},'l',this)">🔗 لینک</button><button class="tab" onclick="sw(${i},'q',this)">📱 QR</button></div><div id="TL${i}"><div class="lnk" id="LNK${i}">${esc(cfg.link)}</div><button class="btn" onclick="cp('LNK${i}',this)">📋 کپی کانفیگ</button></div><div id="TQ${i}" style="display:none"><div class="qrw"><img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(cfg.link)}&margin=8&color=a78bfa&bgcolor=080818" width="160" height="160" loading="lazy" alt="QR"></div></div></div>`).join('')}<div class="ftr"><div>🔮 Persian Panel</div><div style="margin-top:3px">📅 انقضا: ${expD}</div></div></div><div class="tc" id="TC"></div><script>function cp(id,btn){const t=document.getElementById(id).textContent.trim();navigator.clipboard.writeText(t).then(()=>{const o=btn.innerHTML;btn.innerHTML='✅ کپی شد!';btn.style.background='linear-gradient(135deg,#059669,#10b981)';setTimeout(()=>{btn.innerHTML=o;btn.style.background='';},2000);toast('✅ کپی شد');}).catch(()=>{const e=document.createElement('textarea');e.value=t;document.body.appendChild(e);e.select();document.execCommand('copy');document.body.removeChild(e);toast('✅ کپی شد');});}function sw(i,tab,el){document.getElementById('TL'+i).style.display=tab==='l'?'':'none';document.getElementById('TQ'+i).style.display=tab==='q'?'':'none';el.closest('.tabs').querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));el.classList.add('on');}function toast(m){const tc=document.getElementById('TC');const t=document.createElement('div');t.className='ts';t.textContent=m;tc.appendChild(t);setTimeout(()=>{t.style.opacity='0';t.style.transition='opacity .3s';setTimeout(()=>t.remove(),300);},2200);}<\/script></body></html>`);
  } catch (e) { res.status(500).send('<h1>Error</h1>'); }
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/sub/')) return res.status(404).json({ success: false, message: 'Not Found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

cron.schedule('0 * * * *', () => {
  try {
    const now = new Date().toISOString();
    const r1 = db.prepare('UPDATE clients SET enabled=0 WHERE expire_date IS NOT NULL AND expire_date<? AND enabled=1').run(now);
    const r2 = db.prepare('UPDATE clients SET enabled=0 WHERE traffic_limit>0 AND traffic_used>=traffic_limit AND enabled=1').run();
    if (r1.changes || r2.changes) console.log(`[cron] ${r1.changes} expired, ${r2.changes} traffic`);
  } catch (e) { console.error('[cron]', e.message); }
});

initDB();
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🔮 Persian Panel → https://${process.env.RAILWAY_PUBLIC_DOMAIN || `localhost:${PORT}`}\n👤 admin / admin\n`);
});
