'use strict';
const express = require('express');
const session = require('express-session');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const cron = require('node-cron');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── DB ───
let dbPath = path.join(__dirname, 'persian.db');
try {
  if (!fs.existsSync('/data')) fs.mkdirSync('/data', { recursive: true });
  dbPath = '/data/persian.db';
} catch (e) {}

let db;
try {
  db = new Database(dbPath);
} catch (e) {
  console.error('DB error:', e.message);
  db = new Database(path.join(__dirname, 'persian.db'));
}

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS panel_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'admin',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS inbounds (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tag TEXT UNIQUE NOT NULL,
      protocol TEXT NOT NULL,
      port INTEGER NOT NULL,
      network TEXT NOT NULL,
      security TEXT DEFAULT 'none',
      external_proxy TEXT DEFAULT '',
      path TEXT DEFAULT '/',
      host TEXT DEFAULT '',
      service_name TEXT DEFAULT 'grpc',
      header_type TEXT DEFAULT 'none',
      xhttp_mode TEXT DEFAULT 'auto',
      tls_sni TEXT DEFAULT '',
      enabled INTEGER DEFAULT 1,
      remark TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      inbound_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      uuid TEXT NOT NULL,
      email TEXT DEFAULT '',
      traffic_limit INTEGER DEFAULT 0,
      traffic_used INTEGER DEFAULT 0,
      expire_date TEXT DEFAULT NULL,
      max_connections INTEGER DEFAULT 0,
      external_proxy TEXT DEFAULT '',
      enabled INTEGER DEFAULT 1,
      sub_token TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
    );
  `);

  if (!db.prepare('SELECT id FROM panel_users WHERE username=?').get('admin')) {
    db.prepare('INSERT INTO panel_users (username,password,role) VALUES (?,?,?)')
      .run('admin', bcrypt.hashSync('admin', 10), 'superadmin');
    console.log('✅ Admin created: admin/admin');
  }

  const rd = process.env.RAILWAY_PUBLIC_DOMAIN || '';
  const defaults = {
    panel_name: 'Persian Panel',
    panel_domain: rd || 'localhost',
    theme: 'dark',
    tcp_proxy: ''
  };
  for (const [k, v] of Object.entries(defaults)) {
    if (!db.prepare('SELECT key FROM settings WHERE key=?').get(k))
      db.prepare('INSERT INTO settings (key,value) VALUES (?,?)').run(k, v);
  }
  if (rd) db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)').run('panel_domain', rd);
  console.log('✅ DB ready at:', dbPath);
}

const G = k => { const r = db.prepare('SELECT value FROM settings WHERE key=?').get(k); return r ? r.value : ''; };
const S = (k, v) => db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)').run(k, String(v));

// ─── LINK BUILDER ───
function makeLink(client, ib) {
  const domain = G('panel_domain') || 'localhost';
  const proxy = client.external_proxy || ib.external_proxy || G('tcp_proxy') || '';
  let addr = domain, port = ib.port;
  if (proxy && proxy.includes(':')) {
    const pp = proxy.split(':');
    addr = pp[0].trim();
    port = parseInt(pp[1]) || ib.port;
  }
  const net = ib.network;
  const sec = ib.security || 'none';
  const pr = ib.path || '/';
  const ho = ib.host || '';
  const sn = ib.service_name || 'grpc';
  const ht = ib.header_type || 'none';
  const xm = ib.xhttp_mode || 'auto';
  const sni = ib.tls_sni || domain;
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
    const obj = { v:'2', ps:`${client.name}|PersianPanel`, add:addr, port:String(port), id:client.uuid, aid:'0', scy:'auto', net, type:'none', host:ho, path:pr, tls:sec==='tls'?'tls':'', sni:sec==='tls'?sni:'', alpn:sec==='tls'?'h2,http/1.1':'', fp:sec==='tls'?'chrome':'' };
    if (net==='grpc') { obj.path=sn; obj.type='gun'; obj.host=''; }
    if (net==='tcp'&&ht==='http') obj.type='http';
    return `vmess://${Buffer.from(JSON.stringify(obj)).toString('base64')}`;
  }
  if (ib.protocol === 'trojan') {
    const q = new URLSearchParams({ type:net, security:'tls', sni, alpn:'h2,http/1.1', fp:'chrome' });
    if (net==='ws') { q.set('path',pr); if(ho) q.set('host',ho); }
    if (net==='grpc') q.set('serviceName',sn);
    if (net==='httpupgrade') { q.set('path',pr); if(ho) q.set('host',ho); }
    return `trojan://${client.uuid}@${addr}:${port}?${q.toString()}#${nm}`;
  }
  return '';
}

// ─── MIDDLEWARE ───
app.use(compression());
app.use(morgan('tiny'));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'pp2024secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 7*24*60*60*1000 }
}));

const auth = (req, res, next) =>
  req.session && req.session.uid ? next() : res.status(401).json({ success:false, message:'Unauthorized' });

// ─── HEALTH ───
app.get('/health', (_, res) => res.json({ status:'ok', uptime:process.uptime() }));

// ─── AUTH ROUTES ───
app.get('/api/auth/me', (req, res) =>
  req.session && req.session.uid
    ? res.json({ success:true, user:{ id:req.session.uid, username:req.session.uname } })
    : res.status(401).json({ success:false })
);

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success:false, message:'وارد کنید' });
    const user = db.prepare('SELECT * FROM panel_users WHERE username=?').get(username.trim());
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ success:false, message:'نام کاربری یا رمز اشتباه' });
    req.session.uid = user.id;
    req.session.uname = user.username;
    req.session.role = user.role;
    res.json({ success:true, user:{ id:user.id, username:user.username } });
  } catch(e) { res.status(500).json({ success:false, message:'خطا' }); }
});

app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ success:true })));

app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword, newUsername } = req.body;
    const user = db.prepare('SELECT * FROM panel_users WHERE id=?').get(req.session.uid);
    if (!user || !(await bcrypt.compare(currentPassword, user.password)))
      return res.status(401).json({ success:false, message:'رمز فعلی اشتباه' });
    const upd=[], prm=[];
    if (newPassword && newPassword.length >= 4) { upd.push('password=?'); prm.push(await bcrypt.hash(newPassword, 10)); }
    if (newUsername && newUsername.trim().length >= 2) { upd.push('username=?'); prm.push(newUsername.trim()); }
    if (!upd.length) return res.json({ success:false, message:'چیزی تغییر نکرد' });
    prm.push(req.session.uid);
    db.prepare(`UPDATE panel_users SET ${upd.join(',')} WHERE id=?`).run(...prm);
    if (newUsername) req.session.uname = newUsername.trim();
    res.json({ success:true, message:'✅ تغییر یافت' });
  } catch(e) { res.status(500).json({ success:false, message:'خطا' }); }
});

// ─── SETTINGS ───
app.get('/api/settings', auth, (_, res) => {
  const d = {};
  ['panel_name','panel_domain','tcp_proxy','theme'].forEach(k => d[k] = G(k));
  res.json({ success:true, data:d });
});
app.post('/api/settings', auth, (req, res) => {
  const { panel_domain, tcp_proxy, theme, panel_name } = req.body;
  if (panel_domain !== undefined) S('panel_domain', panel_domain.trim());
  if (tcp_proxy !== undefined) S('tcp_proxy', tcp_proxy.trim());
  if (theme !== undefined) S('theme', theme);
  if (panel_name !== undefined) S('panel_name', panel_name.trim());
  res.json({ success:true, message:'✅ ذخیره شد' });
});
app.get('/api/server-info', auth, (req, res) => res.json({ success:true, data:{ domain: process.env.RAILWAY_PUBLIC_DOMAIN || req.get('host') || `localhost:${PORT}`, uptime:process.uptime(), memory:process.memoryUsage(), node:process.version, env:process.env.RAILWAY_ENVIRONMENT||'local' } }));

// ─── INBOUNDS ───
app.get('/api/inbounds', auth, (_, res) => {
  try {
    res.json({ success:true, data: db.prepare('SELECT i.*,COUNT(c.id) client_count FROM inbounds i LEFT JOIN clients c ON i.id=c.inbound_id AND c.enabled=1 GROUP BY i.id ORDER BY i.created_at DESC').all() });
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

app.post('/api/inbounds', auth, (req, res) => {
  try {
    const { protocol, port, network, security, remark, path, host, serviceName, headerType, xhttpMode, tlsSni, externalProxy } = req.body;
    if (!protocol||!port||!network) return res.status(400).json({ success:false, message:'پروتکل، پورت و شبکه لازم است' });
    const portN = parseInt(port);
    if (isNaN(portN)||portN<1||portN>65535) return res.status(400).json({ success:false, message:'پورت نامعتبر' });
    if (db.prepare('SELECT id FROM inbounds WHERE port=?').get(portN))
      return res.status(400).json({ success:false, message:`پورت ${portN} قبلاً استفاده شده` });
    const tag = `ib_${Date.now()}`;
    db.prepare('INSERT INTO inbounds (tag,protocol,port,network,security,external_proxy,path,host,service_name,header_type,xhttp_mode,tls_sni,remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(tag, protocol, portN, network, security||'none', externalProxy||'', path||'/', host||'', serviceName||'grpc', headerType||'none', xhttpMode||'auto', tlsSni||'', remark||`${protocol.toUpperCase()}-${network.toUpperCase()}-${portN}`);
    res.json({ success:true, message:'✅ ایجاد شد', data:db.prepare('SELECT * FROM inbounds WHERE tag=?').get(tag) });
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

app.put('/api/inbounds/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(id);
    if (!ib) return res.status(404).json({ success:false, message:'یافت نشد' });
    const { protocol, port, network, security, remark, enabled, path, host, serviceName, headerType, xhttpMode, tlsSni, externalProxy } = req.body;
    db.prepare('UPDATE inbounds SET protocol=?,port=?,network=?,security=?,external_proxy=?,path=?,host=?,service_name=?,header_type=?,xhttp_mode=?,tls_sni=?,remark=?,enabled=? WHERE id=?')
      .run(protocol||ib.protocol, port?parseInt(port):ib.port, network||ib.network, security!==undefined?security:ib.security, externalProxy!==undefined?externalProxy:ib.external_proxy, path!==undefined?path:ib.path, host!==undefined?host:ib.host, serviceName||ib.service_name, headerType||ib.header_type, xhttpMode||ib.xhttp_mode, tlsSni!==undefined?tlsSni:ib.tls_sni, remark||ib.remark, enabled!==undefined?(enabled?1:0):ib.enabled, id);
    res.json({ success:true, message:'✅ آپدیت شد', data:db.prepare('SELECT * FROM inbounds WHERE id=?').get(id) });
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

app.delete('/api/inbounds/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!db.prepare('SELECT id FROM inbounds WHERE id=?').get(id)) return res.status(404).json({ success:false, message:'یافت نشد' });
    db.prepare('DELETE FROM inbounds WHERE id=?').run(id);
    res.json({ success:true, message:'حذف شد' });
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

// ─── CLIENTS ───
app.get('/api/clients/stats/overview', auth, (_, res) => {
  try {
    const now = new Date().toISOString();
    res.json({ success:true, data:{
      total: db.prepare('SELECT COUNT(*) c FROM clients').get().c,
      active: db.prepare('SELECT COUNT(*) c FROM clients WHERE enabled=1 AND (expire_date IS NULL OR expire_date>?)').get(now).c,
      expired: db.prepare('SELECT COUNT(*) c FROM clients WHERE expire_date IS NOT NULL AND expire_date<=?').get(now).c,
      total_inbounds: db.prepare('SELECT COUNT(*) c FROM inbounds').get().c,
      total_traffic: db.prepare('SELECT COALESCE(SUM(traffic_used),0) t FROM clients').get().t
    }});
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

app.get('/api/clients', auth, (req, res) => {
  try {
    const { inbound_id, search } = req.query;
    let q = 'SELECT c.*,i.protocol i_protocol,i.network i_network,i.port i_port,i.remark inbound_remark,i.security i_security,i.path i_path,i.host i_host,i.service_name,i.header_type,i.xhttp_mode,i.tls_sni,i.external_proxy i_proxy FROM clients c JOIN inbounds i ON c.inbound_id=i.id WHERE 1=1';
    const p=[];
    if (inbound_id) { q+=' AND c.inbound_id=?'; p.push(parseInt(inbound_id)); }
    if (search) { q+=' AND (c.name LIKE ? OR c.email LIKE ?)'; p.push(`%${search}%`,`%${search}%`); }
    q+=' ORDER BY c.created_at DESC';
    const now = new Date();
    res.json({ success:true, data: db.prepare(q).all(...p).map(c=>({ ...c, is_expired: c.expire_date ? new Date(c.expire_date)<now : false })) });
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

app.post('/api/clients', auth, (req, res) => {
  try {
    const { inbound_id, name, email, traffic_limit_gb, expire_days, max_connections, external_proxy, custom_uuid } = req.body;
    if (!inbound_id||!name) return res.status(400).json({ success:false, message:'Inbound و نام لازم است' });
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=? AND enabled=1').get(parseInt(inbound_id));
    if (!ib) return res.status(404).json({ success:false, message:'Inbound یافت نشد' });
    const uuidRx = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const uuid = (custom_uuid && uuidRx.test(custom_uuid.trim())) ? custom_uuid.trim() : uuidv4();
    const sub = uuidv4().replace(/-/g,'')+uuidv4().replace(/-/g,'');
    const tBytes = traffic_limit_gb ? Math.floor(parseFloat(traffic_limit_gb)*1073741824) : 0;
    let expDate = null;
    if (expire_days && parseInt(expire_days)>0) { const d=new Date(); d.setDate(d.getDate()+parseInt(expire_days)); expDate=d.toISOString(); }
    const mail = email && email.trim() ? email.trim() : `${name.trim().toLowerCase().replace(/[^a-z0-9]/g,'.')}.${Date.now()}@persian.panel`;
    const r = db.prepare('INSERT INTO clients (inbound_id,name,uuid,email,traffic_limit,traffic_used,expire_date,max_connections,external_proxy,enabled,sub_token) VALUES (?,?,?,?,?,0,?,?,?,1,?)')
      .run(parseInt(inbound_id), name.trim(), uuid, mail, tBytes, expDate, parseInt(max_connections)||0, external_proxy?external_proxy.trim():'', sub);
    res.json({ success:true, message:'✅ کلاینت ایجاد شد', data:db.prepare('SELECT * FROM clients WHERE id=?').get(r.lastInsertRowid) });
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

app.put('/api/clients/:id', auth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const c = db.prepare('SELECT * FROM clients WHERE id=?').get(id);
    if (!c) return res.status(404).json({ success:false, message:'یافت نشد' });
    const { name, email, traffic_limit_gb, expire_days, max_connections, enabled, external_proxy, reset_traffic } = req.body;
    const tBytes = traffic_limit_gb!==undefined ? Math.floor(parseFloat(traffic_limit_gb)*1073741824) : c.traffic_limit;
    let expDate = c.expire_date;
    if (expire_days!==undefined) { if (!expire_days||parseInt(expire_days)<=0) expDate=null; else { const d=new Date(); d.setDate(d.getDate()+parseInt(expire_days)); expDate=d.toISOString(); } }
    db.prepare('UPDATE clients SET name=?,email=?,traffic_limit=?,traffic_used=?,expire_date=?,max_connections=?,enabled=?,external_proxy=? WHERE id=?')
      .run(name||c.name, email||c.email, tBytes, reset_traffic?0:c.traffic_used, expDate, max_connections!==undefined?parseInt(max_connections):c.max_connections, enabled!==undefined?(enabled?1:0):c.enabled, external_proxy!==undefined?external_proxy.trim():c.external_proxy, id);
    res.json({ success:true, message:'✅ آپدیت شد', data:db.prepare('SELECT * FROM clients WHERE id=?').get(id) });
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

app.delete('/api/clients/:id', auth, (req, res) => {
  try {
    if (!db.prepare('SELECT id FROM clients WHERE id=?').get(parseInt(req.params.id))) return res.status(404).json({ success:false, message:'یافت نشد' });
    db.prepare('DELETE FROM clients WHERE id=?').run(parseInt(req.params.id));
    res.json({ success:true, message:'حذف شد' });
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

app.post('/api/clients/:id/reset-traffic', auth, (req, res) => {
  try { db.prepare('UPDATE clients SET traffic_used=0 WHERE id=?').run(parseInt(req.params.id)); res.json({ success:true, message:'✅ ری‌ست شد' }); }
  catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

app.get('/api/clients/:id/config', auth, (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE id=?').get(parseInt(req.params.id));
    if (!c) return res.status(404).json({ success:false, message:'یافت نشد' });
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(c.inbound_id);
    if (!ib) return res.status(404).json({ success:false, message:'Inbound یافت نشد' });
    const lnk = makeLink(c, ib);
    res.json({ success:true, data: lnk ? [{ type:ib.protocol, network:ib.network, name:`${c.name}|${ib.network.toUpperCase()}`, link:lnk }] : [] });
  } catch(e) { res.status(500).json({ success:false, message:e.message }); }
});

// ─── SUB ───
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

app.get('/sub/:token', (req, res) => {
  try {
    const { token } = req.params;
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(token);
    if (!c||!c.enabled) return res.status(404).send('Not Found');
    if (c.expire_date&&new Date(c.expire_date)<new Date()) return res.status(403).send('Expired');
    if (c.traffic_limit>0&&c.traffic_used>=c.traffic_limit) return res.status(403).send('Traffic Exceeded');
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=? AND enabled=1').get(c.inbound_id);
    if (!ib) return res.status(404).send('Not Found');
    const lnk = makeLink(c, ib);
    if (!lnk) return res.status(500).send('Config Error');
    const exp = c.expire_date ? Math.floor(new Date(c.expire_date).getTime()/1000) : 0;
    res.setHeader('Content-Type','text/plain; charset=utf-8');
    res.setHeader('Subscription-Userinfo',`upload=0; download=${c.traffic_used}; total=${c.traffic_limit||0}; expire=${exp}`);
    res.setHeader('Profile-Title', Buffer.from(`PersianPanel-${c.name}`).toString('base64'));
    res.setHeader('Profile-Update-Interval','12');
    res.send(Buffer.from(lnk).toString('base64'));
  } catch(e) { res.status(500).send('Error'); }
});

app.get('/sub/html/:token', (req, res) => {
  try {
    const c = db.prepare('SELECT * FROM clients WHERE sub_token=?').get(req.params.token);
    if (!c) return res.status(404).send(`<html><body style="background:#08081a;color:#a78bfa;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;flex-direction:column"><h1>404</h1><p>یافت نشد</p></body></html>`);
    const ib = db.prepare('SELECT * FROM inbounds WHERE id=?').get(c.inbound_id);
    if (!ib) return res.status(404).send('<h1>Not Found</h1>');
    const now = new Date();
    const isExp = c.expire_date && new Date(c.expire_date) < now;
    const isTraf = c.traffic_limit > 0 && c.traffic_used >= c.traffic_limit;
    const ok = !isExp && !isTraf && c.enabled;
    const lnk = makeLink(c, ib);
    const subUrl = `${req.protocol}://${req.get('host')}/sub/${c.sub_token}`;
    const tU = (c.traffic_used/1073741824).toFixed(2);
    const tT = c.traffic_limit > 0 ? (c.traffic_limit/1073741824).toFixed(0) : '∞';
    const pct = c.traffic_limit > 0 ? Math.min(100,(c.traffic_used/c.traffic_limit)*100) : 0;
    const expD = c.expire_date ? new Date(c.expire_date).toLocaleDateString('fa-IR',{year:'numeric',month:'long',day:'numeric'}) : 'نامحدود';
    const dL = c.expire_date ? Math.max(0,Math.ceil((new Date(c.expire_date)-now)/86400000)) : '∞';
    const pColor = pct>90?'#ef4444':pct>70?'#f59e0b':'#7c3aed';
    res.setHeader('Content-Type','text/html; charset=utf-8');
    res.send(`<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Persian Panel — ${esc(c.name)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#08081a,#13082c,#0b1828);min-height:100vh;color:#e0e0ff;padding:14px}
.w{max-width:520px;margin:0 auto}
.card{background:rgba(255,255,255,.04);border:1px solid rgba(120,100,255,.18);border-radius:16px;padding:20px;margin-bottom:12px;backdrop-filter:blur(10px)}
.logo{font-size:16px;font-weight:900;background:linear-gradient(135deg,#a78bfa,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;text-align:center;margin-bottom:6px}
.name{font-size:20px;font-weight:700;text-align:center}
.email{font-size:11px;color:#8888aa;text-align:center;margin-top:2px}
.badge{display:inline-block;padding:3px 14px;border-radius:20px;font-size:11px;font-weight:700;margin:8px auto 0;display:block;width:fit-content;margin-left:auto;margin-right:auto}
.ok{background:rgba(16,185,129,.12);color:#10b981;border:1px solid rgba(16,185,129,.25)}
.bad{background:rgba(239,68,68,.12);color:#ef4444;border:1px solid rgba(239,68,68,.25)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
@media(min-width:380px){.grid{grid-template-columns:repeat(4,1fr)}}
.sc{text-align:center}
.sv{font-size:18px;font-weight:800;color:#a78bfa}
.sl{font-size:10px;color:#8888aa;margin-top:2px}
.pb{background:rgba(255,255,255,.08);border-radius:8px;height:7px;overflow:hidden;margin-top:6px}
.pf{height:100%;border-radius:8px}
.sub-lnk{font-family:monospace;font-size:10px;word-break:break-all;color:#c4b5fd;background:rgba(0,0,0,.2);border-radius:6px;padding:7px;margin-bottom:8px;line-height:1.5}
.lnk-box{font-family:monospace;font-size:10px;word-break:break-all;color:#a78bfa;background:rgba(0,0,0,.25);border-radius:6px;padding:8px;margin:7px 0;line-height:1.5}
.btn{display:flex;align-items:center;justify-content:center;padding:10px;border-radius:8px;border:none;cursor:pointer;font-size:12px;font-weight:700;width:100%;transition:all .2s;font-family:inherit;background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff}
.btn:hover{opacity:.88}
.btn-s{background:rgba(255,255,255,.06);border:1px solid rgba(120,100,255,.2);color:#e0e0ff}
.row{display:flex;gap:6px;margin-top:6px}
.row .btn{flex:1}
.tabs{display:flex;gap:3px;background:rgba(255,255,255,.04);border:1px solid rgba(120,100,255,.12);border-radius:7px;padding:2px;margin-bottom:8px}
.tab{flex:1;padding:6px;border-radius:6px;border:none;background:transparent;color:#8888aa;cursor:pointer;font-size:11px;font-weight:700;font-family:inherit}
.tab.on{background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff}
.qrw{text-align:center}
.qrw img{border-radius:9px;border:2px solid rgba(167,139,250,.2)}
.al{padding:10px;border-radius:8px;font-size:11px;text-align:center;font-weight:600;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#f87171;margin-bottom:10px}
.ftr{text-align:center;color:#444466;font-size:10px;margin-top:14px}
.tp{background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff;padding:2px 9px;border-radius:20px;font-size:10px;font-weight:700}
.tn{background:rgba(59,130,246,.12);color:#60a5fa;border:1px solid rgba(59,130,246,.25);padding:2px 7px;border-radius:20px;font-size:9px;font-weight:600}
.tc{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);z-index:99;display:flex;flex-direction:column;gap:4px;align-items:center}
.ts{background:rgba(10,10,30,.95);border:1px solid rgba(124,58,237,.3);border-radius:8px;padding:8px 16px;font-size:11px;color:#e0e0ff}
</style>
</head>
<body>
<div class="w">

<div class="card">
  <div class="logo">🔮 Persian Panel</div>
  <div class="name">${esc(c.name)}</div>
  <div class="email">${esc(c.email)}</div>
  <span class="badge ${ok?'ok':'bad'}">${ok?'✅ فعال':isExp?'⏰ منقضی':isTraf?'📦 تمام':'🚫 غیرفعال'}</span>
</div>

${!ok?`<div class="al">${isExp?'⚠️ اشتراک منقضی شده':isTraf?'⚠️ ترافیک تمام شده':'🚫 اشتراک غیرفعال'}</div>`:''}

<div class="card">
  <div class="grid">
    <div class="sc"><div class="sv">${tU}</div><div class="sl">GB مصرف</div></div>
    <div class="sc"><div class="sv">${tT}</div><div class="sl">GB کل</div></div>
    <div class="sc"><div class="sv">${dL}</div><div class="sl">روز مانده</div></div>
    <div class="sc"><div class="sv">${c.max_connections>0?c.max_connections:'∞'}</div><div class="sl">اتصال</div></div>
  </div>
  ${c.traffic_limit>0?`<div class="pb"><div class="pf" style="width:${pct}%;background:${pColor}"></div></div><div style="font-size:9px;color:#8888aa;text-align:center;margin-top:4px">${tU} از ${tT} GB — ${pct.toFixed(0)}%</div>`:''}
</div>

<div class="card">
  <div style="font-size:11px;font-weight:700;color:#a78bfa;margin-bottom:6px">🔗 لینک ساب‌اسکریپشن</div>
  <div class="sub-lnk" id="SURL">${esc(subUrl)}</div>
  <button class="btn" onclick="cp('SURL',this)">📋 کپی لینک ساب</button>
</div>

${lnk?`
<div class="card">
  <div style="display:flex;gap:5px;align-items:center;margin-bottom:10px">
    <span class="tp">${esc(ib.protocol.toUpperCase())}</span>
    <span class="tn">${esc(ib.network.toUpperCase())}</span>
  </div>
  <div class="tabs">
    <button class="tab on" onclick="sw('l',this)">🔗 لینک</button>
    <button class="tab" onclick="sw('q',this)">📱 QR کد</button>
  </div>
  <div id="TL">
    <div class="lnk-box" id="LNK">${esc(lnk)}</div>
    <button class="btn" onclick="cp('LNK',this)">📋 کپی کانفیگ</button>
  </div>
  <div id="TQ" style="display:none">
    <div class="qrw">
      <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(lnk)}&margin=8&color=a78bfa&bgcolor=080818" width="180" height="180" loading="lazy" alt="QR">
    </div>
    <div style="text-align:center;font-size:10px;color:#8888aa;margin-top:6px">با دوربین موبایل اسکن کنید</div>
  </div>
</div>`:''}

<div class="ftr">🔮 Persian Panel &nbsp;|&nbsp; انقضا: ${expD}</div>
</div>
<div class="tc" id="TC"></div>
<script>
function cp(id,btn){
  const t=document.getElementById(id).textContent.trim();
  navigator.clipboard.writeText(t).then(()=>{
    const o=btn.innerHTML;
    btn.innerHTML='✅ کپی شد!';
    btn.style.background='linear-gradient(135deg,#059669,#10b981)';
    setTimeout(()=>{btn.innerHTML=o;btn.style.background='';},2000);
    toast('✅ کپی شد');
  }).catch(()=>{
    const e=document.createElement('textarea');
    e.value=t;document.body.appendChild(e);e.select();
    document.execCommand('copy');document.body.removeChild(e);
    toast('✅ کپی شد');
  });
}
function sw(tab,el){
  document.getElementById('TL').style.display=tab==='l'?'':'none';
  document.getElementById('TQ').style.display=tab==='q'?'':'none';
  el.closest('.tabs').querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
  el.classList.add('on');
}
function toast(m){
  const tc=document.getElementById('TC');
  const t=document.createElement('div');
  t.className='ts';t.textContent=m;tc.appendChild(t);
  setTimeout(()=>{t.style.opacity='0';t.style.transition='opacity .3s';setTimeout(()=>t.remove(),300);},2200);
}
</script>
</body>
</html>`);
  } catch(e) { res.status(500).send('<h1>Error</h1><p>'+e.message+'</p>'); }
});

// ─── STATIC ───
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir, { recursive: true });
app.use(express.static(publicDir));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')||req.path.startsWith('/sub/'))
    return res.status(404).json({ success:false, message:'Not Found' });
  const indexPath = path.join(publicDir, 'index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.send(`<html><body style="background:#08081a;color:#a78bfa;font-family:sans-serif;text-align:center;padding-top:20vh"><h2>🔮 Persian Panel</h2><p style="color:#8888aa;margin-top:10px">public/index.html یافت نشد</p></body></html>`);
});

// ─── CRON ───
cron.schedule('0 * * * *', () => {
  try {
    const now = new Date().toISOString();
    const r1 = db.prepare('UPDATE clients SET enabled=0 WHERE expire_date IS NOT NULL AND expire_date<? AND enabled=1').run(now);
    const r2 = db.prepare('UPDATE clients SET enabled=0 WHERE traffic_limit>0 AND traffic_used>=traffic_limit AND enabled=1').run();
    if (r1.changes||r2.changes) console.log(`[cron] ${r1.changes} expired, ${r2.changes} traffic`);
  } catch(e) { console.error('[cron]',e.message); }
});

// ─── START ───
initDB();
app.listen(PORT, '0.0.0.0', () => {
  const d = process.env.RAILWAY_PUBLIC_DOMAIN || `localhost:${PORT}`;
  console.log(`\n🔮 Persian Panel\n🌐 https://${d}\n👤 admin / admin\n`);
});
