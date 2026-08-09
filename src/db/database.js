const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

// ===== Database Path =====
const dataDir = path.join(__dirname, '../../data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const DB_PATH = path.join(dataDir, 'persian-panel.db');
console.log('📦 Database path:', DB_PATH);

const db = new Database(DB_PATH);

// Performance settings
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

// ===== Create Tables =====
db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS inbounds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tag TEXT UNIQUE NOT NULL,
        remark TEXT NOT NULL,
        protocol TEXT NOT NULL DEFAULT 'vless',
        port INTEGER NOT NULL DEFAULT 443,
        network TEXT DEFAULT 'ws',
        security TEXT DEFAULT 'none',
        tls_sni TEXT,
        ws_path TEXT DEFAULT '/ws',
        grpc_service TEXT,
        reality_pbk TEXT,
        reality_sid TEXT,
        header_type TEXT,
        xhttp_mode TEXT,
        enabled INTEGER DEFAULT 1,
        up_bytes INTEGER DEFAULT 0,
        down_bytes INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        inbound_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        uuid TEXT UNIQUE NOT NULL,
        email TEXT,
        traffic_limit INTEGER DEFAULT 0,
        traffic_used INTEGER DEFAULT 0,
        expire_date TEXT,
        max_connections INTEGER DEFAULT 2,
        enabled INTEGER DEFAULT 1,
        sub_token TEXT UNIQUE NOT NULL,
        note TEXT,
        up_bytes INTEGER DEFAULT 0,
        down_bytes INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS outbounds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tag TEXT NOT NULL,
        protocol TEXT NOT NULL DEFAULT 'freedom',
        address TEXT,
        port INTEGER,
        settings TEXT,
        enabled INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS routing_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'field',
        outbound_tag TEXT,
        domain TEXT,
        ip TEXT,
        port TEXT,
        network TEXT,
        priority INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        ip TEXT NOT NULL,
        type TEXT DEFAULT 'A',
        enabled INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
`);

// ===== Create Default Admin =====
const adminUsername = process.env.ADMIN_USERNAME || 'admin';
const adminPassword = process.env.ADMIN_PASSWORD || 'admin';

const existingAdmin = db.prepare('SELECT id FROM admins LIMIT 1').get();
if (!existingAdmin) {
    const hashedPassword = bcrypt.hashSync(adminPassword, 10);
    db.prepare('INSERT INTO admins (username, password) VALUES (?, ?)')
        .run(adminUsername, hashedPassword);
    console.log(`✅ Admin created: ${adminUsername} / ${adminPassword}`);
}

// ===== Default Settings =====
const defaultSettings = {
    panel_name: 'PERSIAN PANEL',
    cf_domain: '',
    theme: 'dark'
};

const insertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
for (const [key, val] of Object.entries(defaultSettings)) {
    insertSetting.run(key, JSON.stringify(val));
}

// ===== Default Outbounds =====
const existingOutbound = db.prepare('SELECT id FROM outbounds LIMIT 1').get();
if (!existingOutbound) {
    db.prepare('INSERT INTO outbounds (tag, protocol) VALUES (?, ?)').run('direct', 'freedom');
    db.prepare('INSERT INTO outbounds (tag, protocol) VALUES (?, ?)').run('blocked', 'blackhole');
    console.log('✅ Default outbounds created');
}

console.log('✅ All tables ready');

// ===== HELPER FUNCTIONS =====

// Admin
const getAdminByUsername = (username) => {
    return db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
};

const updateAdminPassword = (username, password) => {
    const hashed = bcrypt.hashSync(password, 10);
    return db.prepare('UPDATE admins SET password = ?, updated_at = datetime("now") WHERE username = ?')
        .run(hashed, username);
};

const updateAdminUsername = (oldUsername, newUsername) => {
    return db.prepare('UPDATE admins SET username = ?, updated_at = datetime("now") WHERE username = ?')
        .run(newUsername, oldUsername);
};

// Inbounds
const getAllInbounds = () => {
    const inbounds = db.prepare('SELECT * FROM inbounds ORDER BY created_at DESC').all();

    // Add client count to each inbound
    const countStmt = db.prepare('SELECT COUNT(*) as cnt FROM clients WHERE inbound_id = ?');
    return inbounds.map(ib => {
        const result = countStmt.get(ib.id);
        ib.client_count = result ? result.cnt : 0;
        return ib;
    });
};

const getInboundById = (id) => {
    return db.prepare('SELECT * FROM inbounds WHERE id = ?').get(id);
};

const createInbound = (data) => {
    const tag = data.tag || `inbound-${Date.now()}`;
    return db.prepare(`
        INSERT INTO inbounds (tag, remark, protocol, port, network, security, tls_sni, ws_path, grpc_service, reality_pbk, reality_sid, header_type, xhttp_mode, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        tag, data.remark, data.protocol, data.port,
        data.network || 'ws', data.security || 'none',
        data.tls_sni || null, data.ws_path || null,
        data.grpc_service || null, data.reality_pbk || null,
        data.reality_sid || null, data.header_type || null,
        data.xhttp_mode || null, data.enabled !== false ? 1 : 0
    );
};

const updateInbound = (id, data) => {
    return db.prepare(`
        UPDATE inbounds SET
            remark = COALESCE(?, remark),
            protocol = COALESCE(?, protocol),
            port = COALESCE(?, port),
            network = COALESCE(?, network),
            security = COALESCE(?, security),
            tls_sni = ?,
            ws_path = ?,
            grpc_service = ?,
            reality_pbk = ?,
            reality_sid = ?,
            header_type = ?,
            xhttp_mode = ?,
            enabled = COALESCE(?, enabled),
            updated_at = datetime('now')
        WHERE id = ?
    `).run(
        data.remark, data.protocol, data.port,
        data.network, data.security,
        data.tls_sni || null, data.ws_path || null,
        data.grpc_service || null, data.reality_pbk || null,
        data.reality_sid || null, data.header_type || null,
        data.xhttp_mode || null,
        data.enabled !== undefined ? (data.enabled ? 1 : 0) : null,
        id
    );
};

const deleteInbound = (id) => {
    db.prepare('DELETE FROM clients WHERE inbound_id = ?').run(id);
    return db.prepare('DELETE FROM inbounds WHERE id = ?').run(id);
};

// Clients
const getAllClients = (search, inbound_id) => {
    let query = `
        SELECT
            c.*,
            i.remark as inbound_remark,
            i.protocol as i_protocol,
            i.network as i_network,
            i.port as i_port,
            i.security as i_security,
            i.ws_path,
            i.tls_sni,
            i.grpc_service,
            CASE WHEN c.expire_date IS NOT NULL AND c.expire_date < datetime('now') THEN 1 ELSE 0 END as is_expired,
            CASE WHEN c.traffic_limit > 0 AND c.traffic_used >= c.traffic_limit THEN 1 ELSE 0 END as over_traffic
        FROM clients c
        LEFT JOIN inbounds i ON c.inbound_id = i.id
        WHERE 1=1
    `;

    const params = [];

    if (search) {
        query += ' AND (c.name LIKE ? OR c.email LIKE ? OR c.note LIKE ?)';
        const s = `%${search}%`;
        params.push(s, s, s);
    }

    if (inbound_id) {
        query += ' AND c.inbound_id = ?';
        params.push(inbound_id);
    }

    query += ' ORDER BY c.created_at DESC';

    return db.prepare(query).all(...params);
};

const getClientById = (id) => {
    return db.prepare(`
        SELECT c.*,
            i.remark as inbound_remark,
            i.protocol as i_protocol,
            i.network as i_network,
            i.port as i_port,
            i.security as i_security,
            i.ws_path,
            i.tls_sni,
            i.grpc_service
        FROM clients c
        LEFT JOIN inbounds i ON c.inbound_id = i.id
        WHERE c.id = ?
    `).get(id);
};

const getClientBySubToken = (token) => {
    return db.prepare(`
        SELECT c.*,
            i.protocol as i_protocol,
            i.network as i_network,
            i.port as i_port,
            i.security as i_security,
            i.ws_path,
            i.tls_sni,
            i.grpc_service
        FROM clients c
        LEFT JOIN inbounds i ON c.inbound_id = i.id
        WHERE c.sub_token = ? AND c.enabled = 1
    `).get(token);
};

const createClient = (data) => {
    const clientUuid = data.custom_uuid || uuidv4();
    const subToken = uuidv4().replace(/-/g, '').substring(0, 16);

    let expireDate = null;
    if (data.expire_days && data.expire_days > 0) {
        const d = new Date();
        d.setDate(d.getDate() + parseInt(data.expire_days));
        expireDate = d.toISOString();
    }

    const trafficLimit = (data.traffic_limit_gb && data.traffic_limit_gb > 0)
        ? Math.floor(data.traffic_limit_gb * 1024 * 1024 * 1024)
        : 0;

    return db.prepare(`
        INSERT INTO clients (inbound_id, name, uuid, email, traffic_limit, expire_date, max_connections, enabled, sub_token, note)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `).run(
        data.inbound_id, data.name, clientUuid,
        data.email || null, trafficLimit, expireDate,
        data.max_connections || 2, subToken, data.note || null
    );
};

const updateClient = (id, data) => {
    const sets = [];
    const params = [];

    if (data.name !== undefined) { sets.push('name = ?'); params.push(data.name); }
    if (data.email !== undefined) { sets.push('email = ?'); params.push(data.email || null); }
    if (data.note !== undefined) { sets.push('note = ?'); params.push(data.note || null); }
    if (data.max_connections !== undefined) { sets.push('max_connections = ?'); params.push(data.max_connections); }
    if (data.enabled !== undefined) { sets.push('enabled = ?'); params.push(data.enabled ? 1 : 0); }

    if (data.traffic_limit_gb !== undefined) {
        const limit = data.traffic_limit_gb > 0 ? Math.floor(data.traffic_limit_gb * 1024 * 1024 * 1024) : 0;
        sets.push('traffic_limit = ?');
        params.push(limit);
    }

    if (data.expire_days !== undefined) {
        let expireDate = null;
        if (data.expire_days > 0) {
            const d = new Date();
            d.setDate(d.getDate() + parseInt(data.expire_days));
            expireDate = d.toISOString();
        }
        sets.push('expire_date = ?');
        params.push(expireDate);
    }

    if (data.reset_traffic) {
        sets.push('traffic_used = 0');
        sets.push('up_bytes = 0');
        sets.push('down_bytes = 0');
    }

    sets.push("updated_at = datetime('now')");
    params.push(id);

    if (sets.length <= 1) return; // Only updated_at

    return db.prepare(`UPDATE clients SET ${sets.join(', ')} WHERE id = ?`).run(...params);
};

const deleteClient = (id) => {
    return db.prepare('DELETE FROM clients WHERE id = ?').run(id);
};

const resetClientTraffic = (id) => {
    return db.prepare(`UPDATE clients SET traffic_used = 0, up_bytes = 0, down_bytes = 0, updated_at = datetime('now') WHERE id = ?`).run(id);
};

// Stats
const getStats = () => {
    const total = db.prepare('SELECT COUNT(*) as c FROM clients').get().c;
    const active = db.prepare(`
        SELECT COUNT(*) as c FROM clients
        WHERE enabled = 1
        AND (expire_date IS NULL OR expire_date > datetime('now'))
        AND (traffic_limit = 0 OR traffic_used < traffic_limit)
    `).get().c;
    const expired = db.prepare(`
        SELECT COUNT(*) as c FROM clients
        WHERE expire_date IS NOT NULL AND expire_date < datetime('now')
    `).get().c;
    const disabled = db.prepare('SELECT COUNT(*) as c FROM clients WHERE enabled = 0').get().c;
    const total_inbounds = db.prepare('SELECT COUNT(*) as c FROM inbounds').get().c;
    const trafficRow = db.prepare('SELECT COALESCE(SUM(up_bytes + down_bytes), 0) as t FROM clients').get();

    return {
        total,
        active,
        expired,
        disabled,
        total_inbounds,
        total_traffic: trafficRow.t
    };
};

// Settings
const getAllSettings = () => {
    const rows = db.prepare('SELECT key, value FROM settings').all();
    const result = {};
    rows.forEach(r => {
        try { result[r.key] = JSON.parse(r.value); }
        catch { result[r.key] = r.value; }
    });
    return result;
};

const setSetting = (key, value) => {
    return db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, JSON.stringify(value));
};

// Outbounds
const getAllOutbounds = () => {
    return db.prepare('SELECT * FROM outbounds ORDER BY id').all();
};

const createOutbound = (data) => {
    return db.prepare('INSERT INTO outbounds (tag, protocol, address, port, settings, enabled) VALUES (?, ?, ?, ?, ?, ?)')
        .run(data.tag, data.protocol, data.address || null, data.port || null, data.settings || null, 1);
};

const deleteOutbound = (id) => {
    return db.prepare('DELETE FROM outbounds WHERE id = ?').run(id);
};

// Routing
const getAllRoutingRules = () => {
    return db.prepare('SELECT * FROM routing_rules ORDER BY priority').all();
};

const createRoutingRule = (data) => {
    return db.prepare('INSERT INTO routing_rules (name, type, outbound_tag, domain, ip, port, network, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(data.name, data.type || 'field', data.outbound_tag, data.domain || null, data.ip || null, data.port || null, data.network || null, data.priority || 0, 1);
};

const deleteRoutingRule = (id) => {
    return db.prepare('DELETE FROM routing_rules WHERE id = ?').run(id);
};

// Hosts
const getAllHosts = () => {
    return db.prepare('SELECT * FROM hosts ORDER BY id').all();
};

const createHost = (data) => {
    return db.prepare('INSERT INTO hosts (domain, ip, type, enabled) VALUES (?, ?, ?, ?)')
        .run(data.domain, data.ip, data.type || 'A', 1);
};

const deleteHost = (id) => {
    return db.prepare('DELETE FROM hosts WHERE id = ?').run(id);
};

// ===== Export Everything =====
module.exports = {
    db,
    getAdminByUsername,
    updateAdminPassword,
    updateAdminUsername,
    getAllInbounds,
    getInboundById,
    createInbound,
    updateInbound,
    deleteInbound,
    getAllClients,
    getClientById,
    getClientBySubToken,
    createClient,
    updateClient,
    deleteClient,
    resetClientTraffic,
    getStats,
    getAllSettings,
    setSetting,
    getAllOutbounds,
    createOutbound,
    deleteOutbound,
    getAllRoutingRules,
    createRoutingRule,
    deleteRoutingRule,
    getAllHosts,
    createHost,
    deleteHost
};
