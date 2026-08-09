const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// مسیر دیتابیس
const DB_PATH = process.env.DATABASE_URL?.replace('sqlite:///', '') || 
                path.join(__dirname, '../../data/persian-panel.db');

// ایجاد دیتابیس
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ایجاد جداول
function initDatabase() {
    // جدول کاربران ادمین
    db.exec(`
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // جدول Inbounds
    db.exec(`
        CREATE TABLE IF NOT EXISTS inbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT UNIQUE NOT NULL,
            remark TEXT,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            network TEXT DEFAULT 'ws',
            security TEXT DEFAULT 'none',
            tls_sni TEXT,
            ws_path TEXT,
            grpc_service TEXT,
            reality_pbk TEXT,
            reality_sid TEXT,
            header_type TEXT,
            xhttp_mode TEXT,
            enabled BOOLEAN DEFAULT 1,
            client_count INTEGER DEFAULT 0,
            up_bytes INTEGER DEFAULT 0,
            down_bytes INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // جدول Clients (کاربران VPN)
    db.exec(`
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inbound_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            uuid TEXT UNIQUE NOT NULL,
            email TEXT,
            traffic_limit INTEGER DEFAULT 0,
            traffic_used INTEGER DEFAULT 0,
            expire_date DATETIME,
            max_connections INTEGER DEFAULT 2,
            enabled BOOLEAN DEFAULT 1,
            sub_token TEXT UNIQUE,
            note TEXT,
            up_bytes INTEGER DEFAULT 0,
            down_bytes INTEGER DEFAULT 0,
            last_online DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
        )
    `);

    // جدول Outbounds
    db.exec(`
        CREATE TABLE IF NOT EXISTS outbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT UNIQUE NOT NULL,
            protocol TEXT NOT NULL,
            address TEXT,
            port INTEGER,
            settings TEXT,
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // جدول Routing Rules
    db.exec(`
        CREATE TABLE IF NOT EXISTS routing_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            outbound_tag TEXT,
            domain TEXT,
            ip TEXT,
            port TEXT,
            network TEXT,
            priority INTEGER DEFAULT 0,
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // جدول Hosts
    db.exec(`
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            ip TEXT NOT NULL,
            type TEXT DEFAULT 'A',
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // جدول Settings
    db.exec(`
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // ایجاد کاربر ادمین پیش‌فرض
    const adminExists = db.prepare('SELECT id FROM admins WHERE username = ?')
        .get(process.env.ADMIN_USERNAME || 'admin');

    if (!adminExists) {
        const hashedPassword = bcrypt.hashSync(
            process.env.ADMIN_PASSWORD || 'admin', 
            10
        );
        
        db.prepare('INSERT INTO admins (username, password) VALUES (?, ?)')
            .run(process.env.ADMIN_USERNAME || 'admin', hashedPassword);
        
        console.log('✅ Admin user created successfully');
    }

    // تنظیمات پیش‌فرض
    const settingsDefaults = {
        panel_name: 'PERSIAN PANEL',
        cf_domain: '',
        theme: 'dark',
        lang: 'fa'
    };

    for (const [key, value] of Object.entries(settingsDefaults)) {
        const exists = db.prepare('SELECT key FROM settings WHERE key = ?').get(key);
        if (!exists) {
            db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)')
                .run(key, JSON.stringify(value));
        }
    }

    console.log('✅ Database initialized successfully');
}

// Helper Functions
const dbHelpers = {
    // Admin
    getAdminByUsername: (username) => {
        return db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
    },

    updateAdminPassword: (username, password) => {
        const hashedPassword = bcrypt.hashSync(password, 10);
        return db.prepare('UPDATE admins SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?')
            .run(hashedPassword, username);
    },

    updateAdminUsername: (oldUsername, newUsername) => {
        return db.prepare('UPDATE admins SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?')
            .run(newUsername, oldUsername);
    },

    // Inbounds
    getAllInbounds: () => {
        return db.prepare('SELECT * FROM inbounds ORDER BY created_at DESC').all();
    },

    getInboundById: (id) => {
        return db.prepare('SELECT * FROM inbounds WHERE id = ?').get(id);
    },

    createInbound: (data) => {
        const stmt = db.prepare(`
            INSERT INTO inbounds (
                tag, remark, protocol, port, network, security, 
                tls_sni, ws_path, grpc_service, reality_pbk, reality_sid,
                header_type, xhttp_mode, enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        
        return stmt.run(
            data.tag || `inbound-${Date.now()}`,
            data.remark,
            data.protocol,
            data.port,
            data.network,
            data.security,
            data.tls_sni || null,
            data.ws_path || null,
            data.grpc_service || null,
            data.reality_pbk || null,
            data.reality_sid || null,
            data.header_type || null,
            data.xhttp_mode || null,
            data.enabled !== false ? 1 : 0
        );
    },

    updateInbound: (id, data) => {
        const stmt = db.prepare(`
            UPDATE inbounds SET
                remark = ?, protocol = ?, port = ?, network = ?, security = ?,
                tls_sni = ?, ws_path = ?, grpc_service = ?, reality_pbk = ?,
                reality_sid = ?, header_type = ?, xhttp_mode = ?, enabled = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `);
        
        return stmt.run(
            data.remark,
            data.protocol,
            data.port,
            data.network,
            data.security,
            data.tls_sni || null,
            data.ws_path || null,
            data.grpc_service || null,
            data.reality_pbk || null,
            data.reality_sid || null,
            data.header_type || null,
            data.xhttp_mode || null,
            data.enabled !== false ? 1 : 0,
            id
        );
    },

    deleteInbound: (id) => {
        return db.prepare('DELETE FROM inbounds WHERE id = ?').run(id);
    },

    // Clients
    getAllClients: (search = '', inbound_id = null) => {
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
                CASE 
                    WHEN c.expire_date IS NOT NULL AND c.expire_date < datetime('now') THEN 1
                    ELSE 0
                END as is_expired,
                CASE
                    WHEN c.traffic_limit > 0 AND c.traffic_used >= c.traffic_limit THEN 1
                    ELSE 0
                END as over_traffic
            FROM clients c
            LEFT JOIN inbounds i ON c.inbound_id = i.id
            WHERE 1=1
        `;
        
        const params = [];
        
        if (search) {
            query += ' AND (c.name LIKE ? OR c.email LIKE ? OR c.note LIKE ?)';
            const searchPattern = `%${search}%`;
            params.push(searchPattern, searchPattern, searchPattern);
        }
        
        if (inbound_id) {
            query += ' AND c.inbound_id = ?';
            params.push(inbound_id);
        }
        
        query += ' ORDER BY c.created_at DESC';
        
        return db.prepare(query).all(...params);
    },

    getClientById: (id) => {
        return db.prepare(`
            SELECT c.*, i.* FROM clients c
            LEFT JOIN inbounds i ON c.inbound_id = i.id
            WHERE c.id = ?
        `).get(id);
    },

    createClient: (data) => {
        const uuid = data.custom_uuid || uuidv4();
        const subToken = uuidv4();
        
        const expireDate = data.expire_days && data.expire_days > 0
            ? new Date(Date.now() + data.expire_days * 24 * 60 * 60 * 1000).toISOString()
            : null;
        
        const trafficLimit = data.traffic_limit_gb && data.traffic_limit_gb > 0
            ? data.traffic_limit_gb * 1024 * 1024 * 1024
            : 0;
        
        const stmt = db.prepare(`
            INSERT INTO clients (
                inbound_id, name, uuid, email, traffic_limit, expire_date,
                max_connections, enabled, sub_token, note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        
        return stmt.run(
            data.inbound_id,
            data.name,
            uuid,
            data.email || null,
            trafficLimit,
            expireDate,
            data.max_connections || 2,
            data.enabled !== false ? 1 : 0,
            subToken,
            data.note || null
        );
    },

    updateClient: (id, data) => {
        const updates = [];
        const params = [];
        
        if (data.name !== undefined) {
            updates.push('name = ?');
            params.push(data.name);
        }
        if (data.email !== undefined) {
            updates.push('email = ?');
            params.push(data.email);
        }
        if (data.note !== undefined) {
            updates.push('note = ?');
            params.push(data.note);
        }
        if (data.traffic_limit_gb !== undefined) {
            const trafficLimit = data.traffic_limit_gb > 0 
                ? data.traffic_limit_gb * 1024 * 1024 * 1024 
                : 0;
            updates.push('traffic_limit = ?');
            params.push(trafficLimit);
        }
        if (data.expire_days !== undefined) {
            const expireDate = data.expire_days > 0
                ? new Date(Date.now() + data.expire_days * 24 * 60 * 60 * 1000).toISOString()
                : null;
            updates.push('expire_date = ?');
            params.push(expireDate);
        }
        if (data.max_connections !== undefined) {
            updates.push('max_connections = ?');
            params.push(data.max_connections);
        }
        if (data.enabled !== undefined) {
            updates.push('enabled = ?');
            params.push(data.enabled ? 1 : 0);
        }
        if (data.reset_traffic) {
            updates.push('traffic_used = 0, up_bytes = 0, down_bytes = 0');
        }
        
        updates.push('updated_at = CURRENT_TIMESTAMP');
        params.push(id);
        
        const query = `UPDATE clients SET ${updates.join(', ')} WHERE id = ?`;
        return db.prepare(query).run(...params);
    },

    deleteClient: (id) => {
        return db.prepare('DELETE FROM clients WHERE id = ?').run(id);
    },

    resetClientTraffic: (id) => {
        return db.prepare(`
            UPDATE clients 
            SET traffic_used = 0, up_bytes = 0, down_bytes = 0, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(id);
    },

    // Stats
    getStats: () => {
        const total = db.prepare('SELECT COUNT(*) as count FROM clients').get().count;
        const active = db.prepare(`
            SELECT COUNT(*) as count FROM clients 
            WHERE enabled = 1 
            AND (expire_date IS NULL OR expire_date > datetime('now'))
            AND (traffic_limit = 0 OR traffic_used < traffic_limit)
        `).get().count;
        const expired = db.prepare(`
            SELECT COUNT(*) as count FROM clients 
            WHERE expire_date IS NOT NULL AND expire_date < datetime('now')
        `).get().count;
        const disabled = db.prepare('SELECT COUNT(*) as count FROM clients WHERE enabled = 0').get().count;
        const totalInbounds = db.prepare('SELECT COUNT(*) as count FROM inbounds').get().count;
        const totalTraffic = db.prepare(`
            SELECT SUM(up_bytes + down_bytes) as total FROM clients
        `).get().total || 0;

        return {
            total,
            active,
            expired,
            disabled,
            total_inbounds: totalInbounds,
            total_traffic: totalTraffic
        };
    },

    // Settings
    getSetting: (key) => {
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
        return row ? JSON.parse(row.value) : null;
    },

    setSetting: (key, value) => {
        return db.prepare(`
            INSERT INTO settings (key, value, updated_at) 
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET 
                value = excluded.value, 
                updated_at = CURRENT_TIMESTAMP
        `).run(key, JSON.stringify(value));
    },

    getAllSettings: () => {
        const rows = db.prepare('SELECT key, value FROM settings').all();
        const settings = {};
        rows.forEach(row => {
            settings[row.key] = JSON.parse(row.value);
        });
        return settings;
    }
};

// Initialize database on load
initDatabase();

module.exports = {
    db,
    ...dbHelpers
};
