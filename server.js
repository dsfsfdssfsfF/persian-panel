const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const path = require('path');
const fs = require('fs');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 2053;
const PANEL_PATH = process.env.PANEL_PATH || '/panel';

// ===== Create data directory =====
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log('📁 Data directory created');
}

// ===== Middleware =====
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET || 'persian-panel-secret-' + Date.now(),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// ===== Static Files =====
app.use(PANEL_PATH, express.static(path.join(__dirname, 'public')));
app.use('/', express.static(path.join(__dirname, 'public')));

// ===== Health Check =====
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'OK', time: new Date().toISOString() });
});

// ===== Initialize Database =====
let db;
try {
    db = require('./src/db/database');
    console.log('✅ Database loaded');
} catch (err) {
    console.error('❌ Database error:', err.message);
    process.exit(1);
}

// ===== API Routes =====
try {
    app.use('/api/auth', require('./src/routes/auth'));
    app.use('/api/clients', require('./src/routes/clients'));
    app.use('/api/inbounds', require('./src/routes/inbounds'));
    app.use('/api/settings', require('./src/routes/settings'));
    console.log('✅ Routes loaded');
} catch (err) {
    console.error('❌ Routes error:', err.message);
    process.exit(1);
}

// ===== Stats Endpoint =====
app.get('/api/stats', (req, res) => {
    try {
        const stats = db.getStats();
        res.json(stats);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ===== Server Info Endpoint =====
app.get('/api/server-info', (req, res) => {
    const uptime = process.uptime();
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const mem = process.memoryUsage();

    res.json({
        domain: process.env.DOMAIN || 'localhost',
        uptime: `${hours} ساعت ${minutes} دقیقه`,
        memory: `${Math.round(mem.heapUsed / 1024 / 1024)} MB / ${Math.round(mem.heapTotal / 1024 / 1024)} MB`,
        node: process.version,
        env: process.env.NODE_ENV || 'development',
        panel_path: PANEL_PATH
    });
});

// ===== Build Config Link Helper =====
function buildConfigLink(client, domain) {
    const protocol = client.i_protocol || 'vless';
    const network = client.i_network || 'ws';
    const port = client.i_port || 443;
    const wsPath = client.ws_path || '/ws';
    const sni = client.tls_sni || domain;
    const security = client.i_security || 'none';

    let link = '';

    if (protocol === 'vless') {
        link = `vless://${client.uuid}@${domain}:${port}`;
        link += `?type=${network}&security=${security}`;
        if (network === 'ws' || network === 'httpupgrade' || network === 'xhttp') {
            link += `&path=${encodeURIComponent(wsPath)}&host=${domain}`;
        }
        if (network === 'grpc') {
            link += `&serviceName=${client.grpc_service || ''}`;
        }
        if (security === 'tls') {
            link += `&sni=${sni}`;
        }
        if (security === 'reality') {
            link += `&sni=${sni}&pbk=${client.reality_pbk || ''}&sid=${client.reality_sid || ''}&fp=chrome`;
        }
        link += `&flow=`;
        link += `#${encodeURIComponent(client.name)}`;

    } else if (protocol === 'vmess') {
        const cfg = {
            v: "2",
            ps: client.name,
            add: domain,
            port: port,
            id: client.uuid,
            aid: 0,
            scy: "auto",
            net: network,
            type: "none",
            host: domain,
            path: wsPath,
            tls: security === 'tls' ? 'tls' : '',
            sni: sni
        };
        link = 'vmess://' + Buffer.from(JSON.stringify(cfg)).toString('base64');

    } else if (protocol === 'trojan') {
        link = `trojan://${client.uuid}@${domain}:${port}`;
        link += `?type=${network}&security=${security}`;
        if (network === 'ws' || network === 'httpupgrade') {
            link += `&path=${encodeURIComponent(wsPath)}&host=${domain}`;
        }
        if (network === 'grpc') {
            link += `&serviceName=${client.grpc_service || ''}`;
        }
        if (security === 'tls') {
            link += `&sni=${sni}`;
        }
        link += `#${encodeURIComponent(client.name)}`;
    }

    return { link, protocol, network, security };
}

// ===== Subscription Endpoint (raw config for apps) =====
app.get('/sub/:token', (req, res) => {
    try {
        const client = db.getClientBySubToken(req.params.token);
        if (!client) {
            return res.status(404).send('Not Found');
        }

        // Check if client is active
        if (!client.enabled) {
            return res.status(403).send('Account Disabled');
        }

        const domain = process.env.DOMAIN || req.headers.host || 'localhost';
        const { link } = buildConfigLink(client, domain);

        const output = Buffer.from(link).toString('base64');

        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.set('Profile-Title', Buffer.from(client.name).toString('base64'));
        res.set('Subscription-UserInfo',
            `upload=${client.up_bytes || 0}; download=${client.down_bytes || 0}; total=${client.traffic_limit || 0}; expire=${client.expire_date ? Math.floor(new Date(client.expire_date).getTime() / 1000) : 0}`
        );
        res.set('Content-Disposition', `attachment; filename="${client.name}.txt"`);
        res.send(output);

    } catch (err) {
        console.error('Sub error:', err);
        res.status(500).send('Error');
    }
});

// ===== Sub Info API (for sub.html page) =====
app.get('/api/sub/info/:token', (req, res) => {
    try {
        const client = db.getClientBySubToken(req.params.token);
        if (!client) {
            return res.status(404).json({ error: 'Not found' });
        }

        const domain = process.env.DOMAIN || req.headers.host || 'localhost';
        const { link, protocol, network, security } = buildConfigLink(client, domain);
        const subUrl = `https://${domain}/sub/${client.sub_token}`;

        const isExpired = client.expire_date && new Date(client.expire_date) < new Date();
        const overTraffic = client.traffic_limit > 0 && client.traffic_used >= client.traffic_limit;

        res.json({
            name: client.name,
            email: client.email,
            uuid: client.uuid,
            enabled: client.enabled === 1,
            traffic_limit: client.traffic_limit,
            traffic_used: client.traffic_used,
            up_bytes: client.up_bytes || 0,
            down_bytes: client.down_bytes || 0,
            expire_date: client.expire_date,
            max_connections: client.max_connections,
            is_expired: isExpired,
            over_traffic: overTraffic,
            protocol: protocol,
            network: network,
            security: security,
            link: link,
            subUrl: subUrl
        });
    } catch (err) {
        console.error('Sub info error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== Sub Info Page (serves sub.html) =====
app.get('/sub/info/:token', (req, res) => {
    const subPath = path.join(__dirname, 'public', 'sub.html');
    if (fs.existsSync(subPath)) {
        res.sendFile(subPath);
    } else {
        res.status(404).send('Sub page not found. Make sure public/sub.html exists.');
    }
});

// ===== SPA Fallback =====
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'Endpoint not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== Error Handler =====
app.use((err, req, res, next) => {
    console.error('💥 Error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ===== Start Server =====
app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('🇮🇷 ══════════════════════════════════════════');
    console.log('   PERSIAN PANEL v1.0.0');
    console.log('   ──────────────────────────────────────────');
    console.log(`   🚀 Port: ${PORT}`);
    console.log(`   🌐 Panel: http://0.0.0.0:${PORT}${PANEL_PATH}`);
    console.log(`   📡 Sub URL: http://0.0.0.0:${PORT}/sub/TOKEN`);
    console.log(`   📄 Sub Info: http://0.0.0.0:${PORT}/sub/info/TOKEN`);
    console.log(`   📂 Env: ${process.env.NODE_ENV || 'development'}`);
    console.log('   ══════════════════════════════════════════');
    console.log('');
});

module.exports = app;
