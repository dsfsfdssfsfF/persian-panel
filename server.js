const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const path = require('path');
const fs = require('fs');

// Load env
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
// Serve panel at /panel and also at root
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

// ===== Subscription Endpoint =====
app.get('/sub/:token', (req, res) => {
    try {
        const client = db.getClientBySubToken(req.params.token);
        if (!client) {
            return res.status(404).send('Not Found');
        }

        // Build config based on protocol
        const domain = process.env.DOMAIN || req.headers.host || 'localhost';
        let link = '';

        const protocol = client.i_protocol || 'vless';
        const network = client.i_network || 'ws';
        const port = client.i_port || 443;
        const wsPath = client.ws_path || '/ws';
        const sni = client.tls_sni || domain;

        if (protocol === 'vless') {
            link = `vless://${client.uuid}@${domain}:${port}?type=${network}&security=tls&path=${encodeURIComponent(wsPath)}&host=${domain}&sni=${sni}#${encodeURIComponent(client.name)}`;
        } else if (protocol === 'vmess') {
            const vmessConfig = {
                v: "2", ps: client.name, add: domain, port: port,
                id: client.uuid, aid: 0, scy: "auto", net: network,
                type: "none", host: domain, path: wsPath,
                tls: "tls", sni: sni
            };
            link = 'vmess://' + Buffer.from(JSON.stringify(vmessConfig)).toString('base64');
        } else if (protocol === 'trojan') {
            link = `trojan://${client.uuid}@${domain}:${port}?type=${network}&security=tls&path=${encodeURIComponent(wsPath)}&host=${domain}&sni=${sni}#${encodeURIComponent(client.name)}`;
        }

        const output = Buffer.from(link).toString('base64');
        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.set('Content-Disposition', `attachment; filename="${client.name}.txt"`);
        res.send(output);

    } catch (err) {
        res.status(500).send('Error');
    }
});

// ===== Sub Info Page =====
app.get('/sub/info/:token', (req, res) => {
    try {
        const client = db.getClientBySubToken(req.params.token);
        if (!client) {
            return res.status(404).send('Not Found');
        }
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } catch (err) {
        res.status(500).send('Error');
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
    console.log('   PERSIAN PANEL');
    console.log('   ══════════════════════════════════════════');
    console.log(`   🚀 Port: ${PORT}`);
    console.log(`   🌐 Panel: http://0.0.0.0:${PORT}${PANEL_PATH}`);
    console.log(`   📂 Env: ${process.env.NODE_ENV || 'development'}`);
    console.log('   ══════════════════════════════════════════');
    console.log('');
});
