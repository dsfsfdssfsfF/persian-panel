const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 2053;

// Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Disable for inline scripts in production adjust as needed
}));
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'persian-panel-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Static files
const panelPath = process.env.PANEL_PATH || '/panel';
app.use(panelPath, express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// API Routes (import from src/routes/)
const authRoutes = require('./src/routes/auth');
const clientsRoutes = require('./src/routes/clients');
const inboundsRoutes = require('./src/routes/inbounds');
const settingsRoutes = require('./src/routes/settings');

app.use('/api/auth', authRoutes);
app.use('/api/clients', clientsRoutes);
app.use('/api/inbounds', inboundsRoutes);
app.use('/api/settings', settingsRoutes);

// Stats endpoint
app.get('/api/stats', (req, res) => {
    // TODO: Implement real stats from database
    res.json({
        total: 0,
        active: 0,
        expired: 0,
        disabled: 0,
        total_inbounds: 0,
        total_traffic: 0
    });
});

// Server info endpoint
app.get('/api/server-info', (req, res) => {
    res.json({
        domain: process.env.DOMAIN || 'localhost',
        uptime: Math.floor(process.uptime()),
        memory: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
        node: process.version,
        env: process.env.NODE_ENV || 'development',
        panel_path: panelPath
    });
});

// Catch all for SPA
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal server error'
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log('\n🇮🇷 ═══════════════════════════════════════════════════');
    console.log('   PERSIAN PANEL - Advanced VPN Management System');
    console.log('   ═══════════════════════════════════════════════════');
    console.log(`   🚀 Server running on port ${PORT}`);
    console.log(`   🌐 Panel URL: http://localhost${panelPath}`);
    console.log(`   📂 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`   🗄️ Database: ${process.env.DATABASE_URL || 'SQLite'}`);
    console.log('   ═══════════════════════════════════════════════════\n');
});

module.exports = app;
