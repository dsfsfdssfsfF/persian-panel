const express = require('express');
const router = express.Router();
const db = require('../db/database');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

// GET /api/settings
router.get('/', (req, res) => {
    try {
        res.json(db.getAllSettings());
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/settings
router.post('/', (req, res) => {
    try {
        const { panel_name, cf_domain, theme } = req.body;

        if (panel_name !== undefined) db.setSetting('panel_name', panel_name);
        if (cf_domain !== undefined) db.setSetting('cf_domain', cf_domain);
        if (theme !== undefined) db.setSetting('theme', theme);

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ===== Outbounds =====
// GET /api/settings/outbounds
router.get('/outbounds', (req, res) => {
    try {
        res.json(db.getAllOutbounds());
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/settings/outbounds
router.post('/outbounds', (req, res) => {
    try {
        const result = db.createOutbound(req.body);
        res.status(201).json({ success: true, id: result.lastInsertRowid });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/settings/outbounds/:id
router.delete('/outbounds/:id', (req, res) => {
    try {
        db.deleteOutbound(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ===== Routing =====
// GET /api/settings/routing
router.get('/routing', (req, res) => {
    try {
        res.json(db.getAllRoutingRules());
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/settings/routing
router.post('/routing', (req, res) => {
    try {
        const result = db.createRoutingRule(req.body);
        res.status(201).json({ success: true, id: result.lastInsertRowid });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/settings/routing/:id
router.delete('/routing/:id', (req, res) => {
    try {
        db.deleteRoutingRule(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ===== Hosts =====
// GET /api/settings/hosts
router.get('/hosts', (req, res) => {
    try {
        res.json(db.getAllHosts());
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/settings/hosts
router.post('/hosts', (req, res) => {
    try {
        const result = db.createHost(req.body);
        res.status(201).json({ success: true, id: result.lastInsertRowid });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/settings/hosts/:id
router.delete('/hosts/:id', (req, res) => {
    try {
        db.deleteHost(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
