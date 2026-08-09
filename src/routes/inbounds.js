const express = require('express');
const router = express.Router();
const db = require('../db/database');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

// GET /api/inbounds
router.get('/', (req, res) => {
    try {
        res.json(db.getAllInbounds());
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/inbounds/:id
router.get('/:id', (req, res) => {
    try {
        const inbound = db.getInboundById(req.params.id);
        if (!inbound) return res.status(404).json({ error: 'یافت نشد' });
        res.json(inbound);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/inbounds
router.post('/', (req, res) => {
    try {
        const { remark, protocol, port } = req.body;
        if (!remark || !protocol || !port) {
            return res.status(400).json({ error: 'نام، پروتکل و پورت الزامی است' });
        }

        const result = db.createInbound(req.body);
        res.status(201).json({ success: true, id: result.lastInsertRowid });
    } catch (err) {
        console.error('Create inbound error:', err);
        res.status(500).json({ error: err.message });
    }
});

// PUT /api/inbounds/:id
router.put('/:id', (req, res) => {
    try {
        const inbound = db.getInboundById(req.params.id);
        if (!inbound) return res.status(404).json({ error: 'یافت نشد' });

        db.updateInbound(req.params.id, req.body);
        res.json({ success: true });
    } catch (err) {
        console.error('Update inbound error:', err);
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/inbounds/:id
router.delete('/:id', (req, res) => {
    try {
        const inbound = db.getInboundById(req.params.id);
        if (!inbound) return res.status(404).json({ error: 'یافت نشد' });

        db.deleteInbound(req.params.id);
        res.json({ success: true });
    } catch (err) {
        console.error('Delete inbound error:', err);
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
