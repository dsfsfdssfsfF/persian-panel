const express = require('express');
const router = express.Router();
const { 
    getAllInbounds, 
    getInboundById, 
    createInbound, 
    updateInbound, 
    deleteInbound 
} = require('../db/database');
const { requireAuth } = require('../middleware/auth');

// همه route ها نیاز به احراز هویت دارند
router.use(requireAuth);

// GET /api/inbounds - دریافت لیست Inbounds
router.get('/', (req, res) => {
    try {
        const inbounds = getAllInbounds();
        res.json(inbounds);
    } catch (error) {
        console.error('Get inbounds error:', error);
        res.status(500).json({ error: error.message });
    }
});

// GET /api/inbounds/:id - دریافت اطلاعات یک Inbound
router.get('/:id', (req, res) => {
    try {
        const inbound = getInboundById(req.params.id);
        if (!inbound) {
            return res.status(404).json({ error: 'Inbound یافت نشد' });
        }
        res.json(inbound);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /api/inbounds - ایجاد Inbound جدید
router.post('/', (req, res) => {
    try {
        const { remark, protocol, port } = req.body;

        if (!remark || !protocol || !port) {
            return res.status(400).json({ 
                error: 'نام، پروتکل و پورت الزامی است' 
            });
        }

        const result = createInbound(req.body);
        
        res.status(201).json({
            success: true,
            id: result.lastInsertRowid,
            message: 'Inbound با موفقیت ایجاد شد'
        });
    } catch (error) {
        console.error('Create inbound error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PUT /api/inbounds/:id - ویرایش Inbound
router.put('/:id', (req, res) => {
    try {
        const inbound = getInboundById(req.params.id);
        if (!inbound) {
            return res.status(404).json({ error: 'Inbound یافت نشد' });
        }

        updateInbound(req.params.id, req.body);
        
        res.json({
            success: true,
            message: 'Inbound با موفقیت ویرایش شد'
        });
    } catch (error) {
        console.error('Update inbound error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/inbounds/:id - حذف Inbound
router.delete('/:id', (req, res) => {
    try {
        const inbound = getInboundById(req.params.id);
        if (!inbound) {
            return res.status(404).json({ error: 'Inbound یافت نشد' });
        }

        deleteInbound(req.params.id);
        
        res.json({
            success: true,
            message: 'Inbound با موفقیت حذف شد'
        });
    } catch (error) {
        console.error('Delete inbound error:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
