const express = require('express');
const router = express.Router();
const { 
    getAllClients, 
    getClientById, 
    createClient, 
    updateClient, 
    deleteClient,
    resetClientTraffic 
} = require('../db/database');
const { requireAuth } = require('../middleware/auth');

// همه route ها نیاز به احراز هویت دارند
router.use(requireAuth);

// GET /api/clients - دریافت لیست کاربران
router.get('/', (req, res) => {
    try {
        const { search = '', inbound_id } = req.query;
        const clients = getAllClients(search, inbound_id);
        res.json(clients);
    } catch (error) {
        console.error('Get clients error:', error);
        res.status(500).json({ error: error.message });
    }
});

// GET /api/clients/:id - دریافت اطلاعات یک کاربر
router.get('/:id', (req, res) => {
    try {
        const client = getClientById(req.params.id);
        if (!client) {
            return res.status(404).json({ error: 'کاربر یافت نشد' });
        }
        res.json(client);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /api/clients - ایجاد کاربر جدید
router.post('/', (req, res) => {
    try {
        const { inbound_id, name } = req.body;

        if (!inbound_id || !name) {
            return res.status(400).json({ 
                error: 'Inbound و نام کاربر الزامی است' 
            });
        }

        const result = createClient(req.body);
        
        res.status(201).json({
            success: true,
            id: result.lastInsertRowid,
            message: 'کاربر با موفقیت ایجاد شد'
        });
    } catch (error) {
        console.error('Create client error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PUT /api/clients/:id - ویرایش کاربر
router.put('/:id', (req, res) => {
    try {
        const client = getClientById(req.params.id);
        if (!client) {
            return res.status(404).json({ error: 'کاربر یافت نشد' });
        }

        updateClient(req.params.id, req.body);
        
        res.json({
            success: true,
            message: 'کاربر با موفقیت ویرایش شد'
        });
    } catch (error) {
        console.error('Update client error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/clients/:id - حذف کاربر
router.delete('/:id', (req, res) => {
    try {
        const client = getClientById(req.params.id);
        if (!client) {
            return res.status(404).json({ error: 'کاربر یافت نشد' });
        }

        deleteClient(req.params.id);
        
        res.json({
            success: true,
            message: 'کاربر با موفقیت حذف شد'
        });
    } catch (error) {
        console.error('Delete client error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/clients/:id/reset-traffic - ریست ترافیک
router.post('/:id/reset-traffic', (req, res) => {
    try {
        const client = getClientById(req.params.id);
        if (!client) {
            return res.status(404).json({ error: 'کاربر یافت نشد' });
        }

        resetClientTraffic(req.params.id);
        
        res.json({
            success: true,
            message: 'ترافیک با موفقیت ریست شد'
        });
    } catch (error) {
        console.error('Reset traffic error:', error);
        res.status(500).json({ error: error.message });
    }
});

// GET /api/clients/:id/config - دریافت کانفیگ کاربر
router.get('/:id/config', (req, res) => {
    try {
        const client = getClientById(req.params.id);
        if (!client) {
            return res.status(404).json({ error: 'کاربر یافت نشد' });
        }

        // ساخت لینک کانفیگ (نمونه ساده - باید بر اساس پروتکل واقعی باشد)
        const domain = process.env.DOMAIN || 'localhost';
        const port = client.i_port || 443;
        const protocol = client.i_protocol || 'vless';
        
        let link = '';
        if (protocol === 'vless') {
            link = `vless://${client.uuid}@${domain}:${port}?type=${client.i_network || 'ws'}&security=${client.i_security || 'none'}`;
            if (client.ws_path) link += `&path=${encodeURIComponent(client.ws_path)}`;
            if (client.tls_sni) link += `&sni=${client.tls_sni}`;
            link += `#${encodeURIComponent(client.name)}`;
        }

        const subUrl = `https://${domain}/sub/${client.sub_token}`;

        res.json({
            link,
            subUrl,
            uuid: client.uuid,
            protocol: client.i_protocol,
            network: client.i_network
        });
    } catch (error) {
        console.error('Get config error:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
