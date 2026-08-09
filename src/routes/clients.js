const express = require('express');
const router = express.Router();
const db = require('../db/database');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

// GET /api/clients
router.get('/', (req, res) => {
    try {
        const { search, inbound_id } = req.query;
        res.json(db.getAllClients(search || '', inbound_id || null));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/clients
router.post('/', (req, res) => {
    try {
        const { inbound_id, name } = req.body;
        if (!inbound_id || !name) {
            return res.status(400).json({ error: 'Inbound و نام الزامی است' });
        }

        // Check inbound exists
        const inbound = db.getInboundById(inbound_id);
        if (!inbound) {
            return res.status(400).json({ error: 'Inbound یافت نشد' });
        }

        const result = db.createClient(req.body);
        res.status(201).json({ success: true, id: result.lastInsertRowid });
    } catch (err) {
        console.error('Create client error:', err);
        res.status(500).json({ error: err.message });
    }
});

// PUT /api/clients/:id
router.put('/:id', (req, res) => {
    try {
        const client = db.getClientById(req.params.id);
        if (!client) return res.status(404).json({ error: 'کاربر یافت نشد' });

        db.updateClient(req.params.id, req.body);
        res.json({ success: true });
    } catch (err) {
        console.error('Update client error:', err);
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/clients/:id
router.delete('/:id', (req, res) => {
    try {
        const client = db.getClientById(req.params.id);
        if (!client) return res.status(404).json({ error: 'کاربر یافت نشد' });

        db.deleteClient(req.params.id);
        res.json({ success: true });
    } catch (err) {
        console.error('Delete client error:', err);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/clients/:id/reset-traffic
router.post('/:id/reset-traffic', (req, res) => {
    try {
        const client = db.getClientById(req.params.id);
        if (!client) return res.status(404).json({ error: 'کاربر یافت نشد' });

        db.resetClientTraffic(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/clients/:id/config
router.get('/:id/config', (req, res) => {
    try {
        const client = db.getClientById(req.params.id);
        if (!client) return res.status(404).json({ error: 'کاربر یافت نشد' });

        const domain = process.env.DOMAIN || req.headers.host || 'localhost';
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
            if (network === 'ws') link += `&path=${encodeURIComponent(wsPath)}&host=${domain}`;
            if (network === 'grpc') link += `&serviceName=${client.grpc_service || ''}`;
            if (security === 'tls') link += `&sni=${sni}`;
            if (security === 'reality') link += `&sni=${sni}&pbk=${client.reality_pbk || ''}&sid=${client.reality_sid || ''}`;
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
            if (network === 'ws') link += `&path=${encodeURIComponent(wsPath)}&host=${domain}`;
            if (security === 'tls') link += `&sni=${sni}`;
            link += `#${encodeURIComponent(client.name)}`;
        }

        const subUrl = `https://${domain}/sub/${client.sub_token}`;

        res.json({
            link,
            subUrl,
            uuid: client.uuid,
            protocol,
            network
        });
    } catch (err) {
        console.error('Get config error:', err);
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
