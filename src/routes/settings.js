const express = require('express');
const router = express.Router();
const { getAllSettings, setSetting } = require('../db/database');
const { requireAuth } = require('../middleware/auth');

// همه route ها نیاز به احراز هویت دارند
router.use(requireAuth);

// GET /api/settings - دریافت تنظیمات
router.get('/', (req, res) => {
    try {
        const settings = getAllSettings();
        res.json(settings);
    } catch (error) {
        console.error('Get settings error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/settings - ذخیره تنظیمات
router.post('/', (req, res) => {
    try {
        const { panel_name, cf_domain, theme, lang } = req.body;

        if (panel_name) setSetting('panel_name', panel_name);
        if (cf_domain !== undefined) setSetting('cf_domain', cf_domain);
        if (theme) setSetting('theme', theme);
        if (lang) setSetting('lang', lang);

        res.json({
            success: true,
            message: 'تنظیمات با موفقیت ذخیره شد'
        });
    } catch (error) {
        console.error('Save settings error:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
