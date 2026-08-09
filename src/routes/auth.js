const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../db/database');
const { requireAuth } = require('../middleware/auth');

// GET /api/auth/me
router.get('/me', requireAuth, (req, res) => {
    res.json({
        id: req.session.user.id,
        username: req.session.user.username
    });
});

// POST /api/auth/login
router.post('/login', (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'نام کاربری و رمز عبور الزامی است' });
        }

        const admin = db.getAdminByUsername(username);
        if (!admin) {
            return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' });
        }

        const valid = bcrypt.compareSync(password, admin.password);
        if (!valid) {
            return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' });
        }

        req.session.user = { id: admin.id, username: admin.username };

        res.json({
            success: true,
            user: { id: admin.id, username: admin.username }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'خطا در ورود' });
    }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, (req, res) => {
    try {
        const { currentPassword, newPassword, newUsername } = req.body;

        if (!currentPassword) {
            return res.status(400).json({ error: 'رمز عبور فعلی الزامی است' });
        }

        const admin = db.getAdminByUsername(req.session.user.username);
        const valid = bcrypt.compareSync(currentPassword, admin.password);

        if (!valid) {
            return res.status(401).json({ error: 'رمز عبور فعلی اشتباه است' });
        }

        if (newPassword) {
            if (newPassword.length < 4) {
                return res.status(400).json({ error: 'رمز عبور حداقل ۴ کاراکتر باشد' });
            }
            db.updateAdminPassword(req.session.user.username, newPassword);
        }

        if (newUsername && newUsername !== req.session.user.username) {
            db.updateAdminUsername(req.session.user.username, newUsername);
            req.session.user.username = newUsername;
        }

        res.json({ success: true, message: 'با موفقیت ذخیره شد' });
    } catch (err) {
        console.error('Change password error:', err);
        res.status(500).json({ error: 'خطا در تغییر اطلاعات' });
    }
});

module.exports = router;
