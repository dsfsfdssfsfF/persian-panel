const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { getAdminByUsername, updateAdminPassword, updateAdminUsername } = require('../db/database');
const { requireAuth, getCurrentUser } = require('../middleware/auth');

// GET /api/auth/me - دریافت اطلاعات کاربر فعلی
router.get('/me', requireAuth, (req, res) => {
    try {
        const user = getCurrentUser(req);
        res.json({
            username: user.username,
            id: user.id
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /api/auth/login - ورود به سیستم
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ 
                error: 'نام کاربری و رمز عبور الزامی است' 
            });
        }

        const admin = getAdminByUsername(username);

        if (!admin) {
            return res.status(401).json({ 
                error: 'نام کاربری یا رمز عبور اشتباه است' 
            });
        }

        const isPasswordValid = await bcrypt.compare(password, admin.password);

        if (!isPasswordValid) {
            return res.status(401).json({ 
                error: 'نام کاربری یا رمز عبور اشتباه است' 
            });
        }

        // ایجاد session
        req.session.user = {
            id: admin.id,
            username: admin.username
        };

        res.json({
            success: true,
            user: {
                id: admin.id,
                username: admin.username
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'خطا در ورود به سیستم' });
    }
});

// POST /api/auth/logout - خروج از سیستم
router.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'خطا در خروج از سیستم' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

// POST /api/auth/change-password - تغییر رمز عبور
router.post('/change-password', requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword, newUsername } = req.body;
        const user = getCurrentUser(req);

        if (!currentPassword) {
            return res.status(400).json({ 
                error: 'رمز عبور فعلی الزامی است' 
            });
        }

        const admin = getAdminByUsername(user.username);
        const isPasswordValid = await bcrypt.compare(currentPassword, admin.password);

        if (!isPasswordValid) {
            return res.status(401).json({ 
                error: 'رمز عبور فعلی اشتباه است' 
            });
        }

        // تغییر رمز عبور
        if (newPassword) {
            if (newPassword.length < 4) {
                return res.status(400).json({ 
                    error: 'رمز عبور جدید باید حداقل 4 کاراکتر باشد' 
                });
            }
            updateAdminPassword(user.username, newPassword);
        }

        // تغییر نام کاربری
        if (newUsername && newUsername !== user.username) {
            updateAdminUsername(user.username, newUsername);
            req.session.user.username = newUsername;
        }

        res.json({ 
            success: true,
            message: 'تغییرات با موفقیت ذخیره شد' 
        });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'خطا در تغییر اطلاعات' });
    }
});

module.exports = router;
