// Middleware برای بررسی احراز هویت

function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ 
            error: 'لطفا ابتدا وارد سیستم شوید',
            code: 'UNAUTHORIZED' 
        });
    }
    next();
}

function isAuthenticated(req) {
    return req.session && req.session.user;
}

function getCurrentUser(req) {
    return req.session?.user || null;
}

module.exports = {
    requireAuth,
    isAuthenticated,
    getCurrentUser
};
