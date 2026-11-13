'use strict';
const { hasPermission } = require('../permissions');

// Both assume authenticate already ran. Missing req.user => 401, not 403.
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    return next();
  };
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!hasPermission(req.user.role, permission)) return res.status(403).json({ error: 'Forbidden' });
    return next();
  };
}

module.exports = { requireRole, requirePermission };
