'use strict';

// Role -> permissions. Routes check PERMISSIONS, never role names (except /admin).
const ROLE_PERMISSIONS = Object.freeze({
  waiter: Object.freeze(['orders:create', 'orders:read']),
  cashier: Object.freeze(['orders:read', 'payments:create']),
  manager: Object.freeze(['orders:read', 'reports:read']),
  admin: Object.freeze(['users:manage', 'orders:read', 'reports:read']),
});

// Deny by default: an unknown role (or a missing one) gets NO permissions.
function permissionsFor(role) {
  return Object.prototype.hasOwnProperty.call(ROLE_PERMISSIONS, role)
    ? ROLE_PERMISSIONS[role]
    : [];
}

function hasPermission(role, permission) {
  return permissionsFor(role).includes(permission);
}

module.exports = { ROLE_PERMISSIONS, permissionsFor, hasPermission };
