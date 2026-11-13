'use strict';

// THE object-level authorization policy. Every route that returns or acts on an
// order MUST call this. Admins are chain-wide; everyone else is limited to their branch.
function canAccessOrder(user, order) {
  if (!user || !order) return false;
  if (user.role === 'admin') return true;
  return typeof user.branchId === 'string' && user.branchId === order.branchId;
}

module.exports = { canAccessOrder };
