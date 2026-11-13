'use strict';
const bcrypt = require('bcryptjs');

// In-memory data. All passwords below are INVENTED demo values; only bcrypt hashes are stored.
const DEMO_PASSWORD = 'Demo-Password-123!';

function createStore({ bcryptRounds = 10 } = {}) {
  const hash = bcrypt.hashSync(DEMO_PASSWORD, bcryptRounds);
  const u = (id, name, email, role, branchId) => ({
    id, name, email, role, branchId, active: true, passwordHash: hash,
  });

  const users = [
    u('u1', 'Abebe (Bole waiter)', 'waiter.bole@dinedesk.test', 'waiter', 'bole'),
    u('u2', 'Tigist (Piassa waiter)', 'waiter.piassa@dinedesk.test', 'waiter', 'piassa'),
    u('u3', 'Dawit (Bole cashier)', 'cashier.bole@dinedesk.test', 'cashier', 'bole'),
    u('u4', 'Hana (Piassa cashier)', 'cashier.piassa@dinedesk.test', 'cashier', 'piassa'),
    u('u5', 'Meron (Bole manager)', 'manager.bole@dinedesk.test', 'manager', 'bole'),
    u('u6', 'Yonas (Piassa manager)', 'manager.piassa@dinedesk.test', 'manager', 'piassa'),
    u('u7', 'Selam (administrator)', 'admin@dinedesk.test', 'admin', null),
  ];

  const now = new Date().toISOString();
  const order = (id, branchId, table, items, status = 'open') => ({
    id, branchId, table, items, status, createdAt: now,
    total: items.reduce((s, i) => s + i.qty * i.price, 0),
  });

  const orders = [
    order('1001', 'bole', 'B1', [{ name: 'Tibs', qty: 2, price: 350 }]),
    order('1002', 'bole', 'B2', [{ name: 'Kitfo', qty: 1, price: 420 }], 'paid'),
    order('1003', 'piassa', 'P1', [{ name: 'Shiro', qty: 3, price: 180 }]),
    order('1004', 'piassa', 'P2', [{ name: 'Doro Wat', qty: 1, price: 450 }], 'paid'),
  ];

  return { users, orders, payments: [], nextOrderId: 1005, nextPaymentId: 1 };
}

module.exports = { createStore, DEMO_PASSWORD };
