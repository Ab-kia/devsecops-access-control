'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { makeAuthenticate } = require('./middleware/auth');
const { requireRole, requirePermission } = require('./middleware/rbac');
const { canAccessOrder } = require('./policy');

function createApp(config, store) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '10kb' }));

  const authenticate = makeAuthenticate(config, store);

  // A real bcrypt hash of a throwaway value: compared when the email is unknown so that
  // "unknown email" and "wrong password" take about the same time.
  const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

  // ---------- POST /api/auth/login ----------
  app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body || {}; // any role/branchId in the body is ignored
    const fail = () => res.status(401).json({ error: 'Invalid email or password' });
    if (typeof email !== 'string' || typeof password !== 'string') return fail();

    const user = store.users.find((x) => x.email === email.toLowerCase());
    const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
    if (!user || !ok || !user.active) return fail();

    const token = jwt.sign({ sub: user.id }, config.jwtSecret, {
      algorithm: config.jwtAlgorithm,
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      expiresIn: config.accessTokenTtlSeconds,
    });
    return res.json({ token, expiresIn: config.accessTokenTtlSeconds });
  });

  // ---------- Orders ----------
  const publicOrder = (o) => ({ ...o });

  app.get('/api/orders', authenticate, requirePermission('orders:read'), (req, res) => {
    res.json(store.orders.filter((o) => canAccessOrder(req.user, o)).map(publicOrder));
  });

  app.get('/api/orders/:id', authenticate, requirePermission('orders:read'), (req, res) => {
    const order = store.orders.find((o) => o.id === req.params.id);
    // 404 for "missing" AND "not yours": identical responses, so IDs cannot be probed.
    if (!order || !canAccessOrder(req.user, order)) return res.status(404).json({ error: 'Not found' });
    return res.json(publicOrder(order));
  });

  app.post('/api/orders', authenticate, requirePermission('orders:create'), (req, res) => {
    const { table, items } = req.body || {};
    const validItems = Array.isArray(items) && items.length >= 1 && items.length <= 50 &&
      items.every((i) => i && typeof i.name === 'string' && i.name.length >= 1 && i.name.length <= 60 &&
        Number.isInteger(i.qty) && i.qty >= 1 && i.qty <= 50 &&
        typeof i.price === 'number' && i.price > 0 && i.price <= 100000);
    if (typeof table !== 'string' || table.length < 1 || table.length > 20 || !validItems) {
      return res.status(400).json({ error: 'Invalid order' });
    }
    const clean = items.map((i) => ({ name: i.name, qty: i.qty, price: i.price }));
    const order = {
      id: String(store.nextOrderId++),
      branchId: req.user.branchId, // from verified identity - a branchId in the body is ignored
      table, items: clean, status: 'open', createdAt: new Date().toISOString(),
      total: clean.reduce((s, i) => s + i.qty * i.price, 0),
    };
    store.orders.push(order);
    return res.status(201).json(publicOrder(order));
  });

  // ---------- Payments (no card data ever touches this API) ----------
  app.post('/api/payments', authenticate, requirePermission('payments:create'), (req, res) => {
    const { orderId, amount } = req.body || {};
    const order = typeof orderId === 'string' ? store.orders.find((o) => o.id === orderId) : undefined;
    if (!order || !canAccessOrder(req.user, order)) return res.status(404).json({ error: 'Not found' });
    if (order.status === 'paid') return res.status(409).json({ error: 'Order already paid' });
    if (amount !== order.total) return res.status(400).json({ error: 'Amount does not match order total' });
    order.status = 'paid';
    const payment = { id: `p${store.nextPaymentId++}`, orderId: order.id, amount, takenBy: req.user.id };
    store.payments.push(payment);
    return res.status(201).json(payment);
  });

  // ---------- Report: branch comes from req.user, NEVER from the query string ----------
  app.get('/api/reports/branch', authenticate, requirePermission('reports:read'), (req, res) => {
    const scope = req.user.role === 'admin' ? null : req.user.branchId; // admin = whole chain
    const orders = store.orders.filter((o) => canAccessOrder(req.user, o) && (scope === null || o.branchId === scope));
    res.json({
      branchId: scope === null ? 'all' : scope,
      orderCount: orders.length,
      totalSales: orders.reduce((s, o) => s + o.total, 0),
      paidSales: orders.filter((o) => o.status === 'paid').reduce((s, o) => s + o.total, 0),
      orderIds: orders.map((o) => o.id),
    });
  });

  // ---------- Admin ----------
  app.get('/api/admin/users', authenticate, requireRole('admin'), (_req, res) => {
    res.json(store.users.map(({ id, name, email, role, branchId, active }) => ({ id, name, email, role, branchId, active })));
  });

  // ---------- Errors ----------
  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
    return res.status(500).json({ error: 'Internal error' }); // never leak err.message / stack
  });

  return app;
}

module.exports = { createApp };
