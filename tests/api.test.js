'use strict';
const crypto = require('crypto');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const { loadConfig } = require('../src/config');
const { createStore, DEMO_PASSWORD } = require('../src/store');
const { createApp } = require('../src/app');
const { permissionsFor } = require('../src/permissions');
const { canAccessOrder } = require('../src/policy');

// The signing key is generated fresh for every test run: no real secret is needed, anywhere.
const TEST_SECRET = crypto.randomBytes(32).toString('hex');
const config = loadConfig({ JWT_SECRET: TEST_SECRET });

let store;
let app;
beforeEach(() => {
  store = createStore({ bcryptRounds: 4 }); // low cost = fast tests
  app = createApp(config, store);
});

const claims = { issuer: config.jwtIssuer, audience: config.jwtAudience };
const tokenFor = (userId, opts = {}) =>
  jwt.sign({ sub: userId }, opts.secret || TEST_SECRET, {
    algorithm: 'HS256', expiresIn: 600, ...claims, ...opts.sign,
  });
const auth = (userId) => ({ Authorization: `Bearer ${tokenFor(userId)}` });
const idOf = (email) => store.users.find((u) => u.email === email).id;

describe('authentication -> 401', () => {
  test('no token -> 401', async () => {
    const res = await request(app).get('/api/orders');
    expect(res.status).toBe(401);
  });

  test('non-Bearer scheme -> 401', async () => {
    const res = await request(app).get('/api/orders').set('Authorization', 'Basic abc');
    expect(res.status).toBe(401);
  });

  test('token signed with the wrong key -> 401', async () => {
    const bad = tokenFor('u1', { secret: crypto.randomBytes(32).toString('hex') });
    const res = await request(app).get('/api/orders').set('Authorization', `Bearer ${bad}`);
    expect(res.status).toBe(401);
  });

  test('expired token -> 401', async () => {
    const expired = jwt.sign(
      { sub: 'u1', exp: Math.floor(Date.now() / 1000) - 60 },
      TEST_SECRET, { algorithm: 'HS256', ...claims },
    );
    const res = await request(app).get('/api/orders').set('Authorization', `Bearer ${expired}`);
    expect(res.status).toBe(401);
  });

  test('"alg: none" token -> 401', async () => {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'u7', iss: config.jwtIssuer, aud: config.jwtAudience, exp: 9999999999 })}.AAAA`;
    const res = await request(app).get('/api/orders').set('Authorization', `Bearer ${forged}`);
    expect(res.status).toBe(401);
  });

  test('wrong audience -> 401', async () => {
    const bad = tokenFor('u1', { sign: { audience: 'someone-else' } });
    const res = await request(app).get('/api/orders').set('Authorization', `Bearer ${bad}`);
    expect(res.status).toBe(401);
  });

  test('valid token for a disabled user -> 401 (cut off immediately)', async () => {
    const id = idOf('cashier.bole@dinedesk.test');
    store.users.find((u) => u.id === id).active = false;
    const res = await request(app).get('/api/orders').set(auth(id));
    expect(res.status).toBe(401);
  });

  test('x-user-role header cannot raise privileges', async () => {
    const res = await request(app).get('/api/admin/users')
      .set(auth(idOf('waiter.bole@dinedesk.test'))).set('x-user-role', 'admin');
    expect(res.status).toBe(403);
  });
});

describe('login', () => {
  test('success returns a short-lived token and ignores role/branch in the body', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'waiter.bole@dinedesk.test', password: DEMO_PASSWORD, role: 'admin', branchId: 'piassa',
    });
    expect(res.status).toBe(200);
    const payload = jwt.decode(res.body.token);
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(900);
    expect(payload.iss).toBe(config.jwtIssuer);
    expect(payload.aud).toBe(config.jwtAudience);
    expect(Object.keys(payload).sort()).toEqual(['aud', 'exp', 'iat', 'iss', 'sub']);
    const me = await request(app).get('/api/admin/users').set('Authorization', `Bearer ${res.body.token}`);
    expect(me.status).toBe(403); // still a waiter
  });

  test('wrong email and wrong password give the same generic error', async () => {
    const a = await request(app).post('/api/auth/login').send({ email: 'nobody@dinedesk.test', password: 'x' });
    const b = await request(app).post('/api/auth/login').send({ email: 'waiter.bole@dinedesk.test', password: 'wrong' });
    expect(a.status).toBe(401);
    expect(b.status).toBe(401);
    expect(a.body).toEqual(b.body);
  });
});

describe('role / permission checks -> 403', () => {
  test('waiter calling GET /api/admin/users -> 403', async () => {
    const res = await request(app).get('/api/admin/users').set(auth(idOf('waiter.bole@dinedesk.test')));
    expect(res.status).toBe(403);
  });

  test('administrator calling GET /api/admin/users -> 200 with no password hashes', async () => {
    const res = await request(app).get('/api/admin/users').set(auth(idOf('admin@dinedesk.test')));
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(store.users.length);
    const text = JSON.stringify(res.body);
    expect(text).not.toMatch(/passwordHash/i);
    expect(text).not.toContain('$2'); // bcrypt hash prefix
  });

  test('waiter creating an order -> 201, branch taken from identity', async () => {
    const res = await request(app).post('/api/orders')
      .set(auth(idOf('waiter.bole@dinedesk.test')))
      .send({ table: 'B9', items: [{ name: 'Tibs', qty: 2, price: 350 }], branchId: 'piassa' });
    expect(res.status).toBe(201);
    expect(res.body.branchId).toBe('bole'); // body branchId ignored
    expect(res.body.total).toBe(700);
  });

  test('cashier creating an order -> 403', async () => {
    const res = await request(app).post('/api/orders')
      .set(auth(idOf('cashier.bole@dinedesk.test')))
      .send({ table: 'B9', items: [{ name: 'Tibs', qty: 1, price: 350 }] });
    expect(res.status).toBe(403);
  });

  test('waiter calling GET /api/reports/branch -> 403', async () => {
    const res = await request(app).get('/api/reports/branch').set(auth(idOf('waiter.bole@dinedesk.test')));
    expect(res.status).toBe(403);
  });

  test('unknown role has no permissions at all', () => {
    expect(permissionsFor('intern')).toEqual([]);
    expect(permissionsFor(undefined)).toEqual([]);
    expect(permissionsFor('__proto__')).toEqual([]);
  });
});

describe('branch-level authorization (the Piassa/Bole incident)', () => {
  test('Bole manager reading a Bole order -> 200', async () => {
    const res = await request(app).get('/api/orders/1001').set(auth(idOf('manager.bole@dinedesk.test')));
    expect(res.status).toBe(200);
    expect(res.body.branchId).toBe('bole');
  });

  test('Bole manager reading a Piassa order -> 404, identical to a non-existent order', async () => {
    const other = await request(app).get('/api/orders/1003').set(auth(idOf('manager.bole@dinedesk.test')));
    const missing = await request(app).get('/api/orders/9999').set(auth(idOf('manager.bole@dinedesk.test')));
    expect(other.status).toBe(404);
    expect(other.body).toEqual(missing.body);
  });

  test('order list only contains the caller\'s own branch', async () => {
    const res = await request(app).get('/api/orders').set(auth(idOf('manager.bole@dinedesk.test')));
    expect(res.status).toBe(200);
    expect(res.body.length).toBeGreaterThan(0);
    expect(res.body.every((o) => o.branchId === 'bole')).toBe(true);
  });

  test('Piassa manager calling /reports/branch?branchId=bole -> still only Piassa data', async () => {
    const piassa = store.orders.filter((o) => o.branchId === 'piassa');
    const res = await request(app).get('/api/reports/branch?branchId=bole')
      .set(auth(idOf('manager.piassa@dinedesk.test')));
    expect(res.status).toBe(200);
    expect(res.body.branchId).toBe('piassa');
    expect(res.body.orderIds.sort()).toEqual(piassa.map((o) => o.id).sort());
    expect(res.body.totalSales).toBe(piassa.reduce((s, o) => s + o.total, 0));
  });

  test('cashier cannot take payment for another branch\'s order -> 404', async () => {
    const res = await request(app).post('/api/payments')
      .set(auth(idOf('cashier.bole@dinedesk.test'))).send({ orderId: '1003', amount: 540 });
    expect(res.status).toBe(404);
    expect(store.orders.find((o) => o.id === '1003').status).toBe('open');
  });

  test('cashier pays own-branch order -> 201', async () => {
    const res = await request(app).post('/api/payments')
      .set(auth(idOf('cashier.bole@dinedesk.test'))).send({ orderId: '1001', amount: 700 });
    expect(res.status).toBe(201);
  });

  test('policy function: same branch yes, other branch no, admin yes, null user no', () => {
    const order = { branchId: 'bole' };
    expect(canAccessOrder({ role: 'manager', branchId: 'bole' }, order)).toBe(true);
    expect(canAccessOrder({ role: 'manager', branchId: 'piassa' }, order)).toBe(false);
    expect(canAccessOrder({ role: 'admin', branchId: null }, order)).toBe(true);
    expect(canAccessOrder(null, order)).toBe(false);
  });
});
