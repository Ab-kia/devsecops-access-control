'use strict';
const jwt = require('jsonwebtoken');

// Exactly "Bearer <three base64url parts>" - nothing else is accepted.
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

function unauthorized(res) {
  res.set('WWW-Authenticate', 'Bearer');
  return res.status(401).json({ error: 'Unauthorized' }); // one generic body for every failure
}

function makeAuthenticate(config, store) {
  return function authenticate(req, res, next) {
    const match = BEARER.exec(req.headers.authorization || '');
    if (!match) return unauthorized(res);

    let payload;
    try {
      payload = jwt.verify(match[1], config.jwtSecret, {
        algorithms: [config.jwtAlgorithm], // allowlist: rejects "none" and algorithm confusion
        issuer: config.jwtIssuer,
        audience: config.jwtAudience,
      });
    } catch (_err) {
      return unauthorized(res); // expired, bad signature, wrong iss/aud, malformed...
    }

    // Identity comes ONLY from the verified token's subject + our own user records.
    const user = typeof payload.sub === 'string'
      ? store.users.find((x) => x.id === payload.sub)
      : undefined;
    if (!user || !user.active) return unauthorized(res); // deleted/disabled => cut off at once

    req.user = { id: user.id, role: user.role, branchId: user.branchId, email: user.email };
    return next();
  };
}

module.exports = { makeAuthenticate };
