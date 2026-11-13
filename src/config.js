'use strict';
// The ONE place configuration and secrets are read. Nothing else touches process.env.

const MIN_SECRET_LENGTH = 32;

function loadConfig(env = process.env) {
  const problems = [];

  const jwtSecret = env.JWT_SECRET;
  if (!jwtSecret) {
    problems.push('JWT_SECRET is required but not set');
  } else if (jwtSecret.length < MIN_SECRET_LENGTH) {
    // We report the setting name and the rule - never the value.
    problems.push(`JWT_SECRET must be at least ${MIN_SECRET_LENGTH} characters`);
  }

  const port = Number(env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    problems.push('PORT must be an integer between 1 and 65535');
  }

  if (problems.length > 0) {
    throw new Error(`Invalid configuration: ${problems.join('; ')}`);
  }

  const config = {
    port,
    jwtIssuer: env.JWT_ISSUER || 'dinedesk-api',
    jwtAudience: env.JWT_AUDIENCE || 'dinedesk-staff',
    jwtAlgorithm: 'HS256',
    accessTokenTtlSeconds: 15 * 60, // 15 minutes
  };
  // Non-enumerable: console.log(config) / JSON.stringify(config) cannot print the secret.
  Object.defineProperty(config, 'jwtSecret', { value: jwtSecret, enumerable: false });
  return Object.freeze(config);
}

module.exports = { loadConfig, MIN_SECRET_LENGTH };
