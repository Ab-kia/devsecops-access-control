'use strict';
const { loadConfig } = require('./config');

// Validate configuration BEFORE loading anything else: fail fast, name the setting, print no value.
let config;
try {
  config = loadConfig();
} catch (err) {
  console.error(`DineDesk cannot start. ${err.message}`);
  process.exit(1);
}

const { createStore } = require('./store');
const { createApp } = require('./app');

const app = createApp(config, createStore());
app.listen(config.port, () => console.log(`DineDesk API listening on port ${config.port}`));
