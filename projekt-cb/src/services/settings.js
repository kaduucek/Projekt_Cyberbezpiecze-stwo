// Odczyt i zapis ustawień z tabeli settings
const { db } = require('../db/database');

function getSetting(key, fallback = null) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : fallback;
}

function getNumberSetting(key, fallback) {
  const n = Number(getSetting(key));
  return Number.isFinite(n) ? n : fallback;
}

function setSetting(key, value) {
  db.prepare(`
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, String(value));
}

module.exports = { getSetting, getNumberSetting, setSetting };