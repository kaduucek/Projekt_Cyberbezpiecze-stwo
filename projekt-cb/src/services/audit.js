// Zapisywanie zdarzeń (logowania, wylogowania, błędy) do tabeli audit_log
const { db } = require('../db/database');

function logEvent(req, event, { userId = null, login = null, details = null } = {}) {
  db.prepare(`
    INSERT INTO audit_log (user_id, login, event, details, ip, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(userId, login, event, details, req ? req.ip : null, Date.now());
}

module.exports = { logEvent };