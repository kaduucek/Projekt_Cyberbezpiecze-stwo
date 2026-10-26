// Zapisuje nowe hasło użytkownika i dopisuje je do historii haseł
const { db } = require('../db/database');
const { hashPassword } = require('./passwords');
const { getNumberSetting } = require('./settings');

async function setUserPassword(userId, newPassword) {
  const hash = await hashPassword(newPassword);
  const now = Date.now();
  const keep = getNumberSetting('password_history_count', 5);

  // Transakcja: albo wszystkie trzy operacje się udadzą, albo żadna
  const save = db.transaction(() => {
    db.prepare(`
      UPDATE users
      SET password_hash = ?, password_is_otp = 0, otp_expires_at = NULL,
          must_change_password = 0, password_changed_at = ?
      WHERE id = ?
    `).run(hash, now, userId);

    db.prepare('INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)')
      .run(userId, hash, now);

    // Zostawiamy w historii tylko ostatnie "keep" haseł
    db.prepare(`
      DELETE FROM password_history
      WHERE user_id = ? AND id NOT IN (
        SELECT id FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?
      )
    `).run(userId, userId, keep);
  });

  save();
}

module.exports = { setUserPassword };