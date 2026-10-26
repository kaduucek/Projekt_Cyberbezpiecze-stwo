// Operacje administratora na kontach użytkowników
const { db } = require('../db/database');
const { hashPassword } = require('./passwords');
const { generateOneTimePassword, OTP_VALIDITY_MS } = require('./otp');

// Lista użytkowników razem z nazwami ról
function listUsers() {
  return db.prepare(`
    SELECT u.*, GROUP_CONCAT(r.name, ', ') AS role_names
    FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r ON r.id = ur.role_id
    GROUP BY u.id
    ORDER BY u.is_protected DESC, u.login
  `).all();
}

function listRoles() {
  return db.prepare('SELECT id, name, description FROM roles ORDER BY id').all();
}

function roleExists(roleId) {
  return Boolean(db.prepare('SELECT 1 FROM roles WHERE id = ?').get(roleId));
}

function getUserRoleId(userId) {
  const row = db.prepare('SELECT role_id FROM user_roles WHERE user_id = ? LIMIT 1').get(userId);
  return row ? row.role_id : null;
}

// Usuwa wszystkie sesje danego użytkownika (natychmiastowe wylogowanie)
function destroyUserSessions(userId) {
  db.prepare("DELETE FROM sessions WHERE json_extract(data, '$.userId') = ?").run(userId);
}

// Nowe hasło jednorazowe: jawne (do pokazania adminowi) + hash (do bazy)
async function newOneTimePassword() {
  const otp = generateOneTimePassword();
  return { otp, hash: await hashPassword(otp), expiresAt: Date.now() + OTP_VALIDITY_MS };
}

async function createUser({ login, fullName, roleId }) {
  const { otp, hash, expiresAt } = await newOneTimePassword();
  const now = Date.now();

  const create = db.transaction(() => {
    const id = db.prepare(`
      INSERT INTO users (login, full_name, password_hash, password_is_otp, otp_expires_at,
                         must_change_password, password_changed_at, created_at)
      VALUES (?, ?, ?, 1, ?, 1, ?, ?)
    `).run(login, fullName, hash, expiresAt, now, now).lastInsertRowid;
    db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(id, roleId);
    return id;
  });

  return { id: create(), otp, expiresAt };
}

function updateUser({ id, fullName, roleId, mustChange, isProtected }) {
  const update = db.transaction(() => {
    db.prepare('UPDATE users SET full_name = ?, must_change_password = ? WHERE id = ?')
      .run(fullName, mustChange ? 1 : 0, id);
    if (!isProtected) { // roli konta ADMIN nie zmieniamy
      db.prepare('DELETE FROM user_roles WHERE user_id = ?').run(id);
      db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(id, roleId);
    }
  });
  update();
}

function setBlocked(id, blocked) {
  db.prepare('UPDATE users SET is_blocked = ?, failed_attempts = 0 WHERE id = ?').run(blocked ? 1 : 0, id);
  if (blocked) destroyUserSessions(id);
}

async function resetPassword(id) {
  const { otp, hash, expiresAt } = await newOneTimePassword();
  db.prepare(`
    UPDATE users
    SET password_hash = ?, password_is_otp = 1, otp_expires_at = ?,
        must_change_password = 1, failed_attempts = 0
    WHERE id = ?
  `).run(hash, expiresAt, id);
  destroyUserSessions(id); // stare sesje przestają działać
  return { otp, expiresAt };
}

function deleteUser(id) {
  destroyUserSessions(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id); // role i historia haseł usuną się same (CASCADE)
}

module.exports = {
  listUsers, listRoles, roleExists, getUserRoleId,
  createUser, updateUser, setBlocked, resetPassword, deleteUser,
};