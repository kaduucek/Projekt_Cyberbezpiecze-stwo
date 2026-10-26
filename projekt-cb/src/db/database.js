// Połączenie z bazą danych SQLite oraz definicja wszystkich tabel.
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// Baza będzie w pliku data/app.db w głównym folderze projektu
const DATA_DIR = path.join(__dirname, '..', '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'app.db'));
db.pragma('foreign_keys = ON'); // pilnowanie powiązań między tabelami

const SCHEMA = `
-- Użytkownicy
CREATE TABLE IF NOT EXISTS users (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  login                TEXT NOT NULL UNIQUE COLLATE NOCASE,
  full_name            TEXT NOT NULL DEFAULT '',
  password_hash        TEXT NOT NULL,              -- hash Argon2id (z solą)
  password_is_otp      INTEGER NOT NULL DEFAULT 0, -- 1 = obecne hasło jest jednorazowe
  otp_expires_at       INTEGER,                    -- kiedy wygasa hasło jednorazowe
  must_change_password INTEGER NOT NULL DEFAULT 0, -- 1 = wymuś zmianę przy logowaniu
  password_changed_at  INTEGER NOT NULL,           -- do liczenia ważności hasła
  is_blocked           INTEGER NOT NULL DEFAULT 0,
  is_protected         INTEGER NOT NULL DEFAULT 0, -- 1 = konto ADMIN (nie można usunąć)
  totp_secret          TEXT,                       -- sekret do 2FA
  totp_enabled         INTEGER NOT NULL DEFAULT 0,
  failed_attempts      INTEGER NOT NULL DEFAULT 0, -- przyda się w module 2
  created_at           INTEGER NOT NULL
);

-- RBAC: role, uprawnienia i powiązania
CREATE TABLE IF NOT EXISTS roles (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS permissions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  code        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

-- Historia haseł (żeby nowe hasło różniło się od poprzednich)
CREATE TABLE IF NOT EXISTS password_history (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

-- Ustawienia zmieniane przez administratora
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Dziennik zdarzeń (logowania, zmiany haseł itd.)
CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER,
  login      TEXT,
  event      TEXT NOT NULL,
  details    TEXT,
  ip         TEXT,
  created_at INTEGER NOT NULL
);

-- Dokumenty, na których pokażemy działanie ról
CREATE TABLE IF NOT EXISTS articles (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  title      TEXT NOT NULL,
  content    TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
  author_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
`;

function createSchema() {
  db.exec(SCHEMA);
}

// Usuwa wszystkie tabele (używane przy tworzeniu bazy od nowa)
function dropSchema() {
  db.exec(`
    DROP TABLE IF EXISTS role_permissions;
    DROP TABLE IF EXISTS user_roles;
    DROP TABLE IF EXISTS password_history;
    DROP TABLE IF EXISTS articles;
    DROP TABLE IF EXISTS audit_log;
    DROP TABLE IF EXISTS settings;
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS roles;
    DROP TABLE IF EXISTS permissions;
  `);
}

createSchema();

module.exports = { db, createSchema, dropSchema };