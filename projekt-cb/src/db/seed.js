// Tworzy bazę od nowa: role, uprawnienia, ustawienia, konto ADMIN
// i 6 użytkowników testowych. Uruchamianie: npm run seed
const { db, createSchema, dropSchema } = require('./database');
const { hashPassword } = require('../services/passwords');
const { generateOneTimePassword, OTP_VALIDITY_MS } = require('../services/otp');

const ROLES = [
  { name: 'Administrator', description: 'Pełne uprawnienia, zarządzanie użytkownikami i ustawieniami' },
  { name: 'Kierownik',     description: 'Zarządzanie dokumentami i wgląd w dziennik zdarzeń' },
  { name: 'Redaktor',      description: 'Edycja i publikowanie dokumentów' },
  { name: 'Pracownik',     description: 'Tworzenie własnych szkiców dokumentów' },
  { name: 'Czytelnik',     description: 'Tylko odczyt opublikowanych dokumentów' },
];

const PERMISSIONS = [
  { code: 'articles.read',     description: 'Czytanie opublikowanych dokumentów' },
  { code: 'articles.create',   description: 'Tworzenie własnych szkiców' },
  { code: 'articles.edit_any', description: 'Edycja dokumentów innych osób' },
  { code: 'articles.publish',  description: 'Publikowanie dokumentów' },
  { code: 'articles.delete',   description: 'Usuwanie dokumentów' },
  { code: 'reports.view',      description: 'Przeglądanie dziennika zdarzeń' },
  { code: 'users.manage',      description: 'Zarządzanie użytkownikami' },
  { code: 'settings.manage',   description: 'Zmiana ustawień bezpieczeństwa' },
];

// Które uprawnienia ma która rola (każda wyższa rola ma też uprawnienia niższych)
const CZYTELNIK = ['articles.read'];
const PRACOWNIK = [...CZYTELNIK, 'articles.create'];
const REDAKTOR  = [...PRACOWNIK, 'articles.edit_any', 'articles.publish'];
const KIEROWNIK = [...REDAKTOR, 'articles.delete', 'reports.view'];
const ADMINISTRATOR = PERMISSIONS.map((p) => p.code);

const ROLE_PERMISSIONS = {
  Czytelnik: CZYTELNIK,
  Pracownik: PRACOWNIK,
  Redaktor: REDAKTOR,
  Kierownik: KIEROWNIK,
  Administrator: ADMINISTRATOR,
};

// Ustawienia domyślne (administrator może je zmienić w panelu)
const DEFAULT_SETTINGS = {
  password_policy_enabled: '1', // polityka haseł z wariantu włączona
  password_expiry_days: '90',   // ważność hasła w dniach
  session_idle_minutes: '15',   // wylogowanie po bezczynności
  password_history_count: '5',  // ile poprzednich haseł pamiętamy
};

// 6 użytkowników testowych (hasła tylko do testów!)
const TEST_USERS = [
  { login: 'kierownik',  full_name: 'Anna Kowalska',        role: 'Kierownik', password: 'Kierownik-Haslo-Testowe' },
  { login: 'redaktor',   full_name: 'Piotr Nowak',          role: 'Redaktor',  password: 'Redaktor-Haslo-Testowe' },
  { login: 'pracownik1', full_name: 'Katarzyna Wiśniewska', role: 'Pracownik', password: 'Pracownik1-Haslo-Testowe' },
  { login: 'pracownik2', full_name: 'Tomasz Wójcik',        role: 'Pracownik', password: 'Pracownik2-Haslo-Testowe' },
  { login: 'czytelnik1', full_name: 'Magdalena Kamińska',   role: 'Czytelnik', password: 'Czytelnik1-Haslo-Testowe' },
  { login: 'czytelnik2', full_name: 'Michał Lewandowski',   role: 'Czytelnik', password: 'Czytelnik2-Haslo-Testowe' },
];

async function seed() {
  console.log('Tworzę bazę danych od nowa...');
  dropSchema();
  createSchema();
  const now = Date.now();

  // --- Role i uprawnienia ---
  const insertRole = db.prepare('INSERT INTO roles (name, description) VALUES (?, ?)');
  for (const r of ROLES) insertRole.run(r.name, r.description);

  const insertPerm = db.prepare('INSERT INTO permissions (code, description) VALUES (?, ?)');
  for (const p of PERMISSIONS) insertPerm.run(p.code, p.description);

  const roleId = (name) => db.prepare('SELECT id FROM roles WHERE name = ?').get(name).id;
  const permId = (code) => db.prepare('SELECT id FROM permissions WHERE code = ?').get(code).id;

  const insertRolePerm = db.prepare('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)');
  for (const [role, perms] of Object.entries(ROLE_PERMISSIONS)) {
    for (const code of perms) insertRolePerm.run(roleId(role), permId(code));
  }

  // --- Ustawienia ---
  const insertSetting = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
  for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) insertSetting.run(key, value);

  // --- Użytkownicy ---
  const insertUser = db.prepare(`
    INSERT INTO users (login, full_name, password_hash, password_is_otp, otp_expires_at,
                       must_change_password, password_changed_at, is_protected, created_at)
    VALUES (@login, @full_name, @password_hash, @password_is_otp, @otp_expires_at,
            @must_change_password, @now, @is_protected, @now)
  `);
  const insertUserRole = db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)');
  const insertHistory = db.prepare('INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)');

  // Konto ADMIN dostaje hasło jednorazowe i musi je zmienić przy pierwszym logowaniu
  const adminOtp = generateOneTimePassword();
  const adminId = insertUser.run({
    login: 'ADMIN',
    full_name: 'Administrator systemu',
    password_hash: await hashPassword(adminOtp),
    password_is_otp: 1,
    otp_expires_at: now + OTP_VALIDITY_MS,
    must_change_password: 1,
    is_protected: 1,
    now,
  }).lastInsertRowid;
  insertUserRole.run(adminId, roleId('Administrator'));

  // Użytkownicy testowi dostają zwykłe hasła, żeby łatwo testować role
  const userIds = {};
  for (const u of TEST_USERS) {
    const hash = await hashPassword(u.password);
    const id = insertUser.run({
      login: u.login,
      full_name: u.full_name,
      password_hash: hash,
      password_is_otp: 0,
      otp_expires_at: null,
      must_change_password: 0,
      is_protected: 0,
      now,
    }).lastInsertRowid;
    insertUserRole.run(id, roleId(u.role));
    insertHistory.run(id, hash, now);
    userIds[u.login] = id;
  }

  // --- Przykładowe dokumenty ---
  const insertArticle = db.prepare(`
    INSERT INTO articles (title, content, status, author_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  insertArticle.run('Regulamin pracy zdalnej', 'Treść regulaminu pracy zdalnej...', 'published', userIds.kierownik, now, now);
  insertArticle.run('Instrukcja BHP', 'Treść instrukcji BHP...', 'published', userIds.redaktor, now, now);
  insertArticle.run('Szkic: raport miesięczny', 'Wstępna wersja raportu...', 'draft', userIds.pracownik1, now, now);

  // --- Podsumowanie ---
  console.log('\nBaza gotowa!\n');
  console.log('=============================================');
  console.log(' Konto ADMIN – hasło jednorazowe (ważne 4 h):');
  console.log(`   login: ADMIN`);
  console.log(`   hasło: ${adminOtp}`);
  console.log(`   ważne do: ${new Date(now + OTP_VALIDITY_MS).toLocaleString('pl-PL')}`);
  console.log('=============================================\n');
  console.log('Użytkownicy testowi:');
  for (const u of TEST_USERS) console.log(`   ${u.login.padEnd(11)} ${u.role.padEnd(10)} hasło: ${u.password}`);
}

seed().catch((err) => {
  console.error('Błąd podczas tworzenia bazy:', err);
  process.exit(1);
});