// Panel administratora: użytkownicy, ustawienia, dziennik zdarzeń
const express = require('express');
const { db } = require('../db/database');
const { requirePermission } = require('../middleware/auth');
const { findUserById, findUserByLogin } = require('../services/users');
const { getNumberSetting, setSetting } = require('../services/settings');
const { logEvent } = require('../services/audit');
const userAdmin = require('../services/userAdmin');

const router = express.Router();

// RBAC – każda trasa wymaga konkretnego uprawnienia
const canManageUsers = requirePermission('users.manage');
const canManageSettings = requirePermission('settings.manage');
const canViewReports = requirePermission('reports.view');

const LOGIN_PATTERN = /^[a-zA-Z0-9._-]{3,32}$/;

// Pozwala używać "async" w trasach – błędy trafią do obsługi błędów w app.js
const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function notFound(res) {
  return res.status(404).render('error', { title: 'Nie znaleziono', message: 'Nie ma takiego użytkownika.' });
}

function notAllowed(res, message) {
  return res.status(403).render('error', { title: 'Operacja niedozwolona', message });
}

function log(req, event, details) {
  logEvent(req, event, { userId: req.user.id, login: req.user.login, details });
}

// Strona z hasłem jednorazowym – pokazywana tylko raz, bez zapisu w przeglądarce
function showOneTimePassword(res, info) {
  res.set('Cache-Control', 'no-store');
  res.render('admin/otp', { title: 'Hasło jednorazowe', info });
}

// ===================== UŻYTKOWNICY =====================

router.get('/admin/users', canManageUsers, (req, res) => {
  res.render('admin/users', {
    title: 'Użytkownicy',
    users: userAdmin.listUsers(),
    expiryDays: getNumberSetting('password_expiry_days', 90),
  });
});

// --- Dodawanie ---
router.get('/admin/users/new', canManageUsers, (req, res) => {
  res.render('admin/user-form', {
    title: 'Nowy użytkownik', mode: 'new', userId: null, isProtected: false,
    roles: userAdmin.listRoles(), errors: [],
    values: { login: '', full_name: '', role_id: '', must_change_password: 1 },
  });
});

router.post('/admin/users/new', canManageUsers, asyncRoute(async (req, res) => {
  const values = {
    login: String(req.body.login || '').trim(),
    full_name: String(req.body.full_name || '').trim(),
    role_id: Number(req.body.role_id),
    must_change_password: 1,
  };

  const errors = [];
  if (!LOGIN_PATTERN.test(values.login)) {
    errors.push('Login: 3–32 znaki, tylko litery bez polskich znaków, cyfry, kropka, myślnik i podkreślenie.');
  } else if (findUserByLogin(values.login)) {
    errors.push('Taki login już istnieje.');
  }
  if (!values.full_name) errors.push('Podaj imię i nazwisko.');
  if (!userAdmin.roleExists(values.role_id)) errors.push('Wybierz rolę.');

  if (errors.length > 0) {
    return res.status(400).render('admin/user-form', {
      title: 'Nowy użytkownik', mode: 'new', userId: null, isProtected: false,
      roles: userAdmin.listRoles(), errors, values,
    });
  }

  const { otp, expiresAt } = await userAdmin.createUser({
    login: values.login, fullName: values.full_name, roleId: values.role_id,
  });
  log(req, 'USER_CREATED', `utworzono konto ${values.login}`);
  showOneTimePassword(res, { login: values.login, otp, expiresAt, action: 'created' });
}));

// --- Edycja ---
router.get('/admin/users/:id/edit', canManageUsers, (req, res) => {
  const user = findUserById(Number(req.params.id));
  if (!user) return notFound(res);

  res.render('admin/user-form', {
    title: `Edycja: ${user.login}`, mode: 'edit', userId: user.id,
    isProtected: Boolean(user.is_protected),
    roles: userAdmin.listRoles(), errors: [],
    values: {
      login: user.login,
      full_name: user.full_name,
      role_id: userAdmin.getUserRoleId(user.id),
      must_change_password: user.must_change_password,
    },
  });
});

router.post('/admin/users/:id/edit', canManageUsers, (req, res) => {
  const user = findUserById(Number(req.params.id));
  if (!user) return notFound(res);

  const values = {
    login: user.login,
    full_name: String(req.body.full_name || '').trim(),
    role_id: user.is_protected ? userAdmin.getUserRoleId(user.id) : Number(req.body.role_id),
    must_change_password: req.body.must_change_password ? 1 : 0,
  };

  const errors = [];
  if (!values.full_name) errors.push('Podaj imię i nazwisko.');
  if (!user.is_protected && !userAdmin.roleExists(values.role_id)) errors.push('Wybierz rolę.');

  if (errors.length > 0) {
    return res.status(400).render('admin/user-form', {
      title: `Edycja: ${user.login}`, mode: 'edit', userId: user.id,
      isProtected: Boolean(user.is_protected), roles: userAdmin.listRoles(), errors, values,
    });
  }

  userAdmin.updateUser({
    id: user.id,
    fullName: values.full_name,
    roleId: values.role_id,
    mustChange: values.must_change_password,
    isProtected: user.is_protected,
  });
  log(req, 'USER_UPDATED', `zmieniono dane konta ${user.login}`);
  req.session.flash = { type: 'success', message: `Zapisano zmiany konta ${user.login}.` };
  res.redirect('/admin/users');
});

// --- Blokowanie / odblokowanie ---
router.post('/admin/users/:id/block', canManageUsers, (req, res) => {
  const user = findUserById(Number(req.params.id));
  if (!user) return notFound(res);
  if (user.is_protected || user.id === req.user.id) {
    return notAllowed(res, 'Konta ADMIN ani własnego konta nie można zablokować.');
  }

  const block = !user.is_blocked;
  userAdmin.setBlocked(user.id, block);
  log(req, block ? 'USER_BLOCKED' : 'USER_UNBLOCKED', `konto ${user.login}`);
  req.session.flash = {
    type: 'success',
    message: `Konto ${user.login} zostało ${block ? 'zablokowane' : 'odblokowane'}.`,
  };
  res.redirect('/admin/users');
});

// --- Reset hasła (nowe hasło jednorazowe) ---
router.post('/admin/users/:id/reset-password', canManageUsers, asyncRoute(async (req, res) => {
  const user = findUserById(Number(req.params.id));
  if (!user) return notFound(res);
  if (user.is_protected || user.id === req.user.id) {
    return notAllowed(res, 'Hasła konta ADMIN nie resetuje się – użyj „Zmień hasło”.');
  }

  const { otp, expiresAt } = await userAdmin.resetPassword(user.id);
  log(req, 'PASSWORD_RESET', `nowe hasło jednorazowe dla ${user.login}`);
  showOneTimePassword(res, { login: user.login, otp, expiresAt, action: 'reset' });
}));

// --- Usuwanie ---
router.post('/admin/users/:id/delete', canManageUsers, (req, res) => {
  const user = findUserById(Number(req.params.id));
  if (!user) return notFound(res);
  if (user.is_protected || user.id === req.user.id) {
    return notAllowed(res, 'Konta ADMIN ani własnego konta nie można usunąć.');
  }

  userAdmin.deleteUser(user.id);
  log(req, 'USER_DELETED', `usunięto konto ${user.login}`);
  req.session.flash = { type: 'success', message: `Konto ${user.login} zostało usunięte.` };
  res.redirect('/admin/users');
});

// ===================== USTAWIENIA =====================

function currentSettings() {
  return {
    password_policy_enabled: getNumberSetting('password_policy_enabled', 1),
    password_expiry_days: getNumberSetting('password_expiry_days', 90),
    session_idle_minutes: getNumberSetting('session_idle_minutes', 15),
    password_history_count: getNumberSetting('password_history_count', 5),
  };
}

router.get('/admin/settings', canManageSettings, (req, res) => {
  res.render('admin/settings', { title: 'Ustawienia', values: currentSettings(), errors: [] });
});

router.post('/admin/settings', canManageSettings, (req, res) => {
  const values = {
    password_policy_enabled: req.body.password_policy_enabled ? 1 : 0,
    password_expiry_days: Number(req.body.password_expiry_days),
    session_idle_minutes: Number(req.body.session_idle_minutes),
    password_history_count: Number(req.body.password_history_count),
  };

  const inRange = (n, min, max) => Number.isInteger(n) && n >= min && n <= max;
  const errors = [];
  if (!inRange(values.password_expiry_days, 0, 365)) errors.push('Ważność hasła: od 0 do 365 dni (0 = hasło nie wygasa).');
  if (!inRange(values.session_idle_minutes, 1, 240)) errors.push('Czas bezczynności: od 1 do 240 minut.');
  if (!inRange(values.password_history_count, 1, 24)) errors.push('Historia haseł: od 1 do 24.');

  if (errors.length > 0) {
    return res.status(400).render('admin/settings', { title: 'Ustawienia', values, errors });
  }

  for (const [key, value] of Object.entries(values)) setSetting(key, value);
  log(req, 'SETTINGS_CHANGED', JSON.stringify(values));
  req.session.flash = { type: 'success', message: 'Ustawienia zostały zapisane.' };
  res.redirect('/admin/settings');
});

// ===================== DZIENNIK ZDARZEŃ =====================

function eventColor(event) {
  if (/FAILED|DENIED|^USER_BLOCKED|DELETED|EXPIRED/.test(event)) return 'red';
  if (/SUCCESS|PASSWORD_CHANGED|CREATED|UNBLOCKED/.test(event)) return 'green';
  return '';
}

router.get('/audit', canViewReports, (req, res) => {
  const entries = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 200').all()
    .map((e) => ({ ...e, color: eventColor(e.event) }));
  res.render('audit', { title: 'Dziennik zdarzeń', entries });
});

module.exports = router;