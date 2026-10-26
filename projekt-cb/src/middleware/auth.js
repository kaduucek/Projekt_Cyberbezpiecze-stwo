// Middleware związane z sesją, uwierzytelnianiem i autoryzacją
const { findUserById, getUserRoles, getUserPermissions } = require('../services/users');
const { getNumberSetting } = require('../services/settings');
const { logEvent } = require('../services/audit');

// Strony dostępne, gdy użytkownik MUSI najpierw zmienić hasło
const ALLOWED_DURING_PASSWORD_CHANGE = ['/change-password', '/logout'];

// 1. Automatyczne wylogowanie po bezczynności
function sessionIdleTimeout(req, res, next) {
  if (!req.session.userId) return next();

  const idleMs = getNumberSetting('session_idle_minutes', 15) * 60 * 1000;
  const now = Date.now();

  if (req.session.lastActivity && now - req.session.lastActivity > idleMs) {
    logEvent(req, 'SESSION_EXPIRED', { userId: req.session.userId, login: req.session.login });
    return req.session.destroy(() => {
      res.clearCookie('sid');
      res.redirect('/login?expired=1');
    });
  }

  req.session.lastActivity = now; // każda akcja odnawia czas aktywności
  next();
}

// 2. Wczytanie zalogowanego użytkownika, jego ról i uprawnień
function loadUser(req, res, next) {
  res.locals.currentUser = null;
  res.locals.can = () => false;
  if (!req.session.userId) return next();

  const user = findUserById(req.session.userId);

  // Konto usunięte lub zablokowane w trakcie sesji -> natychmiastowe wylogowanie
  if (!user || user.is_blocked) {
    return req.session.destroy(() => {
      res.clearCookie('sid');
      res.redirect('/login');
    });
  }

  user.roles = getUserRoles(user.id);
  user.permissions = getUserPermissions(user.id);
  req.user = user;

  
  // Admin zaznaczył "wymuś zmianę hasła" w trakcie trwania sesji użytkownika
  if (!req.session.mustChangeReason && (user.must_change_password || user.password_is_otp)) {
    req.session.mustChangeReason = user.password_is_otp ? 'otp' : 'forced';
  }

  res.locals.currentUser = user;
  res.locals.can = (code) => user.permissions.includes(code);
  res.locals.idleMinutes = getNumberSetting('session_idle_minutes', 15);

  // Wymuszona zmiana hasła: dopóki jej nie zrobi, nie wejdzie nigdzie indziej
  if (req.session.mustChangeReason && !ALLOWED_DURING_PASSWORD_CHANGE.includes(req.path)) {
    return res.redirect('/change-password');
  }

  next();
}

// 3. Strona tylko dla zalogowanych
function requireLogin(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}

// 4. Strona tylko dla osób z konkretnym uprawnieniem (RBAC)
function requirePermission(code) {
  return (req, res, next) => {
    if (!req.user) return res.redirect('/login');
    if (!req.user.permissions.includes(code)) {
      logEvent(req, 'ACCESS_DENIED', {
        userId: req.user.id,
        login: req.user.login,
        details: `${req.method} ${req.originalUrl} (brak: ${code})`,
      });
      return res.status(403).render('error', {
        title: 'Brak dostępu',
        message: 'Nie masz uprawnień do tej strony.',
      });
    }
    next();
  };
}

module.exports = { sessionIdleTimeout, loadUser, requireLogin, requirePermission };