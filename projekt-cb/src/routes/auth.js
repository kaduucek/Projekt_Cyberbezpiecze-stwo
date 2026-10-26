// Logowanie i wylogowanie
const express = require('express');
const crypto = require('crypto');
const { findUserByLogin } = require('../services/users');
const { hashPassword, verifyPassword } = require('../services/passwords');
const { getNumberSetting } = require('../services/settings');
const { logEvent } = require('../services/audit');

const router = express.Router();

// Jeden wspólny komunikat – nie zdradza, czy login istnieje
const LOGIN_ERROR = 'Login lub hasło niepoprawne';

// "Udawany" hash: sprawdzamy go, gdy login nie istnieje, żeby odpowiedź
// trwała tyle samo czasu (atakujący nie pozna po czasie, czy konto istnieje)
const dummyHashPromise = hashPassword(crypto.randomBytes(16).toString('hex'));

router.get('/login', (req, res) => {
  if (req.user) return res.redirect('/');

  let info = null;
  if (req.query.expired) info = 'Sesja wygasła z powodu bezczynności. Zaloguj się ponownie.';
  if (req.query.loggedOut) info = 'Wylogowano poprawnie.';

  res.render('login', { title: 'Logowanie', error: null, info, login: '' });
});

router.post('/login', async (req, res, next) => {
  try {
    const login = String(req.body.login || '').trim();
    const password = String(req.body.password || '');
    const now = Date.now();

    const user = login ? findUserByLogin(login) : undefined;
    const hashToCheck = user ? user.password_hash : await dummyHashPromise;
    const passwordOk = await verifyPassword(hashToCheck, password);
    const otpExpired = user && user.password_is_otp && user.otp_expires_at < now;

    // Każdy rodzaj błędu -> ten sam komunikat dla użytkownika
    if (!user || !passwordOk || user.is_blocked || otpExpired) {
      let reason = 'nieistniejący login';
      if (user && !passwordOk) reason = 'błędne hasło';
      else if (user && user.is_blocked) reason = 'konto zablokowane';
      else if (user && otpExpired) reason = 'hasło jednorazowe wygasło';

      logEvent(req, 'LOGIN_FAILED', { userId: user ? user.id : null, login, details: reason });
      return res.status(401).render('login', {
        title: 'Logowanie', error: LOGIN_ERROR, info: null, login,
      });
    }

    // Czy użytkownik musi od razu zmienić hasło?
    const expiryDays = getNumberSetting('password_expiry_days', 90);
    const passwordExpired = expiryDays > 0 && now - user.password_changed_at > expiryDays * 24 * 60 * 60 * 1000;

    let mustChangeReason = null;
    if (user.password_is_otp) mustChangeReason = 'otp';
    else if (user.must_change_password) mustChangeReason = 'forced';
    else if (passwordExpired) mustChangeReason = 'expired';

    // Nowy identyfikator sesji po zalogowaniu (ochrona przed "session fixation")
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.session.login = user.login;
      req.session.lastActivity = now;
      req.session.mustChangeReason = mustChangeReason;

      logEvent(req, 'LOGIN_SUCCESS', { userId: user.id, login: user.login });
      req.session.save(() => res.redirect(mustChangeReason ? '/change-password' : '/'));
    });
  } catch (err) {
    next(err);
  }
});

// Wylogowanie ręczne – sesja jest niszczona po stronie serwera
router.post('/logout', (req, res) => {
  if (req.session.userId) {
    logEvent(req, 'LOGOUT', { userId: req.session.userId, login: req.session.login });
  }
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.redirect('/login?loggedOut=1');
  });
});

module.exports = router;