// Zmiana hasła: dobrowolna oraz wymuszona (pierwsze logowanie, reset, wygaśnięcie)
const express = require('express');
const { requireLogin } = require('../middleware/auth');
const { verifyPassword } = require('../services/passwords');
const { validateNewPassword, getPolicyDescription } = require('../services/passwordPolicy');
const { setUserPassword } = require('../services/passwordChange');
const { logEvent } = require('../services/audit');

const router = express.Router();

const REASONS = {
  otp: 'Logujesz się hasłem jednorazowym od administratora. Aby kontynuować, ustaw własne hasło.',
  forced: 'Administrator wymaga zmiany hasła. Aby kontynuować, ustaw nowe hasło.',
  expired: 'Twoje hasło wygasło. Aby kontynuować, ustaw nowe hasło.',
};

function renderForm(req, res, errors = [], status = 200) {
  const reason = req.session.mustChangeReason;
  res.status(status).render('change-password', {
    title: 'Zmiana hasła',
    reasonText: REASONS[reason] || null,
    forced: Boolean(reason),
    isOtp: reason === 'otp',
    rules: getPolicyDescription(),
    errors,
  });
}

router.get('/change-password', requireLogin, (req, res) => renderForm(req, res));

router.post('/change-password', requireLogin, async (req, res, next) => {
  try {
    const user = req.user;
    const currentPassword = String(req.body.current_password || '');
    const newPassword = String(req.body.new_password || '');
    const confirmPassword = String(req.body.new_password_confirm || '');

    // 1. Stare hasło musi być poprawne
    if (!(await verifyPassword(user.password_hash, currentPassword))) {
      logEvent(req, 'PASSWORD_CHANGE_FAILED', { userId: user.id, login: user.login, details: 'błędne obecne hasło' });
      return renderForm(req, res, ['Obecne hasło jest niepoprawne.'], 400);
    }

    // 2. Hasło jednorazowe mogło wygasnąć w trakcie
    if (user.password_is_otp && user.otp_expires_at < Date.now()) {
      return renderForm(req, res, ['Hasło jednorazowe wygasło. Poproś administratora o nowe.'], 400);
    }

    // 3. Nowe hasło podane dwa razy tak samo
    if (newPassword !== confirmPassword) {
      return renderForm(req, res, ['Nowe hasło i jego powtórzenie nie są takie same.'], 400);
    }

    // 4. Polityka haseł (stare hasło jest znane -> sprawdzamy też Levenshteina)
    const errors = await validateNewPassword({ user, newPassword, oldPassword: currentPassword });
    if (errors.length > 0) {
      logEvent(req, 'PASSWORD_CHANGE_FAILED', { userId: user.id, login: user.login, details: errors.join(' ') });
      return renderForm(req, res, errors, 400);
    }

    // 5. Zapis
    await setUserPassword(user.id, newPassword);
    const reason = req.session.mustChangeReason;
    logEvent(req, 'PASSWORD_CHANGED', {
      userId: user.id,
      login: user.login,
      details: reason ? `wymuszona (${reason})` : 'dobrowolna',
    });

    // 6. Nowy identyfikator sesji po zmianie hasła, bez flagi wymuszonej zmiany
    const { userId, login } = req.session;
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = userId;
      req.session.login = login;
      req.session.lastActivity = Date.now();
      req.session.flash = { type: 'success', message: 'Hasło zostało zmienione.' };
      req.session.save(() => res.redirect('/'));
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;