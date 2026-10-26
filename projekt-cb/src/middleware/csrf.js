// Ochrona CSRF: każdy formularz musi odesłać tajny token zapisany w sesji.
// Dzięki temu obca strona nie może wysłać formularza w imieniu użytkownika.
const crypto = require('crypto');

function csrfProtection(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;

  if (req.method === 'POST') {
    const sent = String((req.body && req.body._csrf) || '');
    const expected = req.session.csrfToken;
    const ok =
      sent.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected));

    if (!ok) {
      return res.status(403).render('error', {
        title: 'Błąd formularza',
        message: 'Formularz wygasł lub jest nieprawidłowy. Odśwież stronę i spróbuj ponownie.',
      });
    }
  }
  next();
}

module.exports = { csrfProtection };