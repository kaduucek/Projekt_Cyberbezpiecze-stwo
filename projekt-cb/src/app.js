// Główny plik aplikacji
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');

const SqliteSessionStore = require('./db/sessionStore');
const { sessionIdleTimeout, loadUser, requireLogin } = require('./middleware/auth');
const { csrfProtection } = require('./middleware/csrf');
const { getUserPermissionDetails } = require('./services/users');
const authRoutes = require('./routes/auth');
const passwordRoutes = require('./routes/password');
const adminRoutes = require('./routes/admin');

const articlesRoutes = require('./routes/articles');
const { getRolePermissionMatrix } = require('./services/rbac');
const { getNumberSetting } = require('./services/settings');

const app = express();
const PORT = 3000;

// Sekret do podpisywania ciasteczka sesji – losowany raz i zapisywany w pliku
const secretFile = path.join(__dirname, '..', 'data', 'session-secret.txt');
if (!fs.existsSync(secretFile)) {
  fs.writeFileSync(secretFile, crypto.randomBytes(32).toString('hex'));
}
const SESSION_SECRET = fs.readFileSync(secretFile, 'utf8').trim();

// Szablony stron (EJS)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Pliki statyczne (CSS, JS) i odczyt danych z formularzy
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.urlencoded({ extended: false }));

// Sesja – ciasteczko niedostępne dla JavaScriptu (httpOnly)
app.use(session({
  name: 'sid',
  secret: SESSION_SECRET,
  store: new SqliteSessionStore(),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false },
}));

// Kolejność ma znaczenie!
app.use(sessionIdleTimeout); // 1. wylogowanie po bezczynności
app.use(loadUser);           // 2. kto jest zalogowany + uprawnienia
app.use(csrfProtection);     // 3. ochrona formularzy

// Dane dostępne we wszystkich szablonach
app.use((req, res, next) => {
  res.locals.flash = req.session.flash || null; // jednorazowy komunikat
  delete req.session.flash;
  res.locals.formatDate = (ms) => (ms ? new Date(ms).toLocaleString('pl-PL') : '—');
  res.locals.now = Date.now();
  next();
});

// Strony
app.use(authRoutes);

app.use(articlesRoutes);

app.use(passwordRoutes);
app.use(adminRoutes);

app.get('/', requireLogin, (req, res) => {
  const expiryDays = getNumberSetting('password_expiry_days', 90);
  res.render('dashboard', {
    title: 'Strona główna',
    permissionDetails: getUserPermissionDetails(req.user.id),
    matrix: getRolePermissionMatrix(),
    passwordExpiresAt: expiryDays > 0
      ? req.user.password_changed_at + expiryDays * 24 * 60 * 60 * 1000
      : null,
  });
});

// Nieznany adres
app.use((req, res) => {
  res.status(404).render('error', { title: 'Nie znaleziono', message: 'Taka strona nie istnieje.' });
});

// Nieoczekiwany błąd
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', { title: 'Błąd serwera', message: 'Wystąpił nieoczekiwany błąd.' });
});

app.listen(PORT, () => {
  console.log(`Serwer działa: http://localhost:${PORT}`);
});