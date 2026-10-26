// Dokumenty – demonstracja ról i uprawnień (RBAC + reguła właściciela)
const express = require('express');
const { db } = require('../db/database');
const { requirePermission } = require('../middleware/auth');
const { logEvent } = require('../services/audit');

const router = express.Router();

const has = (user, code) => user.permissions.includes(code);

// Kto może ZOBACZYĆ dokument:
//  - opublikowany: każdy z uprawnieniem articles.read
//  - szkic: tylko autor albo osoba z articles.edit_any (Redaktor i wyżej)
function canView(user, article) {
  if (article.status === 'published') return has(user, 'articles.read');
  return article.author_id === user.id || has(user, 'articles.edit_any');
}

// Kto może EDYTOWAĆ dokument:
//  - Redaktor i wyżej (articles.edit_any): każdy dokument
//  - Pracownik (articles.create): tylko własny, nieopublikowany szkic
function canEdit(user, article) {
  if (has(user, 'articles.edit_any')) return true;
  return has(user, 'articles.create') && article.author_id === user.id && article.status === 'draft';
}

function getArticle(id) {
  return db.prepare(`
    SELECT a.*, u.login AS author_login, u.full_name AS author_name
    FROM articles a LEFT JOIN users u ON u.id = a.author_id
    WHERE a.id = ?
  `).get(id);
}

function denied(req, res, details) {
  logEvent(req, 'ACCESS_DENIED', { userId: req.user.id, login: req.user.login, details });
  return res.status(403).render('error', { title: 'Brak dostępu', message: 'Nie masz uprawnień do tej operacji.' });
}

function notFound(res) {
  return res.status(404).render('error', { title: 'Nie znaleziono', message: 'Nie ma takiego dokumentu.' });
}

function readForm(body) {
  const values = {
    title: String(body.title || '').trim(),
    content: String(body.content || '').trim(),
  };
  const errors = [];
  if (values.title.length < 1 || values.title.length > 200) errors.push('Tytuł: od 1 do 200 znaków.');
  if (values.content.length < 1 || values.content.length > 20000) errors.push('Treść: od 1 do 20 000 znaków.');
  return { values, errors };
}

function log(req, event, details) {
  logEvent(req, event, { userId: req.user.id, login: req.user.login, details });
}

// --- Lista ---
router.get('/articles', requirePermission('articles.read'), (req, res) => {
  const articles = db.prepare(`
    SELECT a.*, u.login AS author_login
    FROM articles a LEFT JOIN users u ON u.id = a.author_id
    ORDER BY a.updated_at DESC
  `).all()
    .filter((a) => canView(req.user, a))
    .map((a) => ({ ...a, editable: canEdit(req.user, a) }));

  res.render('articles/list', { title: 'Dokumenty', articles });
});

// --- Nowy szkic (musi być PRZED /articles/:id) ---
router.get('/articles/new', requirePermission('articles.create'), (req, res) => {
  res.render('articles/form', { title: 'Nowy dokument', mode: 'new', articleId: null, values: { title: '', content: '' }, errors: [] });
});

router.post('/articles/new', requirePermission('articles.create'), (req, res) => {
  const { values, errors } = readForm(req.body);
  if (errors.length > 0) {
    return res.status(400).render('articles/form', { title: 'Nowy dokument', mode: 'new', articleId: null, values, errors });
  }
  const now = Date.now();
  const id = db.prepare(`
    INSERT INTO articles (title, content, status, author_id, created_at, updated_at)
    VALUES (?, ?, 'draft', ?, ?, ?)
  `).run(values.title, values.content, req.user.id, now, now).lastInsertRowid;

  log(req, 'ARTICLE_CREATED', `szkic #${id}: ${values.title}`);
  req.session.flash = { type: 'success', message: 'Utworzono szkic dokumentu.' };
  res.redirect(`/articles/${id}`);
});

// --- Podgląd ---
router.get('/articles/:id', requirePermission('articles.read'), (req, res) => {
  const article = getArticle(Number(req.params.id));
  if (!article) return notFound(res);
  if (!canView(req.user, article)) return denied(req, res, `podgląd szkicu #${article.id}`);

  res.render('articles/view', {
    title: article.title,
    a: { ...article, editable: canEdit(req.user, article) },
  });
});

// --- Edycja ---
router.get('/articles/:id/edit', requirePermission('articles.read'), (req, res) => {
  const article = getArticle(Number(req.params.id));
  if (!article) return notFound(res);
  if (!canEdit(req.user, article)) return denied(req, res, `edycja dokumentu #${article.id}`);

  res.render('articles/form', {
    title: 'Edycja dokumentu', mode: 'edit', articleId: article.id,
    values: { title: article.title, content: article.content }, errors: [],
  });
});

router.post('/articles/:id/edit', requirePermission('articles.read'), (req, res) => {
  const article = getArticle(Number(req.params.id));
  if (!article) return notFound(res);
  if (!canEdit(req.user, article)) return denied(req, res, `edycja dokumentu #${article.id}`);

  const { values, errors } = readForm(req.body);
  if (errors.length > 0) {
    return res.status(400).render('articles/form', { title: 'Edycja dokumentu', mode: 'edit', articleId: article.id, values, errors });
  }
  db.prepare('UPDATE articles SET title = ?, content = ?, updated_at = ? WHERE id = ?')
    .run(values.title, values.content, Date.now(), article.id);

  log(req, 'ARTICLE_UPDATED', `dokument #${article.id}: ${values.title}`);
  req.session.flash = { type: 'success', message: 'Zapisano zmiany.' };
  res.redirect(`/articles/${article.id}`);
});

// --- Publikowanie / cofnięcie publikacji ---
router.post('/articles/:id/publish', requirePermission('articles.publish'), (req, res) => {
  const article = getArticle(Number(req.params.id));
  if (!article) return notFound(res);

  const newStatus = article.status === 'published' ? 'draft' : 'published';
  db.prepare('UPDATE articles SET status = ?, updated_at = ? WHERE id = ?').run(newStatus, Date.now(), article.id);

  log(req, newStatus === 'published' ? 'ARTICLE_PUBLISHED' : 'ARTICLE_UNPUBLISHED', `dokument #${article.id}: ${article.title}`);
  req.session.flash = {
    type: 'success',
    message: newStatus === 'published' ? 'Dokument został opublikowany.' : 'Cofnięto publikację dokumentu.',
  };
  res.redirect(`/articles/${article.id}`);
});

// --- Usuwanie ---
router.post('/articles/:id/delete', requirePermission('articles.delete'), (req, res) => {
  const article = getArticle(Number(req.params.id));
  if (!article) return notFound(res);

  db.prepare('DELETE FROM articles WHERE id = ?').run(article.id);
  log(req, 'ARTICLE_DELETED', `dokument #${article.id}: ${article.title}`);
  req.session.flash = { type: 'success', message: 'Dokument został usunięty.' };
  res.redirect('/articles');
});

module.exports = router;