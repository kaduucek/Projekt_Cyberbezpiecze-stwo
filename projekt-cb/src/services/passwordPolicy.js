const fs = require('fs');
const path = require('path');
const { db } = require('../db/database');
const { getNumberSetting } = require('./settings');
const { verifyPassword } = require('./passwords');
const { levenshtein } = require('./levenshtein');

const BASELINE_MIN_LENGTH = 8;  // minimum NIST – obowiązuje zawsze
const POLICY_MIN_LENGTH = 14;   // wariant 7 – gdy polityka jest włączona
const MAX_LENGTH = 128;
const MIN_DISTANCE = 4;         // wariant 7 – min. odległość Levenshteina

// Wczytanie listy haseł zakazanych (raz, przy starcie serwera)
const BANNED_FILE = path.join(__dirname, '..', '..', 'data', 'banned-passwords.txt');
let bannedPasswords = new Set();
try {
  bannedPasswords = new Set(
    fs.readFileSync(BANNED_FILE, 'utf8')
      .split(/\r?\n/)
      .map((line) => line.trim().toLowerCase())
      .filter((line) => line && !line.startsWith('#'))
  );
  console.log(`Wczytano listę haseł zakazanych: ${bannedPasswords.size} pozycji`);
} catch {
  console.warn('UWAGA: brak pliku data/banned-passwords.txt – lista haseł zakazanych jest pusta!');
}

function isPolicyEnabled() {
  return getNumberSetting('password_policy_enabled', 1) === 1;
}

// Opis wymagań do wyświetlenia na stronie
function getPolicyDescription() {
  const enabled = isPolicyEnabled();
  const historyCount = getNumberSetting('password_history_count', 5);
  const rules = [
    `co najmniej ${enabled ? POLICY_MIN_LENGTH : BASELINE_MIN_LENGTH} znaków (maksymalnie ${MAX_LENGTH})`,
    'nie może znajdować się na liście popularnych (zakazanych) haseł',
    'nie może zawierać loginu',
    `musi różnić się od obecnego hasła i ${historyCount} poprzednich`,
  ];
  if (enabled) {
    rules.push(`musi różnić się od obecnego hasła o co najmniej ${MIN_DISTANCE} znaki (odległość Levenshteina)`);
  }
  return rules;
}

// Sprawdza nowe hasło. Zwraca listę błędów (pusta lista = hasło OK).
// oldPassword podajemy, gdy znamy stare hasło (przy zmianie przez użytkownika).
async function validateNewPassword({ user, newPassword, oldPassword = null }) {
  const errors = [];
  const enabled = isPolicyEnabled();
  const length = [...newPassword].length;
  const minLength = enabled ? POLICY_MIN_LENGTH : BASELINE_MIN_LENGTH;

  if (length < minLength) {
    errors.push(`Hasło musi mieć co najmniej ${minLength} znaków (obecnie: ${length}).`);
  }
  if (length > MAX_LENGTH) {
    errors.push(`Hasło może mieć najwyżej ${MAX_LENGTH} znaków.`);
  }
  if (bannedPasswords.has(newPassword.toLowerCase())) {
    errors.push('To hasło znajduje się na liście popularnych haseł – wybierz inne.');
  }
  if (user.login && newPassword.toLowerCase().includes(user.login.toLowerCase())) {
    errors.push('Hasło nie może zawierać loginu.');
  }
  if (enabled && oldPassword !== null) {
    const distance = levenshtein(oldPassword, newPassword);
    if (distance < MIN_DISTANCE) {
      errors.push(`Nowe hasło musi różnić się od obecnego o co najmniej ${MIN_DISTANCE} znaki (różnica: ${distance}).`);
    }
  }

  // Porównanie z historią sprawdzamy na końcu (każde porównanie Argon2 trwa chwilę)
  if (errors.length === 0 && user.id) {
    const historyCount = getNumberSetting('password_history_count', 5);
    const oldHashes = db.prepare(`
      SELECT password_hash FROM password_history
      WHERE user_id = ? ORDER BY id DESC LIMIT ?
    `).all(user.id, historyCount).map((row) => row.password_hash);

    for (const hash of [user.password_hash, ...oldHashes]) {
      if (await verifyPassword(hash, newPassword)) {
        errors.push(`Nowe hasło nie może być takie samo jak obecne ani jak żadne z ${historyCount} poprzednich.`);
        break;
      }
    }
  }

  return errors;
}

module.exports = { validateNewPassword, getPolicyDescription, isPolicyEnabled };