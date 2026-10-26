// Hashowanie i sprawdzanie haseł algorytmem Argon2id.
// Sól jest losowana automatycznie i zapisywana razem z hashem.
const argon2 = require('argon2');

// Parametry zalecane przez OWASP dla Argon2id
const HASH_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB pamięci
  timeCost: 2,       // 2 iteracje
  parallelism: 1,
};

// Zamienia hasło na hash (np. "$argon2id$v=19$m=19456,t=2,p=1$sól$hash")
async function hashPassword(password) {
  return argon2.hash(password, HASH_OPTIONS);
}

// Sprawdza, czy hasło pasuje do zapisanego hasha
async function verifyPassword(hash, password) {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword };