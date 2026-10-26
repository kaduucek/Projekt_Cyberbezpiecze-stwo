// Generowanie haseł jednorazowych zgodnie z wariantem 7:
// 16 znaków alfanumerycznych, ważne 4 godziny.
const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const OTP_LENGTH = 16;
const OTP_VALIDITY_MS = 4 * 60 * 60 * 1000; // 4 godziny w milisekundach

// crypto.randomInt to bezpieczny (kryptograficzny) generator liczb losowych
function generateOneTimePassword() {
  let result = '';
  for (let i = 0; i < OTP_LENGTH; i++) {
    result += ALPHABET[crypto.randomInt(ALPHABET.length)];
  }
  return result;
}

module.exports = { generateOneTimePassword, OTP_LENGTH, OTP_VALIDITY_MS };