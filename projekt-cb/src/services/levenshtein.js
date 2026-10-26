// Odległość Levenshteina = najmniejsza liczba operacji (wstawienie, usunięcie
// lub zamiana jednego znaku), które zamieniają jeden napis w drugi.
// Przykład: "kot" -> "kit" = 1 (zamiana o na i), "kitten" -> "sitting" = 3.
function levenshtein(a, b) {
  const s = [...a]; // [...tekst] dzieli na znaki poprawnie także dla polskich liter i emoji
  const t = [...b];

  // prev[j] = odległość między pierwszymi i-1 znakami s a pierwszymi j znakami t
  let prev = Array.from({ length: t.length + 1 }, (_, j) => j);

  for (let i = 1; i <= s.length; i++) {
    const curr = [i];
    for (let j = 1; j <= t.length; j++) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,        // usunięcie znaku
        curr[j - 1] + 1,    // wstawienie znaku
        prev[j - 1] + cost  // zamiana znaku (albo brak zmiany)
      );
    }
    prev = curr;
  }
  return prev[t.length];
}

module.exports = { levenshtein };