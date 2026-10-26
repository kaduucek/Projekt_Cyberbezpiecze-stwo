// Odlicza czas do wygaśnięcia sesji i po jego upływie przenosi do logowania.
// Serwer też pilnuje czasu – ten skrypt tylko pokazuje licznik i przekierowuje.
(function () {
  const el = document.getElementById('session-timer');
  if (!el) return;

  const idleMs = Number(el.dataset.idleMinutes) * 60 * 1000;
  const end = Date.now() + idleMs + 1000; // +1 s zapasu

  function tick() {
    const left = end - Date.now();
    if (left <= 0) {
      window.location.href = '/login?expired=1';
      return;
    }
    const m = Math.floor(left / 60000);
    const s = Math.floor((left % 60000) / 1000);
    el.textContent = `⏱ Sesja wygaśnie za ${m}:${String(s).padStart(2, '0')}`;
    setTimeout(tick, 1000);
  }
  tick();
})();