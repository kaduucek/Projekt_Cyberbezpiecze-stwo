System CB – Identyfikacja, uwierzytelnianie i autoryzacja

Webówka: Node.js + Express + EJS + SQLite.

Uruchomienie
npm install      # instalacja bibliotek (tylko za pierwszym razem)
npm run seed     # utworzenie bazy, ról, konta ADMIN i 6 kont testowych
npm run dev      # uruchomienie serwera

Aplikacja: http://localhost:3000

Hasło jednorazowe konta ADMIN jest wypisywane w terminalu po `npm run seed`
(ważne 4 godziny, wymagana zmiana przy pierwszym logowaniu).

Konta testowe

| Login        | Rola          | Hasło                      |
|--------------|---------------|----------------------------|
| ADMIN        | Administrator | jednorazowe – z terminala  |
| kierownik    | Kierownik     | Kierownik-Haslo-Testowe    |
| redaktor     | Redaktor      | Redaktor-Haslo-Testowe     |
| pracownik1   | Pracownik     | Pracownik1-Haslo-Testowe   |
| pracownik2   | Pracownik     | Pracownik2-Haslo-Testowe   |
| czytelnik1   | Czytelnik     | Czytelnik1-Haslo-Testowe   |
| czytelnik2   | Czytelnik     | Czytelnik2-Haslo-Testowe   |

Wariant 7
- minimalna długość hasła: 14 znaków
- nowe hasło musi różnić się od poprzedniego o co najmniej 4 znaki
- role: Administrator, Kierownik, Redaktor, Pracownik, Czytelnik
- hasło jednorazowe: 16 znaków alfanumerycznych, ważne 4 h
- 6 użytkowników testowych
