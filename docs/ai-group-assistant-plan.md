# Plan jawnego asystenta AI dla grupy Telegram

## Cel i zakres

Asystent ma wspierać grupę w bezpiecznej triage, odpowiadaniu na pytania,
przypominaniu o procedurach i kierowaniu spraw do człowieka. Jest jawny:
wiadomość powitalna, nazwa konta i każda odpowiedź informują, że odpowiada
automatyzacja AI. Bot nie udaje członka zespołu ani operatora.

Plan nie obejmuje C2, evasion, ukrytej persistence, reverse shelli, port
knockingu, eksfiltracji, Shadow Agent ani self-erasure. Asystent nie wykonuje
poleceń systemowych, nie skanuje celów, nie pobiera danych poza Telegramem i
nie usuwa ani nie ukrywa śladów rozmowy.

## Architektura i przepływ

1. Telethon odbiera wyłącznie zdarzenia z jawnie skonfigurowanych grup i
   tematów. Allowlista opiera się na stabilnym chat ID, nie na samej nazwie.
2. Warstwa walidacji odrzuca nieznane czaty, nieobsługiwane typy wiadomości,
   zbyt duże załączniki i żądania wykraczające poza katalog funkcji.
3. Router rozpoznaje komendy, prośby o podsumowanie i pytania. Treść jest
   traktowana jako niezaufany input; instrukcje znalezione w cytowanych
   dokumentach nie zmieniają polityki bota.
4. Model generuje propozycję z krótkim uzasadnieniem, źródłem kontekstu i
   poziomem pewności. Osobna warstwa polityk sprawdza zakres, PII i prompt
   injection przed wysłaniem.
5. Odpowiedź jest publikowana z oznaczeniem `AI assistant`. Działania
   skutkujące zmianą, powiadomieniem lub decyzją wymagają zatwierdzenia
   człowieka w panelu lub przez jawne polecenie moderatora.

## Najmniejsze uprawnienia Telethon

- Konto bota ma dostęp tylko do wskazanych grup; prywatne rozmowy, kontakty,
  historię innych czatów i listę członków wyłącza się, jeśli nie są potrzebne.
- Uprawnienia administratora nie są przyznawane. Bot może wysyłać wiadomości
  i odczytywać minimalny zakres zdarzeń potrzebny do odpowiedzi; usuwanie,
  banowanie, pinowanie, zapraszanie i zmianę uprawnień pozostają wyłączone.
- Sesja Telethon i tokeny są w menedżerze sekretów, poza repozytorium i
  logami. Tokeny rotuje się, ogranicza do jednego środowiska i unieważnia po
  podejrzeniu wycieku.
- Egress jest ograniczony do Telegram API, zatwierdzonego dostawcy modelu i
  centralnego logowania przez TLS. Brak arbitralnych URL-i, proxy i tuneli.
- Deployment działa jako nieuprzywilejowany użytkownik w odseparowanym
  środowisku, z limitem CPU/pamięci i bez montowania hostowego systemu plików.

## Human-in-the-loop

Automatyczne odpowiedzi są dozwolone tylko dla niskiego ryzyka: FAQ, status
usługi, link do zatwierdzonej procedury oraz neutralne podsumowanie. Człowiek
zatwierdza:

- rekomendacje bezpieczeństwa, klasyfikację incydentu i komunikaty kryzysowe;
- odpowiedzi zawierające dane osobowe, dane klientów lub informacje
  niepubliczne;
- każdą akcję moderacyjną, zmianę konfiguracji, wysłanie wiadomości poza
  grupę i integrację z innym systemem;
- przypadki niskiej pewności, sprzecznego kontekstu lub wykrytej próby
  prompt injection.

Przycisk/komenda zatwierdzenia pokazuje pełną treść, odbiorców, zakres danych,
ryzyko i czas wygaśnięcia. Brak decyzji w TTL oznacza odrzucenie i eskalację,
nie ponawianie w nieskończoność. Każda decyzja ma approver ID, timestamp,
powód i correlation ID.

## Bezpieczeństwo treści i danych

- Waliduj długość, kodowanie, załączniki i formaty. Nie wykonuj tekstu,
  Markdownu, poleceń ani kodu pochodzącego z wiadomości użytkownika.
- Redaguj tokeny, hasła, klucze, numery identyfikacyjne i zbędne PII przed
  przekazaniem do modelu. Wysyłaj tylko minimalny kontekst.
- Dostawca modelu nie może trenować na danych organizacji; używaj szyfrowania
  w tranzycie i w spoczynku oraz umowy określającej role administratora.
- Odpowiedzi muszą odróżniać fakty, hipotezy i brak danych. Nie obiecuj
  wykonania czynności, której system nie wykonał.

## Audyt, monitoring i IR

Loguj: chat ID (pseudonimizowany, gdy możliwe), message/event ID, decyzję
routera, wersję promptu i modelu, zakres redakcji, wynik polityk, approver ID,
czas, status wysyłki oraz błędy Telethon. Nie loguj pełnej treści, jeśli nie
jest to konieczne do audytu; przechowuj hash lub odnośnik do kontrolowanego
repozytorium dowodów.

Alerty obejmują: wzrost odrzuceń, próbę dostępu spoza allowlisty, wielokrotne
błędy autoryzacji, zmianę uprawnień, nietypowy egress, prompt injection i
opóźnienia kolejki. Przy incydencie człowiek zatrzymuje wysyłanie, unieważnia
sesję/token, zachowuje logi, ocenia zakres dostępu i wdraża nowy, znany-dobry
obraz. Nie wolno kasować logów ani ukrywać aktywności.

## Retencja i recovery

| Dane | Domyślna retencja | Kontrola |
|---|---:|---|
| Metadane audytowe i decyzje | 180 dni | append-only, dostęp RBAC |
| Treść wiadomości przekazana do modelu | 30 dni | minimalizacja i szyfrowanie |
| Cache kontekstu | do 24 h | automatyczne wygasanie |
| Sekrety Telethon/modelu | do rotacji | KMS/Vault, bez backupu jawnego |

Właściciel danych może skrócić retencję zgodnie z prawem i polityką
organizacji. Usuwanie danych podlega zatwierdzonej polityce retencji i jest
rejestrowane; nie jest mechanizmem zacierania śladów audytowych. Kopie
zapasowe są szyfrowane, ograniczone do niezbędnego zakresu i regularnie
testowane pod kątem odtworzenia bez ujawnienia sekretów.

Recovery obejmuje odtworzenie z podpisanego obrazu, ponowną konfigurację
allowlisty, rotację tokenów, test połączenia z ograniczonym kontem, test
human-in-the-loop i weryfikację centralnych logów. W razie niepewności bot
przechodzi w tryb read-only/maintenance i informuje moderatorów.

## Kryteria akceptacji

- [ ] Każda odpowiedź jest jawnie oznaczona jako wygenerowana przez AI.
- [ ] Allowlista chatów i minimalne uprawnienia są testowane negatywnie.
- [ ] Brak akcji uprzywilejowanych bez zatwierdzenia człowieka.
- [ ] PII i sekrety są redagowane przed wywołaniem modelu.
- [ ] Audyt, alerty, retencja i rotacja sekretów mają właściciela.
- [ ] Przetestowano prompt injection, wyciek tokenu, niedostępność API i recovery.
