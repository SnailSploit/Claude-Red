# Blueprint ephemeral OS

## Cel i granice

Ten dokument opisuje defensywny, jednorazowy (ephemeral) system operacyjny do
pracy administracyjnej, analitycznej i reagowania na incydenty. Obraz systemu
powinien być odtwarzalny z kontrolowanego źródła, uruchamiany na zaufanym
sprzęcie i niszczony po zakończeniu sesji. Każdy wyjątek od tej zasady wymaga
udokumentowanej zgody właściciela systemu.

Projekt **nie obejmuje** C2, evasion, ukrytej persistence, reverse shelli, port
knockingu, eksfiltracji danych, Shadow Agent ani self-erasure. Nie należy
dodawać mechanizmów omijania kontroli, ukrywania aktywności ani automatycznego
usuwania śladów audytowych.

## Łańcuch zaufania przy starcie

1. **Secure Boot** powinien być włączony w UEFI, z własnością kluczy
   zarządzaną przez organizację (PK/KEK/db/dbx). Do obrazu trafiają wyłącznie
   podpisane komponenty bootloadera, kernela i initramfs. Wyłączenie Secure
   Boot jest zmianą kontrolowaną, jednorazową i rejestrowaną.
2. **Measured boot** mierzy kolejno firmware, bootloader, konfigurację kernela,
   initramfs i polityki uruchomieniowe do PCR TPM. Same pomiary nie blokują
   startu, dlatego ich wartości należy porównywać z zaakceptowanym manifestem.
3. **TPM attestation** dostarcza zdalnemu weryfikatorowi quote podpisany
   kluczem attestation key oraz nonce, aby potwierdzić świeżość odpowiedzi.
   Weryfikator sprawdza certyfikat AK, PCR, manifest wersji i stan revocation.
   Odmowa attestation oznacza brak dostępu do sekretów sesji, a nie próbę
   obejścia kontroli.
4. Klucze dyskowe i sekret bootstrapu są wydawane dopiero po pozytywnej
   atestacji (np. przez KMS/Vault). Nie przechowuje się ich w obrazie ani w
   repozytorium.

### Kontrola integralności

- Obraz jest budowany deterministycznie, podpisywany i publikowany wraz z
  sumą, SBOM-em oraz numerem wersji.
- Przy starcie i przed każdą sesją sprawdza się podpis obrazu, initramfs,
  konfigurację, polityki systemd i listę dozwolonych modułów.
- System plików bazowy jest tylko do odczytu (np. dm-verity); zapisy trafiają
  do jawnie zdefiniowanych warstw tymczasowych.
- Zmiana obrazu, polityki lub firmware wymaga code review, dwóch osób
  zatwierdzających i ponownego pomiaru PCR.

## Pamięć operacyjna i dane tymczasowe

- `/tmp`, `/run` i obszary robocze montuje się jako ograniczone `tmpfs`, z
  limitami rozmiaru, `nodev`, `nosuid` i `noexec` tam, gdzie nie koliduje to z
  działaniem systemu.
- Swap jest wyłączony albo szyfrowany kluczem sesyjnym; nie wolno przenosić do
  niego sekretów w postaci jawnej.
- Dane potrzebne do dowodów zapisuje się do zatwierdzonego, szyfrowanego
  repozytorium audytowego przed końcem sesji. Pamięć tymczasowa jest
  czyszczona przez kontrolowaną procedurę wyłączenia, bez obietnicy
  nierealistycznego wymazania wszystkich śladów z nośnika.
- Sesja ma identyfikator, właściciela, cel, czas rozpoczęcia i czas wygaśnięcia.
  Po wygaśnięciu dostęp jest blokowany, a instancję odtwarza się z obrazu
  zamiast „naprawiać” ją ręcznie.

## Dostęp administracyjny i SSH

- Dostęp SSH jest możliwy wyłącznie z zarządzanej sieci lub przez zatwierdzony
  bastion, z kluczami FIDO2/ed25519 i MFA. Logowanie hasłem, kontem root oraz
  współdzielonymi kluczami jest wyłączone.
- `sshd` ma wyłączone `PermitRootLogin`, `PasswordAuthentication`,
  `AllowAgentForwarding` i `GatewayPorts`; `AllowTcpForwarding` jest wyłączane
  lub ograniczane do udokumentowanej potrzeby.
- `AllowGroups`, krótki `LoginGraceTime`, limity prób, aktualne algorytmy
  kryptograficzne i jawna lista administratorów ograniczają powierzchnię.
  Zmiany konfiguracji wymagają testu składni i przeglądu.
- Klucze są krótkotrwałe, rotowane i unieważniane po sesji. Każda komenda
  uprzywilejowana jest przypisana do użytkownika i identyfikatora sesji.

## Centralne logowanie i audyt

- `journald`, logi uwierzytelniania, auditd/eBPF (zgodnie z polityką systemu),
  status attestation, zmiany konfiguracji i działania administratorów są
  wysyłane przez TLS do centralnego, append-only systemu logów.
- Log zawiera czas synchronizowany przez zaufane źródło, host/session ID,
  podmiot, działanie, wynik i correlation ID. Sekrety, tokeny i pełne dane
  osobowe są maskowane przed wysłaniem.
- Lokalny bufor ma limit i jawne zachowanie przy niedostępności kolektora:
  operacja ryzykowna jest wstrzymywana, a nie wykonywana po cichu.
- Retencja jest opisana klasą danych, właścicielem i podstawą prawną.
  Dostęp do logów jest najmniejszym wymaganym uprawnieniem i sam podlega
  audytowi.

## Reagowanie na incydenty (IR)

1. **Wykrycie i kwalifikacja:** potwierdź alert, przypisz severity, zachowaj
   correlation ID i nie modyfikuj dowodów.
2. **Ograniczenie:** odetnij sesję lub poświadczenia przez zatwierdzony proces,
   zachowując logi; nie stosuj ukrywania ani automatycznego czyszczenia.
3. **Analiza:** zweryfikuj PCR/attestation, integralność obrazu, logi SSH,
   audit i zmiany w repozytoriach. Zbieraj minimalny, uzasadniony zakres danych.
4. **Eradykacja i odtworzenie:** unieważnij klucze, zbuduj znany-dobry obraz,
   ponownie przeprowadź atestację i odtwórz ephemeral host. Każdy krok jest
   zatwierdzony i odnotowany.
5. **Lessons learned:** zamknij incydent dopiero po korelacji dowodów,
   przeglądzie kontroli i aktualizacji runbooka.

## Recovery i testy

- Utrzymuj podpisany obraz, konfigurację jako kod, manifest PCR, kopie
  konfiguracji kolektora i listę kontaktów eskalacyjnych w co najmniej dwóch
  niezależnych lokalizacjach.
- Recovery point objective i recovery time objective są ustalane dla każdej
  klasy danych. Sekrety odtwarza się przez KMS/Vault, nigdy z kopii obrazu.
- Co najmniej kwartalnie testuj: odtworzenie hosta, negatywną attestation,
  unieważnienie klucza, niedostępność logowania centralnego oraz odtworzenie
  dowodów. Wyniki i wyjątki przechowuj w audycie.

## Minimalna checklista wdrożenia

- [ ] Secure Boot i polityka kluczy są aktywne.
- [ ] Measured boot i TPM attestation są weryfikowane przed wydaniem sekretów.
- [ ] Obraz, initramfs i konfiguracja mają podpis oraz manifest integralności.
- [ ] `/tmp`/`/run` używają ograniczonego `tmpfs`, a swap nie ujawnia sekretów.
- [ ] SSH wymaga MFA, kluczy krótkotrwałych i minimalnych uprawnień.
- [ ] Logi i audyt trafiają centralnie, są maskowane i objęte retencją.
- [ ] IR, recovery, właściciele i kontakty eskalacyjne są przećwiczone.
