# 802.15.4 Recon research dla ESP32-C5 / ESP-IDF 6.0

Status: research plus pierwsza implementacja JanOS CLI/firmware. Zakres obejmuje pasywny recon, parser MAC 802.15.4, snapshoty i komendy UART; tab5 zostaje konsumentem danych `[ZIG]`.

Zrodlo prawdy na ten etap:
- lokalny ESP-IDF: `C:\esp\v6.0\esp-idf`, `git describe`: `v6.0-dirty`, commit `662a3be3`
- projekt Monster: `main/main.c`, `main/CMakeLists.txt`, `sdkconfig.defaults`
- przyklad bazowy: `C:\esp\v6.0\esp-idf\examples\ieee802154\ieee802154_cli`
- przyklady referencyjne: `examples/openthread`, `examples/zigbee`

## Cel funkcji

Dodac pozniej do taba 5 koncept pasywnego `802.15.4 Recon`, podobny do ekranu ze screena:
- aktualny kanal 802.15.4: 11-26
- liczba odebranych pakietow
- liczba wykrytych sieci/PAN
- lista PAN ID, typ/protokol heurystyczny, liczba node'ow i pakietow
- start/stop skanowania
- docelowo zapis wynikow/logow na SD, ale nie jako etap 1

Zakres ma byc recon/pasywny skan, nie aktywne dolaczanie do sieci Zigbee/Thread/Matter.

## Najwazniejsze findingi z ESP-IDF 6.0

ESP-IDF ma natywny komponent `ieee802154` dla radia 802.15.4. Do minimalnego pasywnego skanera potrzebne sa:
- `esp_ieee802154_enable()`
- `esp_ieee802154_disable()`
- `esp_ieee802154_set_channel(uint8_t channel)`; zakres kanalow: 11-26
- `esp_ieee802154_set_promiscuous(true)`
- `esp_ieee802154_receive()`
- `esp_ieee802154_set_rx_when_idle(true)`
- callback `esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info)`
- po obsludze kazdej ramki trzeba wywolac `esp_ieee802154_receive_handle_done(frame)`

Przyklad `ieee802154_cli` robi dokladnie te operacje:
- `app_main()` najpierw wywoluje `esp_ieee802154_enable()`
- komenda `promisc --enable` wlacza `esp_ieee802154_set_promiscuous(true)`
- komenda `rx --receive 1` robi `esp_ieee802154_receive()` i `esp_ieee802154_set_rx_when_idle(true)`
- callback `esp_ieee802154_receive_done()` drukuje ramke i oddaje bufor przez `esp_ieee802154_receive_handle_done(frame)`

`esp_ieee802154_frame_info_t` w lokalnym IDF daje co najmniej:
- `channel`
- `rssi`
- `lqi`
- `timestamp`
- flagi `pending` i `process`

Callbacki sa z kontekstu ISR lub blisko ISR. W Monsterze nie wolno w nich parsowac ciezko, alokowac duzo ani drukowac po UART. Poprawny wzorzec:
- szybka kopia minimalnego frame + metadanych do statycznej kolejki/ring bufora
- natychmiast `esp_ieee802154_receive_handle_done(frame)`
- osobny task `zig_recon_task` parsuje i aktualizuje tabele PAN/node

## Coex i ograniczenia ESP32-C5

ESP32-C5 ma jedno radio 2.4 GHz wspoldzielone przez Wi-Fi/BLE/802.15.4. Przyklady Espressif dla Zigbee gateway ostrzegaja, ze na single-SoC Wi-Fi i Zigbee nie odbieraja jednoczesnie i wydajnosc mocno spada; zalecane bywa rozwiazanie dwu-SoC/RCP. Dla Monstera oznacza to:
- `802.15.4 Recon` powinien byc trybem ekskluzywnym wzgledem Wi-Fi promisc/wardrive, BLE scan i nRF24 jammer.
- `stop` musi jednoznacznie wylaczac RX 15.4 i oddawac radio.
- Nie mieszac na start z obecnym `start_wardrive_promisc`, bo ten juz agresywnie uzywa Wi-Fi promiscuous i BLE.
- Trzeba uzyc istniejacego modelu "jedna aktywna akcja naraz" w `main.c`, jesli juz istnieje przy `stop`.

W `main/CMakeLists.txt` obecnie nie ma `ieee802154`; trzeba bedzie dodac `ieee802154` do `REQUIRES` dopiero w etapie implementacji. W `sdkconfig.defaults` obecnie nie ma `CONFIG_IEEE802154_ENABLED`; trzeba bedzie zweryfikowac, czy menuconfig ustawia to automatycznie dla targetu ESP32-C5 po dodaniu komponentu, czy wpisujemy jawnie.

## Zigbee, Thread, Matter: co da sie rozpoznac pasywnie

Wszystkie te technologie uzywaja IEEE 802.15.4 PHY/MAC w 2.4 GHz, wiec pierwszy poziom recon jest wspolny: kanal, PAN ID, adresy short/extended, typ ramki, RSSI/LQI.

Zigbee:
- zwykle widoczny jako ruch 802.15.4 z PAN ID i czesto beaconami/komendami sieciowymi.
- Dla UI mozna tagowac jako `Zigbee?` po typach ramek i polach NWK, ale wiele payloadow bedzie szyfrowanych.
- Pewne rozpoznanie Zigbee wymaga parsera NWK/APS/ZCL tam, gdzie payload nie jest zaszyfrowany albo w beaconach jest wystarczajaca sygnatura.

Thread:
- Thread to IPv6/6LoWPAN nad 802.15.4.
- Pasywnie mozna tagowac jako `Thread?` po wzorcach 6LoWPAN/MLE, ale payloady moga byc zabezpieczone.
- Pelne dolaczenie do Thread wymagaloby OpenThread, datasetu i logiki sieciowej; to nie jest potrzebne do recon etapu 1.

Matter:
- Matter nie jest osobna warstwa radiowa. Matter over Thread bedzie wygladal radiowo jak Thread.
- W pasywnym 802.15.4 recon tag `Matter` moze byc co najwyzej `Matter/Thread?`, chyba ze pozniej dodamy parser warstwy aplikacyjnej po dolaczeniu do sieci lub po widocznych, nieszyfrowanych metadanych.
- Implementacja ma heurystyke `matter_thread`: najpierw payload musi wygladac jak Thread/6LoWPAN, a potem musi zawierac widoczny slad portu/uslugi Matter/CoAP/mDNS/MeshCoP (`5540`, `5683`, `5353`, `_matter`, `_meshcop`). Wynik pozostaje `confidence=probable`.
- Dlatego UI nie powinno obiecywac "Matter detected" jako pewnika na etapie pasywnym.

## Minimalna architektura dla Monstera

Proponowany komponent:
- `components/zig_recon/`
- publiczne API:
  - `zig_recon_start(const zig_recon_config_t *cfg)`
  - `zig_recon_stop(void)`
  - `zig_recon_get_snapshot(zig_recon_snapshot_t *out)`
  - opcjonalnie `zig_recon_clear(void)`
- wewnatrz:
  - task kanalo-hopera 11-26
  - task parsera ramek albo jeden task laczacy parser + hopper
  - statyczna kolejka z callbacku RX
  - tabela PAN z limitem, np. 32/64 wpisy
  - tabela node z limitem, np. 128/256 wpisow

Parser etap 1:
- dekoduje Frame Control Field
- typ ramki: beacon/data/ack/mac command
- adresowanie: PAN ID, src/dst short/extended tam, gdzie pola sa obecne
- aktualizuje:
  - `packets_total`
  - `current_channel`
  - `pan_count`
  - per PAN: `pan_id`, `channel_mask_seen`, `packet_count`, `node_count`, `last_rssi`, `best_rssi`, `last_seen_ms`, `proto_guess`

Heurystyka protokolu etap 1:
- domyslnie `802.15.4`
- `Zigbee?` dla wzorcow Zigbee beacon/NWK, jesli parser je potwierdzi
- `Thread?` dla wzorcow 6LoWPAN/MLE
- `Matter/Thread?` dla wzorcow Thread/6LoWPAN plus widoczny slad Matter/CoAP/mDNS/MeshCoP; zawsze `probable`, nie `confirmed`

UI/tab5 etap 1:
- panel statusu: kanal, pakiety, PAN-y, status aktywny
- lista PAN: `PAN: 0x1234`, badge `802.15.4` / `Zigbee?` / `Thread?`, `n nodes | n packets`
- start/stop przez istniejacy mechanizm komend/akcji

CLI etap 1:
- `start_zig_recon`
- `stop` zatrzymuje recon
- `zig_recon_status`
- `zig_recon_list [all]`
- `zig_recon_nodes <pan_id|all>`
- `zig_recon_clear`

## Prezentacja znalezisk: tab5

Konkurencyjna apka pokazuje to dobrze jako ekran roboczy, nie raport. Najbardziej wartosciowe elementy:
- naglowek `802.15.4 Recon`
- pasek metryk: aktualny kanal, laczna liczba pakietow, liczba sieci/PAN
- karty PAN, domyslnie zwijane
- po rozwinieciu PAN: mini topologia i lista node'ow
- wyrazny przycisk start/stop jako stan skanera

Proponowany widok dla tab5:
- top app bar:
  - `802.15.4 Recon`
  - back
  - clear/trash do wyczyszczenia wynikow sesji
  - help z legenda pewnosci protokolu
- status strip:
  - `Channel`: aktualny kanal hoppera, np. `11`
  - `Packets`: laczna liczba ramek w sesji
  - `Networks`: liczba unikalnych PAN ID
  - status dot: zielony skanuje, szary idle, czerwony blad/coex lock
- lista PAN:
  - `PAN: 0x1A62`
  - badge protokolu: `Zigbee`, `Zigbee?`, `Thread?`, `802.15.4`
  - podtytul: `6 nodes | 48 packets | ch 11,15 | -63 dBm`
  - sortowanie domyslne: ostatnio widziane i liczba pakietow, nie po PAN ID

Stan rozwiniety PAN:
- sekcja `Topology`
  - node coordinator jako pomaranczowy wiekszy punkt, jesli rozpoznany
  - routery jako niebieskie punkty
  - end devices jako zielone punkty
  - unknown jako szare punkty
  - krawedzie tylko gdy mamy realna relacje z ramek; inaczej nie rysowac udawanej siatki
- sekcja `Nodes`
  - adres short, np. `0x0000`, `0x13D7`
  - rola: `Coordinator`, `Router`, `End Device`, `Unknown`
  - liczba pakietow
  - ostatni RSSI
  - opcjonalnie `last seen`, jesli jest miejsce

Wazne UX:
- nie obiecywac pewnej detekcji Matter. Dla pasywnego sniffingu pokazujemy `Thread?` albo `Matter/Thread?` dopiero gdy mamy wystarczajaca heurystyke i nadal z oznaczeniem niepewnosci.
- Badge bez `?` tylko dla rozpoznania mocnego, np. Zigbee beacon/NWK pattern potwierdzony parserem.
- Nie mieszac PAN z roznych kanalow bez pokazania `channels seen`, bo ten sam PAN moze byc obserwowany w roznych momentach hoppera.
- W stanie pustym pokazac metryki i tekst neutralny typu `No 802.15.4 networks yet`, bez tutoriala.
- Dla malego ekranu topologia jest drugorzedna; lista node'ow ma byc bardziej przydatna niz ladny graf.

Minimalny kontrakt danych dla UI:
```text
zig_recon_snapshot
  active: bool
  current_channel: uint8
  packets_total: uint32
  pan_count: uint16
  dropped_frames: uint32
  pans[]
    pan_id: uint16
    proto: enum unknown/ieee802154/zigbee/thread/matter_thread
    confidence: enum confirmed/probable/unknown
    channel_mask: uint32
    packets: uint32
    nodes: uint16
    best_rssi: int8
    last_rssi: int8
    last_seen_ms: uint32
    expanded_nodes[]
      short_addr: uint16
      ext_addr: optional uint64
      addr_type: enum short/ext/unknown
      role: enum coordinator/router/end_device/unknown
      packets: uint32
      last_rssi: int8
      last_seen_ms: uint32
```

## Prezentacja znalezisk: JanOS konsola

Konsola powinna miec dwa poziomy: szybki status dla czlowieka i format maszynowy dla UI/JanOS.

Komendy proponowane:
- `start_zig_recon [channels|all] [dwell_ms]`
- `zig_recon_status`
- `zig_recon_list`
- `zig_recon_nodes <pan_id>`
- `zig_recon_clear`
- `stop`

Format ludzki `zig_recon_status`:
```text
802.15.4 Recon: running
Channel: 11  Packets: 55  Networks: 4  Dropped: 0
Hopping: 11-26 dwell=250ms  Mode: passive
```

Format ludzki `zig_recon_list`:
```text
PAN       Proto       Ch        Nodes  Packets  RSSI  Last
0x1A62    Zigbee      11,15     6      48       -63   2s
0x889A    Zigbee?     20        1      3        -77   8s
```

`PAN 0xFFFF` to broadcast/special PAN, nie normalna siec. Domyslne `zig_recon_list` ukrywa go z listy sieci; `zig_recon_list all` pokazuje go z `kind=broadcast`.

Format ludzki `zig_recon_nodes 0x1A62`:
```text
PAN 0x1A62  Proto: Zigbee  Channels: 11,15  Packets: 48
ADDR      ROLE         PKTS  RSSI  LAST
0x0000    Coordinator  42    -63   2s
0x13D7    Router       3     -73   4s
0x94F3    Router       2     -84   6s
0x9853    End Device   1     -79   9s
```

Format maszynowy powinien byc stabilny i prefiksowany, z markerem konca jak obecne `[WDCFG] END`:
```text
[ZIG] status active=1 channel=11 packets=55 pans=4 dropped=0 dwell_ms=250
[ZIG] pan id=0x1A62 kind=network proto=zigbee confidence=confirmed channels=0x00000011 nodes=6 packets=48 best_rssi=-63 last_rssi=-67 last_seen_ms=123456 age_ms=2000
[ZIG] node pan=0x1A62 addr_type=short short=0x0000 ext=na role=coordinator packets=42 last_rssi=-63 best_rssi=-58 avg_rssi=-61 lqi=172 sample_count=42 last_channel=11 vendor=na device_hint=na battery=na last_seen_ms=123456 age_ms=2000
[ZIG] END
```

`last_seen_ms` jest timestampem uptime urzadzenia. `age_ms` jest wiekiem obserwacji i to pole powinno karmic UI `last seen`.
`short=na` oznacza, ze ramka miala tylko extended source address; UI ma wtedy uzyc `ext` jako adresu i nie renderowac falszywego `0xFFFF`.
`best_rssi`, `avg_rssi`, `sample_count`, `last_channel` i `lqi` sluza do oceny jakosci sygnalu i namierzania po trendzie RSSI; nie sa dystansem w metrach. `vendor`, `device_hint` i `battery` maja wartosc `na`, dopoki parser nie potwierdzi ich z ramek.

Zasady konsoli:
- `start_zig_recon` ma odmowic startu, jesli aktywny jest Wi-Fi promisc/wardrive/BLE scan/nRF24, z komunikatem `FAILED: radio busy (...)`.
- `stop` ma byc idempotentny.
- `zig_recon_list` nie powinien zalewac UART; limit domyslny 20 PAN, opcjonalnie `zig_recon_list all`.
- `zig_recon_nodes all` sluzy do synchronizacji tab5 bez odpytywania kazdego PAN osobno.
- format maszynowy nie powinien zmieniac nazw pol bez potrzeby, bo JanOS/UI bedzie go parsowal.
- RSSI `unknown` kodowac jako puste `rssi=na`, nie jako magiczne `0`.
- Duze tabele recon PAN/node sa alokowane raz w PSRAM. FreeRTOS queue dla callbacku RX zostaje przez `xQueueCreate`, bo jest uzywana z ISR.

## TODO etapami

Etap 0 - decyzje przed kodem:
- [ ] Potwierdzic, czy w tab5 pokazujemy nazwe `802.15.4 Recon`, `Zig Recon`, czy `Zigbee/Thread Recon`.
- [ ] Potwierdzic, czy tryb ma byc tylko pasywny bez TX. Rekomendacja: tylko pasywny.
- [ ] Potwierdzic, czy na start blokujemy Wi-Fi/BLE/wardrive podczas recon. Rekomendacja: tak.
- [ ] Dostac sciezke do "innego softu", ktory juz to robi na ESP32-C5, jezeli mamy porownac parser/UI z realnym kodem.
- [ ] Uzgodnic, czy JanOS bedzie parsowal linie `[ZIG]`, czy dostanie pozniej osobny JSON/transport.

Etap 1 - spike techniczny:
- [x] Dodac maly komponent `zig_recon` z samym start/stop RX i licznikami.
- [x] Dodac `ieee802154` do `REQUIRES`.
- [x] Dodac/zweryfikowac `CONFIG_IEEE802154_ENABLED=y` dla ESP32-C5.
- [x] Zrobic callback RX z kolejka i `receive_handle_done`.
- [x] Zweryfikowac build na ESP-IDF z `C:\esp\v6.0\esp-idf`.

Etap 2 - parser i model danych:
- [x] Dekodowac MAC 802.15.4: FCF, sequence, PAN ID, adresy, typ ramki.
- [x] Zliczac PAN-y i node'y.
- [x] Zliczac per-node `best_rssi`, `avg_rssi`, `sample_count`, `last_channel` i `lqi`.
- [x] Dodac podstawowa heurystyke `Zigbee?`/`Thread?`.
- [x] Dodac snapshot API; duze tabele robocze i snapshoty CLI alokowac w PSRAM, bez dynamicznej alokacji per odebrana ramke.

Etap 3 - integracja Monster:
- [x] Podpiac `start_zig_recon` i status do konsoli.
- [x] Podpiac `stop`.
- [x] Dodac `zig_recon_list` i `zig_recon_nodes <pan_id|all>`.
- [x] Dodac prefiksowany output `[ZIG] ... [ZIG] END` dla JanOS/UI.
- [ ] Dodac status do OLED lub UI tab5, zgodnie z tym jak tab5 jest faktycznie zrobiony w Monsterze.
- [x] Zablokowac konflikt z aktywnym Wi-Fi promisc/BLE/nRF24.

Etap 4 - zapis i eksport:
- [ ] Zapis CSV/JSON na SD z timestampem, kanalem, PAN, RSSI/LQI, typem ramki.
- [ ] Opcjonalny PCAP z linktype dla IEEE 802.15.4, jesli narzedzia docelowe tego potrzebuja.
- [ ] Opcjonalny ring log ostatnich ramek do debugowania.

Etap 5 - pelniejsze rozpoznawanie protokolow:
- [ ] Parser Zigbee beacon/NWK tam, gdzie dane sa dostepne.
- [ ] Parser Thread/6LoWPAN/MLE heurystyczny.
- [x] Dodac ostrozna heurystyke `Matter/Thread?` nad widocznym Thread/6LoWPAN payloadem.
- [ ] Jasne oznaczanie pewnosci: `confirmed`, `probable`, `unknown`.

Etap 6 - oczekiwane wyniki i implementacja tab5:
- [ ] Dodac ekran `802.15.4 Recon` w tab5 jako narzedzie robocze, nie raport ani landing page.
- [ ] Start skanowania z UI ma wysylac `start_zig_recon` albo `start_zig_recon <channels> <dwell_ms>`; stop ma wysylac globalne `stop`.
- [ ] UI po starcie ma cyklicznie pobierac `zig_recon_status`, `zig_recon_list` i `zig_recon_nodes all`; rekomendowany interwal: status 1 s, lista/nody 2-3 s.
- [ ] Parser tab5 ma czytac tylko linie `[ZIG]` i konczyc request na `[ZIG] END`; tekst ludzki ignorowac.
- [ ] Status strip ma pokazywac `channel`, `packets`, `pans/networks`, `dropped` i stan `active`.
- [ ] Lista PAN ma uzywac `[ZIG] pan`: `id`, `kind`, `proto`, `confidence`, `channels`, `nodes`, `packets`, `best_rssi`, `last_rssi`, `age_ms`.
- [ ] `kind=broadcast` / `PAN 0xFFFF` nie pokazujemy jako normalnej sieci; mozna pokazac w sekcji debug albo po wlaczeniu filtra `show broadcast`.
- [ ] Badge protokolu: `Zigbee`/`Thread` bez znaku zapytania tylko dla `confidence=confirmed`; dla `probable` pokazac `Zigbee?`/`Thread?`; dla `unknown` pokazac `802.15.4`.
- [ ] `Matter` w UI nie moze byc pewnym wynikiem pasywnego reconu; `proto=matter_thread` pokazac jako `Matter/Thread?` i tylko dla `confidence=probable`.
- [ ] Sortowanie PAN: aktywne/ostatnio widziane (`age_ms` rosnaco), potem liczba pakietow malejaco; nie sortowac domyslnie po PAN ID.
- [ ] Rozwiniety PAN ma pokazac sekcje `Nodes` z `[ZIG] node`: `addr_type`, `short`, `ext`, `role`, `packets`, `last_rssi`, `age_ms`.
- [ ] Topologia w tab5 ma rysowac pewne role: coordinator `0x0000` jako centralny punkt, router jako drugi kolor, unknown jako neutralny; krawedzie tylko jesli backend pozniej dostarczy realna relacje, bez udawania polaczen.
- [ ] Stan pusty: pokazac metryki i neutralny komunikat `No 802.15.4 networks yet`; bez tutoriala i bez blokowania przycisku stop, jesli `active=1`.
- [ ] Stan radio busy: gdy `start_zig_recon` zwroci `FAILED: radio busy (...)`, UI ma pokazac powod i akcje `Stop current operation`.
- [ ] Stan idle z wynikami: po `stop` wyniki zostaja widoczne, a przycisk zmienia sie na start/resume.
- [ ] `clear` w UI ma wysylac `zig_recon_clear`, czyscic lokalny cache i odswiezyc status/listy.
- [ ] Widok musi obslugiwac przyrostowe wyniki bez migania: aktualizowac rekordy PAN/node po kluczach `pan id` i `pan+short`.
- [ ] Oczekiwany wynik MVP tab5: po skanie widzimy te same informacje co z konsoli: np. `PAN 0x1A62`, badge `Zigbee?`, `2 nodes`, `22 packets`, RSSI, oraz nody `0x0000 Coordinator` i `0x96A5 Unknown`.
- [ ] Oczekiwany wynik finalny tab5: ekran podobny funkcjonalnie do referencji ze screenshotow: status strip, karty PAN, rozwiniecie z mini topologia, lista node'ow, start/stop, clear i filtry debug.

Etap 7 - plan kodowania tab5 krok po kroku:
- [ ] Znalezc w kodzie tab5 istniejacy adapter komend JanOS/UART i dopisac metody: `startZigRecon(channels?, dwellMs?)`, `stopZigRecon()`, `getZigReconStatus()`, `getZigReconList(all?)`, `getZigReconNodes(allOrPanId)`, `clearZigRecon()`.
- [ ] Dodac parser liniowy `[ZIG]`: rozpoznawac rekordy `status`, `pan`, `node`, ignorowac inne linie, konczyc na `[ZIG] END`, timeout traktowac jako blad transportu.
- [ ] Parser ma mapowac wartosci hex/decimal: `id`, `pan`, `short`, `channels` jako maska bitowa kanalow 11-26, `packets`, `nodes`, `rssi`, `age_ms`, `last_seen_ms`.
- [ ] Dodac model danych tab5:
  - `ZigReconStatus`: `active`, `channel`, `packets`, `pans`, `nodes`, `dropped`, `dwellMs`, `channelMask`.
  - `ZigPan`: `id`, `kind`, `proto`, `confidence`, `channels[]`, `nodes`, `packets`, `bestRssi`, `lastRssi`, `ageMs`.
  - `ZigNode`: `panId`, `addrType`, `shortAddr?`, `extAddr?`, `role`, `packets`, `lastRssi`, `ageMs`.
- [ ] Dodac store/cache sesji: aktualizacja po kluczu `pan.id`; nody po kluczu `${panId}:short:${shortAddr}` albo `${panId}:ext:${extAddr}`; po `zig_recon_clear` wyczyscic lokalny cache.
- [ ] Dodac kontroler pollingu:
  - idle: nie spamowac UART, odswiezac tylko na wejscie w ekran albo recznie.
  - active: `status` co 1 s, `list` + `nodes all` co 2-3 s.
  - po `stop`: zatrzymac polling active, zostawic ostatnie wyniki.
- [ ] Dodac ekran glowny: top bar `802.15.4 Recon`, przyciski back, clear, help/debug, start/stop.
- [ ] Dodac status strip: `Channel`, `Packets`, `Networks`, `Dropped/status dot`; status dot zielony dla `active=1`, szary dla idle, czerwony dla bledu/radio busy.
- [ ] Dodac liste PAN jako karty:
  - tytul `PAN: 0x1A62`.
  - badge wedlug `proto/confidence`: `Zigbee?`, `Thread?`, `Matter/Thread?`, `802.15.4`.
  - subtitle: `${nodes} nodes | ${packets} packets | ch ${channels} | ${lastRssi} dBm | ${age}`.
  - domyslnie ukryc `kind=broadcast`; filtr debug moze go pokazac.
- [ ] Dodac rozwiniecie karty PAN:
  - mini topologia bez falszywych krawedzi.
  - coordinator `role=coordinator` albo `short=0x0000` jako glowny punkt.
  - lista nodow z kolorem roli, pakietami, RSSI i age.
- [ ] Dodac stany UI:
  - pusty aktywny: licznik kanalow/pakietow dziala, lista pusta.
  - pusty idle: brak wynikow.
  - radio busy: komunikat z `FAILED: radio busy (...)` i akcja stop.
  - transport timeout: pokazac blad, nie kasowac ostatnich wynikow.
- [ ] Dodac formatowanie kanalow z maski `0x07fff800` do `11,12,...,26` oraz `age_ms` do `Xs`, `Xm`, `Xh`.
- [ ] Dodac logike wyboru kanalow/dwell dla UI: MVP moze startowac `all/250`; pozniej panel debug: kanal pojedynczy/lista i dwell 50-5000 ms.
- [ ] Dodac testy parsera na realnych logach:
  - log z Zigbee PAN `0x1A62`.
  - log z Thread PAN `0x2786`.
  - log z `kind=broadcast`/`0xFFFF`.
  - log z przyszlym `proto=matter_thread`.
- [ ] Dodac fixture testowy z aktualnego wyniku konsoli, zanonimizowany tylko jesli trzeba; parser musi przejsc bez dostepu do hardware.
- [ ] Kryterium akceptacji MVP: po skanie z Twojego logu tab5 pokazuje normalne PAN, ukrywa `0xFFFF`, pokazuje `Thread?` tam gdzie parser wykryl `proto=thread`, a `zig_recon_nodes all` nie renderuje braku short address jako `0xFFFF`.
- [ ] Kryterium akceptacji Matter: jesli pojawi sie `[ZIG] pan ... proto=matter_thread confidence=probable`, tab5 pokazuje `Matter/Thread?`, nie `Matter`, i nie oznacza tego jako potwierdzone.

## Ryzyka

- Single radio: Wi-Fi/BLE/802.15.4 beda sobie przeszkadzac. Recon powinien byc osobnym trybem.
- ISR callback: bledne logowanie/alokacje w `receive_done` moga destabilizowac firmware.
- Szyfrowanie: Zigbee/Thread/Matter czesto ukryja warstwy wyzsze, wiec UI musi pokazywac pewnosc heurystyki.
- Rozjazd lokalnego `v6.0-dirty`: przed implementacja trzeba budowac i patrzec na realne naglowki z `C:\esp\v6.0\esp-idf`.
- Obecny `main.c` jest bardzo duzy; lepiej nie dopisywac parsera w srodku, tylko wydzielic komponent.

## Pytania do uzgodnienia przed implementacja

1. Jak nazywamy funkcje w UI/CLI: `802.15.4 Recon`, `Zig Recon`, czy `Zigbee/Thread Recon`?
2. Czy etap 1 ma byc absolutnie pasywny, bez zadnego TX/commissioningu? Moja rekomendacja: tak.
3. Czy podczas recon mamy automatycznie zatrzymywac/odmawiac startu Wi-Fi wardrive, BLE scan i nRF24 jammer? Moja rekomendacja: odmawiac startu z jasnym komunikatem.
4. Gdzie jest lokalne repo tego drugiego softu na ESP32-C5? Warto je porownac przed kodowaniem, szczegolnie parser PAN/protocol badge.
5. Czy tab5 to docelowy ekran w zewnetrznym UI, czy w obecnym firmware mamy tylko CLI/OLED i tab5 bedzie dodany pozniej?
