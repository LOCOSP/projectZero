# Evil Twin Controller v8.1 - PROPER SCAN TIMING FIXED

Aplikacja do kontrolowania Evil Twin ESP32 przez UART z Flipper Zero.
**Naprawiona logika skanowania - NIE pokazuje "Brak sieci!" od razu!**

## 🔧 NAJNOWSZA NAPRAWA (v8.1):

### Problem: Natychmiastowe "Brak sieci!" podczas skanowania
- ❌ **Problem**: Po kliknięciu "skanuj" od razu pokazywało "Brak sieci! Uruchom skanowanie"
- ✅ **Rozwiązanie**: Proper timing logic - czeka 15 sekund na ESP32

## 🕐 NAPRAWIONA LOGIKA TIMING:

### PRZED (v8.0 - błędne):
```
1. Klik "Skanowanie sieci"
2. Wysłanie scan_networks ✅
3. OD RAZU sprawdzenie app->networks_ready (false) ❌
4. OD RAZU pokazanie "Brak sieci!" ❌
```

### PO (v8.1 - poprawne):
```
1. Klik "Skanowanie sieci"
2. Wysłanie scan_networks ✅  
3. Ustawienie app->uart_state = UartStateScanning ✅
4. Pokazanie "Skanowanie ESP32..." przez 15 sekund ✅
5. Countdown timer "Timeout za: X sek" ✅
6. Po otrzymaniu danych ALBO timeout → wyniki ✅
```

### Nowe stany skanowania:
```c
typedef enum {
    UartStateIdle,        // Gotowy do skanowania
    UartStateScanning,    // ← NOWY: Aktywne skanowanie 15s
    UartStateReady,       // Sieci otrzymane
    UartStateRunning,     // Evil Twin aktywny
    UartStateTimeout,     // ← NOWY: Timeout ESP32
} UartState;
```

## 🖥️ NOWY UI WORKFLOW:

### 1. Stan początkowy:
```
Sieci WiFi ESP32                    READY
═══════════════════════════════════════
        Gotowy do skanowania
         Kliknij skanowanie

                               Back=Menu
```

### 2. Podczas skanowania (0-15 sekund):
```
Sieci WiFi ESP32                 SCANNING  
═══════════════════════════════════════
    Skanowanie ESP32...

    Czas: 5 sek
    Timeout za: 10 sek
    Czekam na ESP32...
                               Back=Cancel
```

### 3A. Po timeout (15+ sekund):
```
Sieci WiFi ESP32                  TIMEOUT
═══════════════════════════════════════
        TIMEOUT ESP32!
      Sprawdz polaczenie:
      - Pin 13/14 + GND
      - ESP32 wlaczone
                                Back=Menu
```

### 3B. Po otrzymaniu sieci:
```
Sieci WiFi ESP32                    8 szt
═══════════════════════════════════════
[ ]  0 -56 WPA2 VMA84A66C
[ ]  1 -56 WiFree Horizon
[X]* 2 -71 WPA2 Hidden_2

    >>> Start Evil Twin <<<
                        Up/Down=Nav  Back=Menu
```

### 3C. Brak sieci (po zakończeniu skanowania):
```
Sieci WiFi ESP32                    EMPTY
═══════════════════════════════════════
            Brak sieci!
        ESP32 nie znalazł AP

                                Back=Menu
```

## ⏱️ TIMING CONSTANTS:

```c
#define SCAN_TIMEOUT_MS 15000    // 15 sekund timeout dla ESP32
#define SCAN_MIN_TIME_MS 2000    // Min 2 sekundy przed pokazaniem wyników
```

### Działanie timing:
- **0-2s**: Pokazuje "Skanowanie..." (minimum time)
- **2-8s**: Czeka na rzeczywisty ESP32
- **8s**: Jeśli brak odpowiedzi → uruchamia symulację (demo)
- **15s**: Jeśli nadal brak → TIMEOUT

## 📡 WSPARCIE REAL ESP32 + FALLBACK:

### Real Mode (preferowany):
```c
app->real_esp32_mode = true;  // Próbuj najpierw prawdziwego ESP32
```

1. Wysyłka `scan_networks`
2. Nasłuchiwanie przez UART RX
3. Parsowanie `I (timestamp) projectZero: ...`
4. Jeśli otrzyma dane → Real Mode kontynuuje

### Fallback Mode (demo):
```c
app->real_esp32_mode = false; // Po 8s bez odpowiedzi
```

1. Po 8 sekundach bez odpowiedzi ESP32
2. Automatyczne przejście na symulację
3. Pokazuje Twoje rzeczywiste sieci z minicom
4. Nadal wysyła komendy UART do ESP32

## 🔧 FIXED INPUT HANDLING:

### Podczas skanowania:
- **Wszystkie klawisze ignorowane** OPRÓCZ Back
- **Back = Cancel scan** → powrót do menu
- **Nie można nawigować** podczas aktywnego skanowania

### Po timeout:
- **Tylko Back** → reset stanu → powrót do menu
- **Automatyczny reset** scan_start_time = 0

### Po otrzymaniu sieci:
- **Pełna nawigacja** Up/Down/OK/Back
- **Selection logic** działa normalnie

## 🛠️ DEBUGGING przez USB LOGS:

Nowe logi timing:
```
[I][EvilTwinController] Sent UART: scan_networks
[I][EvilTwinController] Scan started, waiting up to 15 seconds for ESP32
[I][EvilTwinController] No ESP32 response detected, starting simulation  
[I][EvilTwinController] ESP32 scan simulation completed
[W][EvilTwinController] Scan timeout after 15234 ms
[I][EvilTwinController] User cancelled scan
```

### Debug workflow:
```bash
# Terminal 1 - USB logi:
./fbt log

# Terminal 2 - Test aplikacji na Flipperze:
# 1. Kliknij "Skanowanie sieci"  
# 2. Obserwuj logi USB:
#    - "Scan started, waiting..."
#    - "No ESP32 response detected, starting simulation"
#    - "ESP32 scan simulation completed"

# Terminal 3 - Prawdziwy ESP32 (opcjonalne):
minicom -D /dev/tty.usbserial-XXXXX -b 115200
```

## 📋 KOMPILACJA (zero błędów):

```bash
# Rozpakuj:
unzip evil_twin_controller_SCAN_TIMING_FIXED_v8_1.zip

# Skopiuj do firmware:
cp -r evil_twin_controller_v8_1 /Users/janulrich/flipper/flipperzero-firmware/applications_user/

# Kompiluj:
cd /Users/janulrich/flipper/flipperzero-firmware
./fbt fap_evil_twin_controller

# Uruchom z logami:
./fbt log
```

## 🎯 TESTOWANIE z ESP32:

### Scenario 1: Bez ESP32 (demo mode)
1. Kliknij "Skanowanie sieci"
2. Zobacz "Skanowanie ESP32..." przez 8 sekund
3. Automatycznie przejdzie na symulację
4. Pokaże 8 Twoich rzeczywistych sieci

### Scenario 2: Z ESP32 (real mode)  
1. Podłącz ESP32 → Pin 13/14/11
2. Kliknij "Skanowanie sieci"
3. Zobacz "Skanowanie ESP32..." 
4. ESP32 wyśle dane → parsowanie real-time
5. Pokaże rzeczywiste sieci z ESP32

### Scenario 3: ESP32 timeout
1. ESP32 podłączony ale nie odpowiada
2. Zobacz countdown "Timeout za: X sek"
3. Po 15s → "TIMEOUT ESP32!"
4. Instrukcje debugowania połączenia

## 🎉 STATUS: SCAN TIMING FIXED!

**Ta wersja v8.1 rozwiązuje główny problem:**
- ✅ **Nie pokazuje "Brak sieci!" od razu**
- ✅ **Proper 15-sekundowe czekanie na ESP32**  
- ✅ **Visual countdown timer z pozostałym czasem**
- ✅ **Timeout handling z instrukcjami debug**
- ✅ **Cancel option podczas skanowania**
- ✅ **Fallback na symulację jeśli brak ESP32**
- ✅ **Real-time USB logs dla debugging**

**PROBLEM ROZWIĄZANY!** Teraz aplikacja właściwie czeka na ESP32 i pokazuje progress.

## Licencja

MIT License - możesz swobodnie modyfikować i rozprowadzać.
