# Evil Twin Controller v8.3 - EXTENDED TIMEOUT for Slow ESP32

Aplikacja do kontrolowania Evil Twin ESP32 przez UART z Flipper Zero.
**EXTENDED 25s timeout dla ESP32 która potrzebuje 12+ sekund na skanowanie!**

## 🕐 EXTENDED TIMEOUT FIX (v8.3):

### Problem: ESP32 potrzebuje 12+ sekund, ale aplikacja ma timeout 15s
- ❌ **Problem**: ESP32 skanuje 12+ sekund, aplikacja timeout po 15s  
- ❌ **Log**: `Scan timeout after 15091 ms` - ESP32 wysyła dane tuż PO timeout
- ✅ **Rozwiązanie**: Extended timeout 15s → 25s + lepszy timing control

## 🔧 NAPRAWIONE TIMING ISSUES:

### PRZED (v8.2 - za krótki timeout):
```
ESP32 skan:     |████████████████| (12+ sekund)
App timeout:    |███████████████|  (15 sekund) ❌ TIMEOUT!
                                ^
                         ESP32 dane przychodzą tutaj
```

### PO (v8.3 - extended timeout):
```
ESP32 skan:     |████████████████| (12+ sekund)
App timeout:    |█████████████████████████| (25 sekund) ✅ SUCCESS!
                                ^
                         ESP32 dane przychodzą tutaj
```

## ⏱️ NOWE TIMING CONSTANTS:

```c
// PRZED v8.2:
#define SCAN_TIMEOUT_MS 15000           // 15 seconds ❌ Za krótko!

// PO v8.3:  
#define SCAN_TIMEOUT_MS 25000           // 25 seconds ✅ Wystarczająco!
#define SCAN_FALLBACK_DELAY_MS 18000    // 18 seconds fallback (było 8)
```

### Nowy timing flow:
- **0-2s**: Minimum time przed pokazaniem wyników
- **2-18s**: Czeka na rzeczywistą ESP32 odpowiedź  
- **18s**: Jeśli brak odpowiedzi → uruchom fallback simulation
- **25s**: Final timeout jeśli nadal brak odpowiedzi

## 🖥️ NOWY UI z EXTENDED TIMEOUT:

### 1. Initial State (przed skanowaniem):
```
Sieci WiFi ESP32                    READY
═══════════════════════════════════════
        Gotowy do skanowania
         ESP32 timeout: 25s          ← NOWE!
        Kliknij skanowanie

                               Back=Menu
```

### 2. Podczas skanowania (0-25 sekund):
```
Sieci WiFi ESP32                 SCANNING  
═══════════════════════════════════════
     Skanowanie ESP32...

     Czas: 12 sek
     Timeout za: 13 sek              ← EXTENDED!
     ESP32 odpowiada...              ← ESP32 detection

                               Back=Cancel
```

### 3. Po extended timeout (25+ sekund):
```
Sieci WiFi ESP32                  TIMEOUT
═══════════════════════════════════════
        TIMEOUT ESP32!
       ESP32 odpowiadał ale         ← Lepsze info
      skan trwał >25 sekund
      ESP32 firmware OK?
                                Back=Menu
```

### 4. Fallback simulation (po 18s bez ESP32):
```
Sieci WiFi ESP32                 SCANNING  
═══════════════════════════════════════
     Skanowanie ESP32...

     Czas: 19 sek  
     Timeout za: 6 sek
     Fallback aktywny               ← Nowe!

                               Back=Cancel
```

## 📱 NOWE FEATURES v8.3:

### ✅ ESP32 Response Detection:
```c
bool esp32_response_detected;    // Track if ESP32 actually responds
uint32_t last_uart_rx_time;     // Track last UART RX activity

void debug_uart_rx_activity(EvilTwinControllerApp* app, const char* data) {
    app->esp32_response_detected = true;  // Mark ESP32 as responding
    FURI_LOG_D(TAG, "ESP32 UART RX: '%s'", data);
}
```

### ✅ Better Timeout Messages:
```c
if(app->esp32_response_detected) {
    add_log_line_safe(app, "TIMEOUT: ESP32 responded but scan took too long");
    add_log_line_safe(app, "Try increasing timeout or check ESP32 performance");
} else {
    add_log_line_safe(app, "TIMEOUT: No response from ESP32 after 25 seconds");
}
```

### ✅ Smart Fallback Logic:
```c
bool should_start_fallback_simulation(EvilTwinControllerApp* app) {
    uint32_t elapsed = get_scan_elapsed_ms(app);
    return (elapsed > 18000 &&              // After 18 seconds
            !app->esp32_response_detected &&  // No ESP32 response yet  
            app->real_esp32_mode &&           // In real ESP32 mode
            !app->scan_completed);            // Scan not completed yet
}
```

### ✅ Progress Logging:
```c
// Log progress every 5 seconds during long scan
if(elapsed > 0 && (elapsed % 5000) < 200) {
    FURI_LOG_D(TAG, "ESP32 scan progress: %lu/%lu seconds (response: %s)", 
              elapsed/1000, SCAN_TIMEOUT_MS/1000,
              app->esp32_response_detected ? "YES" : "NO");
}
```

## 🧪 TESTOWANIE Z TWOJA ESP32 (12+ sekund scan):

### Workflow z extended timeout:
```bash
# Terminal 1 - Logi USB:
./fbt log

# Terminal 2 - Kompiluj aplikację:
./fbt fap_evil_twin_controller

# Flipper - Test aplikacji:
# 1. Applications → Examples → Evil Twin Controller
# 2. "Skanowanie sieci"
# 3. Zobacz "ESP32 timeout: 25s" w initial state
# 4. Podczas skanowania - countdown do 25 sekund
# 5. "ESP32 odpowiada..." gdy ESP32 wyśle pierwsze dane
# 6. Po 12-15s - ESP32 wyśle pełne wyniki
# 7. ✅ SUCCESS - sieci wyświetlone!
```

### Expected logs dla Twojej ESP32:
```
[I][EvilTwinController] ESP32 scan started, EXTENDED timeout: 25 seconds
[I][EvilTwinController] Waiting for ESP32 response (up to 25 seconds)...
[D][EvilTwinController] ESP32 scan progress: 5/25 seconds (response: NO)
[D][EvilTwinController] ESP32 scan progress: 10/25 seconds (response: NO)
[D][EvilTwinController] UART RX activity detected: 'I (6269) projectZero: About to start scan...'
[I][EvilTwinController] ESP32 found networks, starting data collection
[D][EvilTwinController] ESP32 scan progress: 15/25 seconds (response: YES)
[I][EvilTwinController] Added ESP32 network 0: VMA84A66C-2.4 (RSSI: -56)
[I][EvilTwinController] ESP32 scan completed successfully
```

## 📋 KOMPILACJA:

```bash
# Rozpakuj:
unzip evil_twin_controller_EXTENDED_TIMEOUT_v8_3.zip

# Skopiuj do firmware:
cp -r evil_twin_controller_v8_3 /Users/janulrich/flipper/flipperzero-firmware/applications_user/

# Kompiluj:
cd /Users/janulrich/flipper/flipperzero-firmware
./fbt fap_evil_twin_controller

# Uruchom z logami:
./fbt log
```

## 🚀 WSZYSTKIE FIXES (zachowane z poprzednich wersji):

| # | Problem | Fix v8.3 | Status |
|---|---------|----------|--------|
| 12 | ESP32 timeout po 15s, ale skan trwa 12+s | Extended 25s timeout | ✅ FIXED |
| 11 | NULL pointer dereference crash | Atomic flags + mutex safety | ✅ FIXED |  
| 10 | Scan timing logic - od razu "Brak sieci!" | Proper wait flow | ✅ FIXED |
| 9 | Mutex crash w furi/core/mutex.c | Safe shutdown sequence | ✅ FIXED |
| 8 | API functions undeclared | API compatibility | ✅ FIXED |
| 7+ | Wszystkie poprzednie błędy kompilacji | - | ✅ FIXED |

## 🎯 SPECJALNIE DLA TWOJEJ ESP32:

### Twoja ESP32 charakterystyka:
- **Czas skanowania**: 12+ sekund (bardzo powolne)
- **Format output**: `I (timestamp) projectZero: ...`  
- **Timeout potrzebny**: Minimum 20 sekund, aplikacja daje 25s
- **Expected workflow**: TX scan_networks → 12s delay → RX network data

### Aplikacja v8.3 obsługuje:
- ✅ **25s timeout** zamiast 15s - wystarczy dla Twojej ESP32
- ✅ **ESP32 response detection** - wykrywa gdy ESP32 zaczyna odpowiadać
- ✅ **Progress tracking** - logi co 5s podczas długiego skanowania
- ✅ **Smart fallback** - simulation dopiero po 18s (nie przeszkadza ESP32)
- ✅ **Better error messages** - informuje czy ESP32 w ogóle odpowiadał

## 🎉 STATUS: EXTENDED TIMEOUT READY!

**Ta wersja v8.3 została specjalnie dostosowana do Twojej ESP32:**
- ✅ **25s timeout** obsługuje ESP32 która skanuje 12+ sekund
- ✅ **Real-time progress** pokazuje czy ESP32 odpowiada
- ✅ **Smart fallback** nie przeszkadza prawdziwemu ESP32  
- ✅ **Comprehensive logging** dla debugging timing issues
- ✅ **All previous fixes** zachowane (mutex safety, crash fixes)

**TWOJA ESP32 POWINNA TERAZ DZIAŁAĆ!**

Jeśli nadal będzie timeout, w logach zobaczysz czy ESP32 w ogóle odpowiadała, czy może problem jest w połączeniu/firmware.

## Licencja

MIT License - możesz swobodnie modyfikować i rozprowadzać.
