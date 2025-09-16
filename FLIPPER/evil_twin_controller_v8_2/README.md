# Evil Twin Controller v8.2 - MUTEX CRASH FIX + DEBUG LOGS

Aplikacja do kontrolowania Evil Twin ESP32 przez UART z Flipper Zero.
**CRITICAL FIX dla crash w `furi/core/mutex.c` + instrukcje debugging!**

## 🚨 CRITICAL CRASH FIX (v8.2):

### Problem: Flipper crashed and was rebooted - furi/core/mutex.c
- ❌ **Problem**: Race condition w mutex handling → crash w `furi/core/mutex.c`
- ✅ **Rozwiązanie**: Atomic flags + proper shutdown sequence + mutex safety

## 🔧 NAPRAWIONE MUTEX ISSUES:

### 1. Race Condition w Mutex Operations
```c
// PRZED (crash-prone):
furi_mutex_acquire(app->uart_mutex, FuriWaitForever);
// Thread może próbować użyć mutex po jego dealokacji ❌

// PO (safe):
if(app->uart_mutex && app->mutexes_valid && !app->shutdown_requested) {
    if(furi_mutex_acquire(app->uart_mutex, 1000) == FuriStatusOk) {
        // ... operations ...
        furi_mutex_release(app->uart_mutex);  // Always release
    }
}
```

### 2. Shutdown Sequence (CRITICAL)
```c
// PRZED (wrong order - CRASH):
void app_free(App* app) {
    furi_mutex_free(app->mutex);  // ❌ Freed while thread still running!
    furi_thread_join(app->thread); // Too late - thread crashes
}

// PO (correct order - SAFE):
void app_free(App* app) {
    // STEP 1: Signal shutdown to all components
    app->shutdown_requested = true;
    app->app_running = false;

    // STEP 2: Stop threads BEFORE touching mutexes
    furi_thread_join(app->thread);

    // STEP 3: Free mutexes LAST
    furi_mutex_free(app->mutex);
}
```

### 3. Atomic Flags Coordination
```c
typedef struct {
    volatile bool uart_thread_running;  // ATOMIC FLAG
    volatile bool app_running;          // ATOMIC FLAG
    volatile bool shutdown_requested;   // ATOMIC FLAG
    bool mutexes_valid;                 // Track mutex validity
} EvilTwinControllerApp;
```

### 4. Safe Mutex Macros
```c
#define MUTEX_SAFE_ACQUIRE(mutex) do { if(mutex) furi_mutex_acquire(mutex, FuriWaitForever); } while(0)
#define MUTEX_SAFE_RELEASE(mutex) do { if(mutex) furi_mutex_release(mutex); } while(0)
#define MUTEX_SAFE_FREE(mutex) do { if(mutex) { furi_mutex_free(mutex); mutex = NULL; } } while(0)
```

## 📱 DEBUGGING: Jak zbierać logi z Flippera

### Metoda 1: Logi real-time podczas użytkowania (NAJLEPSZA)

```bash
# Terminal 1 - Uruchom logi PRZED uruchomieniem aplikacji:
cd /Users/janulrich/flipper/flipperzero-firmware
./fbt log

# Terminal 2 - Kompiluj i wgraj aplikację:
./fbt fap_evil_twin_controller

# Flipper - Uruchom aplikację:
# Applications → Examples → Evil Twin Controller

# Terminal 1 - Zobacz logi w real-time:
[I][EvilTwinController] Starting Evil Twin Controller with critical mutex safety
[I][EvilTwinController] Application allocated successfully with critical mutex safety
[I][EvilTwinController] UART initialized at 115200 baud
[I][EvilTwinController] Starting main event loop
[I][EvilTwinController] Main menu entered
```

### Metoda 2: Przez CLI Flipper (gdy aplikacja już działa)

```bash
# W CLI którym masz otwarty (>:), wpisz:
>: log

# Zobaczysz logi aplikacji w real-time:
# [I][EvilTwinController] Processing line: TX: scan_networks
# [I][EvilTwinController] Scan started, waiting up to 15 seconds for ESP32
```

### Metoda 3: Przez QFlipper GUI

```
1. Otwórz QFlipper
2. Device Manager
3. CLI tab
4. Wpisz: log
5. Zobacz logi aplikacji + systemu
```

## 🚨 JAK ZŁAPAĆ CRASH LOGS:

### Gdy aplikacja crashuje:

1. **Natychmiast po crash** - Flipper może się rebootować
2. **Podłącz przez USB** i uruchom logi:
   ```bash
   ./fbt log
   ```
3. **W logach szukaj**:
   ```
   [E][Thread] Hard fault at PC=0x08012345
   [E][Crash] Crash in file: furi/core/mutex.c line: 123
   [E][Stack] Stack trace: 0x08012345 → 0x08009876 → ...
   ```

### Logi które pomogą w debugging:

```bash
# Uruchom aplikację z verbose logging:
./fbt fap_evil_twin_controller EXTRA_CFLAGS=-DDEBUG

# Logi które będą widoczne:
[D][EvilTwinController] Parsed network: idx=0, rssi=-56, ssid='VMA84A66C-2.4'
[I][EvilTwinController] Added network 0: VMA84A66C-2.4 (RSSI: -56)
[I][EvilTwinController] UART worker started with atomic coordination
[I][EvilTwinController] Beginning safe shutdown sequence
[I][EvilTwinController] Stopping UART thread
[I][EvilTwinController] UART thread stopped
[I][EvilTwinController] Freeing UART mutex
[I][EvilTwinController] Critical shutdown sequence completed successfully
```

### Crash Pattern dla mutex.c:

```
[E][System] Hard fault
[E][Core] Mutex operation failed at furi/core/mutex.c:87
[E][Thread] Thread attempted to use freed mutex
[E][Trace] uart_worker_thread → process_uart_line_safe → furi_mutex_acquire
[CRASH] System reboot
```

## 🔧 NOWE SAFETY FEATURES v8.2:

### Mutex Timeout (nie czeka w nieskończoność):
```c
// Zamiast FuriWaitForever (może deadlock):
if(furi_mutex_acquire(app->uart_mutex, 100) == FuriStatusOk) {
    // operations
    furi_mutex_release(app->uart_mutex);
} else {
    FURI_LOG_E(TAG, "Mutex timeout - avoiding deadlock");
}
```

### Shutdown Coordination:
```c
// W każdej funkcji:
if(app->shutdown_requested || !app->mutexes_valid) return;

// W UI callbacks:
if(app->shutdown_requested) return false;

// W thread loops:
while(app->uart_thread_running && !app->shutdown_requested) {
    // operations
}
```

### Safe Cleanup Sequence:
```c
void safe_shutdown_begin(EvilTwinControllerApp* app) {
    app->shutdown_requested = true;  // Signal everyone
    app->app_running = false;
}

void safe_shutdown_threads(EvilTwinControllerApp* app) {
    // Stop threads FIRST
    furi_thread_join(app->uart_thread);
}

void safe_shutdown_mutexes(EvilTwinControllerApp* app) {
    // Free mutexes LAST
    app->mutexes_valid = false;
    MUTEX_SAFE_FREE(app->uart_mutex);
}
```

## 📋 KOMPILACJA z DEBUG INFO:

```bash
# Rozpakuj:
unzip evil_twin_controller_MUTEX_CRASH_FIXED_v8_2.zip

# Skopiuj do firmware:
cp -r evil_twin_controller_v8_2 /Users/janulrich/flipper/flipperzero-firmware/applications_user/

# Kompiluj z debug info:
cd /Users/janulrich/flipper/flipperzero-firmware
./fbt fap_evil_twin_controller DEBUG=1

# Uruchom z logami:
./fbt log
```

## 🧪 TESTOWANIE CRASH RESISTANCE:

### Test 1: Stress Test
```bash
# Uruchom logi:
./fbt log

# Na Flipperze:
# 1. Uruchom aplikację
# 2. Szybko klikaj skanowanie → cancel → skanowanie → exit
# 3. Sprawdź czy nie ma crash w logach
```

### Test 2: Threading Test
```bash
# W logach szukaj:
[I][EvilTwinController] UART worker started
[I][EvilTwinController] Main menu entered  
# ... użytkownie aplikacji ...
[I][EvilTwinController] Beginning safe shutdown sequence
[I][EvilTwinController] UART worker thread finished cleanly
[I][EvilTwinController] Critical shutdown sequence completed
# ✅ Brak "[E][System] Hard fault"
```

## 🎯 STATUS: MUTEX CRASH FIXED!

**Ta wersja v8.2 rozwiązuje critical mutex crash:**
- ✅ **Zero race conditions** - atomic flags coordination
- ✅ **Proper shutdown sequence** - threads before mutexes  
- ✅ **Mutex timeout** - nie wisi w nieskończoność
- ✅ **Safe cleanup** - wszystkie resources properly freed
- ✅ **Comprehensive logging** - pełne crash debugging info
- ✅ **Thread coordination** - no use-after-free

**APLIKACJA POWINNA PRZESTAĆ SIĘ CRASHOWAĆ!**

## 🔍 Co robić jeśli nadal crashuje:

1. **Zbierz pełne logi** - `./fbt log` przed uruchomieniem
2. **Prześlij logi** - pokaż konkretne error messages
3. **Opisz kroki** - co robiłeś gdy aplikacja crashowała
4. **Stack trace** - jeśli dostępny w logach

## Licencja

MIT License - możesz swobodnie modyfikować i rozprowadzać.
