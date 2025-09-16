#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <gui/modules/popup.h>
#include <gui/modules/loading.h>
#include <gui/modules/widget.h>
#include <notification/notification_messages.h>
#include <furi_hal_serial.h>

#define TAG "EvilTwinController"
#define MAX_NETWORKS 20
#define MAX_UART_BUFFER_SIZE 4096
#define MAX_LINE_LENGTH 512
#define UART_RX_BUFFER_SIZE 256

// Scan timing constants
#define SCAN_TIMEOUT_MS 15000    
#define SCAN_MIN_TIME_MS 2000    

// CRITICAL: Mutex safety macros
#define MUTEX_SAFE_ACQUIRE(mutex) do { if(mutex) furi_mutex_acquire(mutex, FuriWaitForever); } while(0)
#define MUTEX_SAFE_RELEASE(mutex) do { if(mutex) furi_mutex_release(mutex); } while(0)
#define MUTEX_SAFE_FREE(mutex) do { if(mutex) { furi_mutex_free(mutex); mutex = NULL; } } while(0)

// Defensive programming macros
#define SAFE_CHECK(ptr) do { if(!(ptr)) { FURI_LOG_E(TAG, "NULL check failed: %s at %s:%d", #ptr, __FILE__, __LINE__); return; } } while(0)
#define SAFE_CHECK_RETURN(ptr, ret) do { if(!(ptr)) { FURI_LOG_E(TAG, "NULL check failed: %s at %s:%d", #ptr, __FILE__, __LINE__); return ret; } } while(0)

typedef enum {
    EvilTwinControllerEventTypeKey,
    EvilTwinControllerEventTypeTick,
    EvilTwinControllerEventTypeUartRx,
} EvilTwinControllerEventType;

typedef struct {
    EvilTwinControllerEventType type;
    InputEvent input;
} EvilTwinControllerEvent;

typedef enum {
    EvilTwinControllerViewMainMenu,
    EvilTwinControllerViewNetworkList,
    EvilTwinControllerViewEvilTwinLogs,
} EvilTwinControllerView;

typedef enum {
    EvilTwinControllerSceneMainMenu,
    EvilTwinControllerSceneNetworkList,
    EvilTwinControllerSceneEvilTwinLogs,
    EvilTwinControllerSceneNum,
} EvilTwinControllerScene;

typedef enum {
    UartStateIdle,
    UartStateScanning,
    UartStateReady,
    UartStateRunning,
    UartStateTimeout,
} UartState;

typedef struct {
    int index;
    int rssi;
    int auth;
    int channel;
    char bssid[20];
    char ssid[68];
} NetworkInfo;

typedef struct {
    SceneManager* scene_manager;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    Widget* widget;
    NotificationApp* notifications;
    FuriMessageQueue* event_queue;

    // UART - CRITICAL MUTEX FIXES
    FuriHalSerialHandle* serial_handle;
    FuriThread* uart_thread;
    volatile bool uart_thread_running;  // ATOMIC FLAG
    char uart_rx_buffer[UART_RX_BUFFER_SIZE];
    size_t uart_rx_pos;
    FuriMutex* uart_mutex;
    bool uart_initialized;

    // Network data - with mutex protection  
    NetworkInfo networks[MAX_NETWORKS];
    int network_count;
    int selected_networks[10];
    int selected_count;
    int first_selected_network;

    // State - with atomic flags
    UartState uart_state;
    bool evil_twin_running;
    FuriString* log_buffer;
    bool networks_ready;
    uint32_t scan_start_time;
    volatile bool app_running;      // ATOMIC FLAG
    bool scan_completed;
    bool real_esp32_mode;

    // CRITICAL: Shutdown coordination
    volatile bool shutdown_requested;  // ATOMIC FLAG for clean shutdown
    bool mutexes_valid;               // Track mutex validity
} EvilTwinControllerApp;

// Scene handlers
void evil_twin_controller_scene_main_menu_on_enter(void* context);
bool evil_twin_controller_scene_main_menu_on_event(void* context, SceneManagerEvent event);
void evil_twin_controller_scene_main_menu_on_exit(void* context);

void evil_twin_controller_scene_network_list_on_enter(void* context);
bool evil_twin_controller_scene_network_list_on_event(void* context, SceneManagerEvent event);
void evil_twin_controller_scene_network_list_on_exit(void* context);

void evil_twin_controller_scene_evil_twin_logs_on_enter(void* context);
bool evil_twin_controller_scene_evil_twin_logs_on_event(void* context, SceneManagerEvent event);
void evil_twin_controller_scene_evil_twin_logs_on_exit(void* context);

// UART functions with CRITICAL mutex safety
int32_t uart_worker_thread(void* context);
void uart_send_command_safe(EvilTwinControllerApp* app, const char* command);
void uart_process_rx_data_safe(EvilTwinControllerApp* app, const char* data, size_t length);
void process_uart_line_safe(EvilTwinControllerApp* app, const char* line);
bool parse_network_line_safe(const char* line, NetworkInfo* network);
void clear_networks_safe(EvilTwinControllerApp* app);
void add_log_line_safe(EvilTwinControllerApp* app, const char* line);
void simulate_esp32_scan_data_safe(EvilTwinControllerApp* app);
bool uart_init_safe(EvilTwinControllerApp* app);
void uart_cleanup_safe(EvilTwinControllerApp* app);
void handle_scan_timeout(EvilTwinControllerApp* app);
bool is_scan_timed_out(EvilTwinControllerApp* app);
uint32_t get_scan_elapsed_ms(EvilTwinControllerApp* app);

// CRITICAL: Safe shutdown functions
void safe_shutdown_begin(EvilTwinControllerApp* app);
void safe_shutdown_threads(EvilTwinControllerApp* app);
void safe_shutdown_mutexes(EvilTwinControllerApp* app);
