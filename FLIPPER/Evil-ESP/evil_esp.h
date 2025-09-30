#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/modules/popup.h>
#include <gui/modules/widget.h>
#include <notification/notification_messages.h>
#include <dialogs/dialogs.h>
#include <storage/storage.h>

#define EVIL_ESP_TEXT_BOX_STORE_SIZE (8192)
#define EVIL_ESP_TEXT_INPUT_STORE_SIZE (2048)
#define EVIL_ESP_UART_BAUD_RATE (115200)
#define EVIL_ESP_UART_RX_BUF_SIZE (4096)
#define EVIL_ESP_MAX_NETWORKS (200)
#define EVIL_ESP_MAX_TARGETS (200)

// Scene definitions
typedef enum {
    EvilEspSceneStart,
    EvilEspSceneMainMenu,
    EvilEspSceneScanner,
    EvilEspSceneScannerResults,
    EvilEspSceneAttacks,
    EvilEspSceneAttackConfig,
    EvilEspSceneSniffer,
    EvilEspSceneSnifferResults,
    EvilEspSceneConfig,
    EvilEspSceneDeviceInfo,
    EvilEspSceneUartTerminal,
    EvilEspSceneNum,
} EvilEspScene;

// View definitions
typedef enum {
    EvilEspViewMainMenu,
    EvilEspViewScanner,
    EvilEspViewAttacks,
    EvilEspViewSniffer,
    EvilEspViewConfig,
    EvilEspViewTextBox,
    EvilEspViewTextInput,
    EvilEspViewPopup,
    EvilEspViewWidget,
} EvilEspView;

// Command types
typedef enum {
    EvilEspCommandScan,
    EvilEspCommandStartDeauth,
    EvilEspCommandStopDeauth,
    EvilEspCommandDisassoc,
    EvilEspCommandStartSniff,
    EvilEspCommandStopSniff,
    EvilEspCommandHopOn,
    EvilEspCommandHopOff,
    EvilEspCommandSetTarget,
    EvilEspCommandSetChannel,
    EvilEspCommandInfo,
    EvilEspCommandRandomAttack,
    EvilEspCommandTimedAttack,
    EvilEspCommandResults,
    EvilEspCommandHelp,
} EvilEspCommand;

// Response types
typedef enum {
    EvilEspResponseInfo,
    EvilEspResponseError,
    EvilEspResponseDebug,
    EvilEspResponseScanResult,
    EvilEspResponseAttackStatus,
    EvilEspResponseCommand,
    EvilEspResponseChannelHop,
    EvilEspResponseUnknown,
} EvilEspResponseType;

// Attack modes
typedef enum {
    EvilEspAttackModeDeauth,
    EvilEspAttackModeDisassoc,
    EvilEspAttackModeRandom,
} EvilEspAttackMode;

// Sniffer modes
typedef enum {
    EvilEspSniffModeAll,
    EvilEspSniffModeBeacon,
    EvilEspSniffModeProbe,
    EvilEspSniffModeDeauth,
    EvilEspSniffModeEapol,
    EvilEspSniffModePwnagotchi,
} EvilEspSniffMode;

// WiFi band types
typedef enum {
    EvilEspBandUnknown,
    EvilEspBand24GHz,
    EvilEspBand5GHz,
} EvilEspBand;

// GPIO pin selection for UART
typedef enum {
    EvilEspGpioPins13_14 = 0, // USART (pins 13/14)
    EvilEspGpioPins15_16 = 1, // LPUART (pins 15/16)
} EvilEspGpioPins;

// WiFi Network structure
typedef struct {
    uint8_t index; // Internal array index for menu selection
    uint8_t device_index; // Original index from ESP device (for commands)
    char ssid[64];
    char bssid[18];
    int channel;
    char auth[32]; // Authentication/encryption type (e.g., "WPA/WPA2 Mixed", "Open")
    int rssi;
    EvilEspBand band;
    bool selected;
} EvilEspNetwork;

// Configuration structure
typedef struct {
    uint32_t cycle_delay;
    uint32_t scan_time;
    uint32_t num_frames;
    uint8_t start_channel;
    bool scan_cycles;
    bool led_enabled;
    bool debug_mode;
    EvilEspGpioPins gpio_pins; // GPIO pin selection
} EvilEspConfig;

// Attack state
typedef struct {
    bool active;
    EvilEspAttackMode mode;
    uint32_t duration;
    uint32_t start_time;
    uint8_t target_indices[EVIL_ESP_MAX_TARGETS];
    uint8_t num_targets;
} EvilEspAttackState;

// Sniffer state
typedef struct {
    bool is_running;
    EvilEspSniffMode mode;
    uint8_t channel;
    bool hopping;
    uint32_t packet_count;
} EvilEspSnifferState;

// UART worker
typedef struct EvilEspUartWorker EvilEspUartWorker;

// Main app structure
typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    SceneManager* scene_manager;
    NotificationApp* notifications;
    DialogsApp* dialogs;

    // Views
    Submenu* submenu;
    TextBox* text_box;
    TextInput* text_input;
    Popup* popup;
    Widget* widget;

    // Text storage
    char* text_box_store;
    char* text_input_store;
    FuriString* text_box_string;

    // UART communication
    EvilEspUartWorker* uart_worker;
    FuriStreamBuffer* uart_rx_stream;

    // Data storage
    EvilEspNetwork networks[EVIL_ESP_MAX_NETWORKS];
    uint8_t network_count;
    bool scan_in_progress;

    EvilEspConfig config;
    EvilEspAttackState attack_state;
    EvilEspSnifferState sniffer_state;

    // UI state
    uint8_t selected_menu_index;
    uint8_t selected_network_index;
    bool show_loading;
    bool first_main_menu_visit;

    // Status
    bool device_connected;
    char device_info[256];
    FuriString* log_string;
    FuriString* uart_log_string;
} EvilEspApp;

// Scene manager events
typedef enum {
    EvilEspEventStartScan,
    EvilEspEventScanComplete,
    EvilEspEventStartAttack,
    EvilEspEventStopAttack,
    EvilEspEventStartSniffer,
    EvilEspEventStopSniffer,
    EvilEspEventSnifferStarted,
    EvilEspEventSnifferStopped,
    EvilEspEventPacketReceived,
    EvilEspEventConfigUpdate,
    EvilEspEventUartTerminalRefresh,
    EvilEspEventBack,
    EvilEspEventExit,
} EvilEspEvent;

// Function prototypes

// Main app functions
EvilEspApp* evil_esp_app_alloc(void);
void evil_esp_app_free(EvilEspApp* app);
int32_t evil_esp_app(void* p);

// Scene functions
void evil_esp_scene_on_enter_start(void* context);
void evil_esp_scene_on_enter_main_menu(void* context);
void evil_esp_scene_on_enter_scanner(void* context);
void evil_esp_scene_on_enter_scanner_results(void* context);
void evil_esp_scene_on_enter_attacks(void* context);
void evil_esp_scene_on_enter_attack_config(void* context);
void evil_esp_scene_on_enter_sniffer(void* context);
void evil_esp_scene_on_enter_sniffer_results(void* context);
void evil_esp_scene_on_enter_config(void* context);
void evil_esp_scene_on_enter_device_info(void* context);
void evil_esp_scene_on_enter_uart_terminal(void* context);

bool evil_esp_scene_on_event_start(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_main_menu(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_scanner(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_scanner_results(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_attacks(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_attack_config(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_sniffer(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_sniffer_results(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_config(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_device_info(void* context, SceneManagerEvent event);
bool evil_esp_scene_on_event_uart_terminal(void* context, SceneManagerEvent event);

void evil_esp_scene_on_exit_start(void* context);
void evil_esp_scene_on_exit_main_menu(void* context);
void evil_esp_scene_on_exit_scanner(void* context);
void evil_esp_scene_on_exit_scanner_results(void* context);
void evil_esp_scene_on_exit_attacks(void* context);
void evil_esp_scene_on_exit_attack_config(void* context);
void evil_esp_scene_on_exit_sniffer(void* context);
void evil_esp_scene_on_exit_sniffer_results(void* context);
void evil_esp_scene_on_exit_config(void* context);
void evil_esp_scene_on_exit_device_info(void* context);
void evil_esp_scene_on_exit_uart_terminal(void* context);

// UART Worker Functions
EvilEspUartWorker* evil_esp_uart_init(EvilEspApp* app);
void evil_esp_uart_free(EvilEspUartWorker* worker);
void evil_esp_uart_restart(EvilEspApp* app);
void evil_esp_uart_tx(EvilEspUartWorker* worker, const uint8_t* data, size_t len);
void evil_esp_uart_tx_string(EvilEspUartWorker* worker, const char* str);
void evil_esp_uart_send_command(EvilEspUartWorker* worker, const char* command);
bool evil_esp_uart_read_line(EvilEspUartWorker* worker, char* buffer, size_t buffer_size, uint32_t timeout_ms);
size_t evil_esp_uart_rx_available(EvilEspUartWorker* worker);
bool evil_esp_uart_wait_for_response(EvilEspUartWorker* worker, const char* expected_prefix, char* response_buffer, size_t buffer_size, uint32_t timeout_ms);

// Command Functions
void evil_esp_send_command(EvilEspApp* app, const char* command);
void evil_esp_send_scan_command(EvilEspApp* app);
void evil_esp_send_attack_start(EvilEspApp* app);
void evil_esp_send_attack_stop(EvilEspApp* app);
void evil_esp_send_sniff_command(EvilEspApp* app, const char* mode);
void evil_esp_send_set_target(EvilEspApp* app, const char* targets);
void evil_esp_send_channel_hop(EvilEspApp* app, bool enable);
void evil_esp_send_set_channel(EvilEspApp* app, int channel);
void evil_esp_send_info_command(EvilEspApp* app);
void evil_esp_send_config_to_device(EvilEspApp* app);

// Response Parsing
EvilEspResponseType evil_esp_parse_response_type(const char* response);
bool evil_esp_parse_scan_result(const char* response, EvilEspNetwork* network);

// Utility functions
void evil_esp_show_loading(EvilEspApp* app, const char* text);
void evil_esp_hide_loading(EvilEspApp* app);
void evil_esp_show_popup(EvilEspApp* app, const char* header, const char* text);
void evil_esp_append_log(EvilEspApp* app, const char* text);
void evil_esp_clear_log(EvilEspApp* app);
void evil_esp_notification_message(EvilEspApp* app, const NotificationSequence* sequence);

// Debug functions
void debug_write_to_sd(const char* data);
