#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <furi_hal_light.h>
#include <furi_hal_power.h>
#include <furi_hal_serial.h>
#include <furi_hal_serial_control.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <furi/core/stream_buffer.h>

typedef enum {
    ScreenMenu,
    ScreenSerial,
    ScreenResults,
    ScreenSetupScanner,
} AppScreen;

typedef enum {
    MenuStateSections,
    MenuStateItems,
} MenuState;
#ifndef FAP_VERSION_TEXT
#ifdef FAP_VERSION
#define FAP_VERSION_TEXT FAP_VERSION
#else
#define FAP_VERSION_TEXT "0.1"
#endif
#endif

#define LAB_C5_VERSION_TEXT FAP_VERSION_TEXT

#define MAX_SCAN_RESULTS 64
#define SCAN_LINE_BUFFER_SIZE 192
#define SCAN_SSID_MAX_LEN 33
#define SCAN_CHANNEL_MAX_LEN 8
#define SCAN_TYPE_MAX_LEN 16
#define SCAN_FIELD_BUFFER_LEN 64
#define SCAN_POWER_MIN_DBM (-110)
#define SCAN_POWER_MAX_DBM 0
#define SCAN_POWER_STEP 1
#define BACKLIGHT_ON_LEVEL 255
#define BACKLIGHT_OFF_LEVEL 0

#define SERIAL_BUFFER_SIZE 4096
#define UART_STREAM_SIZE 1024
#define MENU_VISIBLE_COUNT 6
#define SERIAL_VISIBLE_LINES 6
#define SERIAL_LINE_CHAR_LIMIT 22
#define SERIAL_TEXT_LINE_HEIGHT 10
#define DISPLAY_WIDTH 128
#define RESULT_DEFAULT_MAX_LINES 4
#define RESULT_DEFAULT_LINE_HEIGHT 12
#define RESULT_DEFAULT_CHAR_LIMIT (SERIAL_LINE_CHAR_LIMIT - 3)
#define RESULT_START_Y 12
#define RESULT_ENTRY_SPACING 0
#define RESULT_PREFIX_X 2
#define RESULT_TEXT_X 9
#define RESULT_SCROLL_WIDTH 3
#define RESULT_SCROLL_GAP 1
#define MENU_SECTION_SCANNER 0
#define MENU_SECTION_SNIFFERS 1
#define MENU_SECTION_TARGETS 2
#define MENU_SECTION_ATTACKS 3
#define MENU_SECTION_SETUP 4
#define SCANNER_FILTER_VISIBLE_COUNT 3
#define SCANNER_SCAN_COMMAND "scan_networks"
#define TARGETS_RESULTS_COMMAND "show_scan_results"
#define LAB_C5_CONFIG_DIR_PATH "apps_assets/labC5"
#define LAB_C5_CONFIG_FILE_PATH LAB_C5_CONFIG_DIR_PATH "/config.txt"

typedef enum {
    MenuActionCommand,
    MenuActionCommandWithTargets,
    MenuActionResults,
    MenuActionToggleBacklight,
    MenuActionOpenScannerSetup,
} MenuAction;

typedef enum {
    ScannerOptionShowSSID,
    ScannerOptionShowBSSID,
    ScannerOptionShowChannel,
    ScannerOptionShowSecurity,
    ScannerOptionShowPower,
    ScannerOptionShowBand,
    ScannerOptionMinPower,
    ScannerOptionCount,
} ScannerOption;

typedef struct {
    uint16_t number;
    char ssid[SCAN_SSID_MAX_LEN];
    char bssid[SCAN_FIELD_BUFFER_LEN];
    char channel[SCAN_CHANNEL_MAX_LEN];
    char security[SCAN_TYPE_MAX_LEN];
    char power_display[SCAN_FIELD_BUFFER_LEN];
    char band[SCAN_TYPE_MAX_LEN];
    int16_t power_dbm;
    bool power_valid;
    bool selected;
} ScanResult;

typedef struct {
    bool exit_app;
    MenuState menu_state;
    uint32_t section_index;
    uint32_t item_index;
    uint32_t item_offset;
    AppScreen screen;
    FuriHalSerialHandle* serial;
    FuriMutex* serial_mutex;
    FuriStreamBuffer* rx_stream;
    ViewPort* viewport;
    Gui* gui;
    char serial_buffer[SERIAL_BUFFER_SIZE];
    size_t serial_len;
    size_t serial_scroll;
    bool serial_follow_tail;
    bool last_command_sent;
    ScanResult scan_results[MAX_SCAN_RESULTS];
    size_t scan_result_count;
    size_t scan_result_index;
    size_t scan_result_offset;
    uint16_t scan_selected_numbers[MAX_SCAN_RESULTS];
    size_t scan_selected_count;
    bool scan_results_loading;
    char scan_line_buffer[SCAN_LINE_BUFFER_SIZE];
    size_t scan_line_len;
    uint16_t visible_result_indices[MAX_SCAN_RESULTS];
    size_t visible_result_count;
    bool scanner_show_ssid;
    bool scanner_show_bssid;
    bool scanner_show_channel;
    bool scanner_show_security;
    bool scanner_show_power;
    bool scanner_show_band;
    int16_t scanner_min_power;
    size_t scanner_setup_index;
    bool scanner_adjusting_power;
    bool backlight_enabled;
    bool backlight_insomnia;
    size_t scanner_view_offset;
    uint8_t result_line_height;
    uint8_t result_char_limit;
    uint8_t result_max_lines;
    Font result_font;
    NotificationApp* notifications;
    bool backlight_notification_enforced;
    bool config_dirty;
    char status_message[64];
    uint32_t status_message_until;
    bool status_message_fullscreen;
} SimpleApp;
static void simple_app_adjust_result_offset(SimpleApp* app);
static void simple_app_rebuild_visible_results(SimpleApp* app);
static bool simple_app_result_is_visible(const SimpleApp* app, const ScanResult* result);
static ScanResult* simple_app_visible_result(SimpleApp* app, size_t visible_index);
static const ScanResult* simple_app_visible_result_const(const SimpleApp* app, size_t visible_index);
static void simple_app_update_result_layout(SimpleApp* app);
static void simple_app_apply_backlight(SimpleApp* app);
static void simple_app_toggle_backlight(SimpleApp* app);
static void simple_app_mark_config_dirty(SimpleApp* app);
static void simple_app_save_config_if_dirty(SimpleApp* app, const char* message, bool fullscreen);
static bool simple_app_save_config(SimpleApp* app, const char* success_message, bool fullscreen);
static void simple_app_load_config(SimpleApp* app);
static void simple_app_show_status_message(SimpleApp* app, const char* message, uint32_t duration_ms, bool fullscreen);
static void simple_app_clear_status_message(SimpleApp* app);
static bool simple_app_status_message_is_active(SimpleApp* app);
static void simple_app_send_command_with_targets(SimpleApp* app, const char* base_command);

typedef struct {
    const char* label;
    const char* command;
    MenuAction action;
} MenuEntry;

typedef struct {
    const char* title;
    const MenuEntry* entries;
    size_t entry_count;
    uint8_t display_y;
} MenuSection;

static const uint8_t image_icon_0_bits[] = {
    0xff, 0x03, 0xff, 0x03, 0xff, 0x03, 0x11, 0x03, 0xdd, 0x03,
    0x1d, 0x03, 0x71, 0x03, 0x1f, 0x03, 0xff, 0x03, 0xff, 0x03,
};

static const MenuEntry menu_entries_sniffers[] = {
    {"Start Sniffer", "start_sniffer", MenuActionCommand},
    {"Show Sniffer Results", "show_sniffer_results", MenuActionCommand},
    {"Show Probes", "show_probes", MenuActionCommand},
    {"Sniffer Debug", "sniffer_debug 1", MenuActionCommand},
};

static const MenuEntry menu_entries_attacks[] = {
    {"Start Deauth", "start_deauth", MenuActionCommandWithTargets},
    {"Start Evil Twin", "start_evil_twin", MenuActionCommand},
    {"SAE Overflow", "sae_overflow", MenuActionCommand},
    {"Start Wardrive", "start_wardrive", MenuActionCommand},
};

static char menu_label_backlight[24] = "Backlight: On";

static const MenuEntry menu_entries_setup[] = {
    {menu_label_backlight, NULL, MenuActionToggleBacklight},
    {"Scanner Filters", NULL, MenuActionOpenScannerSetup},
};

static const MenuSection menu_sections[] = {
    {"Scanner", NULL, 0, 12},
    {"Sniffers", menu_entries_sniffers, sizeof(menu_entries_sniffers) / sizeof(menu_entries_sniffers[0]), 24},
    {"Targets", NULL, 0, 36},
    {"Attacks", menu_entries_attacks, sizeof(menu_entries_attacks) / sizeof(menu_entries_attacks[0]), 48},
    {"Setup", menu_entries_setup, sizeof(menu_entries_setup) / sizeof(menu_entries_setup[0]), 60},
};

static const size_t menu_section_count = sizeof(menu_sections) / sizeof(menu_sections[0]);

static void simple_app_truncate_text(char* text, size_t max_chars) {
    if(!text || max_chars == 0) return;
    size_t len = strlen(text);
    if(len <= max_chars) return;
    if(max_chars == 1) {
        text[0] = '\0';
        return;
    }
    text[max_chars - 1] = '.';
    text[max_chars] = '\0';
}

static void simple_app_copy_field(char* dest, size_t dest_size, const char* src, const char* fallback) {
    if(dest_size == 0 || !dest) return;
    const char* value = (src && src[0] != '\0') ? src : fallback;
    if(!value) value = "";
    size_t max_copy = dest_size - 1;
    if(max_copy == 0) {
        dest[0] = '\0';
        return;
    }
    strncpy(dest, value, max_copy);
    dest[max_copy] = '\0';
}

static void simple_app_reset_scan_results(SimpleApp* app) {
    if(!app) return;
    memset(app->scan_results, 0, sizeof(app->scan_results));
    memset(app->scan_selected_numbers, 0, sizeof(app->scan_selected_numbers));
    memset(app->scan_line_buffer, 0, sizeof(app->scan_line_buffer));
    memset(app->visible_result_indices, 0, sizeof(app->visible_result_indices));
    app->scan_result_count = 0;
    app->scan_result_index = 0;
    app->scan_result_offset = 0;
    app->scan_selected_count = 0;
    app->scan_line_len = 0;
    app->scan_results_loading = false;
    app->visible_result_count = 0;
}

static bool simple_app_result_is_visible(const SimpleApp* app, const ScanResult* result) {
    if(!app || !result) return false;
    if(result->power_valid && result->power_dbm < app->scanner_min_power) {
        return false;
    }
    return true;
}

static void simple_app_rebuild_visible_results(SimpleApp* app) {
    if(!app) return;
    app->visible_result_count = 0;
    for(size_t i = 0; i < app->scan_result_count && i < MAX_SCAN_RESULTS; i++) {
        if(simple_app_result_is_visible(app, &app->scan_results[i])) {
            app->visible_result_indices[app->visible_result_count++] = (uint16_t)i;
        }
    }
    if(app->scan_result_index >= app->visible_result_count) {
        app->scan_result_index =
            (app->visible_result_count > 0) ? app->visible_result_count - 1 : 0;
    }
    if(app->scan_result_offset >= app->visible_result_count) {
        app->scan_result_offset =
            (app->visible_result_count > 0) ? app->visible_result_count - 1 : 0;
    }
    if(app->scan_result_offset > app->scan_result_index) {
        app->scan_result_offset = app->scan_result_index;
    }
}

static void simple_app_modify_min_power(SimpleApp* app, int16_t delta) {
    if(!app) return;
    int32_t proposed = (int32_t)app->scanner_min_power + delta;
    if(proposed > SCAN_POWER_MAX_DBM) {
        proposed = SCAN_POWER_MAX_DBM;
    } else if(proposed < SCAN_POWER_MIN_DBM) {
        proposed = SCAN_POWER_MIN_DBM;
    }
    if(app->scanner_min_power != proposed) {
        app->scanner_min_power = (int16_t)proposed;
        simple_app_rebuild_visible_results(app);
        simple_app_adjust_result_offset(app);
        simple_app_mark_config_dirty(app);
    }
}

static size_t simple_app_enabled_field_count(const SimpleApp* app) {
    if(!app) return 0;
    size_t count = 0;
    if(app->scanner_show_ssid) count++;
    if(app->scanner_show_bssid) count++;
    if(app->scanner_show_channel) count++;
    if(app->scanner_show_security) count++;
    if(app->scanner_show_power) count++;
    if(app->scanner_show_band) count++;
    return count;
}

static bool* simple_app_scanner_option_flag(SimpleApp* app, ScannerOption option) {
    if(!app) return NULL;
    switch(option) {
    case ScannerOptionShowSSID:
        return &app->scanner_show_ssid;
    case ScannerOptionShowBSSID:
        return &app->scanner_show_bssid;
    case ScannerOptionShowChannel:
        return &app->scanner_show_channel;
    case ScannerOptionShowSecurity:
        return &app->scanner_show_security;
    case ScannerOptionShowPower:
        return &app->scanner_show_power;
    case ScannerOptionShowBand:
        return &app->scanner_show_band;
    default:
        return NULL;
    }
}

static ScanResult* simple_app_visible_result(SimpleApp* app, size_t visible_index) {
    if(!app || visible_index >= app->visible_result_count) return NULL;
    uint16_t actual_index = app->visible_result_indices[visible_index];
    if(actual_index >= MAX_SCAN_RESULTS) return NULL;
    return &app->scan_results[actual_index];
}

static const ScanResult* simple_app_visible_result_const(const SimpleApp* app, size_t visible_index) {
    if(!app || visible_index >= app->visible_result_count) return NULL;
    uint16_t actual_index = app->visible_result_indices[visible_index];
    if(actual_index >= MAX_SCAN_RESULTS) return NULL;
    return &app->scan_results[actual_index];
}

static void simple_app_update_backlight_label(SimpleApp* app) {
    if(!app) return;
    snprintf(
        menu_label_backlight,
        sizeof(menu_label_backlight),
        "Backlight: %s",
        app->backlight_enabled ? "On" : "Off");
}

static void simple_app_update_result_layout(SimpleApp* app) {
    if(!app) return;
    size_t enabled_fields = simple_app_enabled_field_count(app);
    app->result_max_lines = RESULT_DEFAULT_MAX_LINES;
    if(enabled_fields <= 2) {
        app->result_font = FontPrimary;
        app->result_line_height = 14;
        app->result_max_lines = 3;
    } else if(enabled_fields <= 4) {
        app->result_font = FontSecondary;
        app->result_line_height = RESULT_DEFAULT_LINE_HEIGHT;
    } else {
        app->result_font = FontSecondary;
        app->result_line_height = RESULT_DEFAULT_LINE_HEIGHT;
    }

    uint8_t char_width = (app->result_font == FontPrimary) ? 7 : 6;
    uint8_t available_px = DISPLAY_WIDTH - RESULT_TEXT_X - RESULT_SCROLL_WIDTH - RESULT_SCROLL_GAP;
    uint8_t computed_limit = (char_width > 0) ? (available_px / char_width) : RESULT_DEFAULT_CHAR_LIMIT;
    if(computed_limit < 10) {
        computed_limit = 10;
    }
    app->result_char_limit = computed_limit;

    if(app->result_line_height == 0) {
        app->result_line_height = RESULT_DEFAULT_LINE_HEIGHT;
    }
    if(app->result_max_lines == 0) {
        app->result_max_lines = RESULT_DEFAULT_MAX_LINES;
    }
}

static void simple_app_append_field(
    char* buffer,
    size_t buffer_size,
    size_t* offset,
    bool* first_field,
    const char* prefix,
    const char* value,
    const char* suffix) {
    if(!buffer || buffer_size == 0 || !offset || !first_field || !value || value[0] == '\0') {
        return;
    }

    size_t remaining = (buffer_size > *offset) ? (buffer_size - *offset) : 0;
    if(remaining == 0) return;

    const char* separator = *first_field ? " " : " | ";
    int written = snprintf(
        buffer + *offset,
        remaining,
        "%s%s%s%s",
        separator,
        prefix ? prefix : "",
        value,
        suffix ? suffix : "");

    if(written < 0) return;
    size_t consumed = (size_t)written;
    if(consumed >= remaining) {
        *offset = buffer_size - 1;
        buffer[buffer_size - 1] = '\0';
    } else {
        *offset += consumed;
    }
    *first_field = false;
}

static void simple_app_show_status_message(
    SimpleApp* app,
    const char* message,
    uint32_t duration_ms,
    bool fullscreen) {
    if(!app) return;
    if(message && message[0] != '\0') {
        strncpy(app->status_message, message, sizeof(app->status_message) - 1);
        app->status_message[sizeof(app->status_message) - 1] = '\0';
        if(duration_ms == 0) {
            app->status_message_until = UINT32_MAX;
        } else {
            uint32_t timeout_ticks = furi_ms_to_ticks(duration_ms);
            app->status_message_until = furi_get_tick() + timeout_ticks;
        }
        app->status_message_fullscreen = fullscreen;
    } else {
        app->status_message[0] = '\0';
        app->status_message_until = 0;
        app->status_message_fullscreen = false;
    }
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_clear_status_message(SimpleApp* app) {
    if(!app) return;
    app->status_message[0] = '\0';
    app->status_message_until = 0;
    app->status_message_fullscreen = false;
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static bool simple_app_status_message_is_active(SimpleApp* app) {
    if(!app) return false;
    if(app->status_message_until == 0 || app->status_message[0] == '\0') return false;
    if(app->status_message_until != UINT32_MAX && furi_get_tick() >= app->status_message_until) {
        simple_app_clear_status_message(app);
        return false;
    }
    return true;
}

static void simple_app_mark_config_dirty(SimpleApp* app) {
    if(!app) return;
    app->config_dirty = true;
}

static bool simple_app_parse_bool_value(const char* value, bool current) {
    if(!value || value[0] == '\0') return current;
    if((value[0] == '1' && value[1] == '\0') || value[0] == 'Y' || value[0] == 'y' ||
       value[0] == 'T' || value[0] == 't') {
        return true;
    }
    if((value[0] == '0' && value[1] == '\0') || value[0] == 'N' || value[0] == 'n' ||
       value[0] == 'F' || value[0] == 'f') {
        return false;
    }
    return atoi(value) != 0;
}

static void simple_app_trim(char* text) {
    if(!text) return;
    char* start = text;
    while(*start && isspace((unsigned char)*start)) {
        start++;
    }
    char* end = start + strlen(start);
    while(end > start && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    if(start != text) {
        memmove(text, start, (size_t)(end - start) + 1);
    }
}

static void simple_app_parse_config_line(SimpleApp* app, char* line) {
    if(!app || !line) return;
    simple_app_trim(line);
    if(line[0] == '\0' || line[0] == '#') return;
    char* equals = strchr(line, '=');
    if(!equals) return;
    *equals = '\0';
    char* key = line;
    char* value = equals + 1;
    simple_app_trim(key);
    simple_app_trim(value);
    if(strcmp(key, "show_ssid") == 0) {
        app->scanner_show_ssid = simple_app_parse_bool_value(value, app->scanner_show_ssid);
    } else if(strcmp(key, "show_bssid") == 0) {
        app->scanner_show_bssid = simple_app_parse_bool_value(value, app->scanner_show_bssid);
    } else if(strcmp(key, "show_channel") == 0) {
        app->scanner_show_channel = simple_app_parse_bool_value(value, app->scanner_show_channel);
    } else if(strcmp(key, "show_security") == 0) {
        app->scanner_show_security = simple_app_parse_bool_value(value, app->scanner_show_security);
    } else if(strcmp(key, "show_power") == 0) {
        app->scanner_show_power = simple_app_parse_bool_value(value, app->scanner_show_power);
    } else if(strcmp(key, "show_band") == 0) {
        app->scanner_show_band = simple_app_parse_bool_value(value, app->scanner_show_band);
    } else if(strcmp(key, "min_power") == 0) {
        app->scanner_min_power = (int16_t)strtol(value, NULL, 10);
    } else if(strcmp(key, "backlight_enabled") == 0) {
        app->backlight_enabled = simple_app_parse_bool_value(value, app->backlight_enabled);
    }
}

static bool simple_app_save_config(SimpleApp* app, const char* success_message, bool fullscreen) {
    if(!app) return false;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return false;
    storage_simply_mkdir(storage, EXT_PATH("apps_assets"));
    storage_simply_mkdir(storage, EXT_PATH(LAB_C5_CONFIG_DIR_PATH));
    File* file = storage_file_alloc(storage);
    bool success = false;
    if(storage_file_open(file, EXT_PATH(LAB_C5_CONFIG_FILE_PATH), FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        char buffer[256];
        int len = snprintf(
            buffer,
            sizeof(buffer),
            "show_ssid=%d\n"
            "show_bssid=%d\n"
            "show_channel=%d\n"
            "show_security=%d\n"
            "show_power=%d\n"
            "show_band=%d\n"
            "min_power=%d\n"
            "backlight_enabled=%d\n",
            app->scanner_show_ssid ? 1 : 0,
            app->scanner_show_bssid ? 1 : 0,
            app->scanner_show_channel ? 1 : 0,
            app->scanner_show_security ? 1 : 0,
            app->scanner_show_power ? 1 : 0,
            app->scanner_show_band ? 1 : 0,
            (int)app->scanner_min_power,
            app->backlight_enabled ? 1 : 0);
        if(len > 0 && len < (int)sizeof(buffer)) {
            size_t written = storage_file_write(file, buffer, (size_t)len);
            if(written == (size_t)len) {
                success = true;
            }
        }
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    if(success) {
        app->config_dirty = false;
        if(success_message) {
            simple_app_show_status_message(app, success_message, 2000, fullscreen);
        }
    }
    return success;
}

static void simple_app_load_config(SimpleApp* app) {
    if(!app) return;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return;
    File* file = storage_file_alloc(storage);
    bool loaded = false;
    if(storage_file_open(file, EXT_PATH(LAB_C5_CONFIG_FILE_PATH), FSAM_READ, FSOM_OPEN_EXISTING)) {
        char line[96];
        size_t pos = 0;
        uint8_t ch = 0;
        while(storage_file_read(file, &ch, 1) == 1) {
            if(ch == '\r') continue;
            if(ch == '\n') {
                line[pos] = '\0';
                simple_app_parse_config_line(app, line);
                pos = 0;
                continue;
            }
            if(pos + 1 < sizeof(line)) {
                line[pos++] = (char)ch;
            }
        }
        if(pos > 0) {
            line[pos] = '\0';
            simple_app_parse_config_line(app, line);
        }
        storage_file_close(file);
        loaded = true;
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    if(loaded) {
        simple_app_show_status_message(app, "Config loaded", 2000, true);
        app->config_dirty = false;
    } else {
        simple_app_save_config(app, NULL, false);
        simple_app_show_status_message(app, "Config created", 2000, true);
    }
    if(app->scanner_min_power > SCAN_POWER_MAX_DBM) {
        app->scanner_min_power = SCAN_POWER_MAX_DBM;
    } else if(app->scanner_min_power < SCAN_POWER_MIN_DBM) {
        app->scanner_min_power = SCAN_POWER_MIN_DBM;
    }
    simple_app_update_result_layout(app);
    simple_app_rebuild_visible_results(app);
}

static void simple_app_save_config_if_dirty(SimpleApp* app, const char* message, bool fullscreen) {
    if(!app) return;
    if(app->config_dirty) {
        simple_app_save_config(app, message, fullscreen);
    }
}

static void simple_app_apply_backlight(SimpleApp* app) {
    if(!app) return;
    uint8_t level = app->backlight_enabled ? BACKLIGHT_ON_LEVEL : BACKLIGHT_OFF_LEVEL;
    furi_hal_light_set(LightBacklight, level);

    if(app->backlight_enabled) {
        if(!app->backlight_insomnia) {
            furi_hal_power_insomnia_enter();
            app->backlight_insomnia = true;
        }
        if(app->notifications && !app->backlight_notification_enforced) {
            notification_message_block(app->notifications, &sequence_display_backlight_enforce_on);
            app->backlight_notification_enforced = true;
        }
    } else {
        if(app->backlight_insomnia) {
            furi_hal_power_insomnia_exit();
            app->backlight_insomnia = false;
        }
        if(app->notifications && app->backlight_notification_enforced) {
            notification_message(app->notifications, &sequence_display_backlight_enforce_auto);
            app->backlight_notification_enforced = false;
        }
    }

    simple_app_update_backlight_label(app);
}

static void simple_app_toggle_backlight(SimpleApp* app) {
    if(!app) return;
    app->backlight_enabled = !app->backlight_enabled;
    simple_app_apply_backlight(app);
    simple_app_mark_config_dirty(app);
}

static size_t simple_app_parse_quoted_fields(const char* line, char fields[][SCAN_FIELD_BUFFER_LEN], size_t max_fields) {
    if(!line || !fields || max_fields == 0) return 0;

    size_t count = 0;
    const char* ptr = line;
    while(*ptr && count < max_fields) {
        while(*ptr && *ptr != '"') {
            ptr++;
        }
        if(*ptr != '"') break;
        ptr++;
        const char* start = ptr;
        while(*ptr && *ptr != '"') {
            ptr++;
        }
        size_t len = (size_t)(ptr - start);
        if(len >= SCAN_FIELD_BUFFER_LEN) {
            len = SCAN_FIELD_BUFFER_LEN - 1;
        }
        memcpy(fields[count], start, len);
        fields[count][len] = '\0';
        if(*ptr == '"') {
            ptr++;
        }
        while(*ptr && *ptr != '"') {
            ptr++;
        }
        count++;
    }
    return count;
}

static void simple_app_process_scan_line(SimpleApp* app, const char* line) {
    if(!app || !line) return;

    const char* cursor = line;
    while(*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }

    if(strncmp(cursor, "Scan results", 12) == 0) {
        app->scan_results_loading = false;
        if(app->screen == ScreenResults) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(cursor[0] != '"') return;
    if(app->scan_result_count >= MAX_SCAN_RESULTS) return;

    char fields[7][SCAN_FIELD_BUFFER_LEN];
    for(size_t i = 0; i < 7; i++) {
        memset(fields[i], 0, SCAN_FIELD_BUFFER_LEN);
    }

    size_t field_count = simple_app_parse_quoted_fields(cursor, fields, 7);
    if(field_count < 7) return;

    ScanResult* result = &app->scan_results[app->scan_result_count];
    memset(result, 0, sizeof(ScanResult));
    result->number = (uint16_t)strtoul(fields[0], NULL, 10);
    simple_app_copy_field(result->ssid, sizeof(result->ssid), fields[1], "<hidden>");
    simple_app_copy_field(result->bssid, sizeof(result->bssid), fields[2], "??:??:??:??:??:??");
    simple_app_copy_field(result->channel, sizeof(result->channel), fields[3], "?");
    simple_app_copy_field(result->security, sizeof(result->security), fields[4], "Unknown");
    simple_app_copy_field(result->power_display, sizeof(result->power_display), fields[5], "?");
    simple_app_copy_field(result->band, sizeof(result->band), fields[6], "?");

    const char* power_str = fields[5];
    char* power_end = NULL;
    long power_value = strtol(power_str, &power_end, 10);
    if(power_str[0] != '\0' && power_end && *power_end == '\0') {
        if(power_value < SCAN_POWER_MIN_DBM) {
            power_value = SCAN_POWER_MIN_DBM;
        } else if(power_value > SCAN_POWER_MAX_DBM) {
            power_value = SCAN_POWER_MAX_DBM;
        }
        result->power_dbm = (int16_t)power_value;
        result->power_valid = true;
    } else {
        result->power_dbm = 0;
        result->power_valid = false;
    }
    result->selected = false;

    app->scan_result_count++;
    simple_app_rebuild_visible_results(app);

    if(app->screen == ScreenResults) {
        simple_app_adjust_result_offset(app);
        view_port_update(app->viewport);
    }
}

static size_t simple_app_format_result_line(
    const SimpleApp* app,
    const ScanResult* result,
    char* buffer,
    size_t buffer_size) {
    if(!app || !result || !buffer || buffer_size == 0) {
        return 0;
    }

    const char* selection_marker = result->selected ? "*" : "";
    int written = snprintf(buffer, buffer_size, "%u%s", (unsigned)result->number, selection_marker);
    if(written < 0) {
        buffer[0] = '\0';
        return 0;
    }

    size_t offset = (written < (int)buffer_size) ? (size_t)written : buffer_size - 1;
    bool first_field = true;

    if(app->scanner_show_ssid) {
        simple_app_append_field(buffer, buffer_size, &offset, &first_field, NULL, result->ssid, NULL);
    }
    if(app->scanner_show_bssid) {
        simple_app_append_field(
            buffer, buffer_size, &offset, &first_field, NULL, result->bssid, NULL);
    }
    if(app->scanner_show_channel) {
        simple_app_append_field(buffer, buffer_size, &offset, &first_field, NULL, result->channel, NULL);
    }
    if(app->scanner_show_security) {
        simple_app_append_field(
            buffer, buffer_size, &offset, &first_field, NULL, result->security, NULL);
    }
    if(app->scanner_show_power) {
        const char* suffix =
            (strstr(result->power_display, "dBm") != NULL) ? NULL : " dBm";
        simple_app_append_field(
            buffer, buffer_size, &offset, &first_field, NULL, result->power_display, suffix);
    }
    if(app->scanner_show_band) {
        simple_app_append_field(
            buffer, buffer_size, &offset, &first_field, NULL, result->band, NULL);
    }

    size_t length = (offset < buffer_size) ? offset : buffer_size - 1;
    if(buffer[length] != '\0') {
        buffer[length] = '\0';
    }
    return length;
}

static uint8_t simple_app_result_line_count(const SimpleApp* app, const ScanResult* result) {
    if(!app || !result) return 1;
    if(app->result_char_limit == 0) return 1;
    char buffer[96];
    size_t len = simple_app_format_result_line(app, result, buffer, sizeof(buffer));
    size_t lines = (len + app->result_char_limit - 1) / app->result_char_limit;
    if(lines == 0) lines = 1;
    if(app->result_max_lines > 0 && lines > app->result_max_lines) {
        lines = app->result_max_lines;
    }
    return (uint8_t)lines;
}

static size_t simple_app_total_result_lines(SimpleApp* app) {
    if(!app) return 0;
    size_t total = 0;
    for(size_t i = 0; i < app->visible_result_count; i++) {
        const ScanResult* result = simple_app_visible_result_const(app, i);
        if(!result) continue;
        total += simple_app_result_line_count(app, result);
    }
    return total;
}

static size_t simple_app_result_offset_lines(SimpleApp* app) {
    if(!app) return 0;
    size_t lines = 0;
    for(size_t i = 0; i < app->scan_result_offset && i < app->visible_result_count; i++) {
        const ScanResult* result = simple_app_visible_result_const(app, i);
        if(!result) continue;
        lines += simple_app_result_line_count(app, result);
    }
    return lines;
}

static void simple_app_scan_feed(SimpleApp* app, char ch) {
    if(!app || !app->scan_results_loading) return;

    if(ch == '\r') return;

    if(ch == '\n') {
        if(app->scan_line_len > 0) {
            app->scan_line_buffer[app->scan_line_len] = '\0';
            simple_app_process_scan_line(app, app->scan_line_buffer);
        }
        app->scan_line_len = 0;
        return;
    }

    if(app->scan_line_len + 1 >= sizeof(app->scan_line_buffer)) {
        app->scan_line_len = 0;
        return;
    }

    app->scan_line_buffer[app->scan_line_len++] = ch;
}

static void simple_app_update_selected_numbers(SimpleApp* app, const ScanResult* result) {
    if(!app || !result) return;
    if(result->selected) {
        for(size_t i = 0; i < app->scan_selected_count; i++) {
            if(app->scan_selected_numbers[i] == result->number) {
                return;
            }
        }
        if(app->scan_selected_count < MAX_SCAN_RESULTS) {
            app->scan_selected_numbers[app->scan_selected_count++] = result->number;
        }
    } else {
        for(size_t i = 0; i < app->scan_selected_count; i++) {
            if(app->scan_selected_numbers[i] == result->number) {
                for(size_t j = i; j + 1 < app->scan_selected_count; j++) {
                    app->scan_selected_numbers[j] = app->scan_selected_numbers[j + 1];
                }
                app->scan_selected_numbers[app->scan_selected_count - 1] = 0;
                if(app->scan_selected_count > 0) {
                    app->scan_selected_count--;
                }
                break;
            }
        }
    }
}

static void simple_app_toggle_scan_selection(SimpleApp* app, ScanResult* result) {
    if(!app || !result) return;
    result->selected = !result->selected;
    simple_app_update_selected_numbers(app, result);
}

static void simple_app_adjust_result_offset(SimpleApp* app) {
    if(!app) return;

    if(app->visible_result_count == 0) {
        app->scan_result_offset = 0;
        app->scan_result_index = 0;
        return;
    }

    if(app->scan_result_index >= app->visible_result_count) {
        app->scan_result_index = app->visible_result_count - 1;
    }

    if(app->scan_result_offset > app->scan_result_index) {
        app->scan_result_offset = app->scan_result_index;
    }

    while(app->scan_result_offset < app->visible_result_count) {
        size_t lines_used = 0;
        bool index_visible = false;
        size_t available_lines = (app->result_max_lines > 0) ? app->result_max_lines : 1;
        for(size_t i = app->scan_result_offset; i < app->visible_result_count; i++) {
            const ScanResult* result = simple_app_visible_result_const(app, i);
            if(!result) continue;
            uint8_t entry_lines = simple_app_result_line_count(app, result);
            if(entry_lines == 0) entry_lines = 1;
            if(lines_used + entry_lines > available_lines) break;
            lines_used += entry_lines;
            if(i == app->scan_result_index) {
                index_visible = true;
                break;
            }
        }
        if(index_visible) break;
        if(app->scan_result_offset >= app->scan_result_index) {
            break;
        }
        app->scan_result_offset++;
    }

    if(app->scan_result_offset >= app->visible_result_count) {
        app->scan_result_offset =
            (app->visible_result_count > 0) ? app->visible_result_count - 1 : 0;
    }
}

static size_t simple_app_trim_oldest_line(SimpleApp* app) {
    if(!app || app->serial_len == 0) return 0;
    size_t drop = 0;
    size_t removed_lines = 0;

    while(drop < app->serial_len && app->serial_buffer[drop] != '\n') {
        drop++;
    }

    if(drop < app->serial_len) {
        drop++;
        removed_lines = 1;
    } else if(app->serial_len > 0) {
        removed_lines = 1;
    } else {
        drop = app->serial_len;
    }

    if(drop > 0) {
        memmove(app->serial_buffer, app->serial_buffer + drop, app->serial_len - drop);
        app->serial_len -= drop;
        app->serial_buffer[app->serial_len] = '\0';
    }

    return removed_lines;
}

static size_t simple_app_count_display_lines(const char* buffer, size_t length) {
    size_t lines = 0;
    size_t col = 0;

    for(size_t i = 0; i < length; i++) {
        char ch = buffer[i];
        if(ch == '\r') continue;
        if(ch == '\n') {
            lines++;
            col = 0;
            continue;
        }
        if(col >= SERIAL_LINE_CHAR_LIMIT) {
            lines++;
            col = 0;
        }
        col++;
    }

    if(col > 0) {
        lines++;
    }

    return lines;
}

static size_t simple_app_total_display_lines(SimpleApp* app) {
    if(!app->serial_mutex) return 0;
    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    size_t total = simple_app_count_display_lines(app->serial_buffer, app->serial_len);
    furi_mutex_release(app->serial_mutex);
    return total;
}

static size_t simple_app_max_scroll(SimpleApp* app) {
    size_t total = simple_app_total_display_lines(app);
    if(total <= SERIAL_VISIBLE_LINES) return 0;
    return total - SERIAL_VISIBLE_LINES;
}

static void simple_app_update_scroll(SimpleApp* app) {
    if(!app) return;
    size_t max_scroll = simple_app_max_scroll(app);
    if(app->serial_follow_tail) {
        app->serial_scroll = max_scroll;
    } else if(app->serial_scroll > max_scroll) {
        app->serial_scroll = max_scroll;
    }
    if(max_scroll == 0) {
        app->serial_follow_tail = true;
    }
}

static void simple_app_reset_serial_log(SimpleApp* app, const char* status) {
    if(!app || !app->serial_mutex) return;
    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    int written = snprintf(
        app->serial_buffer,
        SERIAL_BUFFER_SIZE,
        "=== UART TERMINAL ===\n115200 baud\nStatus: %s\n\n",
        status ? status : "READY");
    if(written < 0) {
        written = 0;
    } else if(written >= (int)SERIAL_BUFFER_SIZE) {
        written = SERIAL_BUFFER_SIZE - 1;
    }
    app->serial_len = (size_t)written;
    app->serial_buffer[app->serial_len] = '\0';
    furi_mutex_release(app->serial_mutex);
    app->serial_scroll = 0;
    app->serial_follow_tail = true;
    simple_app_update_scroll(app);
}

static void simple_app_append_serial_data(SimpleApp* app, const uint8_t* data, size_t length) {
    if(!app || !data || length == 0 || !app->serial_mutex) return;

    bool trimmed_any = false;

    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    for(size_t i = 0; i < length; i++) {
        while(app->serial_len >= SERIAL_BUFFER_SIZE - 1) {
            trimmed_any = simple_app_trim_oldest_line(app) > 0 || trimmed_any;
        }
        app->serial_buffer[app->serial_len++] = (char)data[i];
    }
    app->serial_buffer[app->serial_len] = '\0';
    furi_mutex_release(app->serial_mutex);

    for(size_t i = 0; i < length; i++) {
        simple_app_scan_feed(app, (char)data[i]);
    }

    if(trimmed_any && !app->serial_follow_tail) {
        size_t max_scroll = simple_app_max_scroll(app);
        if(app->serial_scroll > max_scroll) {
            app->serial_scroll = max_scroll;
        }
    }

    simple_app_update_scroll(app);
}

static void simple_app_send_command(SimpleApp* app, const char* command, bool go_to_serial) {
    if(!app || !command || command[0] == '\0') return;

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "%s\n", command);

    furi_hal_serial_tx(app->serial, (const uint8_t*)cmd, strlen(cmd));
    furi_hal_serial_tx_wait_complete(app->serial);

    furi_stream_buffer_reset(app->rx_stream);
    simple_app_reset_serial_log(app, "COMMAND SENT");

    char log_line[96];
    int log_len = snprintf(log_line, sizeof(log_line), "TX: %s\n", command);
    if(log_len > 0) {
        simple_app_append_serial_data(app, (const uint8_t*)log_line, (size_t)log_len);
    }

    app->last_command_sent = true;
    if(go_to_serial) {
        app->screen = ScreenSerial;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
    }
}

static void simple_app_send_command_with_targets(SimpleApp* app, const char* base_command) {
    if(!app || !base_command || base_command[0] == '\0') return;
    if(app->scan_selected_count == 0) {
        simple_app_show_status_message(app, "Select targets first", 1500, false);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    char command[96];
    size_t written = snprintf(command, sizeof(command), "%s", base_command);
    if(written >= sizeof(command)) {
        command[sizeof(command) - 1] = '\0';
        written = strlen(command);
    }

    for(size_t i = 0; i < app->scan_selected_count && written < sizeof(command) - 1; i++) {
        int added = snprintf(
            command + written,
            sizeof(command) - written,
            " %u",
            (unsigned)app->scan_selected_numbers[i]);
        if(added < 0) {
            break;
        }
        written += (size_t)added;
        if(written >= sizeof(command)) {
            written = sizeof(command) - 1;
            command[written] = '\0';
            break;
        }
    }

    simple_app_send_command(app, command, true);
}

static void simple_app_send_stop_if_needed(SimpleApp* app) {
    if(!app || !app->last_command_sent) return;
    simple_app_send_command(app, "stop", false);
    app->last_command_sent = false;
}

static void simple_app_request_scan_results(SimpleApp* app, const char* command) {
    if(!app) return;
    simple_app_reset_scan_results(app);
    app->scan_results_loading = true;
    if(command && command[0] != '\0') {
        simple_app_send_command(app, command, false);
    }
    app->screen = ScreenResults;
    view_port_update(app->viewport);
}
static void simple_app_draw_menu(SimpleApp* app, Canvas* canvas) {
    canvas_set_color(canvas, ColorBlack);

    canvas_set_bitmap_mode(canvas, true);
    canvas_draw_xbm(canvas, 115, 2, 10, 10, image_icon_0_bits);
    canvas_set_bitmap_mode(canvas, false);

    canvas_set_font(canvas, FontSecondary);
    if(simple_app_status_message_is_active(app) && !app->status_message_fullscreen) {
        canvas_draw_str(canvas, 2, 52, app->status_message);
    }
    char version_text[24];
    snprintf(version_text, sizeof(version_text), "v.%s", LAB_C5_VERSION_TEXT);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 1, 63, AlignRight, AlignBottom, version_text);

    if(app->section_index >= menu_section_count) {
        app->section_index = 0;
    }

    if(app->menu_state == MenuStateSections) {
        canvas_set_font(canvas, FontPrimary);
        for(size_t i = 0; i < menu_section_count; i++) {
            uint8_t y = menu_sections[i].display_y;
            if(app->section_index == i) {
                canvas_draw_str(canvas, 0, y, ">");
                canvas_draw_str(canvas, 12, y, menu_sections[i].title);
            } else {
                canvas_draw_str(canvas, 6, y, menu_sections[i].title);
            }
        }
        return;
    }

    if(app->section_index >= menu_section_count) {
        app->section_index = 0;
    }

    const MenuSection* section = &menu_sections[app->section_index];

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 3, 12, section->title);

    canvas_set_font(canvas, FontSecondary);

    if(section->entry_count == 0) {
        const char* hint = "No options";
        if(app->section_index == MENU_SECTION_SCANNER) {
            hint = "OK: Scan networks";
        } else if(app->section_index == MENU_SECTION_TARGETS) {
            hint = "OK: Show results";
        }
        canvas_draw_str(canvas, 3, 30, hint);
        return;
    }

    if(app->item_index >= section->entry_count) {
        app->item_index = section->entry_count - 1;
    }

    if(app->item_index < app->item_offset) {
        app->item_offset = app->item_index;
    } else if(app->item_index >= app->item_offset + MENU_VISIBLE_COUNT) {
        app->item_offset = app->item_index - MENU_VISIBLE_COUNT + 1;
    }

    for(uint32_t i = 0; i < MENU_VISIBLE_COUNT; i++) {
        uint32_t idx = app->item_offset + i;
        if(idx >= section->entry_count) break;
        uint8_t y = 28 + i * 12;

        if(idx == app->item_index) {
            canvas_draw_str(canvas, 2, y, ">");
            canvas_draw_str(canvas, 12, y, section->entries[idx].label);
        } else {
            canvas_draw_str(canvas, 8, y, section->entries[idx].label);
        }
    }
}

static size_t simple_app_render_display_lines(SimpleApp* app, size_t skip_lines, char dest[][64], size_t max_lines) {
    memset(dest, 0, max_lines * 64);
    if(!app->serial_mutex) return 0;

    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    const char* buffer = app->serial_buffer;
    size_t length = app->serial_len;
    size_t line_index = 0;
    size_t col = 0;
    size_t lines_filled = 0;

    for(size_t idx = 0; idx < length; idx++) {
        char ch = buffer[idx];
        if(ch == '\r') continue;

        if(ch == '\n') {
            if(line_index >= skip_lines && lines_filled < max_lines) {
                dest[lines_filled][col] = '\0';
                lines_filled++;
            }
            line_index++;
            col = 0;
            if(line_index >= skip_lines + max_lines) break;
            continue;
        }

        if(col >= SERIAL_LINE_CHAR_LIMIT) {
            if(line_index >= skip_lines && lines_filled < max_lines) {
                dest[lines_filled][col] = '\0';
                lines_filled++;
            }
            line_index++;
            col = 0;
            if(line_index >= skip_lines + max_lines) {
                continue;
            }
        }

        if(line_index >= skip_lines && lines_filled < max_lines) {
            dest[lines_filled][col] = ch;
        }
        col++;
    }

    if(col > 0) {
        if(line_index >= skip_lines && lines_filled < max_lines) {
            dest[lines_filled][col] = '\0';
            lines_filled++;
        }
    }

    furi_mutex_release(app->serial_mutex);
    return lines_filled;
}

static void simple_app_draw_serial(SimpleApp* app, Canvas* canvas) {
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    char display_lines[SERIAL_VISIBLE_LINES][64];
    size_t lines_filled =
        simple_app_render_display_lines(app, app->serial_scroll, display_lines, SERIAL_VISIBLE_LINES);

    uint8_t y = 8;
    if(lines_filled == 0) {
        canvas_draw_str(canvas, 2, y, "No UART data");
    } else {
        for(size_t i = 0; i < lines_filled; i++) {
            canvas_draw_str(canvas, 2, y, display_lines[i][0] ? display_lines[i] : " ");
            y += SERIAL_TEXT_LINE_HEIGHT;
        }
    }

    size_t total_lines = simple_app_total_display_lines(app);
    if(total_lines > SERIAL_VISIBLE_LINES) {
        const uint8_t track_width = 3;
        const uint8_t track_x = DISPLAY_WIDTH - track_width;
        const uint8_t track_y = 4;
        const uint8_t track_height = 56;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);
        canvas_draw_box(canvas, track_x + 1, track_y + 1, 1, 1);
        canvas_draw_box(canvas, track_x + 1, track_y + track_height - 2, 1, 1);

        size_t max_scroll = simple_app_max_scroll(app);
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)SERIAL_VISIBLE_LINES * track_height) / total_lines);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;

        uint8_t thumb_track_top = track_y;
        uint8_t thumb_track_height = track_height;
        uint8_t thumb_width = (track_width > 2) ? (track_width - 2) : 1;
        uint8_t thumb_x = (track_width > 2) ? (track_x + 1) : track_x;

        if(track_width > 2 && track_height > 2) {
            thumb_track_top = track_y + 1;
            thumb_track_height = track_height - 2;
        }

        if(thumb_height > thumb_track_height) {
            thumb_height = thumb_track_height;
        }

        uint8_t max_thumb_offset =
            (thumb_track_height > thumb_height) ? (thumb_track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_scroll > 0 && max_thumb_offset > 0) {
            thumb_offset = (uint8_t)(((uint32_t)app->serial_scroll * max_thumb_offset) / max_scroll);
        }

        uint8_t thumb_y = thumb_track_top + thumb_offset;
        canvas_draw_box(canvas, thumb_x, thumb_y, thumb_width, thumb_height);
    }
}

static void simple_app_draw_results(SimpleApp* app, Canvas* canvas) {
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, app->result_font);

    if(app->scan_results_loading && app->visible_result_count == 0) {
        canvas_draw_str(canvas, 2, 20, "Loading...");
        canvas_draw_str(canvas, 2, 62, "[Results] Selected: 0");
        return;
    }

    if(app->visible_result_count == 0) {
        canvas_draw_str(canvas, 2, 20, "No results");
        canvas_draw_str(canvas, 2, 62, "[Results] Selected: 0");
        return;
    }

    simple_app_adjust_result_offset(app);

    uint8_t y = RESULT_START_Y;
    size_t visible_line_budget = (app->result_max_lines > 0) ? app->result_max_lines : 1;
    size_t lines_left = visible_line_budget;
    size_t char_limit = (app->result_char_limit > 0) ? app->result_char_limit : 1;

    for(size_t idx = app->scan_result_offset; idx < app->visible_result_count && lines_left > 0; idx++) {
        const ScanResult* result = simple_app_visible_result_const(app, idx);
        if(!result) continue;
        char line_full[96];
        size_t line_len = simple_app_format_result_line(app, result, line_full, sizeof(line_full));

        size_t segments_available = simple_app_result_line_count(app, result);
        if(segments_available == 0) segments_available = 1;
        if(segments_available > lines_left) {
            segments_available = lines_left;
        }

        size_t consumed = 0;
        for(size_t segment = 0; segment < segments_available && lines_left > 0; segment++) {
            size_t remaining = (line_len > consumed) ? (line_len - consumed) : 0;
            size_t segment_len = (remaining > char_limit) ? char_limit : remaining;
            char segment_buffer[64];
            memset(segment_buffer, 0, sizeof(segment_buffer));
            if(segment_len > 0) {
                if(segment_len >= sizeof(segment_buffer)) {
                    segment_len = sizeof(segment_buffer) - 1;
                }
                memcpy(segment_buffer, line_full + consumed, segment_len);
                segment_buffer[segment_len] = '\0';
            } else {
                segment_buffer[0] = '\0';
            }
            consumed += segment_len;
            size_t segment_length_actual = strlen(segment_buffer);
            while(segment_length_actual > 0 && segment_buffer[0] == ' ') {
                memmove(segment_buffer, segment_buffer + 1, segment_length_actual);
                segment_length_actual = strlen(segment_buffer);
            }

            if(segment == 0) {
                if(idx == app->scan_result_index) {
                    canvas_draw_str(canvas, RESULT_PREFIX_X, y, ">");
                } else {
                    canvas_draw_str(canvas, RESULT_PREFIX_X, y, " ");
                }
            }
            canvas_draw_str(canvas, RESULT_TEXT_X, y, segment_buffer);
            y += app->result_line_height;
            lines_left--;
            if(lines_left == 0) break;
        }

        if(lines_left > 0) {
            bool more_entries = false;
            for(size_t next = idx + 1; next < app->visible_result_count; next++) {
                const ScanResult* next_result = simple_app_visible_result_const(app, next);
                if(!next_result) continue;
                uint8_t next_lines = simple_app_result_line_count(app, next_result);
                if(next_lines == 0) next_lines = 1;
                if(next_lines <= lines_left) {
                    more_entries = true;
                    break;
                }
            }
            if(more_entries) {
                y += RESULT_ENTRY_SPACING;
            }
        }
    }

    size_t total_lines = simple_app_total_result_lines(app);
    size_t offset_lines = simple_app_result_offset_lines(app);
    if(total_lines > visible_line_budget) {
        const uint8_t track_width = RESULT_SCROLL_WIDTH;
        const uint8_t track_height = (uint8_t)(app->result_line_height * visible_line_budget);
        const uint8_t track_x = DISPLAY_WIDTH - track_width;
        const uint8_t track_y = (RESULT_START_Y > 5) ? (RESULT_START_Y - 5) : 0;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);

        size_t max_scroll = total_lines - visible_line_budget;
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)visible_line_budget * track_height) / total_lines);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;

        uint8_t max_thumb_offset =
            (track_height > thumb_height) ? (uint8_t)(track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_scroll > 0 && max_thumb_offset > 0) {
            if(offset_lines > max_scroll) offset_lines = max_scroll;
            thumb_offset = (uint8_t)(((uint32_t)offset_lines * max_thumb_offset) / max_scroll);
        }

        uint8_t thumb_x = track_x + 1;
        uint8_t thumb_y = track_y + 1 + thumb_offset;
        uint8_t thumb_inner_height = (thumb_height > 2) ? (uint8_t)(thumb_height - 2) : thumb_height;
        uint8_t thumb_width = (track_width > 2) ? (uint8_t)(track_width - 2) : 1;
        if(thumb_inner_height == 0) thumb_inner_height = thumb_height;
        canvas_draw_box(canvas, thumb_x, thumb_y, thumb_width, thumb_inner_height);
    }

    char footer[48];
    snprintf(footer, sizeof(footer), "[Results] Selected: %u", (unsigned)app->scan_selected_count);
    simple_app_truncate_text(footer, SERIAL_LINE_CHAR_LIMIT);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 62, footer);
    if(app->scan_selected_count > 0) {
        canvas_draw_str(canvas, DISPLAY_WIDTH - 10, 62, "->");
    }
}

static void simple_app_draw_setup_scanner(SimpleApp* app, Canvas* canvas) {
    if(!app) return;

    static const char* option_labels[] = {"SSID", "BSSID", "Channel", "Security", "Power", "Band"};

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 12, "Scanner Filters");

    canvas_set_font(canvas, FontSecondary);
    size_t option_count = ScannerOptionCount;
    if(app->scanner_view_offset >= option_count) {
        app->scanner_view_offset = (option_count > 0 && option_count > SCANNER_FILTER_VISIBLE_COUNT)
                                       ? option_count - SCANNER_FILTER_VISIBLE_COUNT
                                       : 0;
    }

    uint8_t y = 26;
    for(size_t i = 0; i < SCANNER_FILTER_VISIBLE_COUNT; i++) {
        size_t option_index = app->scanner_view_offset + i;
        if(option_index >= option_count) break;

        char line[48];
        memset(line, 0, sizeof(line));

        if(option_index == ScannerOptionMinPower) {
            const char* fmt =
                (app->scanner_adjusting_power && app->scanner_setup_index == ScannerOptionMinPower)
                    ? "Min power*: %d dBm"
                    : "Min power: %d dBm";
            snprintf(line, sizeof(line), fmt, (int)app->scanner_min_power);
        } else {
            bool enabled = false;
            switch(option_index) {
            case ScannerOptionShowSSID:
                enabled = app->scanner_show_ssid;
                break;
            case ScannerOptionShowBSSID:
                enabled = app->scanner_show_bssid;
                break;
            case ScannerOptionShowChannel:
                enabled = app->scanner_show_channel;
                break;
            case ScannerOptionShowSecurity:
                enabled = app->scanner_show_security;
                break;
            case ScannerOptionShowPower:
                enabled = app->scanner_show_power;
                break;
            case ScannerOptionShowBand:
                enabled = app->scanner_show_band;
                break;
            default:
                break;
            }
            snprintf(line, sizeof(line), "[%c] %s", enabled ? 'x' : ' ', option_labels[option_index]);
        }

        simple_app_truncate_text(line, 20);

        if(app->scanner_setup_index == option_index) {
            canvas_draw_str(canvas, 2, y, ">");
        }
        canvas_draw_str(canvas, 12, y, line);
        y += 10;
    }

    if(option_count > SCANNER_FILTER_VISIBLE_COUNT) {
        const uint8_t track_width = 3;
        const uint8_t track_height = (uint8_t)(SCANNER_FILTER_VISIBLE_COUNT * 10);
        const uint8_t track_x = DISPLAY_WIDTH - track_width;
        const uint8_t track_y = 24;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);

        size_t max_offset = option_count - SCANNER_FILTER_VISIBLE_COUNT;
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)SCANNER_FILTER_VISIBLE_COUNT * track_height) / option_count);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;

        uint8_t max_thumb_offset =
            (track_height > thumb_height) ? (uint8_t)(track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_offset > 0 && max_thumb_offset > 0) {
            if(app->scanner_view_offset > max_offset) {
                app->scanner_view_offset = max_offset;
            }
            thumb_offset =
                (uint8_t)(((uint32_t)app->scanner_view_offset * max_thumb_offset) / max_offset);
        }
        uint8_t thumb_x = track_x + 1;
        uint8_t thumb_y = track_y + 1 + thumb_offset;
        uint8_t thumb_inner_height = (thumb_height > 2) ? (uint8_t)(thumb_height - 2) : thumb_height;
        if(thumb_inner_height == 0) thumb_inner_height = thumb_height;
        uint8_t thumb_width = (track_width > 2) ? (uint8_t)(track_width - 2) : 1;
        canvas_draw_box(canvas, thumb_x, thumb_y, thumb_width, thumb_inner_height);
    }

    const char* footer = "OK toggle, Back exit";
    if(app->scanner_setup_index == ScannerOptionMinPower) {
        footer = app->scanner_adjusting_power ? "Up/Down adjust, OK" : "OK edit, Back exit";
    }
    canvas_draw_str(canvas, 2, 62, footer);
}

static void simple_app_draw(Canvas* canvas, void* context) {
    SimpleApp* app = context;
    canvas_clear(canvas);
    bool status_active = simple_app_status_message_is_active(app);
    if(status_active && app->status_message_fullscreen) {
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(
            canvas, DISPLAY_WIDTH / 2, 32, AlignCenter, AlignCenter, app->status_message);
        return;
    }
    switch(app->screen) {
    case ScreenMenu:
        simple_app_draw_menu(app, canvas);
        break;
    case ScreenSerial:
        simple_app_draw_serial(app, canvas);
        break;
    case ScreenResults:
        simple_app_draw_results(app, canvas);
        break;
    case ScreenSetupScanner:
        simple_app_draw_setup_scanner(app, canvas);
        break;
    default:
        simple_app_draw_results(app, canvas);
        break;
    }
}

static void simple_app_handle_menu_input(SimpleApp* app, InputKey key) {
    if(key == InputKeyUp) {
        if(app->menu_state == MenuStateSections) {
            if(app->section_index > 0) {
                app->section_index--;
                view_port_update(app->viewport);
            }
        } else {
            const MenuSection* section = &menu_sections[app->section_index];
            if(section->entry_count == 0) return;
            if(app->item_index > 0) {
                app->item_index--;
                if(app->item_index < app->item_offset) {
                    app->item_offset = app->item_index;
                }
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->menu_state == MenuStateSections) {
            if(app->section_index + 1 < menu_section_count) {
                app->section_index++;
                view_port_update(app->viewport);
            }
        } else {
            const MenuSection* section = &menu_sections[app->section_index];
            if(section->entry_count == 0) return;
            if(app->item_index + 1 < section->entry_count) {
                app->item_index++;
                if(app->item_index >= app->item_offset + MENU_VISIBLE_COUNT) {
                    app->item_offset = app->item_index - MENU_VISIBLE_COUNT + 1;
                }
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyOk) {
        if(app->menu_state == MenuStateSections) {
            if(app->section_index == MENU_SECTION_SCANNER) {
                simple_app_send_command(app, SCANNER_SCAN_COMMAND, true);
                view_port_update(app->viewport);
                return;
            } else if(app->section_index == MENU_SECTION_TARGETS) {
                simple_app_request_scan_results(app, TARGETS_RESULTS_COMMAND);
                return;
            }
            app->menu_state = MenuStateItems;
            app->item_index = 0;
            app->item_offset = 0;
            view_port_update(app->viewport);
            return;
        }

        const MenuSection* section = &menu_sections[app->section_index];
        if(section->entry_count == 0) return;
        if(app->item_index >= section->entry_count) {
            app->item_index = section->entry_count - 1;
        }

        const MenuEntry* entry = &section->entries[app->item_index];
        if(entry->action == MenuActionResults) {
            simple_app_request_scan_results(app, entry->command);
        } else if(entry->action == MenuActionCommandWithTargets) {
            simple_app_send_command_with_targets(app, entry->command);
        } else if(entry->action == MenuActionCommand) {
            if(entry->command && entry->command[0] != '\0') {
                simple_app_send_command(app, entry->command, true);
            }
        } else if(entry->action == MenuActionToggleBacklight) {
            simple_app_toggle_backlight(app);
        } else if(entry->action == MenuActionOpenScannerSetup) {
            app->screen = ScreenSetupScanner;
            app->scanner_setup_index = 0;
            app->scanner_adjusting_power = false;
            app->scanner_view_offset = 0;
        }

        view_port_update(app->viewport);
    } else if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        if(app->menu_state == MenuStateItems) {
            app->menu_state = MenuStateSections;
            view_port_update(app->viewport);
        } else {
            simple_app_save_config_if_dirty(app, NULL, false);
            app->exit_app = true;
        }
    }
}

static void simple_app_handle_setup_scanner_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack) {
        if(app->scanner_adjusting_power) {
            app->scanner_adjusting_power = false;
            view_port_update(app->viewport);
        } else {
            simple_app_save_config_if_dirty(app, "Config saved", true);
            app->screen = ScreenMenu;
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->scanner_adjusting_power && app->scanner_setup_index == ScannerOptionMinPower) {
        if(key == InputKeyUp || key == InputKeyRight) {
            simple_app_modify_min_power(app, SCAN_POWER_STEP);
            view_port_update(app->viewport);
            return;
        } else if(key == InputKeyDown || key == InputKeyLeft) {
            simple_app_modify_min_power(app, -SCAN_POWER_STEP);
            view_port_update(app->viewport);
            return;
        }
    }

    if(key == InputKeyUp) {
        if(app->scanner_setup_index > 0) {
            app->scanner_setup_index--;
            if(app->scanner_setup_index != ScannerOptionMinPower) {
                app->scanner_adjusting_power = false;
            }
            if(app->scanner_setup_index < app->scanner_view_offset) {
                app->scanner_view_offset = app->scanner_setup_index;
            }
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        if(app->scanner_setup_index + 1 < ScannerOptionCount) {
            app->scanner_setup_index++;
            if(app->scanner_setup_index != ScannerOptionMinPower) {
                app->scanner_adjusting_power = false;
            }
            if(app->scanner_setup_index >=
               app->scanner_view_offset + SCANNER_FILTER_VISIBLE_COUNT) {
                app->scanner_view_offset =
                    app->scanner_setup_index - SCANNER_FILTER_VISIBLE_COUNT + 1;
            }
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyOk) {
        if(app->scanner_setup_index == ScannerOptionMinPower) {
            app->scanner_adjusting_power = !app->scanner_adjusting_power;
            view_port_update(app->viewport);
        } else {
            bool* flag =
                simple_app_scanner_option_flag(app, (ScannerOption)app->scanner_setup_index);
            if(flag) {
                if(*flag && simple_app_enabled_field_count(app) <= 1) {
                    view_port_update(app->viewport);
                } else {
                    *flag = !(*flag);
                    simple_app_mark_config_dirty(app);
                    simple_app_update_result_layout(app);
                    simple_app_rebuild_visible_results(app);
                    simple_app_adjust_result_offset(app);
                    view_port_update(app->viewport);
                }
            }
        }
    }
}

static void simple_app_handle_serial_input(SimpleApp* app, InputKey key) {
    if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        app->screen = ScreenMenu;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
        view_port_update(app->viewport);
    } else if(key == InputKeyUp) {
        if(app->serial_scroll > 0) {
            app->serial_scroll--;
            app->serial_follow_tail = false;
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        size_t max_scroll = simple_app_max_scroll(app);
        if(app->serial_scroll < max_scroll) {
            app->serial_scroll++;
            app->serial_follow_tail = (app->serial_scroll == max_scroll);
            view_port_update(app->viewport);
        } else {
            app->serial_follow_tail = true;
            simple_app_update_scroll(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyLeft) {
        size_t step = SERIAL_VISIBLE_LINES;
        if(app->serial_scroll > 0) {
            if(app->serial_scroll > step) {
                app->serial_scroll -= step;
            } else {
                app->serial_scroll = 0;
            }
            app->serial_follow_tail = false;
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyRight) {
        size_t step = SERIAL_VISIBLE_LINES;
        size_t max_scroll = simple_app_max_scroll(app);
        if(app->serial_scroll < max_scroll) {
            app->serial_scroll =
                (app->serial_scroll + step < max_scroll) ? app->serial_scroll + step : max_scroll;
            app->serial_follow_tail = (app->serial_scroll == max_scroll);
            view_port_update(app->viewport);
        } else {
            app->serial_follow_tail = true;
            simple_app_update_scroll(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyOk) {
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
        view_port_update(app->viewport);
    }
}

static void simple_app_handle_results_input(SimpleApp* app, InputKey key) {
    if(key == InputKeyBack || key == InputKeyLeft) {
        simple_app_send_stop_if_needed(app);
        app->screen = ScreenMenu;
        view_port_update(app->viewport);
        return;
    }

    if(app->visible_result_count == 0) return;

    if(key == InputKeyUp) {
        if(app->scan_result_index > 0) {
            app->scan_result_index--;
            simple_app_adjust_result_offset(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        if(app->scan_result_index + 1 < app->visible_result_count) {
            app->scan_result_index++;
            simple_app_adjust_result_offset(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyOk) {
        if(app->scan_result_index < app->visible_result_count) {
            ScanResult* result = simple_app_visible_result(app, app->scan_result_index);
            if(result) {
                simple_app_toggle_scan_selection(app, result);
                simple_app_adjust_result_offset(app);
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyRight) {
        if(app->scan_selected_count > 0) {
            app->screen = ScreenMenu;
            app->menu_state = MenuStateItems;
            app->section_index = MENU_SECTION_ATTACKS;
            app->item_index = 0;
            app->item_offset = 0;
            view_port_update(app->viewport);
        }
    }
}

static bool simple_app_is_direction_key(InputKey key) {
    return (key == InputKeyUp || key == InputKeyDown || key == InputKeyLeft || key == InputKeyRight);
}

static void simple_app_input(InputEvent* event, void* context) {
    SimpleApp* app = context;
    if(!app || !event) return;

    if(simple_app_status_message_is_active(app) && app->status_message_fullscreen) {
        if(event->type == InputTypeShort &&
           (event->key == InputKeyOk || event->key == InputKeyBack)) {
            simple_app_clear_status_message(app);
        }
        return;
    }

    bool allow_event = false;
    if(event->type == InputTypeShort) {
        allow_event = true;
    } else if((event->type == InputTypeRepeat || event->type == InputTypeLong) &&
              simple_app_is_direction_key(event->key)) {
        allow_event = true;
    }

    if(!allow_event) return;

    switch(app->screen) {
    case ScreenMenu:
        simple_app_handle_menu_input(app, event->key);
        break;
    case ScreenSerial:
        simple_app_handle_serial_input(app, event->key);
        break;
    case ScreenResults:
        simple_app_handle_results_input(app, event->key);
        break;
    case ScreenSetupScanner:
        simple_app_handle_setup_scanner_input(app, event->key);
        break;
    default:
        simple_app_handle_results_input(app, event->key);
        break;
    }
}

static void simple_app_process_stream(SimpleApp* app) {
    if(!app || !app->rx_stream) return;

    uint8_t chunk[64];
    bool updated = false;

    while(true) {
        size_t received = furi_stream_buffer_receive(app->rx_stream, chunk, sizeof(chunk), 0);
        if(received == 0) break;
        simple_app_append_serial_data(app, chunk, received);
        updated = true;
    }

    if(updated && app->screen == ScreenSerial) {
        view_port_update(app->viewport);
    }
}

static void simple_app_serial_irq(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context) {
    SimpleApp* app = context;
    if(!app || !app->rx_stream || !(event & FuriHalSerialRxEventData)) return;

    do {
        uint8_t byte = furi_hal_serial_async_rx(handle);
        furi_stream_buffer_send(app->rx_stream, &byte, 1, 0);
    } while(furi_hal_serial_async_rx_available(handle));
}

int32_t Lab_C5_app(void* p) {
    UNUSED(p);

    SimpleApp* app = malloc(sizeof(SimpleApp));
    if(!app) {
        return 0;
    }
    memset(app, 0, sizeof(SimpleApp));
    app->scanner_show_ssid = true;
    app->scanner_show_bssid = true;
    app->scanner_show_channel = true;
    app->scanner_show_security = true;
    app->scanner_show_power = true;
    app->scanner_show_band = true;
    app->scanner_min_power = SCAN_POWER_MIN_DBM;
    app->scanner_setup_index = 0;
    app->scanner_adjusting_power = false;
    app->backlight_enabled = true;
    app->scanner_view_offset = 0;
    simple_app_update_result_layout(app);
    simple_app_update_backlight_label(app);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    simple_app_load_config(app);
    simple_app_update_backlight_label(app);
    simple_app_apply_backlight(app);
    app->menu_state = MenuStateSections;
    app->screen = ScreenMenu;
    app->serial_follow_tail = true;
    simple_app_reset_scan_results(app);

    app->serial = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!app->serial) {
        free(app);
        return 0;
    }

    furi_hal_serial_init(app->serial, 115200);

    app->serial_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    if(!app->serial_mutex) {
        furi_hal_serial_deinit(app->serial);
        furi_hal_serial_control_release(app->serial);
        free(app);
        return 0;
    }

    app->rx_stream = furi_stream_buffer_alloc(UART_STREAM_SIZE, 1);
    if(!app->rx_stream) {
        furi_mutex_free(app->serial_mutex);
        furi_hal_serial_deinit(app->serial);
        furi_hal_serial_control_release(app->serial);
        free(app);
        return 0;
    }

    furi_stream_buffer_reset(app->rx_stream);
    simple_app_reset_serial_log(app, "READY");

    furi_hal_serial_async_rx_start(app->serial, simple_app_serial_irq, app, false);

    app->gui = furi_record_open(RECORD_GUI);
    app->viewport = view_port_alloc();
    view_port_draw_callback_set(app->viewport, simple_app_draw, app);
    view_port_input_callback_set(app->viewport, simple_app_input, app);
    gui_add_view_port(app->gui, app->viewport, GuiLayerFullscreen);

    while(!app->exit_app) {
        simple_app_process_stream(app);
        furi_delay_ms(20);
    }

    simple_app_save_config_if_dirty(app, NULL, false);

    gui_remove_view_port(app->gui, app->viewport);
    view_port_free(app->viewport);
    furi_record_close(RECORD_GUI);

    furi_hal_serial_async_rx_stop(app->serial);
    furi_stream_buffer_free(app->rx_stream);
    furi_hal_serial_deinit(app->serial);
    furi_hal_serial_control_release(app->serial);
    furi_mutex_free(app->serial_mutex);
    if(app->notifications) {
        if(app->backlight_notification_enforced) {
            notification_message(app->notifications, &sequence_display_backlight_enforce_auto);
            app->backlight_notification_enforced = false;
        }
        furi_record_close(RECORD_NOTIFICATION);
        app->notifications = NULL;
    }
    if(app->backlight_insomnia) {
        furi_hal_power_insomnia_exit();
        app->backlight_insomnia = false;
    }
    furi_hal_light_set(LightBacklight, BACKLIGHT_ON_LEVEL);
    free(app);

    return 0;
}
