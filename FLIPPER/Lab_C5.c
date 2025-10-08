#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <furi_hal_serial.h>
#include <furi_hal_serial_control.h>
#include <furi/core/stream_buffer.h>

typedef enum {
    ScreenMenu,
    ScreenSerial,
    ScreenResults,
} AppScreen;

typedef enum {
    MenuStateSections,
    MenuStateItems,
} MenuState;
#define MAX_SCAN_RESULTS 64
#define SCAN_LINE_BUFFER_SIZE 192
#define SCAN_SSID_MAX_LEN 33
#define SCAN_CHANNEL_MAX_LEN 8
#define SCAN_TYPE_MAX_LEN 16
#define SCAN_FIELD_BUFFER_LEN 64

#define SERIAL_BUFFER_SIZE 4096
#define UART_STREAM_SIZE 1024
#define MENU_VISIBLE_COUNT 6
#define SERIAL_VISIBLE_LINES 6
#define SERIAL_LINE_CHAR_LIMIT 22
#define SERIAL_TEXT_LINE_HEIGHT 10
#define DISPLAY_WIDTH 128
#define RESULT_MAX_LINES 4
#define RESULT_LINE_HEIGHT 12
#define RESULT_LINE_CHAR_LIMIT (SERIAL_LINE_CHAR_LIMIT - 3)
#define RESULT_START_Y 12
#define RESULT_ENTRY_SPACING 0
#define MENU_SECTION_ATTACKS 3

typedef enum {
    MenuActionCommand,
    MenuActionResults,
} MenuAction;

typedef struct {
    uint16_t number;
    char ssid[SCAN_SSID_MAX_LEN];
    char channel[SCAN_CHANNEL_MAX_LEN];
    char type[SCAN_TYPE_MAX_LEN];
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
} SimpleApp;
static void simple_app_adjust_result_offset(SimpleApp* app);

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

static const MenuEntry menu_entries_scanners[] = {
    {"Scan", "scan_networks", MenuActionCommand},
    {"Resoults", "show_scan_results", MenuActionResults},
};

static const MenuEntry menu_entries_sniffers[] = {
    {"start_sniffer", "start_sniffer", MenuActionCommand},
    {"show_sniffer_results", "show_sniffer_results", MenuActionCommand},
    {"show_probes", "show_probes", MenuActionCommand},
    {"sniffer_debug", "sniffer_debug 1", MenuActionCommand},
};

static const MenuEntry menu_entries_targets[] = {
    {"select_networks", "select_networks 0 1", MenuActionCommand},
};

static const MenuEntry menu_entries_attacks[] = {
    {"start_deauth", "start_deauth", MenuActionCommand},
    {"start_evil_twin", "start_evil_twin", MenuActionCommand},
    {"sae_overflow", "sae_overflow", MenuActionCommand},
    {"start_wardrive", "start_wardrive", MenuActionCommand},
};

static const MenuEntry menu_entries_setup[] = {
    {"LED on/off (todo)", NULL, MenuActionCommand},
    {"5V on/off (todo)", NULL, MenuActionCommand},
    {"Backlight on/off (todo)", NULL, MenuActionCommand},
};

static const MenuSection menu_sections[] = {
    {"Scanner", menu_entries_scanners, sizeof(menu_entries_scanners) / sizeof(menu_entries_scanners[0]), 12},
    {"Sniffers", menu_entries_sniffers, sizeof(menu_entries_sniffers) / sizeof(menu_entries_sniffers[0]), 24},
    {"Targets", menu_entries_targets, sizeof(menu_entries_targets) / sizeof(menu_entries_targets[0]), 36},
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
    app->scan_result_count = 0;
    app->scan_result_index = 0;
    app->scan_result_offset = 0;
    app->scan_selected_count = 0;
    app->scan_line_len = 0;
    app->scan_results_loading = false;
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
    simple_app_copy_field(result->channel, sizeof(result->channel), fields[3], "?");
    simple_app_copy_field(result->type, sizeof(result->type), fields[6], "?");
    result->selected = false;

    app->scan_result_count++;
    if(app->scan_result_index >= app->scan_result_count && app->scan_result_count > 0) {
        app->scan_result_index = app->scan_result_count - 1;
    }

    if(app->screen == ScreenResults) {
        simple_app_adjust_result_offset(app);
        view_port_update(app->viewport);
    }
}

static size_t simple_app_format_result_line(const ScanResult* result, char* buffer, size_t buffer_size) {
    if(!result || !buffer || buffer_size == 0) {
        return 0;
    }

    int written = snprintf(
        buffer,
        buffer_size,
        "%u/%s/%s/%s",
        result->number,
        result->ssid[0] ? result->ssid : "<hidden>",
        result->channel[0] ? result->channel : "?",
        result->type[0] ? result->type : "?");

    if(written < 0) {
        buffer[0] = '\0';
        return 0;
    }

    size_t length = (size_t)written;
    if(length >= buffer_size) {
        buffer[buffer_size - 1] = '\0';
        length = buffer_size - 1;
    }
    return length;
}

static uint8_t simple_app_result_line_count(const ScanResult* result) {
    if(!result) return 1;
    char buffer[96];
    size_t len = simple_app_format_result_line(result, buffer, sizeof(buffer));
    size_t lines = (len + RESULT_LINE_CHAR_LIMIT - 1) / RESULT_LINE_CHAR_LIMIT;
    if(lines == 0) lines = 1;
    if(lines > 2) lines = 2;
    return (uint8_t)lines;
}

static size_t simple_app_total_result_lines(SimpleApp* app) {
    if(!app) return 0;
    size_t total = 0;
    for(size_t i = 0; i < app->scan_result_count; i++) {
        total += simple_app_result_line_count(&app->scan_results[i]);
    }
    return total;
}

static size_t simple_app_result_offset_lines(SimpleApp* app) {
    if(!app) return 0;
    size_t lines = 0;
    for(size_t i = 0; i < app->scan_result_offset && i < app->scan_result_count; i++) {
        lines += simple_app_result_line_count(&app->scan_results[i]);
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

    if(app->scan_result_count == 0) {
        app->scan_result_offset = 0;
        app->scan_result_index = 0;
        return;
    }

    if(app->scan_result_index >= app->scan_result_count) {
        app->scan_result_index = app->scan_result_count - 1;
    }

    if(app->scan_result_offset > app->scan_result_index) {
        app->scan_result_offset = app->scan_result_index;
    }

    while(app->scan_result_offset < app->scan_result_count) {
        size_t lines_used = 0;
        bool index_visible = false;
        for(size_t i = app->scan_result_offset; i < app->scan_result_count; i++) {
            uint8_t entry_lines = simple_app_result_line_count(&app->scan_results[i]);
            if(entry_lines == 0) entry_lines = 1;
            if(lines_used + entry_lines > RESULT_MAX_LINES) break;
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

    if(app->scan_result_offset >= app->scan_result_count) {
        app->scan_result_offset = (app->scan_result_count > 0) ? app->scan_result_count - 1 : 0;
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
    canvas_draw_str(canvas, 111, 62, "v.01");

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
        canvas_draw_str(canvas, 3, 30, "Coming soon");
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
        canvas_draw_str(canvas, 2, y, "Brak danych z UART");
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
    canvas_set_font(canvas, FontSecondary);

    if(app->scan_results_loading && app->scan_result_count == 0) {
        canvas_draw_str(canvas, 2, 20, "Loading...");
        canvas_draw_str(canvas, 2, 62, "[Resoults] Selected: 0");
        return;
    }

    if(app->scan_result_count == 0) {
        canvas_draw_str(canvas, 2, 20, "No results");
        canvas_draw_str(canvas, 2, 62, "[Resoults] Selected: 0");
        return;
    }

    simple_app_adjust_result_offset(app);

    uint8_t y = RESULT_START_Y;
    size_t lines_left = RESULT_MAX_LINES;

    for(size_t idx = app->scan_result_offset; idx < app->scan_result_count && lines_left > 0; idx++) {
        const ScanResult* result = &app->scan_results[idx];
        char line_full[96];
        size_t line_len = simple_app_format_result_line(result, line_full, sizeof(line_full));

        size_t lines_needed = (line_len + RESULT_LINE_CHAR_LIMIT - 1) / RESULT_LINE_CHAR_LIMIT;
        if(lines_needed == 0) lines_needed = 1;
        if(lines_needed > 2) lines_needed = 2;
        if(lines_needed > lines_left) break;

        size_t first_len =
            (line_len > RESULT_LINE_CHAR_LIMIT) ? RESULT_LINE_CHAR_LIMIT : line_len;
        char line_first[RESULT_LINE_CHAR_LIMIT + 1];
        memset(line_first, 0, sizeof(line_first));
        if(first_len > 0) {
            memcpy(line_first, line_full, first_len);
        }

        size_t remaining = (line_len > first_len) ? (line_len - first_len) : 0;
        char line_second[RESULT_LINE_CHAR_LIMIT + 1];
        memset(line_second, 0, sizeof(line_second));
        if(remaining > 0) {
            size_t second_len =
                (remaining > RESULT_LINE_CHAR_LIMIT) ? RESULT_LINE_CHAR_LIMIT : remaining;
            memcpy(line_second, line_full + first_len, second_len);
            line_second[second_len] = '\0';
        }

        char first_prefix[3] = {' ', ' ', '\0'};
        if(result->selected) {
            first_prefix[0] = '*';
        }
        if(idx == app->scan_result_index) {
            first_prefix[0] = '>';
            first_prefix[1] = result->selected ? '*' : ' ';
        }

        canvas_draw_str(canvas, 2, y, first_prefix);
        canvas_draw_str(canvas, 12, y, line_first);
        y += RESULT_LINE_HEIGHT;
        lines_left--;

        if(lines_needed > 1 && lines_left > 0) {
            canvas_draw_str(canvas, 12, y, line_second);
            y += RESULT_LINE_HEIGHT;
            lines_left--;
        }

        if(lines_left > 0) {
            bool more_entries = false;
            for(size_t next = idx + 1; next < app->scan_result_count; next++) {
                uint8_t next_lines = simple_app_result_line_count(&app->scan_results[next]);
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
    if(total_lines > RESULT_MAX_LINES) {
        const uint8_t track_width = 3;
        const uint8_t track_height = RESULT_LINE_HEIGHT * RESULT_MAX_LINES;
        const uint8_t track_x = DISPLAY_WIDTH - track_width;
        const uint8_t track_y = RESULT_START_Y - 2;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);

        size_t max_scroll = total_lines - RESULT_MAX_LINES;
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)RESULT_MAX_LINES * track_height) / total_lines);
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
    snprintf(footer, sizeof(footer), "[Resoults] Selected: %u", (unsigned)app->scan_selected_count);
    simple_app_truncate_text(footer, SERIAL_LINE_CHAR_LIMIT);
    canvas_draw_str(canvas, 2, 62, footer);
    if(app->scan_selected_count > 0) {
        canvas_draw_str(canvas, DISPLAY_WIDTH - 10, 62, "->");
    }
}

static void simple_app_draw(Canvas* canvas, void* context) {
    SimpleApp* app = context;
    canvas_clear(canvas);
    if(app->screen == ScreenMenu) {
        simple_app_draw_menu(app, canvas);
    } else if(app->screen == ScreenSerial) {
        simple_app_draw_serial(app, canvas);
    } else {
        simple_app_draw_results(app, canvas);
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
        } else if(entry->action == MenuActionCommand) {
            if(entry->command && entry->command[0] != '\0') {
                simple_app_send_command(app, entry->command, true);
            }
        }

        view_port_update(app->viewport);
    } else if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        if(app->menu_state == MenuStateItems) {
            app->menu_state = MenuStateSections;
            view_port_update(app->viewport);
        } else {
            app->exit_app = true;
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

    if(app->scan_result_count == 0) return;

    if(key == InputKeyUp) {
        if(app->scan_result_index > 0) {
            app->scan_result_index--;
            simple_app_adjust_result_offset(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        if(app->scan_result_index + 1 < app->scan_result_count) {
            app->scan_result_index++;
            simple_app_adjust_result_offset(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyOk) {
        if(app->scan_result_index < app->scan_result_count) {
            ScanResult* result = &app->scan_results[app->scan_result_index];
            simple_app_toggle_scan_selection(app, result);
            simple_app_adjust_result_offset(app);
            view_port_update(app->viewport);
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

    bool allow_event = false;
    if(event->type == InputTypeShort) {
        allow_event = true;
    } else if((event->type == InputTypeRepeat || event->type == InputTypeLong) &&
              simple_app_is_direction_key(event->key)) {
        allow_event = true;
    }

    if(!allow_event) return;

    if(app->screen == ScreenMenu) {
        simple_app_handle_menu_input(app, event->key);
    } else if(app->screen == ScreenSerial) {
        simple_app_handle_serial_input(app, event->key);
    } else {
        simple_app_handle_results_input(app, event->key);
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

    gui_remove_view_port(app->gui, app->viewport);
    view_port_free(app->viewport);
    furi_record_close(RECORD_GUI);

    furi_hal_serial_async_rx_stop(app->serial);
    furi_stream_buffer_free(app->rx_stream);
    furi_hal_serial_deinit(app->serial);
    furi_hal_serial_control_release(app->serial);
    furi_mutex_free(app->serial_mutex);
    free(app);

    return 0;
}
