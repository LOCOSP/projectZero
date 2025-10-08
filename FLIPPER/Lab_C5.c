#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <string.h>
#include <stdio.h>
#include <furi_hal.h>
#include <furi_hal_serial.h>

typedef enum {
    ScreenMainMenu,
    ScreenSerialOutput,
} AppScreen;

#define SERIAL_BUFFER_SIZE 512

typedef struct {
    bool exit_app;
    uint8_t menu_index;
    AppScreen screen;
    FuriHalSerialHandle* serial;
    ViewPort* viewport;
    char serial_buffer[SERIAL_BUFFER_SIZE];
    size_t serial_len;
} SimpleApp;

static const char* menu_items[] = {
    "scan_networks",
    "show_scan_results",
    "select_networks",
    "start_evil_twin",
    "start_deauth",
    "sae_overflow",
    "start_wardrive",
    "start_sniffer",
    "show_sniffer_results",
    "show_probes",
    "sniffer_debug",
    "stop",
    "reboot"
};
static const uint8_t menu_count = sizeof(menu_items) / sizeof(menu_items[0]);
#define MENU_VISIBLE_COUNT 5

static void serial_rx_callback(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context);

// Rysowanie ekranu
static void Lab_C5_app_draw_callback(Canvas* canvas, void* ctx) {
    SimpleApp* app = ctx;
    canvas_clear(canvas);

    if(app->screen == ScreenMainMenu) {
        const uint8_t start_y = 12;
        const uint8_t step_y = 12;
        const uint8_t highlight_height = 12;
        const uint8_t highlight_width = 120;
        uint8_t first_visible = 0;
        if(app->menu_index >= MENU_VISIBLE_COUNT)
            first_visible = app->menu_index - MENU_VISIBLE_COUNT + 1;

        for(uint8_t i = 0; i < MENU_VISIBLE_COUNT; i++) {
            uint8_t menu_i = first_visible + i;
            if(menu_i >= menu_count) break;
            uint8_t y = start_y + i * step_y;
            if(app->menu_index == menu_i) {
                // Highlighted: white box, black text, arrow
                canvas_set_color(canvas, ColorWhite);
                canvas_draw_box(canvas, 0, y - 10, highlight_width, highlight_height);
                canvas_set_color(canvas, ColorBlack);
                canvas_set_font(canvas, FontPrimary);
                canvas_draw_str(canvas, 4, y, ">");
                canvas_draw_str(canvas, 16, y, menu_items[menu_i]);
            } else {
                // Normal: black text, no box
                canvas_set_color(canvas, ColorBlack);
                canvas_set_font(canvas, FontPrimary);
                canvas_draw_str(canvas, 16, y, menu_items[menu_i]);
            }
        }
    } else if(app->screen == ScreenSerialOutput) {
        // Wyświetl odpowiedź z UART
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontSecondary);
        uint8_t y = 12;
        // Zamiast strtok
        const char* ptr = app->serial_buffer;
        while(*ptr && y < 64) {
            // Znajdź koniec linii
            const char* end = ptr;
            while(*end && *end != '\n') end++;
            // Skopiuj linię do tymczasowego bufora
            char line[64] = {0};
            size_t len = end - ptr;
            if(len > 63) len = 63;
            memcpy(line, ptr, len);
            line[len] = 0;
            canvas_draw_str(canvas, 2, y, line);
            y += 10;
            // Przejdź do następnej linii
            ptr = (*end) ? end + 1 : end;
        }
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 62, "[Back] - Menu");
    }
}

// Obsługa wejścia
static void Lab_C5_app_input_callback(InputEvent* event, void* ctx) {
    SimpleApp* app = ctx;
    if(event->type != InputTypeShort) return;

    if(app->screen == ScreenMainMenu) {
        if(event->key == InputKeyUp) {
            if(app->menu_index > 0) app->menu_index--;
            view_port_update(app->viewport);
        } else if(event->key == InputKeyDown) {
            if(app->menu_index < menu_count - 1) app->menu_index++;
            view_port_update(app->viewport);
        } else if(event->key == InputKeyOk) {
            // Wyślij komendę
            char cmd[64];
            if(strcmp(menu_items[app->menu_index], "select_networks") == 0) {
                snprintf(cmd, sizeof(cmd), "select_networks 0 1\n");
            } else if(strcmp(menu_items[app->menu_index], "sniffer_debug") == 0) {
                snprintf(cmd, sizeof(cmd), "sniffer_debug 1\n");
            } else {
                snprintf(cmd, sizeof(cmd), "%s\n", menu_items[app->menu_index]);
            }
            furi_hal_serial_tx(app->serial, (const uint8_t*)cmd, strlen(cmd));
            furi_hal_serial_tx_wait_complete(app->serial);
            furi_delay_ms(50);

            furi_hal_serial_async_rx_start(app->serial, serial_rx_callback, NULL, false);

            app->screen = ScreenSerialOutput;
            app->serial_len = 0;
            memset(app->serial_buffer, 0, SERIAL_BUFFER_SIZE);

            uint32_t start = furi_get_tick();
            while((furi_get_tick() - start) < 500 && app->serial_len < SERIAL_BUFFER_SIZE - 1) {
                while(furi_hal_serial_async_rx_available(app->serial)) {
                    uint8_t byte = furi_hal_serial_async_rx(app->serial);
                    if(app->serial_len < SERIAL_BUFFER_SIZE - 1) {
                        app->serial_buffer[app->serial_len++] = byte;
                    }
                }
            }
            app->serial_buffer[app->serial_len] = 0;

            furi_hal_serial_async_rx_stop(app->serial);

            view_port_update(app->viewport);
        } else if(event->key == InputKeyBack) {
            app->exit_app = true;
        }
    } else if(app->screen == ScreenSerialOutput) {
        if(event->key == InputKeyBack) {
            app->screen = ScreenMainMenu;
            view_port_update(app->viewport);
        }
    }
}

static void serial_rx_callback(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context) {
    (void)handle;
    (void)event;
    (void)context;
}

int32_t Lab_C5_app(void* p) {
    (void)p;
    SimpleApp app = {
        .exit_app=false,
        .menu_index=0,
        .screen=ScreenMainMenu,
        .serial=NULL
    };

    app.serial = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!app.serial) {
        return 0; // Serial interface unavailable
    }

    furi_hal_serial_init(app.serial, 115200);

    Gui* gui = furi_record_open(RECORD_GUI);
    app.viewport = view_port_alloc();
    view_port_draw_callback_set(app.viewport, Lab_C5_app_draw_callback, &app);
    view_port_input_callback_set(app.viewport, Lab_C5_app_input_callback, &app);
    gui_add_view_port(gui, app.viewport, GuiLayerFullscreen);

    while(!app.exit_app) {
        furi_delay_ms(100);
    }

    gui_remove_view_port(gui, app.viewport);
    view_port_free(app.viewport);
    furi_record_close(RECORD_GUI);

    if(app.serial) {
        furi_hal_serial_deinit(app.serial);
        furi_hal_serial_control_release(app.serial);
    }

    return 0;
}