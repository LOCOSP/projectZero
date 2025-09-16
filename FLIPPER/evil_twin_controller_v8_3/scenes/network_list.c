#include "../evil_twin_controller_i.h"

#define NETWORK_LIST_MAX_VISIBLE 3

typedef struct {
    int scroll_offset;
    int selected_item;
    bool start_button_focused;
} NetworkListState;

static NetworkListState network_state = {0, 0, false};

// Draw callback for network list with EXTENDED TIMEOUT display
static void network_list_draw_callback(Canvas* canvas, void* context) {
    SAFE_CHECK(canvas);
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = (EvilTwinControllerApp*)context;

    if(app->shutdown_requested) return;  // Don't draw during shutdown

    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);

    // Header
    canvas_draw_str(canvas, 2, 8, "Sieci WiFi ESP32");

    // Show status based on UART state with EXTENDED TIMEOUT
    if(app->uart_state == UartStateScanning) {
        // Still scanning - show progress with EXTENDED timeout
        uint32_t elapsed_ms = get_scan_elapsed_ms(app);
        uint32_t elapsed_sec = elapsed_ms / 1000;

        canvas_draw_str(canvas, 75, 8, "SCANNING");
        canvas_draw_line(canvas, 0, 10, 128, 10);

        canvas_draw_str(canvas, 5, 23, "Skanowanie ESP32...");

        // Show elapsed time
        char time_str[32];
        if(elapsed_sec < 60) {
            snprintf(time_str, sizeof(time_str), "Czas: %lu sek", elapsed_sec);
        } else {
            snprintf(time_str, sizeof(time_str), "Czas: %lu:%02lu", elapsed_sec/60, elapsed_sec%60);
        }
        canvas_draw_str(canvas, 5, 33, time_str);

        // Show EXTENDED timeout countdown (25 seconds)
        uint32_t timeout_sec = SCAN_TIMEOUT_MS / 1000;  // Now 25 seconds
        if(elapsed_sec < timeout_sec) {
            uint32_t remaining = timeout_sec - elapsed_sec;
            char timeout_str[32];
            snprintf(timeout_str, sizeof(timeout_str), "Timeout za: %lu sek", remaining);
            canvas_draw_str(canvas, 5, 43, timeout_str);
        } else {
            canvas_draw_str(canvas, 5, 43, "Timeout...");
        }

        // Show ESP32 response status
        if(app->esp32_response_detected) {
            canvas_draw_str(canvas, 5, 53, "ESP32 odpowiada...");
        } else if(elapsed_sec > 18) {  // After fallback delay
            canvas_draw_str(canvas, 5, 53, "Fallback aktywny");
        } else {
            canvas_draw_str(canvas, 5, 53, "Czekam na ESP32...");
        }

        canvas_draw_str(canvas, 2, 63, "Back=Cancel");
        return;

    } else if(app->uart_state == UartStateTimeout) {
        // Scan timed out - EXTENDED timeout message
        canvas_draw_str(canvas, 75, 8, "TIMEOUT");
        canvas_draw_line(canvas, 0, 10, 128, 10);

        canvas_draw_str(canvas, 5, 25, "TIMEOUT ESP32!");

        if(app->esp32_response_detected) {
            canvas_draw_str(canvas, 2, 35, "ESP32 odpowiadał ale");
            canvas_draw_str(canvas, 2, 45, "skan trwał >25 sekund");
        } else {
            canvas_draw_str(canvas, 2, 35, "Sprawdź połączenie:");
            canvas_draw_str(canvas, 2, 45, "Pin 13/14 + GND");
        }

        canvas_draw_str(canvas, 2, 55, "ESP32 firmware OK?");
        canvas_draw_str(canvas, 2, 63, "Back=Menu");
        return;

    } else if(app->networks_ready && app->network_count > 0) {
        // Networks found - show count
        char count_str[32];
        snprintf(count_str, sizeof(count_str), "%d szt", app->network_count);
        canvas_draw_str(canvas, 90, 8, count_str);

    } else if(app->scan_completed) {
        // Scan completed but no networks
        canvas_draw_str(canvas, 90, 8, "EMPTY");

    } else {
        // Initial state
        canvas_draw_str(canvas, 90, 8, "READY");
    }

    canvas_draw_line(canvas, 0, 10, 128, 10);

    // Show "no networks" message only if scan is actually completed
    if(app->scan_completed && (!app->networks_ready || app->network_count == 0)) {
        canvas_draw_str(canvas, 15, 35, "Brak sieci!");
        if(app->esp32_response_detected) {
            canvas_draw_str(canvas, 2, 45, "ESP32 nie znalazł AP");
        } else {
            canvas_draw_str(canvas, 2, 45, "ESP32 nie odpowiadał");
        }
        canvas_draw_str(canvas, 2, 63, "Back=Menu");
        return;
    }

    // If no scan has been done yet (initial state)
    if(!app->scan_completed && !app->networks_ready && app->uart_state == UartStateIdle) {
        canvas_draw_str(canvas, 8, 30, "Gotowy do skanowania");
        canvas_draw_str(canvas, 8, 40, "ESP32 timeout: 25s");
        canvas_draw_str(canvas, 8, 50, "Kliknij skanowanie");
        canvas_draw_str(canvas, 2, 63, "Back=Menu");
        return;
    }

    // Networks list - CRITICAL MUTEX SAFETY
    int y = 20;
    int visible = 0;

    if(!app->uart_mutex || !app->mutexes_valid || app->shutdown_requested) {
        canvas_draw_str(canvas, 10, 35, "UART Error!");
        return;
    }

    // CRITICAL: Safe mutex acquire with timeout
    if(furi_mutex_acquire(app->uart_mutex, 100) != FuriStatusOk) {
        canvas_draw_str(canvas, 10, 35, "Mutex timeout!");
        return;
    }

    // Validate bounds
    if(network_state.scroll_offset < 0) network_state.scroll_offset = 0;
    if(network_state.scroll_offset >= app->network_count) network_state.scroll_offset = 0;

    for(int i = network_state.scroll_offset; i < app->network_count && visible < NETWORK_LIST_MAX_VISIBLE; i++) {
        if(i < 0 || i >= MAX_NETWORKS) break; // Extra bounds check

        const NetworkInfo* net = &app->networks[i];

        // Highlight selection
        if(!network_state.start_button_focused && network_state.selected_item == i) {
            canvas_draw_box(canvas, 0, y - 8, 128, 9);
            canvas_set_color(canvas, ColorWhite);
        }

        // Check if selected
        bool selected = false;
        bool is_first = false;
        for(int j = 0; j < app->selected_count && j < 10; j++) {
            if(app->selected_networks[j] == i) {
                selected = true;
                is_first = (app->first_selected_network == i);
                break;
            }
        }

        // Format: [X]* 1 -65 WPA2 VMA84A66C - with safe string handling
        char line[64];
        const char* auth_str = 
            (net->auth == 0) ? "Open" :
            (net->auth == 3) ? "WPA2" :
            (net->auth == 4) ? "WPA3" :
            (net->auth == 5) ? "WiFree" :
            (net->auth == 7) ? "WPA3" : "WPA";

        // Safe SSID display
        char safe_ssid[20];
        strncpy(safe_ssid, net->ssid, sizeof(safe_ssid) - 1);
        safe_ssid[sizeof(safe_ssid) - 1] = '\0';

        snprintf(line, sizeof(line), "[%c]%c %d %d %s %.8s",
            selected ? 'X' : ' ',
            is_first ? '*' : ' ',
            net->index, net->rssi,
            auth_str,
            safe_ssid);

        canvas_draw_str(canvas, 2, y, line);
        canvas_set_color(canvas, ColorBlack);

        y += 12;
        visible++;
    }

    // CRITICAL: Always release mutex
    furi_mutex_release(app->uart_mutex);

    // Start button
    if(app->selected_count > 0) {
        y = 54;
        if(network_state.start_button_focused) {
            canvas_draw_box(canvas, 10, y - 8, 108, 9);
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_draw_str(canvas, 30, y, ">>> Start Evil Twin <<<");
        canvas_set_color(canvas, ColorBlack);
    }

    // Footer
    canvas_draw_str(canvas, 2, 63, "Up/Down=Nav  Back=Menu");
}

// Input callback for network list with extended timeout handling
static bool network_list_input_callback(InputEvent* event, void* context) {
    SAFE_CHECK_RETURN(event, false);
    SAFE_CHECK_RETURN(context, false);
    EvilTwinControllerApp* app = (EvilTwinControllerApp*)context;

    if(app->shutdown_requested) return false;  // Don't handle input during shutdown

    bool consumed = false;

    // Handle input while scanning - only allow Back to cancel
    if(app->uart_state == UartStateScanning) {
        if(event->type == InputTypeShort && event->key == InputKeyBack) {
            // Cancel scan and go back
            FURI_LOG_I(TAG, "User cancelled ESP32 scan");
            app->uart_state = UartStateIdle;
            app->scan_start_time = 0;
            app->scan_completed = false;
            app->esp32_response_detected = false;
            if(app->scene_manager && !app->shutdown_requested) {
                scene_manager_previous_scene(app->scene_manager);
            }
            return true;
        }
        // Ignore all other inputs while scanning
        return true;
    }

    // Handle timeout state - only allow Back
    if(app->uart_state == UartStateTimeout) {
        if(event->type == InputTypeShort && event->key == InputKeyBack) {
            // Reset state and go back
            app->uart_state = UartStateIdle;
            app->scan_start_time = 0;
            app->scan_completed = false;
            app->esp32_response_detected = false;
            if(app->scene_manager && !app->shutdown_requested) {
                scene_manager_previous_scene(app->scene_manager);
            }
            return true;
        }
        return true;
    }

    // Handle no networks state - only allow Back
    if(!app->networks_ready || app->network_count == 0) {
        if(event->type == InputTypeShort && event->key == InputKeyBack) {
            if(app->scene_manager && !app->shutdown_requested) {
                scene_manager_previous_scene(app->scene_manager);
            }
            return true;
        }
        return false;
    }

    // Normal network selection input handling
    if(event->type == InputTypeShort) {
        switch(event->key) {
            case InputKeyUp:
                if(network_state.start_button_focused) {
                    network_state.start_button_focused = false;
                    network_state.selected_item = app->network_count - 1;
                    // Bounds check
                    if(network_state.selected_item < 0) network_state.selected_item = 0;
                } else if(network_state.selected_item > 0) {
                    network_state.selected_item--;
                    if(network_state.selected_item < network_state.scroll_offset) {
                        network_state.scroll_offset--;
                        if(network_state.scroll_offset < 0) network_state.scroll_offset = 0;
                    }
                }
                consumed = true;
                break;

            case InputKeyDown:
                if(!network_state.start_button_focused) {
                    if(network_state.selected_item < app->network_count - 1) {
                        network_state.selected_item++;
                        if(network_state.selected_item >= network_state.scroll_offset + NETWORK_LIST_MAX_VISIBLE) {
                            network_state.scroll_offset++;
                        }
                    } else if(app->selected_count > 0) {
                        network_state.start_button_focused = true;
                    }
                }
                consumed = true;
                break;

            case InputKeyOk:
                if(network_state.start_button_focused) {
                    // Build command using snprintf - NO STRCAT!
                    char command[128];
                    int offset = snprintf(command, sizeof(command), "select_networks");

                    for(int i = 0; i < app->selected_count && i < 10 && offset < (int)(sizeof(command) - 8); i++) {
                        offset += snprintf(command + offset, sizeof(command) - offset, " %d", app->selected_networks[i]);
                    }

                    uart_send_command_safe(app, command);
                    uart_send_command_safe(app, "start_evil_twin");

                    if(app->scene_manager && !app->shutdown_requested) {
                        scene_manager_next_scene(app->scene_manager, EvilTwinControllerSceneEvilTwinLogs);
                    }
                } else {
                    // Toggle network selection with bounds checking
                    int idx = network_state.selected_item;
                    if(idx < 0 || idx >= app->network_count) break;

                    bool found = false;
                    int pos = -1;

                    // Find if already selected
                    for(int i = 0; i < app->selected_count && i < 10; i++) {
                        if(app->selected_networks[i] == idx) {
                            found = true;
                            pos = i;
                            break;
                        }
                    }

                    if(found) {
                        // Remove selection
                        for(int i = pos; i < app->selected_count - 1 && i < 9; i++) {
                            app->selected_networks[i] = app->selected_networks[i + 1];
                        }
                        app->selected_count--;
                        if(app->selected_count < 0) app->selected_count = 0;

                        if(app->first_selected_network == idx) {
                            app->first_selected_network = (app->selected_count > 0) ?
                                app->selected_networks[0] : -1;
                        }
                    } else if(app->selected_count < 10) {
                        // Add selection
                        app->selected_networks[app->selected_count] = idx;
                        app->selected_count++;

                        if(app->first_selected_network == -1) {
                            app->first_selected_network = idx;
                        }
                    }

                    // Use sequence_success
                    if(app->notifications && !app->shutdown_requested) {
                        notification_message(app->notifications, &sequence_success);
                    }
                }
                consumed = true;
                break;

            case InputKeyBack:
                if(app->scene_manager && !app->shutdown_requested) {
                    scene_manager_previous_scene(app->scene_manager);
                }
                consumed = true;
                break;

            default:
                break;
        }
    }

    return consumed;
}

void evil_twin_controller_scene_network_list_on_enter(void* context) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;

    if(app->shutdown_requested) return;

    // Reset selection state
    network_state.scroll_offset = 0;
    network_state.selected_item = 0;
    network_state.start_button_focused = false;

    app->selected_count = 0;
    app->first_selected_network = -1;

    // Setup widget with custom draw and input
    if(app->widget) {
        widget_reset(app->widget);

        View* view = widget_get_view(app->widget);
        if(view) {
            view_set_context(view, app);
            view_set_draw_callback(view, network_list_draw_callback);
            view_set_input_callback(view, network_list_input_callback);
        }
    }

    if(app->view_dispatcher && !app->shutdown_requested) {
        view_dispatcher_switch_to_view(app->view_dispatcher, EvilTwinControllerViewNetworkList);
    }

    FURI_LOG_I(TAG, "Network list entered - state: %d, ESP32 response: %s, networks: %d", 
              app->uart_state, app->esp32_response_detected ? "YES" : "NO", app->network_count);
}

bool evil_twin_controller_scene_network_list_on_event(void* context, SceneManagerEvent event) {
    SAFE_CHECK_RETURN(context, false);
    EvilTwinControllerApp* app = context;

    if(app->shutdown_requested) return false;

    // Handle UART RX events to update display
    if(event.type == SceneManagerEventTypeCustom) {
        // Trigger view update when UART data arrives
        if(app->view_dispatcher && !app->shutdown_requested) {
            view_dispatcher_send_custom_event(app->view_dispatcher, 0);
        }
        return true;
    }

    return false;
}

void evil_twin_controller_scene_network_list_on_exit(void* context) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;

    // Don't reset state if we're just switching scenes
    // State should persist for proper operation

    if(app->widget) {
        View* view = widget_get_view(app->widget);
        if(view) {
            view_set_draw_callback(view, NULL);
            view_set_input_callback(view, NULL);
        }
        widget_reset(app->widget);
    }

    FURI_LOG_I(TAG, "Network list exited");
}
