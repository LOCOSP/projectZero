#include "../evil_twin_controller_i.h"

#define NETWORK_LIST_MAX_VISIBLE 4

typedef struct {
    int scroll_offset;
    int selected_item;
    bool start_button_focused;
} NetworkListState;

static NetworkListState network_state = {0, 0, false};

// PROBLEM 2 FIX: Draw callback that ALWAYS shows "Trwa skanowanie" when UartStateScanning
static void network_list_draw_callback(Canvas* canvas, void* context) {
    SAFE_CHECK(canvas);
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = (EvilTwinControllerApp*)context;

    if(app->shutdown_requested) return;  // Don't draw during shutdown

    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);

    // Header
    canvas_draw_str(canvas, 2, 8, "Evil Twin ESP32");

    // PROBLEM 2 FIX: ALWAYS show proper status based on UART state
    if(app->uart_state == UartStateScanning) {
        // SCANNING STATE: "Trwa skanowanie" with progress - PROBLEM 2 FIX
        uint32_t elapsed_ms = get_scan_elapsed_ms(app);
        uint32_t elapsed_sec = elapsed_ms / 1000;

        // Show SCANNING status in header
        canvas_draw_str(canvas, 75, 8, "SCANNING");
        canvas_draw_line(canvas, 0, 10, 128, 10);

        // PROBLEM 2 FIX: Always show "Trwa skanowanie" when in scanning state
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 15, 28, "Trwa skanowanie");
        canvas_set_font(canvas, FontSecondary);

        // Show detailed progress info
        char time_str[32];
        snprintf(time_str, sizeof(time_str), "Czas: %lu sek", elapsed_sec);
        canvas_draw_str(canvas, 25, 40, time_str);

        // Show timeout countdown (25 seconds)
        uint32_t timeout_sec = SCAN_TIMEOUT_MS / 1000;
        if(elapsed_sec < timeout_sec) {
            uint32_t remaining = timeout_sec - elapsed_sec;
            char timeout_str[32];
            snprintf(timeout_str, sizeof(timeout_str), "Timeout za: %lu s", remaining);
            canvas_draw_str(canvas, 18, 50, timeout_str);
        } else {
            canvas_draw_str(canvas, 25, 50, "Processing...");
        }

        // Show ESP32 response status or UART status
        if(!app->real_esp32_mode) {
            canvas_draw_str(canvas, 20, 60, "Demo simulation");
        } else if(app->esp32_response_detected) {
            canvas_draw_str(canvas, 15, 60, "ESP32 odpowiada...");
        } else if(elapsed_sec > 18) {  // After fallback delay
            canvas_draw_str(canvas, 20, 60, "Tryb fallback");
        } else {
            canvas_draw_str(canvas, 18, 60, "Czekam na ESP32");
        }

        // Footer for scanning
        canvas_draw_str(canvas, 2, 63, "Back=Cancel");
        return;  // PROBLEM 2 FIX: Always return here when scanning

    } else if(app->uart_state == UartStateTimeout) {
        // TIMEOUT STATE - better error display
        canvas_draw_str(canvas, 85, 8, "TIMEOUT");
        canvas_draw_line(canvas, 0, 10, 128, 10);

        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 20, 28, "TIMEOUT!");
        canvas_set_font(canvas, FontSecondary);

        if(app->esp32_response_detected) {
            canvas_draw_str(canvas, 8, 38, "ESP32 odpowiadał ale");
            canvas_draw_str(canvas, 8, 48, "skan trwał >25s");
        } else {
            canvas_draw_str(canvas, 15, 38, "Brak odpowiedzi");
            canvas_draw_str(canvas, 8, 48, "Sprawdź połączenie");
        }

        canvas_draw_str(canvas, 2, 63, "Back=Menu  OK=Retry");
        return;

    } else if(app->networks_ready && app->network_count > 0) {
        // NETWORKS FOUND - show count and status
        char count_str[32];
        snprintf(count_str, sizeof(count_str), "%d sieci", app->network_count);
        canvas_draw_str(canvas, 80, 8, count_str);

    } else if(app->scan_completed) {
        // SCAN COMPLETED BUT NO NETWORKS
        canvas_draw_str(canvas, 90, 8, "PUSTE");

    } else {
        // INITIAL STATE
        canvas_draw_str(canvas, 90, 8, "GOTOWY");
    }

    canvas_draw_line(canvas, 0, 10, 128, 10);

    // Show "no networks" message only if scan is actually completed
    if(app->scan_completed && (!app->networks_ready || app->network_count == 0)) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 18, 30, "Brak sieci!");
        canvas_set_font(canvas, FontSecondary);

        if(app->esp32_response_detected) {
            canvas_draw_str(canvas, 8, 42, "ESP32 nie znalazł AP");
        } else if(!app->real_esp32_mode) {
            canvas_draw_str(canvas, 8, 42, "Demo mode - fake data");
        } else {
            canvas_draw_str(canvas, 8, 42, "ESP32 nie odpowiadał");
        }
        canvas_draw_str(canvas, 15, 52, "Spróbuj ponownie");
        canvas_draw_str(canvas, 2, 63, "Back=Menu  OK=Retry");
        return;
    }

    // If no scan has been done yet (initial state)
    if(!app->scan_completed && !app->networks_ready && app->uart_state == UartStateIdle) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 5, 28, "Gotowy do skanowania");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 20, 40, "Timeout: 25 sekund");
        canvas_draw_str(canvas, 15, 50, "Kliknij skanowanie");
        canvas_draw_str(canvas, 2, 63, "Back=Menu  OK=Skanuj");
        return;
    }

    // NETWORK LIST - show beautiful network list
    if(app->networks_ready && app->network_count > 0) {
        int y = 18;
        int visible = 0;

        if(!app->uart_mutex || !app->mutexes_valid || app->shutdown_requested) {
            canvas_draw_str(canvas, 10, 35, "BŁĄD MUTEX!");
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

        // Beautiful network list
        for(int i = network_state.scroll_offset; i < app->network_count && visible < NETWORK_LIST_MAX_VISIBLE; i++) {
            if(i < 0 || i >= MAX_NETWORKS) break; // Extra bounds check

            const NetworkInfo* net = &app->networks[i];

            // Highlight selection - IMPROVED selection indicator
            if(!network_state.start_button_focused && network_state.selected_item == i) {
                canvas_draw_rbox(canvas, 0, y - 7, 128, 10, 2);
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

            // Beautiful format line
            char line[80];
            const char* auth_str = 
                (net->auth == 0) ? "Open" :
                (net->auth == 3) ? "WPA2" :
                (net->auth == 4) ? "WPA3" :
                (net->auth == 5) ? "Free" :
                (net->auth == 7) ? "WPA3" : "WPA";

            // Safe SSID display - shorter for better formatting
            char safe_ssid[16];
            strncpy(safe_ssid, net->ssid, sizeof(safe_ssid) - 1);
            safe_ssid[sizeof(safe_ssid) - 1] = '\0';

            // Format: [X]* SSID (RSSI dBm) AUTH  
            snprintf(line, sizeof(line), "[%c]%c %s (%d) %s",
                selected ? 'X' : ' ',
                is_first ? '*' : ' ',
                safe_ssid,
                net->rssi,
                auth_str);

            canvas_draw_str(canvas, 2, y, line);
            canvas_set_color(canvas, ColorBlack);

            y += 11;
            visible++;
        }

        // CRITICAL: Always release mutex
        furi_mutex_release(app->uart_mutex);

        // Start button - improved styling
        if(app->selected_count > 0) {
            int button_y = 56;
            if(network_state.start_button_focused) {
                canvas_draw_rbox(canvas, 8, button_y - 6, 112, 10, 2);
                canvas_set_color(canvas, ColorWhite);
            }

            char start_text[32];
            snprintf(start_text, sizeof(start_text), ">>> Atakuj %d sieci <<<", app->selected_count);
            canvas_draw_str(canvas, 12, button_y, start_text);
            canvas_set_color(canvas, ColorBlack);
        }

        // Footer with navigation help
        canvas_draw_str(canvas, 2, 63, "↕=Nav ○=Sel/Start ←=Menu");
    }
}

// Input callback for network list with IMPROVED interaction
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
            app->real_esp32_mode = true;  // Reset mode
            if(app->scene_manager && !app->shutdown_requested) {
                scene_manager_previous_scene(app->scene_manager);
            }
            return true;
        }
        // Ignore all other inputs while scanning
        return true;
    }

    // Handle timeout state - allow Back and OK (retry)
    if(app->uart_state == UartStateTimeout) {
        if(event->type == InputTypeShort) {
            if(event->key == InputKeyBack) {
                // Reset state and go back
                app->uart_state = UartStateIdle;
                app->scan_start_time = 0;
                app->scan_completed = false;
                app->esp32_response_detected = false;
                app->real_esp32_mode = true;  // Reset mode
                if(app->scene_manager && !app->shutdown_requested) {
                    scene_manager_previous_scene(app->scene_manager);
                }
                return true;
            } else if(event->key == InputKeyOk) {
                // Retry scan
                clear_networks_safe(app);

                bool uart_success = uart_send_command_safe(app, "scan_networks");
                if(uart_success) {
                    app->uart_state = UartStateScanning;
                    app->real_esp32_mode = true;
                } else {
                    app->uart_state = UartStateScanning;
                    app->real_esp32_mode = false;  // Fallback mode
                }
                app->scan_start_time = furi_get_tick();
                app->scan_completed = false;
                app->esp32_response_detected = false;
                force_ui_refresh(app);
                return true;
            }
        }
        return true;
    }

    // Handle no networks state - allow Back and OK (retry)
    if(app->scan_completed && (!app->networks_ready || app->network_count == 0)) {
        if(event->type == InputTypeShort) {
            if(event->key == InputKeyBack) {
                if(app->scene_manager && !app->shutdown_requested) {
                    scene_manager_previous_scene(app->scene_manager);
                }
                return true;
            } else if(event->key == InputKeyOk) {
                // Retry scan
                clear_networks_safe(app);

                bool uart_success = uart_send_command_safe(app, "scan_networks");
                if(uart_success) {
                    app->uart_state = UartStateScanning;
                    app->real_esp32_mode = true;
                } else {
                    app->uart_state = UartStateScanning;
                    app->real_esp32_mode = false;  // Fallback mode
                }
                app->scan_start_time = furi_get_tick();
                app->scan_completed = false;
                app->esp32_response_detected = false;
                force_ui_refresh(app);
                return true;
            }
        }
        return true;
    }

    // Handle initial state - allow Back and OK (start scan)
    if(!app->scan_completed && !app->networks_ready && app->uart_state == UartStateIdle) {
        if(event->type == InputTypeShort) {
            if(event->key == InputKeyBack) {
                if(app->scene_manager && !app->shutdown_requested) {
                    scene_manager_previous_scene(app->scene_manager);
                }
                return true;
            } else if(event->key == InputKeyOk) {
                // Start scan
                clear_networks_safe(app);

                bool uart_success = uart_send_command_safe(app, "scan_networks");
                if(uart_success) {
                    app->uart_state = UartStateScanning;
                    app->real_esp32_mode = true;
                } else {
                    app->uart_state = UartStateScanning;
                    app->real_esp32_mode = false;  // Fallback mode
                }
                app->scan_start_time = furi_get_tick();
                app->scan_completed = false;
                app->esp32_response_detected = false;
                force_ui_refresh(app);
                return true;
            }
        }
        return true;
    }

    // Normal network selection input handling
    if(app->networks_ready && app->network_count > 0 && event->type == InputTypeShort) {
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
                    // Start Evil Twin attack with selected networks
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
                    // Toggle network selection with visual feedback
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

                    // Visual feedback
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

    // PROBLEM 2 FIX: Force UI refresh immediately when entering
    force_ui_refresh(app);

    FURI_LOG_I(TAG, "Network list entered - state: %d, ESP32 mode: %s, networks: %d", 
              app->uart_state, app->real_esp32_mode ? "REAL" : "DEMO", app->network_count);
}

bool evil_twin_controller_scene_network_list_on_event(void* context, SceneManagerEvent event) {
    SAFE_CHECK_RETURN(context, false);
    EvilTwinControllerApp* app = context;

    if(app->shutdown_requested) return false;

    // Handle UART RX events to update display - IMPROVED refresh
    if(event.type == SceneManagerEventTypeCustom) {
        // Trigger view update when UART data arrives
        if(app->view_dispatcher && !app->shutdown_requested) {
            // Force complete view redraw
            view_dispatcher_send_custom_event(app->view_dispatcher, 0);
        }
        return true;
    }

    return false;
}

void evil_twin_controller_scene_network_list_on_exit(void* context) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;

    // Don't reset network state if we're just switching scenes
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
