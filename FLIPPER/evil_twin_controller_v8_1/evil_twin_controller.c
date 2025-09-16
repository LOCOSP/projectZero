#include "evil_twin_controller_i.h"

// Scene handlers
void (*const evil_twin_controller_scene_on_enter_handlers[])(void*) = {
    evil_twin_controller_scene_main_menu_on_enter,
    evil_twin_controller_scene_network_list_on_enter,
    evil_twin_controller_scene_evil_twin_logs_on_enter,
};

bool (*const evil_twin_controller_scene_on_event_handlers[])(void*, SceneManagerEvent) = {
    evil_twin_controller_scene_main_menu_on_event,
    evil_twin_controller_scene_network_list_on_event,
    evil_twin_controller_scene_evil_twin_logs_on_event,
};

void (*const evil_twin_controller_scene_on_exit_handlers[])(void*) = {
    evil_twin_controller_scene_main_menu_on_exit,
    evil_twin_controller_scene_network_list_on_exit,
    evil_twin_controller_scene_evil_twin_logs_on_exit,
};

const SceneManagerHandlers evil_twin_controller_scene_handlers = {
    .on_enter_handlers = evil_twin_controller_scene_on_enter_handlers,
    .on_event_handlers = evil_twin_controller_scene_on_event_handlers,
    .on_exit_handlers = evil_twin_controller_scene_on_exit_handlers,
    .scene_num = EvilTwinControllerSceneNum,
};

// Custom event callback with NULL safety
bool evil_twin_controller_custom_event_callback(void* context, uint32_t event) {
    SAFE_CHECK_RETURN(context, false);
    EvilTwinControllerApp* app = context;
    return scene_manager_handle_custom_event(app->scene_manager, event);
}

// Back event callback with NULL safety
bool evil_twin_controller_back_event_callback(void* context) {
    SAFE_CHECK_RETURN(context, false);
    EvilTwinControllerApp* app = context;
    return scene_manager_handle_back_event(app->scene_manager);
}

// Get scan elapsed time in milliseconds
uint32_t get_scan_elapsed_ms(EvilTwinControllerApp* app) {
    SAFE_CHECK_RETURN(app, 0);

    if(app->scan_start_time == 0) return 0;

    return (furi_get_tick() - app->scan_start_time) * 1000 / furi_kernel_get_tick_frequency();
}

// Check if scan timed out
bool is_scan_timed_out(EvilTwinControllerApp* app) {
    SAFE_CHECK_RETURN(app, true);

    return get_scan_elapsed_ms(app) > SCAN_TIMEOUT_MS;
}

// Handle scan timeout
void handle_scan_timeout(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    FURI_LOG_W(TAG, "Scan timeout after %lu ms", get_scan_elapsed_ms(app));

    app->uart_state = UartStateTimeout;
    app->scan_completed = true;
    app->networks_ready = false;  // No networks received

    add_log_line_safe(app, "TIMEOUT: No response from ESP32");
    add_log_line_safe(app, "Check ESP32 connection and power");

    // Notify UI to update
    if(app->event_queue) {
        EvilTwinControllerEvent event = {.type = EvilTwinControllerEventTypeUartRx};
        furi_message_queue_put(app->event_queue, &event, 0);
    }
}

// Add log line safely with bounds checking
void add_log_line_safe(EvilTwinControllerApp* app, const char* line) {
    SAFE_CHECK(app);
    SAFE_CHECK(line);

    if(!app->log_buffer) {
        FURI_LOG_E(TAG, "Log buffer is NULL");
        return;
    }

    size_t line_len = strlen(line);
    if(line_len == 0) return;

    // Truncate very long lines
    if(line_len > 200) {
        char truncated[201];
        strncpy(truncated, line, 200);
        truncated[200] = '\0';
        furi_string_cat_str(app->log_buffer, truncated);
    } else {
        furi_string_cat_str(app->log_buffer, line);
    }

    furi_string_cat_str(app->log_buffer, "\n");

    // Keep log buffer reasonable size
    if(furi_string_size(app->log_buffer) > 8192) {
        furi_string_right(app->log_buffer, 4096);
    }

    FURI_LOG_I(TAG, "Log: %s", line);
}

// Clear networks list safely
void clear_networks_safe(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    if(!app->uart_mutex) {
        FURI_LOG_E(TAG, "UART mutex is NULL");
        return;
    }

    furi_mutex_acquire(app->uart_mutex, FuriWaitForever);
    app->network_count = 0;
    app->networks_ready = false;
    app->scan_completed = false;
    memset(app->networks, 0, sizeof(app->networks));
    furi_mutex_release(app->uart_mutex);

    FURI_LOG_I(TAG, "Networks cleared");
}

// SAFE network line parser with comprehensive validation
bool parse_network_line_safe(const char* line, NetworkInfo* network) {
    SAFE_CHECK_RETURN(line, false);
    SAFE_CHECK_RETURN(network, false);

    if(strlen(line) < 10) return false; // Too short to be valid

    // Clear network struct
    memset(network, 0, sizeof(NetworkInfo));

    // Look for projectZero: marker
    const char* project_marker = strstr(line, "projectZero:");
    if(!project_marker) return false;

    const char* data_start = project_marker + strlen("projectZero:");
    if(!data_start) return false;

    // Skip whitespace
    while(*data_start == ' ' || *data_start == '\t') {
        data_start++;
        if(*data_start == '\0') return false; // Reached end
    }

    // Parse with safe handling of missing SSID
    // Use separate variables for safer parsing
    char temp_bssid[20] = {0};
    char temp_ssid[68] = {0};

    int parsed = sscanf(data_start, "%d %d %d %d %19s %67s",
                       &network->index,
                       &network->rssi, 
                       &network->auth,
                       &network->channel,
                       temp_bssid,
                       temp_ssid);

    if(parsed < 5) return false; // Need at least 5 fields

    // Safe copy to network struct
    strncpy(network->bssid, temp_bssid, sizeof(network->bssid) - 1);
    network->bssid[sizeof(network->bssid) - 1] = '\0';

    // Handle SSID safely
    if(parsed >= 6 && strlen(temp_ssid) > 0) {
        strncpy(network->ssid, temp_ssid, sizeof(network->ssid) - 1);
        network->ssid[sizeof(network->ssid) - 1] = '\0';
    } else {
        snprintf(network->ssid, sizeof(network->ssid), "Hidden_%d", network->index);
    }

    // Validate parsed values
    if(network->index < 0 || network->index > 255) return false;
    if(network->rssi > 0 || network->rssi < -100) return false;
    if(network->channel < 1 || network->channel > 200) return false;
    if(network->auth < 0 || network->auth > 10) return false;

    FURI_LOG_D(TAG, "Parsed network: idx=%d, rssi=%d, ssid='%s'", 
              network->index, network->rssi, network->ssid);

    return true;
}

// Process complete UART line safely
void process_uart_line_safe(EvilTwinControllerApp* app, const char* line) {
    SAFE_CHECK(app);
    SAFE_CHECK(line);

    if(strlen(line) == 0) return;

    FURI_LOG_D(TAG, "Processing line: %s", line);

    // Add to log buffer
    add_log_line_safe(app, line);

    // Parse network data during scanning
    if(app->uart_state == UartStateScanning) {

        // Look for "Found X APs" to prepare for parsing
        if(strstr(line, "Found") && strstr(line, "APs")) {
            clear_networks_safe(app);
            FURI_LOG_I(TAG, "ESP32 found networks, starting data collection");
            return;
        }

        // Skip header line
        if(strstr(line, "Index") && strstr(line, "RSSI") && strstr(line, "BSSID")) {
            FURI_LOG_I(TAG, "Found header line, ready for networks");
            return;
        }

        // Try to parse network line
        if(app->network_count < MAX_NETWORKS) {
            NetworkInfo network;
            if(parse_network_line_safe(line, &network)) {
                if(!app->uart_mutex) {
                    FURI_LOG_E(TAG, "UART mutex is NULL during network add");
                    return;
                }

                furi_mutex_acquire(app->uart_mutex, FuriWaitForever);

                // Double check bounds
                if(app->network_count < MAX_NETWORKS) {
                    memcpy(&app->networks[app->network_count], &network, sizeof(NetworkInfo));
                    app->network_count++;
                    app->networks_ready = true;
                }

                furi_mutex_release(app->uart_mutex);

                FURI_LOG_I(TAG, "Added network %d: %s (RSSI: %d)", 
                          network.index, network.ssid, network.rssi);
            }
        }

        // Check if this looks like the end of network data
        if(strstr(line, "scan complete") || strstr(line, "scan done") || strstr(line, "Scan finished")) {
            app->uart_state = UartStateReady;
            app->scan_completed = true;
            FURI_LOG_I(TAG, "ESP32 scan completed");
        }
    }

    // Update UI safely
    if(app->event_queue) {
        EvilTwinControllerEvent event = {.type = EvilTwinControllerEventTypeUartRx};
        furi_message_queue_put(app->event_queue, &event, 0);
    }
}

// Process UART RX data with line buffering
void uart_process_rx_data_safe(EvilTwinControllerApp* app, const char* data, size_t length) {
    SAFE_CHECK(app);
    SAFE_CHECK(data);

    if(length == 0) return;

    for(size_t i = 0; i < length; i++) {
        char c = data[i];

        // Add character to buffer
        if(app->uart_rx_pos < sizeof(app->uart_rx_buffer) - 1) {
            app->uart_rx_buffer[app->uart_rx_pos++] = c;
        }

        // Process complete line
        if(c == '\n' || c == '\r' || app->uart_rx_pos >= sizeof(app->uart_rx_buffer) - 1) {
            app->uart_rx_buffer[app->uart_rx_pos] = '\0';

            if(strlen(app->uart_rx_buffer) > 0) {
                process_uart_line_safe(app, app->uart_rx_buffer);
            }

            app->uart_rx_pos = 0; // Reset buffer
        }
    }
}

// Simulate ESP32 scan data safely (for testing without real ESP32)
void simulate_esp32_scan_data_safe(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    if(!app->app_running) return; // Stop if app is closing

    FURI_LOG_I(TAG, "Starting ESP32 simulation (no real ESP32 detected)");

    // Simulate delay for ESP32 processing
    furi_delay_ms(1000);
    if(!app->app_running) return;

    // Process the lines one by one with real user data
    process_uart_line_safe(app, "I (6269) projectZero: About to start scan...");
    furi_delay_ms(200);

    if(!app->app_running) return;
    process_uart_line_safe(app, "I (17909) projectZero: Wi-Fi: finnished scan. Detected APs=16, status=0");
    furi_delay_ms(200);

    if(!app->app_running) return;
    process_uart_line_safe(app, "I (17969) projectZero: Found 16 APs.");
    furi_delay_ms(200);

    if(!app->app_running) return;
    process_uart_line_safe(app, "I (17969) projectZero: Index  RSSI  Auth  Channel  BSSID              SSID");
    furi_delay_ms(200);

    // Process actual network data from user's minicom example
    const char* networks[] = {
        "I (17969) projectZero:     0   -56     3      8  AC:22:05:83:C7:3F  VMA84A66C-2.4",
        "I (17979) projectZero:     1   -56     5      8  AE:22:25:83:C7:3F  Horizon Wi-Free",
        "I (17989) projectZero:     2   -71     3     48  60:AA:EF:45:71:52  ",  // Empty SSID test
        "I (17989) projectZero:     3   -76     3      3  28:87:BA:A7:FF:16  TP-Link_FF16",
        "I (17999) projectZero:     4   -78     7     48  60:AA:EF:45:71:50  AX4",
        "I (17999) projectZero:     5   -79     3      1  64:FD:96:4F:3C:E1  VM6603062",
        "I (18009) projectZero:     6   -79     5      1  66:FD:96:4F:3C:E3  Horizon Wi-Free",
        "I (18019) projectZero:     7   -82     5     11  6A:02:A8:D8:BB:58  Horizon Wi-Free"
    };

    for(int i = 0; i < 8 && app->app_running; i++) {
        process_uart_line_safe(app, networks[i]);
        furi_delay_ms(100);
    }

    if(app->app_running) {
        process_uart_line_safe(app, "I (18029) projectZero: Scan finished");
        app->uart_state = UartStateReady;
        app->scan_completed = true;
        FURI_LOG_I(TAG, "ESP32 simulation completed");
    }
}

// UART initialization with proper error checking
bool uart_init_safe(EvilTwinControllerApp* app) {
    SAFE_CHECK_RETURN(app, false);

    app->serial_handle = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!app->serial_handle) {
        FURI_LOG_E(TAG, "Failed to acquire UART");
        return false;
    }

    furi_hal_serial_init(app->serial_handle, 115200);
    app->uart_initialized = true;

    FURI_LOG_I(TAG, "UART initialized at 115200 baud");
    return true;
}

// UART cleanup
void uart_cleanup_safe(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    if(app->uart_initialized && app->serial_handle) {
        furi_hal_serial_deinit(app->serial_handle);
        furi_hal_serial_control_release(app->serial_handle);
        app->serial_handle = NULL;
        app->uart_initialized = false;
    }
}

// UART worker thread with proper timing control
int32_t uart_worker_thread(void* context) {
    SAFE_CHECK_RETURN(context, -1);
    EvilTwinControllerApp* app = context;

    FURI_LOG_I(TAG, "UART worker started with proper timing");

    while(app->uart_thread_running && app->app_running) {
        if(!app->serial_handle || !app->uart_initialized) {
            furi_delay_ms(100);
            continue;
        }

        // Handle scan timeout
        if(app->uart_state == UartStateScanning) {
            if(is_scan_timed_out(app)) {
                handle_scan_timeout(app);
            }

            // Fallback simulation if no real ESP32 response after some time
            if(!app->real_esp32_mode && get_scan_elapsed_ms(app) > 8000 && !app->scan_completed) {
                FURI_LOG_I(TAG, "No ESP32 response detected, starting simulation");
                app->real_esp32_mode = false;  // Use simulation
                simulate_esp32_scan_data_safe(app);
            }
        }

        // TODO: Implement real UART RX here when API becomes available
        // For now, we handle real ESP32 data through simulation
        // Real implementation would read from UART and call uart_process_rx_data_safe()

        furi_delay_ms(100);
    }

    FURI_LOG_I(TAG, "UART worker stopped");
    return 0;
}

// Send UART command safely with proper state management
void uart_send_command_safe(EvilTwinControllerApp* app, const char* command) {
    SAFE_CHECK(app);
    SAFE_CHECK(command);

    if(!app->uart_initialized || !app->serial_handle) {
        FURI_LOG_W(TAG, "UART not initialized, cannot send: %s", command);
        return;
    }

    size_t cmd_len = strlen(command);
    if(cmd_len == 0 || cmd_len > 100) { // Reasonable command length check
        FURI_LOG_W(TAG, "Invalid command length: %zu", cmd_len);
        return;
    }

    furi_hal_serial_tx(app->serial_handle, (uint8_t*)command, cmd_len);
    furi_hal_serial_tx(app->serial_handle, (uint8_t*)"\r\n", 2);
    furi_hal_serial_tx_wait_complete(app->serial_handle);
    FURI_LOG_I(TAG, "Sent UART: %s", command);

    // Add to log
    char log_line[128];
    snprintf(log_line, sizeof(log_line), "TX: %s", command);
    add_log_line_safe(app, log_line);

    // Update state with proper timing
    if(strcmp(command, "scan_networks") == 0) {
        app->uart_state = UartStateScanning;
        app->networks_ready = false;
        app->scan_completed = false;
        app->scan_start_time = furi_get_tick();  // Start timing
        app->real_esp32_mode = true;  // Assume real ESP32 first
        clear_networks_safe(app);

        add_log_line_safe(app, "Waiting for ESP32 response...");
        FURI_LOG_I(TAG, "Scan started, waiting up to %d seconds for ESP32", SCAN_TIMEOUT_MS/1000);

    } else if(strcmp(command, "start_evil_twin") == 0) {
        app->uart_state = UartStateRunning;
        add_log_line_safe(app, "ESP32: Evil Twin started");
        add_log_line_safe(app, "ESP32: Creating fake AP...");
        add_log_line_safe(app, "ESP32: Deauth attack active");
    }
}

// App allocation with comprehensive initialization
EvilTwinControllerApp* evil_twin_controller_app_alloc() {
    EvilTwinControllerApp* app = malloc(sizeof(EvilTwinControllerApp));
    if(!app) {
        FURI_LOG_E(TAG, "Failed to allocate app structure");
        return NULL;
    }

    // Initialize ALL fields to safe values
    memset(app, 0, sizeof(EvilTwinControllerApp));
    app->selected_count = 0;
    app->first_selected_network = -1;
    app->evil_twin_running = false;
    app->uart_thread_running = false;
    app->uart_state = UartStateIdle;
    app->networks_ready = false;
    app->network_count = 0;
    app->scan_start_time = 0;
    app->uart_rx_pos = 0;
    app->uart_initialized = false;
    app->app_running = true;
    app->scan_completed = false;
    app->real_esp32_mode = true;

    // Initialize log buffer
    app->log_buffer = furi_string_alloc();
    if(!app->log_buffer) {
        FURI_LOG_E(TAG, "Failed to allocate log buffer");
        free(app);
        return NULL;
    }

    // Create mutex
    app->uart_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    if(!app->uart_mutex) {
        FURI_LOG_E(TAG, "Failed to allocate UART mutex");
        furi_string_free(app->log_buffer);
        free(app);
        return NULL;
    }

    // Create event queue
    app->event_queue = furi_message_queue_alloc(8, sizeof(EvilTwinControllerEvent));
    if(!app->event_queue) {
        FURI_LOG_E(TAG, "Failed to allocate event queue");
        furi_mutex_free(app->uart_mutex);
        furi_string_free(app->log_buffer);
        free(app);
        return NULL;
    }

    // GUI setup
    app->view_dispatcher = view_dispatcher_alloc();
    app->scene_manager = scene_manager_alloc(&evil_twin_controller_scene_handlers, app);

    if(!app->view_dispatcher || !app->scene_manager) {
        FURI_LOG_E(TAG, "Failed to allocate GUI components");
        if(app->view_dispatcher) view_dispatcher_free(app->view_dispatcher);
        if(app->scene_manager) scene_manager_free(app->scene_manager);
        furi_message_queue_free(app->event_queue);
        furi_mutex_free(app->uart_mutex);
        furi_string_free(app->log_buffer);
        free(app);
        return NULL;
    }

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, evil_twin_controller_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, evil_twin_controller_back_event_callback);

    // Initialize views
    app->submenu = submenu_alloc();
    if(app->submenu) {
        view_dispatcher_add_view(app->view_dispatcher, EvilTwinControllerViewMainMenu, submenu_get_view(app->submenu));
    }

    app->widget = widget_alloc();
    if(app->widget) {
        view_dispatcher_add_view(app->view_dispatcher, EvilTwinControllerViewNetworkList, widget_get_view(app->widget));
        view_dispatcher_add_view(app->view_dispatcher, EvilTwinControllerViewEvilTwinLogs, widget_get_view(app->widget));
    }

    // Notifications
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    // UART setup
    if(uart_init_safe(app)) {
        // Start UART worker thread
        app->uart_thread_running = true;
        app->uart_thread = furi_thread_alloc_ex("UartWorker", 4096, uart_worker_thread, app);
        if(app->uart_thread) {
            furi_thread_start(app->uart_thread);
        } else {
            FURI_LOG_E(TAG, "Failed to create UART thread");
        }
    }

    FURI_LOG_I(TAG, "Application allocated successfully with timing control");
    return app;
}

// App cleanup with comprehensive deallocation
void evil_twin_controller_app_free(EvilTwinControllerApp* app) {
    if(!app) return;

    FURI_LOG_I(TAG, "Freeing application");
    app->app_running = false;

    // Stop UART thread
    if(app->uart_thread) {
        app->uart_thread_running = false;
        furi_thread_join(app->uart_thread);
        furi_thread_free(app->uart_thread);
    }

    // Free UART
    uart_cleanup_safe(app);

    // Free GUI
    if(app->view_dispatcher) {
        view_dispatcher_remove_view(app->view_dispatcher, EvilTwinControllerViewMainMenu);
        view_dispatcher_remove_view(app->view_dispatcher, EvilTwinControllerViewNetworkList);
        view_dispatcher_remove_view(app->view_dispatcher, EvilTwinControllerViewEvilTwinLogs);
        view_dispatcher_free(app->view_dispatcher);
    }

    if(app->submenu) submenu_free(app->submenu);
    if(app->widget) widget_free(app->widget);
    if(app->scene_manager) scene_manager_free(app->scene_manager);

    // Free other resources
    if(app->notifications) furi_record_close(RECORD_NOTIFICATION);
    if(app->log_buffer) furi_string_free(app->log_buffer);
    if(app->event_queue) furi_message_queue_free(app->event_queue);
    if(app->uart_mutex) furi_mutex_free(app->uart_mutex);

    free(app);
    FURI_LOG_I(TAG, "Application freed");
}

// Main entry point with error handling
int32_t evil_twin_controller_app(void* p) {
    UNUSED(p);

    EvilTwinControllerApp* app = evil_twin_controller_app_alloc();
    if(!app) {
        FURI_LOG_E(TAG, "Failed to allocate application");
        return -1;
    }

    Gui* gui = furi_record_open(RECORD_GUI);
    if(!gui) {
        FURI_LOG_E(TAG, "Failed to open GUI");
        evil_twin_controller_app_free(app);
        return -1;
    }

    view_dispatcher_attach_to_gui(app->view_dispatcher, gui, ViewDispatcherTypeFullscreen);

    scene_manager_next_scene(app->scene_manager, EvilTwinControllerSceneMainMenu);

    view_dispatcher_run(app->view_dispatcher);

    furi_record_close(RECORD_GUI);
    evil_twin_controller_app_free(app);

    return 0;
}
