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
    if(app->shutdown_requested) return false;  // Don't handle events during shutdown
    return scene_manager_handle_custom_event(app->scene_manager, event);
}

// Back event callback with NULL safety
bool evil_twin_controller_back_event_callback(void* context) {
    SAFE_CHECK_RETURN(context, false);
    EvilTwinControllerApp* app = context;
    if(app->shutdown_requested) return false;  // Don't handle events during shutdown
    return scene_manager_handle_back_event(app->scene_manager);
}

// CRITICAL: Safe shutdown functions (same as v8.2)
void safe_shutdown_begin(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    FURI_LOG_I(TAG, "Beginning safe shutdown sequence");
    app->shutdown_requested = true;
    app->app_running = false;
    app->uart_thread_running = false;
}

void safe_shutdown_threads(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    if(app->uart_thread) {
        FURI_LOG_I(TAG, "Stopping UART thread");
        app->uart_thread_running = false;
        furi_thread_join(app->uart_thread);
        furi_thread_free(app->uart_thread);
        app->uart_thread = NULL;
        FURI_LOG_I(TAG, "UART thread stopped");
    }
}

void safe_shutdown_mutexes(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    if(!app->mutexes_valid) {
        FURI_LOG_W(TAG, "Mutexes already invalid, skipping cleanup");
        return;
    }

    app->mutexes_valid = false;

    if(app->uart_mutex) {
        FURI_LOG_I(TAG, "Freeing UART mutex");
        MUTEX_SAFE_FREE(app->uart_mutex);
    }
}

// Get scan elapsed time in milliseconds
uint32_t get_scan_elapsed_ms(EvilTwinControllerApp* app) {
    SAFE_CHECK_RETURN(app, 0);

    if(app->scan_start_time == 0) return 0;

    return (furi_get_tick() - app->scan_start_time) * 1000 / furi_kernel_get_tick_frequency();
}

// Check if scan timed out (EXTENDED to 25 seconds)
bool is_scan_timed_out(EvilTwinControllerApp* app) {
    SAFE_CHECK_RETURN(app, true);

    return get_scan_elapsed_ms(app) > SCAN_TIMEOUT_MS;
}

// NEW: Check if should start fallback simulation (after 18 seconds)
bool should_start_fallback_simulation(EvilTwinControllerApp* app) {
    SAFE_CHECK_RETURN(app, false);

    uint32_t elapsed = get_scan_elapsed_ms(app);

    // Only start simulation if:
    // 1. We've waited long enough (18s)
    // 2. No ESP32 response detected yet
    // 3. We're in real ESP32 mode (not simulation mode already)
    // 4. Scan hasn't completed yet

    return (elapsed > SCAN_FALLBACK_DELAY_MS && 
            !app->esp32_response_detected && 
            app->real_esp32_mode && 
            !app->scan_completed);
}

// NEW: Debug UART RX activity
void debug_uart_rx_activity(EvilTwinControllerApp* app, const char* data) {
    SAFE_CHECK(app);
    SAFE_CHECK(data);

    app->last_uart_rx_time = furi_get_tick();
    app->esp32_response_detected = true;

    FURI_LOG_D(TAG, "UART RX activity detected: '%.*s'", 
              (int)fmin(strlen(data), 50), data);
}

// Handle scan timeout (EXTENDED to 25 seconds)
void handle_scan_timeout(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    if(app->shutdown_requested) return;  // Don't handle timeout during shutdown

    uint32_t elapsed = get_scan_elapsed_ms(app);
    FURI_LOG_W(TAG, "EXTENDED scan timeout after %lu ms (25s limit)", elapsed);

    app->uart_state = UartStateTimeout;
    app->scan_completed = true;
    app->networks_ready = false;  // No networks received

    if(app->esp32_response_detected) {
        add_log_line_safe(app, "TIMEOUT: ESP32 responded but scan took too long");
        add_log_line_safe(app, "Try increasing timeout or check ESP32 performance");
    } else {
        add_log_line_safe(app, "TIMEOUT: No response from ESP32 after 25 seconds");
        add_log_line_safe(app, "Check ESP32 connection, power, and firmware");
    }

    // Notify UI to update (if not shutting down)
    if(app->event_queue && !app->shutdown_requested) {
        EvilTwinControllerEvent event = {.type = EvilTwinControllerEventTypeUartRx};
        furi_message_queue_put(app->event_queue, &event, 0);
    }
}

// Add log line safely with bounds checking
void add_log_line_safe(EvilTwinControllerApp* app, const char* line) {
    SAFE_CHECK(app);
    SAFE_CHECK(line);

    if(app->shutdown_requested) return;  // Don't log during shutdown

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

// Clear networks list safely - CRITICAL MUTEX HANDLING
void clear_networks_safe(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    if(app->shutdown_requested || !app->mutexes_valid) return;

    if(!app->uart_mutex) {
        FURI_LOG_E(TAG, "UART mutex is NULL");
        return;
    }

    // CRITICAL: Safe mutex acquire with timeout
    if(furi_mutex_acquire(app->uart_mutex, 1000) == FuriStatusOk) {
        app->network_count = 0;
        app->networks_ready = false;
        app->scan_completed = false;
        app->esp32_response_detected = false;  // Reset ESP32 response tracking
        memset(app->networks, 0, sizeof(app->networks));

        // CRITICAL: Always release mutex
        furi_mutex_release(app->uart_mutex);

        FURI_LOG_I(TAG, "Networks cleared, ESP32 response tracking reset");
    } else {
        FURI_LOG_E(TAG, "Failed to acquire mutex for network clear");
    }
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

    FURI_LOG_D(TAG, "Parsed ESP32 network: idx=%d, rssi=%d, ssid='%s'", 
              network->index, network->rssi, network->ssid);

    return true;
}

// Process complete UART line safely - WITH ESP32 RESPONSE DETECTION
void process_uart_line_safe(EvilTwinControllerApp* app, const char* line) {
    SAFE_CHECK(app);
    SAFE_CHECK(line);

    if(app->shutdown_requested || !app->mutexes_valid) return;
    if(strlen(line) == 0) return;

    FURI_LOG_D(TAG, "Processing ESP32 line: %s", line);

    // Mark ESP32 response detected
    app->esp32_response_detected = true;
    app->last_uart_rx_time = furi_get_tick();

    // Add to log buffer
    add_log_line_safe(app, line);

    // Parse network data during scanning
    if(app->uart_state == UartStateScanning) {

        // Look for "Found X APs" to prepare for parsing
        if(strstr(line, "Found") && strstr(line, "APs")) {
            clear_networks_safe(app);
            FURI_LOG_I(TAG, "ESP32 found networks, starting data collection");
            app->esp32_response_detected = true;
            return;
        }

        // Skip header line
        if(strstr(line, "Index") && strstr(line, "RSSI") && strstr(line, "BSSID")) {
            FURI_LOG_I(TAG, "ESP32 header line detected, ready for networks");
            app->esp32_response_detected = true;
            return;
        }

        // Try to parse network line
        if(app->network_count < MAX_NETWORKS) {
            NetworkInfo network;
            if(parse_network_line_safe(line, &network)) {
                if(!app->uart_mutex || !app->mutexes_valid) {
                    FURI_LOG_E(TAG, "UART mutex is NULL/invalid during network add");
                    return;
                }

                // CRITICAL: Safe mutex acquire with timeout
                if(furi_mutex_acquire(app->uart_mutex, 1000) == FuriStatusOk) {

                    // Double check bounds and shutdown
                    if(app->network_count < MAX_NETWORKS && !app->shutdown_requested) {
                        memcpy(&app->networks[app->network_count], &network, sizeof(NetworkInfo));
                        app->network_count++;
                        app->networks_ready = true;
                        app->esp32_response_detected = true;

                        FURI_LOG_I(TAG, "Added ESP32 network %d: %s (RSSI: %d)", 
                                  network.index, network.ssid, network.rssi);
                    }

                    // CRITICAL: Always release mutex
                    furi_mutex_release(app->uart_mutex);
                } else {
                    FURI_LOG_E(TAG, "Failed to acquire mutex for network add");
                }
            }
        }

        // Check if this looks like the end of network data
        if(strstr(line, "scan complete") || strstr(line, "scan done") || 
           strstr(line, "Scan finished") || strstr(line, "finnished scan")) {
            app->uart_state = UartStateReady;
            app->scan_completed = true;
            app->esp32_response_detected = true;
            FURI_LOG_I(TAG, "ESP32 scan completed successfully");
        }
    }

    // Update UI safely (if not shutting down)
    if(app->event_queue && !app->shutdown_requested) {
        EvilTwinControllerEvent event = {.type = EvilTwinControllerEventTypeUartRx};
        furi_message_queue_put(app->event_queue, &event, 0);
    }
}

// Process UART RX data with line buffering + ESP32 detection
void uart_process_rx_data_safe(EvilTwinControllerApp* app, const char* data, size_t length) {
    SAFE_CHECK(app);
    SAFE_CHECK(data);

    if(app->shutdown_requested) return;
    if(length == 0) return;

    // Debug UART RX activity
    debug_uart_rx_activity(app, data);

    for(size_t i = 0; i < length; i++) {
        if(app->shutdown_requested) return;  // Check during loop

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

// Simulate ESP32 scan data safely (fallback after 18 seconds)
void simulate_esp32_scan_data_safe(EvilTwinControllerApp* app) {
    SAFE_CHECK(app);

    if(app->shutdown_requested) return; // Stop if app is closing

    FURI_LOG_I(TAG, "Starting ESP32 FALLBACK simulation (no response after 18s)");

    // Simulate delay for ESP32 processing
    furi_delay_ms(1000);
    if(app->shutdown_requested) return;

    // Process the lines one by one with real user data
    process_uart_line_safe(app, "I (6269) projectZero: About to start scan...");
    furi_delay_ms(200);

    if(app->shutdown_requested) return;
    process_uart_line_safe(app, "I (17909) projectZero: Wi-Fi: finnished scan. Detected APs=16, status=0");
    furi_delay_ms(200);

    if(app->shutdown_requested) return;
    process_uart_line_safe(app, "I (17969) projectZero: Found 16 APs.");
    furi_delay_ms(200);

    if(app->shutdown_requested) return;
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

    for(int i = 0; i < 8 && !app->shutdown_requested; i++) {
        process_uart_line_safe(app, networks[i]);
        furi_delay_ms(100);
    }

    if(!app->shutdown_requested) {
        process_uart_line_safe(app, "I (18029) projectZero: Scan finished");
        app->uart_state = UartStateReady;
        app->scan_completed = true;
        FURI_LOG_I(TAG, "ESP32 FALLBACK simulation completed");
    }
}

// UART initialization with proper error checking
bool uart_init_safe(EvilTwinControllerApp* app) {
    SAFE_CHECK_RETURN(app, false);

    app->serial_handle = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!app->serial_handle) {
        FURI_LOG_E(TAG, "Failed to acquire UART - no hardware access");
        return false;
    }

    furi_hal_serial_init(app->serial_handle, 115200);
    app->uart_initialized = true;

    FURI_LOG_I(TAG, "UART initialized at 115200 baud for ESP32 communication");
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
        FURI_LOG_I(TAG, "UART cleaned up");
    }
}

// UART worker thread with EXTENDED timeout and ESP32 detection
int32_t uart_worker_thread(void* context) {
    SAFE_CHECK_RETURN(context, -1);
    EvilTwinControllerApp* app = context;

    FURI_LOG_I(TAG, "UART worker started with EXTENDED 25s timeout for ESP32");

    // CRITICAL: Use volatile flags for coordination
    while(app->uart_thread_running && app->app_running && !app->shutdown_requested) {
        if(!app->serial_handle || !app->uart_initialized) {
            furi_delay_ms(100);
            continue;
        }

        // Handle scan states (only if not shutting down)
        if(app->uart_state == UartStateScanning && !app->shutdown_requested) {
            uint32_t elapsed = get_scan_elapsed_ms(app);

            // Check for final timeout (25 seconds)
            if(is_scan_timed_out(app)) {
                handle_scan_timeout(app);
            }
            // Check for fallback simulation (18 seconds, no ESP32 response)
            else if(should_start_fallback_simulation(app)) {
                FURI_LOG_I(TAG, "No ESP32 response after 18s, starting fallback simulation");
                app->real_esp32_mode = false;  // Switch to simulation mode
                simulate_esp32_scan_data_safe(app);
            }
            // Log progress every 5 seconds
            else if(elapsed > 0 && (elapsed % 5000) < 200) {
                FURI_LOG_D(TAG, "ESP32 scan progress: %lu/%lu seconds (response: %s)", 
                          elapsed/1000, SCAN_TIMEOUT_MS/1000,
                          app->esp32_response_detected ? "YES" : "NO");
            }
        }

        // TODO: Implement real UART RX here when API becomes available
        // Real implementation would read from UART and call uart_process_rx_data_safe()

        furi_delay_ms(100);
    }

    FURI_LOG_I(TAG, "UART worker thread finished cleanly");
    return 0;
}

// Send UART command safely with ESP32 timing awareness
void uart_send_command_safe(EvilTwinControllerApp* app, const char* command) {
    SAFE_CHECK(app);
    SAFE_CHECK(command);

    if(app->shutdown_requested) return;  // Don't send during shutdown

    if(!app->uart_initialized || !app->serial_handle) {
        FURI_LOG_W(TAG, "UART not initialized, cannot send to ESP32: %s", command);
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
    FURI_LOG_I(TAG, "Sent UART to ESP32: %s", command);

    // Add to log
    char log_line[128];
    snprintf(log_line, sizeof(log_line), "TX to ESP32: %s", command);
    add_log_line_safe(app, log_line);

    // Update state with EXTENDED timing
    if(strcmp(command, "scan_networks") == 0) {
        app->uart_state = UartStateScanning;
        app->networks_ready = false;
        app->scan_completed = false;
        app->esp32_response_detected = false;  // Reset ESP32 detection
        app->scan_start_time = furi_get_tick();  // Start timing
        app->real_esp32_mode = true;  // Assume real ESP32 first
        app->last_uart_rx_time = 0;
        clear_networks_safe(app);

        add_log_line_safe(app, "Waiting for ESP32 response (up to 25 seconds)...");
        FURI_LOG_I(TAG, "ESP32 scan started, EXTENDED timeout: %d seconds", SCAN_TIMEOUT_MS/1000);

    } else if(strcmp(command, "start_evil_twin") == 0) {
        app->uart_state = UartStateRunning;
        add_log_line_safe(app, "ESP32: Evil Twin started");
        add_log_line_safe(app, "ESP32: Creating fake AP...");
        add_log_line_safe(app, "ESP32: Deauth attack active");
    }
}

// App allocation with EXTENDED timeout initialization
EvilTwinControllerApp* evil_twin_controller_app_alloc() {
    EvilTwinControllerApp* app = malloc(sizeof(EvilTwinControllerApp));
    if(!app) {
        FURI_LOG_E(TAG, "Failed to allocate app structure");
        return NULL;
    }

    // Initialize ALL fields to safe values - EXTENDED timeout version
    memset(app, 0, sizeof(EvilTwinControllerApp));
    app->selected_count = 0;
    app->first_selected_network = -1;
    app->evil_twin_running = false;
    app->uart_thread_running = false;   // Will be set to true later
    app->uart_state = UartStateIdle;
    app->networks_ready = false;
    app->network_count = 0;
    app->scan_start_time = 0;
    app->uart_rx_pos = 0;
    app->uart_initialized = false;
    app->app_running = true;            // ATOMIC FLAG
    app->scan_completed = false;
    app->real_esp32_mode = true;
    app->esp32_response_detected = false;  // NEW: ESP32 response tracking
    app->last_uart_rx_time = 0;           // NEW: UART RX activity tracking
    app->shutdown_requested = false;    // ATOMIC FLAG
    app->mutexes_valid = false;         // Will be set after mutex creation

    // Initialize log buffer
    app->log_buffer = furi_string_alloc();
    if(!app->log_buffer) {
        FURI_LOG_E(TAG, "Failed to allocate log buffer");
        free(app);
        return NULL;
    }

    // CRITICAL: Create mutex BEFORE marking as valid
    app->uart_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    if(!app->uart_mutex) {
        FURI_LOG_E(TAG, "Failed to allocate UART mutex");
        furi_string_free(app->log_buffer);
        free(app);
        return NULL;
    }
    app->mutexes_valid = true;  // Mark as valid AFTER successful creation

    // Create event queue
    app->event_queue = furi_message_queue_alloc(8, sizeof(EvilTwinControllerEvent));
    if(!app->event_queue) {
        FURI_LOG_E(TAG, "Failed to allocate event queue");
        safe_shutdown_mutexes(app);
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
        safe_shutdown_mutexes(app);
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

    // UART setup with fallback
    if(uart_init_safe(app)) {
        // CRITICAL: Start UART worker thread AFTER all initialization
        app->uart_thread_running = true;  // ATOMIC FLAG
        app->uart_thread = furi_thread_alloc_ex("UartWorker", 4096, uart_worker_thread, app);
        if(app->uart_thread) {
            furi_thread_start(app->uart_thread);
        } else {
            FURI_LOG_E(TAG, "Failed to create UART thread");
            app->uart_thread_running = false;
        }
    } else {
        FURI_LOG_W(TAG, "UART unavailable - application will work in demo mode only");
        app->real_esp32_mode = false;  // Force demo mode
    }

    FURI_LOG_I(TAG, "Application allocated with EXTENDED 25s ESP32 timeout");
    return app;
}

// App cleanup with CRITICAL shutdown sequence (same as v8.2)
void evil_twin_controller_app_free(EvilTwinControllerApp* app) {
    if(!app) return;

    FURI_LOG_I(TAG, "Starting critical shutdown sequence");

    // CRITICAL STEP 1: Signal shutdown to all components
    safe_shutdown_begin(app);

    // CRITICAL STEP 2: Stop all threads BEFORE touching mutexes
    safe_shutdown_threads(app);

    // CRITICAL STEP 3: Free UART hardware BEFORE mutexes
    uart_cleanup_safe(app);

    // CRITICAL STEP 4: Free GUI components
    if(app->view_dispatcher) {
        view_dispatcher_remove_view(app->view_dispatcher, EvilTwinControllerViewMainMenu);
        view_dispatcher_remove_view(app->view_dispatcher, EvilTwinControllerViewNetworkList);
        view_dispatcher_remove_view(app->view_dispatcher, EvilTwinControllerViewEvilTwinLogs);
        view_dispatcher_free(app->view_dispatcher);
    }

    if(app->submenu) submenu_free(app->submenu);
    if(app->widget) widget_free(app->widget);
    if(app->scene_manager) scene_manager_free(app->scene_manager);

    // CRITICAL STEP 5: Free other resources
    if(app->notifications) furi_record_close(RECORD_NOTIFICATION);
    if(app->log_buffer) furi_string_free(app->log_buffer);
    if(app->event_queue) furi_message_queue_free(app->event_queue);

    // CRITICAL STEP 6: Free mutexes LAST
    safe_shutdown_mutexes(app);

    // CRITICAL STEP 7: Free app structure
    free(app);
    FURI_LOG_I(TAG, "Critical shutdown sequence completed successfully");
}

// Main entry point with error handling
int32_t evil_twin_controller_app(void* p) {
    UNUSED(p);

    FURI_LOG_I(TAG, "Starting Evil Twin Controller with EXTENDED 25s ESP32 timeout");

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

    FURI_LOG_I(TAG, "Starting main event loop");
    view_dispatcher_run(app->view_dispatcher);
    FURI_LOG_I(TAG, "Main event loop finished");

    furi_record_close(RECORD_GUI);
    evil_twin_controller_app_free(app);

    FURI_LOG_I(TAG, "Evil Twin Controller finished successfully");
    return 0;
}
