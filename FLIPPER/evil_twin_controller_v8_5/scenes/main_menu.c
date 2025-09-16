#include "../evil_twin_controller_i.h"

enum SubmenuIndex {
    SubmenuIndexScanNetworks,
    SubmenuIndexReboot,
};

void evil_twin_controller_scene_main_menu_submenu_callback(void* context, uint32_t index) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;
    if(app->shutdown_requested) return;  // Don't handle during shutdown
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void evil_twin_controller_scene_main_menu_on_enter(void* context) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;

    if(app->shutdown_requested) return;

    if(!app->submenu) {
        FURI_LOG_E(TAG, "Submenu is NULL");
        return;
    }

    Submenu* submenu = app->submenu;

    submenu_add_item(
        submenu,
        "Skanowanie sieci",
        SubmenuIndexScanNetworks,
        evil_twin_controller_scene_main_menu_submenu_callback,
        app
    );

    submenu_add_item(
        submenu,
        "Reboot urządzenia",
        SubmenuIndexReboot,
        evil_twin_controller_scene_main_menu_submenu_callback,
        app
    );

    if(app->scene_manager) {
        submenu_set_selected_item(
            submenu, scene_manager_get_scene_state(app->scene_manager, EvilTwinControllerSceneMainMenu)
        );
    }

    if(app->view_dispatcher) {
        view_dispatcher_switch_to_view(app->view_dispatcher, EvilTwinControllerViewMainMenu);
    }

    FURI_LOG_I(TAG, "Main menu entered");
}

bool evil_twin_controller_scene_main_menu_on_event(void* context, SceneManagerEvent event) {
    SAFE_CHECK_RETURN(context, false);
    EvilTwinControllerApp* app = context;

    if(app->shutdown_requested) return false;  // Don't handle during shutdown

    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == SubmenuIndexScanNetworks) {
            // PROBLEM 1 FIX: Clear previous networks first
            clear_networks_safe(app);

            // PROBLEM 1 FIX: Try to send scan command and check if it succeeded
            bool uart_success = uart_send_command_safe(app, "scan_networks");

            if(uart_success) {
                // UART WORKS: Set scanning state and wait for ESP32
                app->uart_state = UartStateScanning;
                app->networks_ready = false;
                app->scan_completed = false;
                app->esp32_response_detected = false;
                app->scan_start_time = furi_get_tick();  // Start timing
                app->real_esp32_mode = true;

                add_log_line_safe(app, "Waiting for ESP32 response (up to 25 seconds)...");
                FURI_LOG_I(TAG, "ESP32 scan started via UART, timeout: %d seconds", SCAN_TIMEOUT_MS/1000);
            } else {
                // PROBLEM 1 FIX: UART FAILED - go to fallback mode immediately
                FURI_LOG_W(TAG, "UART failed, starting immediate fallback simulation");
                app->uart_state = UartStateScanning;  // Still show scanning UI
                app->networks_ready = false;
                app->scan_completed = false;
                app->esp32_response_detected = false;
                app->scan_start_time = furi_get_tick();
                app->real_esp32_mode = false;  // Switch to simulation mode

                add_log_line_safe(app, "UART not available - starting demo simulation");
                add_log_line_safe(app, "Connect ESP32 for real scanning");

                // Start fallback simulation immediately (in separate thread)
                // The UART worker thread will handle the simulation
            }

            // Force UI refresh to show scanning state
            force_ui_refresh(app);

            // Switch to network list scene
            if(app->scene_manager && !app->shutdown_requested) {
                scene_manager_next_scene(app->scene_manager, EvilTwinControllerSceneNetworkList);
            }
            consumed = true;

        } else if(event.event == SubmenuIndexReboot) {
            // Send reboot command via UART (if available)
            bool uart_success = uart_send_command_safe(app, "reboot");

            if(uart_success) {
                add_log_line_safe(app, "Reboot command sent to ESP32");
            } else {
                add_log_line_safe(app, "Cannot reboot - UART not available");
            }

            // Show notification
            if(app->notifications) {
                notification_message(app->notifications, &sequence_success);
            }
            consumed = true;
        }

        if(app->scene_manager) {
            scene_manager_set_scene_state(app->scene_manager, EvilTwinControllerSceneMainMenu, event.event);
        }
    }

    return consumed;
}

void evil_twin_controller_scene_main_menu_on_exit(void* context) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;

    if(app->submenu) {
        submenu_reset(app->submenu);
    }

    FURI_LOG_I(TAG, "Main menu exited");
}
