#include "../evil_twin_controller_i.h"

enum SubmenuIndex {
    SubmenuIndexScanNetworks,
    SubmenuIndexReboot,
};

void evil_twin_controller_scene_main_menu_submenu_callback(void* context, uint32_t index) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void evil_twin_controller_scene_main_menu_on_enter(void* context) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;

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
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == SubmenuIndexScanNetworks) {
            // Clear previous networks and send scan command
            clear_networks_safe(app);
            uart_send_command_safe(app, "scan_networks");

            // Switch to network list scene
            if(app->scene_manager) {
                scene_manager_next_scene(app->scene_manager, EvilTwinControllerSceneNetworkList);
            }
            consumed = true;
        } else if(event.event == SubmenuIndexReboot) {
            // Send reboot command via UART
            uart_send_command_safe(app, "reboot");

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
