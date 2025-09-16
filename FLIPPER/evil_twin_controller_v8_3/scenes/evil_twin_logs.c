#include "../evil_twin_controller_i.h"

#define MAX_LOG_DISPLAY_LINES 5

// SAFE alternative to strtok - split string by newlines with bounds checking
static int split_lines_safe(char* buffer, char** lines, int max_lines) {
    if(!buffer || !lines || max_lines <= 0) return 0;

    int line_count = 0;
    char* current = buffer;
    char* line_start = buffer;

    while(*current && line_count < max_lines) {
        if(*current == '\n') {
            *current = '\0';  // Terminate current line
            if(line_start != current && strlen(line_start) > 0) {  // Skip empty lines
                lines[line_count++] = line_start;
            }
            line_start = current + 1;
        }
        current++;

        // Safety check against infinite loops
        if(current - buffer > 2048) break;
    }

    // Handle last line if it doesn't end with newline
    if(line_start != current && *line_start != '\0' && line_count < max_lines) {
        if(strlen(line_start) > 0) {
            lines[line_count++] = line_start;
        }
    }

    return line_count;
}

// Draw callback for logs with comprehensive NULL safety
static void logs_draw_callback(Canvas* canvas, void* context) {
    SAFE_CHECK(canvas);
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = (EvilTwinControllerApp*)context;

    if(app->shutdown_requested) return;  // Don't draw during shutdown

    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);

    // Header
    canvas_draw_str(canvas, 2, 8, "Evil Twin - Logi UART");
    canvas_draw_str(canvas, 85, 8, app->evil_twin_running ? "ACTIVE" : "STOP");
    canvas_draw_line(canvas, 0, 10, 128, 10);

    // Display logs from log buffer safely
    if(!app->log_buffer) {
        canvas_draw_str(canvas, 10, 35, "Log buffer error!");
        return;
    }

    const char* log_str = furi_string_get_cstr(app->log_buffer);
    if(!log_str) {
        canvas_draw_str(canvas, 10, 35, "Log string error!");
        return;
    }

    size_t log_len = strlen(log_str);
    if(log_len == 0) {
        canvas_draw_str(canvas, 10, 35, "Brak logów...");
        canvas_draw_str(canvas, 5, 45, "Uruchom atak");
        return;
    }

    // Split logs into lines and show last few - WITHOUT strtok!
    char temp_buffer[2048];
    size_t copy_len = (log_len < sizeof(temp_buffer) - 1) ? log_len : sizeof(temp_buffer) - 1;
    strncpy(temp_buffer, log_str, copy_len);
    temp_buffer[copy_len] = '\0';

    // SAFE: Use safe line splitting instead of strtok
    char* lines[20];
    int line_count = split_lines_safe(temp_buffer, lines, 20);

    if(line_count == 0) {
        canvas_draw_str(canvas, 10, 35, "No valid log lines");
        return;
    }

    // Display last MAX_LOG_DISPLAY_LINES lines
    int start_line = (line_count > MAX_LOG_DISPLAY_LINES) ? 
                    line_count - MAX_LOG_DISPLAY_LINES : 0;

    int y = 20;
    for(int i = start_line; i < line_count && y < 60 && i >= 0; i++) {
        if(!lines[i]) continue; // Skip NULL lines

        // Truncate long lines to fit screen
        char display_line[50];
        size_t line_len = strlen(lines[i]);
        size_t display_len = (line_len < sizeof(display_line) - 1) ? line_len : sizeof(display_line) - 1;
        strncpy(display_line, lines[i], display_len);
        display_line[display_len] = '\0';

        canvas_draw_str(canvas, 2, y, display_line);
        y += 9;
    }

    // Show line count
    if(line_count > MAX_LOG_DISPLAY_LINES) {
        char info[20];
        snprintf(info, sizeof(info), "...+%d more", 
                line_count - MAX_LOG_DISPLAY_LINES);
        canvas_draw_str(canvas, 85, 63, info);
    }

    // Footer
    canvas_draw_str(canvas, 2, 63, "Back=Stop & Menu");
}

// Input callback for logs with NULL safety
static bool logs_input_callback(InputEvent* event, void* context) {
    SAFE_CHECK_RETURN(event, false);
    SAFE_CHECK_RETURN(context, false);
    EvilTwinControllerApp* app = (EvilTwinControllerApp*)context;

    if(app->shutdown_requested) return false;  // Don't handle input during shutdown

    bool consumed = false;

    if(event->type == InputTypeShort) {
        switch(event->key) {
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

void evil_twin_controller_scene_evil_twin_logs_on_enter(void* context) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;

    if(app->shutdown_requested) return;

    // Start evil twin
    app->evil_twin_running = true;
    app->uart_state = UartStateRunning;

    // Setup widget safely
    if(app->widget) {
        widget_reset(app->widget);

        View* view = widget_get_view(app->widget);
        if(view) {
            view_set_context(view, app);
            view_set_draw_callback(view, logs_draw_callback);
            view_set_input_callback(view, logs_input_callback);
        }
    }

    if(app->view_dispatcher && !app->shutdown_requested) {
        view_dispatcher_switch_to_view(app->view_dispatcher, EvilTwinControllerViewEvilTwinLogs);
    }

    if(app->notifications && !app->shutdown_requested) {
        notification_message(app->notifications, &sequence_single_vibro);
    }

    FURI_LOG_I(TAG, "Evil twin logs entered");
}

bool evil_twin_controller_scene_evil_twin_logs_on_event(void* context, SceneManagerEvent event) {
    SAFE_CHECK_RETURN(context, false);
    EvilTwinControllerApp* app = context;

    if(app->shutdown_requested) return false;

    // Handle UART RX events to update display
    if(event.type == SceneManagerEventTypeCustom) {
        // Trigger view update when new data arrives
        if(app->view_dispatcher && !app->shutdown_requested) {
            view_dispatcher_send_custom_event(app->view_dispatcher, 0);
        }
        return true;
    }

    return false;
}

void evil_twin_controller_scene_evil_twin_logs_on_exit(void* context) {
    SAFE_CHECK(context);
    EvilTwinControllerApp* app = context;

    // Stop evil twin
    app->evil_twin_running = false;
    app->uart_state = UartStateIdle;
    uart_send_command_safe(app, "stop");

    if(app->widget) {
        View* view = widget_get_view(app->widget);
        if(view) {
            view_set_draw_callback(view, NULL);
            view_set_input_callback(view, NULL);
        }
        widget_reset(app->widget);
    }

    FURI_LOG_I(TAG, "Evil twin logs exited");
}
