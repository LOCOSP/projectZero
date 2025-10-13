#include "evil_esp.h"
#include <furi_hal.h>
#include <ctype.h>

#define BAUDRATE (115200)
#define RX_BUFFER_SIZE (512)
#define MAX_RECENT_COMMANDS 10
#define COMMAND_ECHO_TIMEOUT_MS 10000

// Forward declarations for response handler functions
static void handle_info_response(EvilEspUartWorker* worker, const char* line);
static void handle_error_response(EvilEspUartWorker* worker, const char* line);
static void handle_debug_response(EvilEspUartWorker* worker, const char* line);
static void handle_cmd_response(EvilEspUartWorker* worker, const char* line);
static void handle_mgmt_response(EvilEspUartWorker* worker, const char* line);
static void handle_data_response(EvilEspUartWorker* worker, const char* line);
static void handle_hop_response(EvilEspUartWorker* worker, const char* line);
static void handle_generic_response(EvilEspUartWorker* worker, const char* line);
static void parse_scan_result_line(EvilEspUartWorker* worker, const char* line);
static void parse_portal_line(EvilEspUartWorker* worker, const char* line);
static bool is_command_echo(EvilEspUartWorker* worker, const char* line);
static void store_sent_command(EvilEspUartWorker* worker, const char* command);

struct EvilEspUartWorker {
    FuriThread* thread;
    FuriStreamBuffer* rx_stream;
    FuriHalSerialHandle* serial_handle;
    bool running;
    EvilEspApp* app;
    FuriMutex* tx_mutex;
    char recent_commands[MAX_RECENT_COMMANDS][64];
    uint32_t command_timestamps[MAX_RECENT_COMMANDS];
    int recent_command_index;
    char* line_buffer; // Move line buffer to heap to reduce stack usage
    bool portal_list_active; // Flag to indicate we're parsing portal list
    uint32_t portal_list_last_line_time; // Timestamp of last line during portal parsing
};

static EvilEspUartWorker* uart_worker = NULL;

// UART receive callback function
static void uart_on_irq_cb(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context) {
    EvilEspUartWorker* worker = (EvilEspUartWorker*)context;

    if(event == FuriHalSerialRxEventData) {
        // Read available data and put it in stream buffer
        while(furi_hal_serial_async_rx_available(handle)) {
            uint8_t data = furi_hal_serial_async_rx(handle);
            furi_stream_buffer_send(worker->rx_stream, &data, 1, 0);
        }
    }
}

// Worker thread for processing UART data
static int32_t uart_worker_thread(void* context) {
    EvilEspUartWorker* worker = (EvilEspUartWorker*)context;

    char* line_buffer = worker->line_buffer; // Use heap-allocated buffer
    size_t line_pos = 0;
    const size_t max_line_size = 4096;

    while(worker->running) {
        uint8_t byte;
        size_t received = furi_stream_buffer_receive(worker->rx_stream, &byte, 1, 100);

        // Check portal list timeout (2 seconds without new data)
        if(worker->portal_list_active && worker->app) {
            uint32_t elapsed = furi_get_tick() - worker->portal_list_last_line_time;
            if(elapsed > 2000) {
                FURI_LOG_W("EvilEsp", "[UART Parser] !!! PORTAL LIST TIMEOUT after %lu ms without new data !!!", elapsed);
                FURI_LOG_I("EvilEsp", "[UART Parser] Auto-ending portal list with %u portals", worker->app->portal_count);
                
                worker->portal_list_active = false;
                worker->app->portal_scan_in_progress = false;
                
                if(worker->app->portal_count > 0) {
                    FURI_LOG_I("EvilEsp", "[UART Parser] Sending EvilEspEventPortalScanComplete (timeout, %u portals)", worker->app->portal_count);
                    if(worker->app->view_dispatcher) {
                        view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventPortalScanComplete);
                    }
                } else {
                    FURI_LOG_W("EvilEsp", "[UART Parser] Timeout with 0 portals - sending completion anyway");
                    if(worker->app->view_dispatcher) {
                        view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventPortalScanComplete);
                    }
                }
            }
        }

        if(received > 0) {
            // Handle incoming byte
            if(byte == '\n' || byte == '\r') {
                if(line_pos > 0) {
                    line_buffer[line_pos] = '\0';

                    // Skip empty lines UNLESS we're parsing portals (empty line = end marker)
                    if(strlen(line_buffer) == 0) {
                        if(worker->portal_list_active) {
                            FURI_LOG_I("EvilEsp", "[UART Parser] !!!! EMPTY LINE while portal_list_active - this is END MARKER !!!!");
                            // DON'T skip - let it be processed as end marker below
                            // Fall through to portal list parsing code
                        } else {
                            // Normal case: skip empty lines
                            line_pos = 0;
                            continue;
                        }
                    }

                    // Filter out WebUI spam patterns to reduce log noise
                    if(strstr(line_buffer, "WebSocket") != NULL ||
                       strstr(line_buffer, "HTTP GET") != NULL ||
                       strstr(line_buffer, "Content-Type:") != NULL ||
                       strstr(line_buffer, "Connection:") != NULL ||
                       (line_buffer[0] == '{' && strstr(line_buffer, "\"type\"") != NULL)) {
                        line_pos = 0;
                        continue; // Skip WebUI internal messages
                    }

                    // Process complete line
                    FURI_LOG_I("EvilEsp", "RX: %s", line_buffer);

                    // Check if this is a command echo - but still process it for debugging
                    bool is_echo = is_command_echo(worker, line_buffer);
                    
                    // ALWAYS log to SD card for debugging
                    debug_write_to_sd(line_buffer);

                    // Check for portal list start
                    if(strstr(line_buffer, "HTML files found on SD card:") != NULL) {
                        if(worker->app) {
                            worker->app->portal_count = 0;
                            memset(worker->app->portals, 0, sizeof(worker->app->portals));
                            worker->portal_list_active = true;
                            worker->portal_list_last_line_time = furi_get_tick();
                            FURI_LOG_I("EvilEsp", "[UART Parser] *** PORTAL LIST START *** Line: '%s'", line_buffer);
                            FURI_LOG_I("EvilEsp", "[UART Parser] portal_list_active=TRUE, waiting for portal entries...");
                        }
                    } else if(strstr(line_buffer, "list_sd") != NULL) {
                        FURI_LOG_I("EvilEsp", "[UART Parser] Detected list_sd in line: '%s'", line_buffer);
                    }
                    
                    // Handle portal list parsing
                    if(worker->portal_list_active && worker->app) {
                        // Update timestamp - we got a line
                        worker->portal_list_last_line_time = furi_get_tick();
                        
                        FURI_LOG_D("EvilEsp", "[UART Parser] Portal list active, checking line: '%s'", line_buffer);
                        
                        // Skip the header line itself
                        if(strstr(line_buffer, "HTML files found") != NULL) {
                            // Just skip, keep portal_list_active true
                            FURI_LOG_I("EvilEsp", "[UART Parser] Skipping header line");
                        }
                        // Check if this looks like a portal line (starts with digit)
                        else if(line_buffer[0] >= '0' && line_buffer[0] <= '9') {
                            // Only parse if there's actually content after the number
                            const char* p = line_buffer;
                            while(*p >= '0' && *p <= '9') p++;
                            while(*p == ' ' || *p == '\t') p++;
                            
                            if(*p != '\0' && strlen(p) > 0) {
                                FURI_LOG_I("EvilEsp", "[UART Parser] Parsing portal entry: '%s'", line_buffer);
                                parse_portal_line(worker, line_buffer);
                                FURI_LOG_I("EvilEsp", "[UART Parser] Total portals so far: %u", worker->app->portal_count);
                            } else {
                                FURI_LOG_W("EvilEsp", "[UART Parser] Portal line has no filename: '%s'", line_buffer);
                            }
                        } 
                        // End of portal list if we get a non-portal line
                        else if(strlen(line_buffer) == 0 || 
                                line_buffer[0] == '>' || 
                                line_buffer[0] == '\r' || 
                                line_buffer[0] == '\n') {
                            // Empty line or prompt = end of list
                            FURI_LOG_I("EvilEsp", "[UART Parser] *** END MARKER DETECTED *** (empty/prompt line)");
                            if(worker->app->portal_count > 0) {
                                worker->portal_list_active = false;
                                worker->app->portal_scan_in_progress = false;
                                FURI_LOG_I("EvilEsp", "[UART Parser] *** PORTAL LIST END: %d portals found ***", worker->app->portal_count);
                                FURI_LOG_I("EvilEsp", "[UART Parser] Sending EvilEspEventPortalScanComplete (value=%d)", EvilEspEventPortalScanComplete);
                                // Send event to update portal list scene
                                if(worker->app->view_dispatcher) {
                                    view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventPortalScanComplete);
                                    FURI_LOG_I("EvilEsp", "[UART Parser] Event sent successfully!");
                                } else {
                                    FURI_LOG_E("EvilEsp", "[UART Parser] ERROR: view_dispatcher is NULL!");
                                }
                            } else {
                                // No portals found yet, but got empty line - might be end
                                FURI_LOG_W("EvilEsp", "[UART Parser] Empty line but no portals found yet, ending anyway");
                                // Send completion event anyway to show "no portals" message
                                worker->portal_list_active = false;
                                worker->app->portal_scan_in_progress = false;
                                FURI_LOG_I("EvilEsp", "[UART Parser] Sending completion event (0 portals)");
                                if(worker->app->view_dispatcher) {
                                    view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventPortalScanComplete);
                                }
                            }
                        }
                        else {
                            // Some other line that doesn't look like a portal
                            FURI_LOG_W("EvilEsp", "[UART Parser] Unexpected line in portal mode: '%s'", line_buffer);
                        }
                    }

                    // Check for scan start/completion messages FIRST (before any other processing)
                    // Scan start: "WiFi scan completed", "Found X networks", "Retrieved X network records"
                    if(strstr(line_buffer, "WiFi scan completed") != NULL || 
                       strstr(line_buffer, "Retrieved") != NULL ||
                       (strstr(line_buffer, "Found") != NULL && strstr(line_buffer, "network") != NULL)) {
                        if(worker->app) {
                            worker->app->network_count = 0;
                            memset(worker->app->networks, 0, sizeof(worker->app->networks));
                            worker->app->scan_in_progress = true;
                            FURI_LOG_I("EvilEsp", "SCAN START detected: '%s' - ready to parse CSV", line_buffer);
                        }
                    }
                    // Scan end: "Scan results printed"
                    else if(strstr(line_buffer, "Scan results printed") != NULL) {
                        if(worker->app) {
                            worker->app->scan_in_progress = false;
                            FURI_LOG_I("EvilEsp", "SCAN END detected: %d networks parsed", worker->app->network_count);
                            if(worker->app->view_dispatcher) {
                                view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventScanComplete);
                            }
                        }
                    }

                    // Check if this is a CSV scan result line (without [INFO] prefix)
                    // Format: "1","SSID","BSSID","channel","auth","rssi","freq"
                    if(line_buffer[0] == '"' && strstr(line_buffer, "\",\"") != NULL && strlen(line_buffer) > 20) {
                        FURI_LOG_I("EvilEsp", "CSV line detected: scan_in_progress=%d", worker->app ? worker->app->scan_in_progress : -1);
                        if(worker->app && worker->app->scan_in_progress) {
                            FURI_LOG_I("EvilEsp", "Parsing CSV scan line (no prefix): %s", line_buffer);
                            // Add [INFO] prefix for parser compatibility
                            char temp_line[512];
                            snprintf(temp_line, sizeof(temp_line), "[INFO] %s", line_buffer);
                            parse_scan_result_line(worker, temp_line);
                            FURI_LOG_I("EvilEsp", "After parse: network_count=%d", worker->app->network_count);
                        } else {
                            FURI_LOG_W("EvilEsp", "CSV line ignored - not in scan mode");
                        }
                    }
                    // Parse different response types (even if echo, for debugging)
                    else if(strncmp(line_buffer, "[INFO]", 6) == 0) {
                        handle_info_response(worker, line_buffer);
                    }
                    else if(strncmp(line_buffer, "[ERROR]", 7) == 0) {
                        handle_error_response(worker, line_buffer);
                    }
                    else if(strncmp(line_buffer, "[DEBUG]", 7) == 0) {
                        handle_debug_response(worker, line_buffer);
                    }
                    else if(strncmp(line_buffer, "[CMD]", 5) == 0) {
                        handle_cmd_response(worker, line_buffer);
                    }
                    else if(strncmp(line_buffer, "[MGMT]", 6) == 0) {
                        handle_mgmt_response(worker, line_buffer);
                    }
                    else if(strncmp(line_buffer, "[DATA]", 6) == 0) {
                        handle_data_response(worker, line_buffer);
                    }
                    else if(strncmp(line_buffer, "[HOP]", 5) == 0) {
                        handle_hop_response(worker, line_buffer);
                    }
                    else if(strncmp(line_buffer, "RAW UART RX:", 12) == 0 ||
                            strncmp(line_buffer, "Received Command:", 17) == 0 ||
                            strncmp(line_buffer, "SCAN COMMAND", 12) == 0) {
                        // These are our debug messages from Arduino - handle specially
                        handle_debug_response(worker, line_buffer);
                    }
                    else if(!is_echo) {
                        // Generic response - process all non-echo responses
                        if(strlen(line_buffer) > 3) { // Only process substantial responses
                            handle_generic_response(worker, line_buffer);
                        }
                    }

                    // ALWAYS add to app log for live display (even command echoes)
                    if(worker->app) {
                        evil_esp_append_log(worker->app, line_buffer);

                        // Send immediate UI update for every line UNLESS we're parsing portals
                        // (to avoid flooding the portal scene with refresh events)
                        if(worker->app->view_dispatcher && !worker->portal_list_active) {
                            // Simply send refresh event - the scene handler will ignore it if not in UART terminal
                            view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventUartTerminalRefresh);
                        }
                    }
                }
                line_pos = 0;
            }
            else if(line_pos < max_line_size - 1) {
                line_buffer[line_pos++] = byte;
            } else {
                // Line too long, reset to prevent buffer overflow
                line_pos = 0;
                FURI_LOG_W("EvilEsp", "Line buffer overflow, resetting");
            }
        }
    }

    return 0;
}

// Response handler functions
static void handle_info_response(EvilEspUartWorker* worker, const char* line) {
    if(!worker->app) return;

    FURI_LOG_I("EvilEsp", "[INFO] handler: %s", line);

    // Parse scan results - look for the actual header format
    if(strstr(line, "Index") != NULL && strstr(line, "SSID") != NULL && strstr(line, "BSSID") != NULL) {
        // This is a scan result header - clear previous results
        worker->app->network_count = 0;
        memset(worker->app->networks, 0, sizeof(worker->app->networks));
        worker->app->scan_in_progress = true;
        FURI_LOG_I("EvilEsp", "Scan results header detected - cleared previous results");
    }
    // Look for actual scan result lines - must start with "[INFO] " followed by CSV format
    else if(strncmp(line, "[INFO] ", 7) == 0 && strlen(line) > 8) {
        const char* after_prefix = line + 7; // Skip "[INFO] "
        // Check if this looks like CSV data (starts with quote or digit)
        if((after_prefix[0] == '"' && strstr(after_prefix, "\",\"") != NULL) || 
           (isdigit((unsigned char)after_prefix[0]) && strstr(after_prefix, ",") != NULL)) {
            // This looks like a scan result line in CSV format
            FURI_LOG_I("EvilEsp", "Attempting to parse CSV scan line");
            parse_scan_result_line(worker, line);
        } else {
            FURI_LOG_D("EvilEsp", "INFO line doesn't match CSV format: %s", after_prefix);
        }
    }
    // Scan completion - wait for "Scan results printed" message
    else if(strstr(line, "Scan results printed") != NULL || 
            strstr(line, "Scan completed") != NULL ||
            strstr(line, "scan complete") != NULL ||
            strstr(line, "Networks found") != NULL) {
        // Scan finished - update UI
        worker->app->scan_in_progress = false;
        FURI_LOG_I("EvilEsp", "Scan completed with %d networks", worker->app->network_count);
        // Send event to update scanner scene
        if(worker->app->view_dispatcher) {
            view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventScanComplete);
        }
    }
    else if(strstr(line, "Deauth") != NULL || strstr(line, "deauth") != NULL) {
        // Attack progress notification
        FURI_LOG_I("EvilEsp", "Attack progress: %s", line);
    }
    else {
        // Log any other INFO messages for debugging
        FURI_LOG_D("EvilEsp", "Unhandled INFO: %s", line);
    }
}

static void handle_error_response(EvilEspUartWorker* worker, const char* line) {
    UNUSED(worker);
    FURI_LOG_E("EvilEsp", "[ERROR] handler: %s", line);
}

static void handle_debug_response(EvilEspUartWorker* worker, const char* line) {
    UNUSED(worker);
    FURI_LOG_D("EvilEsp", "[DEBUG] handler: %s", line);
}

static void handle_cmd_response(EvilEspUartWorker* worker, const char* line) {
    if(!worker->app) return;

    FURI_LOG_I("EvilEsp", "[CMD] handler: %s", line);

    // Update sniffer state based on command responses
    if(strstr(line, "sniffing mode") != NULL) {
        worker->app->sniffer_state.is_running = true;
        // Send event to update sniffer UI
        if(worker->app->view_dispatcher) {
            view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventSnifferStarted);
        }
    }
    else if(strstr(line, "Sniffer stopped") != NULL) {
        worker->app->sniffer_state.is_running = false;
        if(worker->app->view_dispatcher) {
            view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventSnifferStopped);
        }
    }
}

static void handle_mgmt_response(EvilEspUartWorker* worker, const char* line) {
    if(!worker->app) return;

    // Increment packet count for management frames
    worker->app->sniffer_state.packet_count++;

    // Log the management frame
    FURI_LOG_I("EvilEsp", "MGMT Frame: %s", line);

    // Send event to update sniffer UI if in sniffer scene
    if(worker->app->view_dispatcher) {
        view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventPacketReceived);
    }
}

static void handle_data_response(EvilEspUartWorker* worker, const char* line) {
    if(!worker->app) return;

    // Increment packet count for data frames
    worker->app->sniffer_state.packet_count++;

    // Log the data frame (especially EAPOL)
    FURI_LOG_I("EvilEsp", "DATA Frame: %s", line);

    // Special handling for EAPOL
    if(strstr(line, "EAPOL") != NULL) {
        FURI_LOG_I("EvilEsp", "EAPOL handshake detected!");
        // Could add special notification here
    }

    if(worker->app->view_dispatcher) {
        view_dispatcher_send_custom_event(worker->app->view_dispatcher, EvilEspEventPacketReceived);
    }
}

static void handle_hop_response(EvilEspUartWorker* worker, const char* line) {
    UNUSED(worker);
    FURI_LOG_I("EvilEsp", "Channel hop: %s", line);
}

static void handle_generic_response(EvilEspUartWorker* worker, const char* line) {
    if(!worker || !line) return;
    
    FURI_LOG_I("EvilEsp", "[GENERIC] handler: %s", line);
    
    // NOTE: Scan start/end detection is now handled in main worker loop
    // to avoid double processing
    
    // Check if this might be a response to select_networks or start_deauth
    if(strstr(line, "select") != NULL || strstr(line, "network") != NULL || 
       strstr(line, "target") != NULL || strstr(line, "deauth") != NULL ||
       strstr(line, "attack") != NULL || strstr(line, "start") != NULL) {
        FURI_LOG_I("EvilEsp", "Possible command response detected: %s", line);
    }
}

static void parse_scan_result_line(EvilEspUartWorker* worker, const char* line) {
    if(!worker || !worker->app) return;
    if(worker->app->network_count >= EVIL_ESP_MAX_NETWORKS) return;

    // Skip "[INFO] " prefix (7 characters)
    const char* data = line + 7;
    
    // Sprawdź czy linia zaczyna się od cudzysłowu (format CSV)
    if(data[0] != '"') {
        return; // To nie jest linia CSV z wynikami skanowania
    }

    FURI_LOG_I("EvilEsp", "Parsing CSV scan line: %s", data);
    
    // Pola do wypełnienia - dodano auth między channel a rssi
    char index_str[16] = "";
    char ssid[64] = "";
    char bssid[32] = "";
    char channel_str[16] = "";
    char auth[32] = "";
    char rssi_str[16] = "";
    char freq_str[16] = "";
    
    // Parsowanie CSV - format: index,ssid,bssid,channel,auth,rssi,freq
    const char* fields[] = {index_str, ssid, bssid, channel_str, auth, rssi_str, freq_str};
    size_t field_sizes[] = {sizeof(index_str), sizeof(ssid), sizeof(bssid), 
                           sizeof(channel_str), sizeof(auth), sizeof(rssi_str), sizeof(freq_str)};
    
    int field_count = sizeof(fields) / sizeof(fields[0]);
    int current_field = 0;
    const char* pos = data;
    
    while(*pos && current_field < field_count) {
        // Oczekuj cudzysłowu na początku pola
        if(*pos != '"') break;
        pos++; // Pomiń otwierający cudzysłów
        
        // Czytaj zawartość pola
        char* field_ptr = (char*)fields[current_field];
        size_t field_pos = 0;
        size_t max_len = field_sizes[current_field] - 1;
        
        while(*pos && field_pos < max_len) {
            if(*pos == '"') {
                // Sprawdź czy to escape'owany cudzysłów
                if(*(pos + 1) == '"') {
                    // Podwójny cudzysłów = escape'owany cudzysłów
                    field_ptr[field_pos++] = '"';
                    pos += 2; // Pomiń oba cudzysłowy
                } else {
                    // Pojedynczy cudzysłów = koniec pola
                    break;
                }
            } else {
                field_ptr[field_pos++] = *pos;
                pos++;
            }
        }
        field_ptr[field_pos] = '\0';
        
        // Pomiń zamykający cudzysłów
        if(*pos == '"') pos++;
        
        // Pomiń przecinek i spacje
        while(*pos && (*pos == ',' || *pos == ' ')) pos++;
        
        current_field++;
    }
    
    // Sprawdź czy mamy wszystkie wymagane pola (index,ssid,bssid,channel,auth,rssi,freq = 7 pól)
    if(current_field < 7 || strlen(index_str) == 0 || strlen(bssid) == 0) {
        FURI_LOG_W("EvilEsp", "Missing required fields in CSV scan line (expected 7, got %d)", current_field);
        return;
    }
    
    // Reszta parsowania jak poprzednio...
    int network_idx = worker->app->network_count;
    EvilEspNetwork* network = &worker->app->networks[network_idx];
    
    int device_index = atoi(index_str);
    
    network->index = network_idx;
    network->device_index = device_index;
    network->selected = false;
    
    // Kopiuj SSID
    if(strlen(ssid) == 0) {
        strcpy(network->ssid, "<Hidden Network>");
    } else {
        strncpy(network->ssid, ssid, sizeof(network->ssid) - 1);
        network->ssid[sizeof(network->ssid) - 1] = '\0';
    }
    
    // Kopiuj BSSID
    strncpy(network->bssid, bssid, sizeof(network->bssid) - 1);
    network->bssid[sizeof(network->bssid) - 1] = '\0';
    
    network->channel = atoi(channel_str);
    if(network->channel == 0) network->channel = 1;
    
    // Kopiuj auth type
    strncpy(network->auth, auth, sizeof(network->auth) - 1);
    network->auth[sizeof(network->auth) - 1] = '\0';
    if(strlen(network->auth) == 0) {
        strcpy(network->auth, "Unknown");
    }
    
    network->rssi = atoi(rssi_str);
    if(network->rssi == 0) network->rssi = -99;
    
    // Określ pasmo
    if(strstr(freq_str, "5GHz")) {
        network->band = EvilEspBand5GHz;
    } else {
        network->band = EvilEspBand24GHz;
    }
    
    worker->app->network_count++;
    
    FURI_LOG_I("EvilEsp", "Parsed CSV network[%d]: '%s' (%s) Ch:%d %s RSSI:%d %s",
        network_idx, network->ssid, network->bssid, 
        network->channel, network->auth, network->rssi,
        (network->band == EvilEspBand5GHz) ? "5GHz" : "2.4GHz");
}

// Parse portal line from list_sd output
// Format: "1 1EXA~145.HTM" or "2 PortalX.HTM"
static void parse_portal_line(EvilEspUartWorker* worker, const char* line) {
    if(!worker || !worker->app) return;
    if(worker->app->portal_count >= EVIL_ESP_MAX_PORTALS) return;

    // Skip leading whitespace
    const char* pos = line;
    while(*pos == ' ' || *pos == '\t') pos++;

    // Parse index number
    char index_str[16];
    int idx_len = 0;
    while(*pos >= '0' && *pos <= '9' && idx_len < 15) {
        index_str[idx_len++] = *pos++;
    }
    index_str[idx_len] = '\0';

    if(idx_len == 0) {
        FURI_LOG_W("EvilEsp", "Failed to parse portal index from: %s", line);
        return;
    }

    int portal_index = atoi(index_str);

    // Skip whitespace after index
    while(*pos == ' ' || *pos == '\t') pos++;

    // The rest is the filename
    if(strlen(pos) == 0) {
        FURI_LOG_W("EvilEsp", "No filename found in portal line: %s", line);
        return;
    }

    // Store portal
    EvilEspPortal* portal = &worker->app->portals[worker->app->portal_count];
    portal->index = portal_index;
    strncpy(portal->filename, pos, sizeof(portal->filename) - 1);
    portal->filename[sizeof(portal->filename) - 1] = '\0';

    worker->app->portal_count++;

    FURI_LOG_I("EvilEsp", "Parsed portal[%d]: index=%d, filename='%s'",
               worker->app->portal_count - 1, portal_index, portal->filename);
}

/*
static void parse_scan_result_line(EvilEspUartWorker* worker, const char* line) {
    if(!worker || !worker->app) return;
    if(worker->app->network_count >= EVIL_ESP_MAX_NETWORKS) return;

    const char* data = line + 7; // Skip "[INFO] "

    char temp[128];
    const char* current = data;

    // Skip leading spaces
    while(*current == ' ') current++;

    // Parse device index
    const char* idx_start = current;
    while(*current && *current != ' ') current++;
    int idx_len = current - idx_start;
    if(idx_len >= (int)sizeof(temp)) idx_len = (int)sizeof(temp) - 1;
    strncpy(temp, idx_start, idx_len);
    temp[idx_len] = '\0';
    int device_index = atoi(temp);

    // Find BSSID (MAC address)
    const char* bssid_start = NULL;
    const char* scan = current;
    while(*scan) {
        if(isxdigit((unsigned char)scan[0]) && isxdigit((unsigned char)scan[1]) && scan[2] == ':' &&
           isxdigit((unsigned char)scan[3]) && isxdigit((unsigned char)scan[4]) && scan[5] == ':' &&
           isxdigit((unsigned char)scan[6]) && isxdigit((unsigned char)scan[7]) && scan[8] == ':' &&
           isxdigit((unsigned char)scan[9]) && isxdigit((unsigned char)scan[10]) && scan[11] == ':' &&
           isxdigit((unsigned char)scan[12]) && isxdigit((unsigned char)scan[13]) && scan[14] == ':' &&
           isxdigit((unsigned char)scan[15]) && isxdigit((unsigned char)scan[16])) {
            bssid_start = scan;
            break;
        }
        scan++;
    }

    if(!bssid_start) {
        FURI_LOG_W("EvilEsp", "No BSSID found in line: %s", line);
        return;
    }

    // Extract SSID (between device index and BSSID)
    int ssid_len = bssid_start - current;
    while(ssid_len > 0 && (current[ssid_len - 1] == ' ' || current[ssid_len - 1] == '\t')) ssid_len--;
    if(ssid_len >= (int)sizeof(temp)) ssid_len = (int)sizeof(temp) - 1;
    strncpy(temp, current, ssid_len);
    temp[ssid_len] = '\0';

    // Extract BSSID
    char bssid[18];
    strncpy(bssid, bssid_start, 17);
    bssid[17] = '\0';

    // Move past BSSID and parse remaining fields
    current = bssid_start + 17;
    int channel = 0, rssi = 0;
    char freq[16] = {0};

    sscanf(current, "%d %d %15s", &channel, &rssi, freq);

    // Store network
    EvilEspNetwork* network = &worker->app->networks[worker->app->network_count];
    network->index = worker->app->network_count;
    network->device_index = device_index;
    network->selected = false;

    strncpy(network->ssid, temp, sizeof(network->ssid) - 1);
    network->ssid[sizeof(network->ssid) - 1] = '\0';

    strncpy(network->bssid, bssid, sizeof(network->bssid) - 1);
    network->bssid[sizeof(network->bssid) - 1] = '\0';

    network->channel = channel;
    network->rssi = rssi;

    if(strstr(freq, "5GHz") || channel >= 36) {
        network->band = EvilEspBand5GHz;
    } else {
        network->band = EvilEspBand24GHz;
    }

    worker->app->network_count++;

    FURI_LOG_I("EvilEsp", "Parsed network[%d] (device_idx=%d): '%s' (%s) Ch:%d RSSI:%d %s", 
               network->index, device_index, network->ssid, network->bssid, network->channel, network->rssi,
               (network->band == EvilEspBand5GHz) ? "5GHz" : "2.4GHz");
}
*/


EvilEspUartWorker* evil_esp_uart_init(EvilEspApp* app) {
    EvilEspUartWorker* worker = malloc(sizeof(EvilEspUartWorker));

    worker->app = app;
    worker->running = true;
    worker->tx_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    worker->rx_stream = furi_stream_buffer_alloc(RX_BUFFER_SIZE, 1);

    // Initialize echo filtering
    worker->recent_command_index = 0;
    memset(worker->recent_commands, 0, sizeof(worker->recent_commands));
    memset(worker->command_timestamps, 0, sizeof(worker->command_timestamps));
    worker->portal_list_active = false;
    worker->portal_list_last_line_time = 0;

    // Allocate line buffer on heap to reduce stack usage
    worker->line_buffer = malloc(4096); // Larger buffer for WebUI data
    if(!worker->line_buffer) {
        FURI_LOG_E("EvilEsp", "Failed to allocate line buffer");
        furi_stream_buffer_free(worker->rx_stream);
        furi_mutex_free(worker->tx_mutex);
        free(worker);
        return NULL;
    }

    // Get serial handle based on GPIO pin configuration
    FuriHalSerialId serial_id;
    const char* pin_description;

    if(app->config.gpio_pins == EvilEspGpioPins13_14) {
        serial_id = FuriHalSerialIdUsart; // Pins 13/14
        pin_description = "USART (pins 13/14)";
    } else {
        serial_id = FuriHalSerialIdLpuart; // Pins 15/16
        pin_description = "LPUART (pins 15/16)";
    }

    FURI_LOG_I("EvilEsp", "Attempting to acquire %s", pin_description);

    worker->serial_handle = furi_hal_serial_control_acquire(serial_id);
    if(!worker->serial_handle) {
        FURI_LOG_E("EvilEsp", "Failed to acquire serial handle for %s", pin_description);
        FURI_LOG_E("EvilEsp", "Serial ID requested: %d", (int)serial_id);
        furi_stream_buffer_free(worker->rx_stream);
        furi_mutex_free(worker->tx_mutex);
        free(worker);
        return NULL;
    }

    FURI_LOG_I("EvilEsp", "Successfully acquired serial handle for %s", pin_description);

    // Initialize UART
    furi_hal_serial_init(worker->serial_handle, BAUDRATE);

    // Start async RX
    furi_hal_serial_async_rx_start(worker->serial_handle, uart_on_irq_cb, worker, false);

    // Start worker thread with larger stack for handling high-volume WebUI data
    worker->thread = furi_thread_alloc_ex("EvilEspUartWorker", 4096, uart_worker_thread, worker);
    furi_thread_start(worker->thread);

    uart_worker = worker;

    FURI_LOG_I("EvilEsp", "Hardware UART initialized on %s at %u baud", pin_description, BAUDRATE);
    FURI_LOG_I("EvilEsp", "UART worker thread started");

    return worker;
}

void evil_esp_uart_restart(EvilEspApp* app) {
    if(!app) return;

    FURI_LOG_I("EvilEsp", "Restarting UART worker with new GPIO configuration...");

    // Stop current UART worker if it exists
    if(app->uart_worker) {
        FURI_LOG_I("EvilEsp", "Stopping existing UART worker...");
        evil_esp_uart_free(app->uart_worker);
        app->uart_worker = NULL;
        // Small delay to ensure cleanup is complete
        furi_delay_ms(50);
    }

    // Clear any pending data in the stream buffer
    if(app->uart_rx_stream) {
        furi_stream_buffer_reset(app->uart_rx_stream);
    }

    // Clear logs to show fresh start
    evil_esp_clear_log(app);

    // Reinitialize UART worker with new configuration
    app->uart_worker = evil_esp_uart_init(app);

    if(app->uart_worker) {
        FURI_LOG_I("EvilEsp", "UART worker restarted successfully");
        // Add small delay to ensure proper initialization
        furi_delay_ms(100);

        // Send a test command to verify communication
        evil_esp_uart_send_command(app->uart_worker, "info");
    } else {
        FURI_LOG_E("EvilEsp", "Failed to restart UART worker");
    }
}

void evil_esp_uart_free(EvilEspUartWorker* worker) {
    if(!worker) return;

    worker->running = false;

    // Stop async RX
    furi_hal_serial_async_rx_stop(worker->serial_handle);

    // Stop worker thread
    furi_thread_join(worker->thread);
    furi_thread_free(worker->thread);

    // Deinitialize UART
    furi_hal_serial_deinit(worker->serial_handle);
    furi_hal_serial_control_release(worker->serial_handle);

    // Free resources
    furi_stream_buffer_free(worker->rx_stream);
    furi_mutex_free(worker->tx_mutex);
    if(worker->line_buffer) {
        free(worker->line_buffer);
    }
    free(worker);

    uart_worker = NULL;

    FURI_LOG_I("EvilEsp", "UART worker freed");
}

void evil_esp_uart_tx(EvilEspUartWorker* worker, const uint8_t* data, size_t len) {
    if(!worker || !data || len == 0) return;

    furi_mutex_acquire(worker->tx_mutex, FuriWaitForever);

    // Send data via hardware UART
    furi_hal_serial_tx(worker->serial_handle, data, len);
    furi_hal_serial_tx_wait_complete(worker->serial_handle);

    furi_mutex_release(worker->tx_mutex);

    FURI_LOG_D("EvilEsp", "TX: %.*s", (int)len, data);
}

void evil_esp_uart_tx_string(EvilEspUartWorker* worker, const char* str) {
    if(!worker || !str) return;
    evil_esp_uart_tx(worker, (const uint8_t*)str, strlen(str));
}

void evil_esp_uart_send_command(EvilEspUartWorker* worker, const char* command) {
    if(!worker || !command) return;

    // Store command for echo filtering
    store_sent_command(worker, command);

    // Add newline to command
    char cmd_with_newline[256];
    snprintf(cmd_with_newline, sizeof(cmd_with_newline), "%s\n", command);

    evil_esp_uart_tx_string(worker, cmd_with_newline);

    FURI_LOG_I("EvilEsp", "Sent command: %s", command);
}

bool evil_esp_uart_read_line(EvilEspUartWorker* worker, char* buffer, size_t buffer_size, uint32_t timeout_ms) {
    if(!worker || !buffer || buffer_size == 0) return false;

    UNUSED(timeout_ms);

    // Try to read a line from stream buffer
    size_t bytes_read = 0;
    uint32_t start_time = furi_get_tick();

    while(bytes_read < buffer_size - 1 && (furi_get_tick() - start_time) < timeout_ms) {
        uint8_t byte;
        if(furi_stream_buffer_receive(worker->rx_stream, &byte, 1, 10) > 0) {
            buffer[bytes_read++] = byte;
            if(byte == '\n') {
                break;
            }
        }
    }

    buffer[bytes_read] = '\0';
    return bytes_read > 0;
}

size_t evil_esp_uart_rx_available(EvilEspUartWorker* worker) {
    if(!worker) return 0;
    return furi_stream_buffer_bytes_available(worker->rx_stream);
}

void evil_esp_uart_flush_rx(EvilEspUartWorker* worker) {
    if(!worker) return;
    furi_stream_buffer_reset(worker->rx_stream);
}

bool evil_esp_uart_wait_for_response(EvilEspUartWorker* worker, const char* expected_prefix, char* response_buffer, size_t buffer_size, uint32_t timeout_ms) {
    if(!worker || !expected_prefix || !response_buffer) return false;

    UNUSED(buffer_size);
    UNUSED(timeout_ms);

    // For now, return false - focusing on TX first
    response_buffer[0] = '\0';
    return false;
}

bool is_command_echo(EvilEspUartWorker* worker, const char* line) {
    if(!worker || !line) return false;

    uint32_t current_time = furi_get_tick();

    // Check if this line matches any recently sent command
    for(int i = 0; i < MAX_RECENT_COMMANDS; i++) {
        if(strlen(worker->recent_commands[i]) > 0) {
            // Check if command timestamp is within echo timeout
            if(current_time - worker->command_timestamps[i] < COMMAND_ECHO_TIMEOUT_MS) {
                // Check if line matches the command (case insensitive)
                if(strcasecmp(line, worker->recent_commands[i]) == 0) {
                    FURI_LOG_D("EvilEsp", "✓ Echo detected and filtered: '%s'", line);
                    return true;
                }
            } else {
                // Clear old command
                worker->recent_commands[i][0] = '\0';
                worker->command_timestamps[i] = 0;
            }
        }
    }

    // Not an echo - this is a real response
    FURI_LOG_D("EvilEsp", "✗ Not an echo, processing: '%s'", line);
    return false;
}

void store_sent_command(EvilEspUartWorker* worker, const char* command) {
    if(!worker || !command) return;

    // Store command in circular buffer
    strncpy(worker->recent_commands[worker->recent_command_index], command, 63);
    worker->recent_commands[worker->recent_command_index][63] = '\0';
    worker->command_timestamps[worker->recent_command_index] = furi_get_tick();

    FURI_LOG_D("EvilEsp", "Stored command for echo filtering: '%s' at index %d", 
               command, worker->recent_command_index);

    worker->recent_command_index = (worker->recent_command_index + 1) % MAX_RECENT_COMMANDS;
}
