#include "nrf24_jammer.h"
#include "nrf24.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"

#define TAG "nrf24_jammer"

/* Pin map: the nRF24 shares the SD card's SPI2 bus (SCK/MOSI/MISO) and uses its
 * own CS + CE. Change these if you wire the module differently. */
#define NRF24_SPI_HOST   SPI2_HOST
#define NRF24_SCK_PIN    6   /* shared with SD_CLK */
#define NRF24_MOSI_PIN   7   /* shared with SD_MOSI */
#define NRF24_MISO_PIN   2   /* shared with SD_MISO */
#define NRF24_CS_PIN     3   /* dedicated chip-select (was CC1101 CS) */
#define NRF24_CE_PIN     4   /* dedicated chip-enable (was CC1101 GDO0) */

/* PA max with the LNA bit set (RF_SETUP low nibble = 0b0111), matching the
 * Arduino RF24 setPALevel(RF24_PA_MAX, true). */
#define NRF24_TX_POWER   7

/* Duty cycle: hop as fast as possible for this many microseconds, then take a
 * single 10 ms (1 tick) breather so the priority-2 console task can run (to
 * receive `stop`) and the idle-task watchdog is fed. ~30 ms busy / 10 ms idle
 * keeps the carrier sweeping ~75% of the time on the single-core C5. */
#define JAM_BUSY_US      30000

static nrf24_device_t s_dev;
static bool s_initialized = false;

static volatile bool s_jam_stop = true;
static volatile bool s_jam_running = false;
static nrf24_jam_band_t s_band = JAM_ALL;
static TaskHandle_t s_jam_task = NULL;

const char* nrf24_jammer_band_name(nrf24_jam_band_t band) {
    switch (band) {
        case JAM_BLE: return "ble";
        case JAM_BT: return "bt";
        case JAM_WIFI: return "wifi";
        case JAM_DRONE: return "drone";
        case JAM_ALL: return "all";
        default: return "all";
    }
}

bool nrf24_jammer_init(void) {
    if (!s_initialized) {
        memset(&s_dev, 0, sizeof(s_dev));
        s_dev.host = NRF24_SPI_HOST;
        s_dev.sck_pin = NRF24_SCK_PIN;
        s_dev.mosi_pin = NRF24_MOSI_PIN;
        s_dev.miso_pin = NRF24_MISO_PIN;
        s_dev.cs_pin = NRF24_CS_PIN;
        s_dev.ce_pin = NRF24_CE_PIN;
        s_dev.initialized = false;

        if (!nrf24_init(&s_dev)) {
            ESP_LOGE(TAG, "SPI device init failed");
            return false;
        }
        s_initialized = true;
    }

    bool connected = nrf24_check_connected(&s_dev);
    if (connected) {
        ESP_LOGI(TAG, "nRF24 detected on SPI%d (CS=%d, CE=%d)",
                 (int)NRF24_SPI_HOST, NRF24_CS_PIN, NRF24_CE_PIN);
    } else {
        ESP_LOGW(TAG, "nRF24 not responding (check wiring/power)");
    }
    return connected;
}

/* ---- jam loop (single module, constant carrier) ------------------------- */

/* Fast constant-carrier sweep over channels [lo, hi]. Hops with no per-hop
 * delay and only yields (10 ms) after JAM_BUSY_US of continuous sweeping, so
 * the carrier covers the band densely while the system stays responsive. */
static void jam_sweep(uint8_t lo, uint8_t hi) {
    nrf24_startConstCarrier(&s_dev, NRF24_TX_POWER, lo);

    int64_t last_yield_us = esp_timer_get_time();
    while (!s_jam_stop) {
        for (uint8_t ch = lo; ch <= hi && !s_jam_stop; ch++) {
            nrf24_write_reg(&s_dev, REG_RF_CH, ch);
            if (esp_timer_get_time() - last_yield_us >= JAM_BUSY_US) {
                vTaskDelay(1);
                last_yield_us = esp_timer_get_time();
            }
        }
    }

    nrf24_stopConstCarrier(&s_dev);
}

static void nrf24_jam_task(void* ctx) {
    (void)ctx;
    s_jam_running = true;

    switch (s_band) {
        case JAM_BLE: jam_sweep(2, 80); break;    /* BLE 2402-2480 MHz */
        case JAM_BT: jam_sweep(0, 83); break;     /* classic BT band */
        case JAM_WIFI: jam_sweep(1, 84); break;   /* WiFi 2.4 GHz span */
        case JAM_DRONE:
        case JAM_ALL:
        default:
            jam_sweep(0, 125);                    /* full 2.4 GHz */
            break;
    }

    /* Leave the radio idle. */
    nrf24_set_idle(&s_dev);

    s_jam_running = false;
    s_jam_task = NULL;
    vTaskDelete(NULL);
}

bool nrf24_jammer_start(nrf24_jam_band_t band) {
    if (!s_initialized) {
        ESP_LOGW(TAG, "start refused: run init_nrf24 first");
        return false;
    }
    if (s_jam_running || s_jam_task != NULL) {
        ESP_LOGW(TAG, "start refused: jammer already running");
        return false;
    }

    s_band = band;
    s_jam_stop = false;

    BaseType_t ok = xTaskCreate(nrf24_jam_task, "nrf24_jam", 4096, NULL, 6, &s_jam_task);
    if (ok != pdPASS) {
        s_jam_task = NULL;
        s_jam_stop = true;
        ESP_LOGE(TAG, "failed to create jam task");
        return false;
    }
    ESP_LOGI(TAG, "jammer started (band=%s)", nrf24_jammer_band_name(band));
    return true;
}

void nrf24_jammer_stop(void) {
    if (!s_jam_running && s_jam_task == NULL) return;

    s_jam_stop = true;

    /* Wait for the task to exit cleanly. */
    for (int i = 0; i < 40 && s_jam_task != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(25));
    }
    if (s_jam_task != NULL) {
        vTaskDelete(s_jam_task);
        s_jam_task = NULL;
        s_jam_running = false;
        ESP_LOGW(TAG, "jam task force-deleted");
    }

    if (s_initialized) {
        nrf24_stopConstCarrier(&s_dev);
        nrf24_set_idle(&s_dev);
    }
    ESP_LOGI(TAG, "jammer stopped");
}

bool nrf24_jammer_is_running(void) {
    return s_jam_running;
}
