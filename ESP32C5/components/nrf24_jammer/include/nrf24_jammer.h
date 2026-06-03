#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    JAM_BLE = 0,   /* BLE advertising channels (2/26/80) */
    JAM_BT,        /* Bluetooth channel list, constant carrier */
    JAM_WIFI,      /* sweep across all WiFi channels, packet spam */
    JAM_DRONE,     /* constant-carrier sweep 0..125 */
    JAM_ALL,       /* full 2.4GHz constant-carrier sweep 0..125 (default) */
} nrf24_jam_band_t;

/* Initialize and probe the single nRF24 module wired to the ESP32-C5.
 * Returns true if the module responds. Safe to call multiple times. */
bool nrf24_jammer_init(void);

/* Start jamming on the given band. Returns false if the module is not
 * initialized/detected, or if a jam is already running. */
bool nrf24_jammer_start(nrf24_jam_band_t band);

/* Stop any active jamming and place the radio in idle. Safe to call when
 * nothing is running. */
void nrf24_jammer_stop(void);

bool nrf24_jammer_is_running(void);

/* Human-readable band name, e.g. for log output. */
const char* nrf24_jammer_band_name(nrf24_jam_band_t band);

#ifdef __cplusplus
}
#endif
