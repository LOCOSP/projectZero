#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "driver/spi_master.h"
#include "driver/gpio.h"

#ifdef __cplusplus
extern "C" {
#endif

/* nRF24L01(+) command set */
#define R_REGISTER 0x00
#define W_REGISTER 0x20
#define REGISTER_MASK 0x1F
#define ACTIVATE 0x50
#define R_RX_PL_WID 0x60
#define R_RX_PAYLOAD 0x61
#define W_TX_PAYLOAD 0xA0
#define W_TX_PAYLOAD_NOACK 0xB0
#define W_ACK_PAYLOAD 0xA8
#define FLUSH_TX 0xE1
#define FLUSH_RX 0xE2
#define REUSE_TX_PL 0xE3
#define RF24_NOP 0xFF

/* Register addresses */
#define REG_CONFIG 0x00
#define REG_EN_AA 0x01
#define REG_EN_RXADDR 0x02
#define REG_SETUP_AW 0x03
#define REG_SETUP_RETR 0x04
#define REG_DYNPD 0x1C
#define REG_FEATURE 0x1D
#define REG_RF_SETUP 0x06
#define REG_STATUS 0x07
#define REG_RX_ADDR_P0 0x0A
#define REG_RX_ADDR_P1 0x0B
#define REG_RX_ADDR_P2 0x0C
#define REG_RX_ADDR_P3 0x0D
#define REG_RX_ADDR_P4 0x0E
#define REG_RX_ADDR_P5 0x0F
#define REG_RF_CH 0x05
#define REG_TX_ADDR 0x10
#define REG_FIFO_STATUS 0x17

#define RX_PW_P0 0x11
#define RX_PW_P1 0x12
#define RX_PW_P2 0x13
#define RX_PW_P3 0x14
#define RX_PW_P4 0x15
#define RX_PW_P5 0x16
#define RX_DR    0x40
#define TX_DS    0x20
#define MAX_RT   0x10

#define NRF24_CONT_WAVE (1 << 7)
#define NRF24_PLL_LOCK (1 << 4)
#define NRF24_EN_CRC (1 << 3)

#define nrf24_TIMEOUT 500

/* nRF24 device handle for the ESP-IDF SPI master port. */
typedef struct {
    spi_host_device_t host;   /* SPI bus this device lives on (shared with SD) */
    spi_device_handle_t spi;  /* allocated by spi_bus_add_device() */
    gpio_num_t sck_pin;
    gpio_num_t mosi_pin;
    gpio_num_t miso_pin;
    gpio_num_t cs_pin;
    gpio_num_t ce_pin;
    bool initialized;
} nrf24_device_t;

/* Initialize the SPI device + CE pin. The SPI bus is initialized here if it is
 * not already owned by another driver (e.g. the SD card). Returns true on
 * success. */
bool nrf24_init(nrf24_device_t* device);

/* Remove the SPI device and release the CE pin. The shared SPI bus itself is
 * left intact (owned by the SD card driver). */
void nrf24_deinit(nrf24_device_t* device);

/* Full-duplex SPI transfer. rx may be NULL. */
void nrf24_spi_trx(
    nrf24_device_t* device,
    uint8_t* tx,
    uint8_t* rx,
    uint8_t size,
    uint32_t timeout);

uint8_t nrf24_write_reg(nrf24_device_t* device, uint8_t reg, uint8_t data);
uint8_t nrf24_write_buf_reg(nrf24_device_t* device, uint8_t reg, uint8_t* data, uint8_t size);
uint8_t nrf24_read_reg(nrf24_device_t* device, uint8_t reg, uint8_t* data, uint8_t size);

uint8_t nrf24_flush_rx(nrf24_device_t* device);
uint8_t nrf24_flush_tx(nrf24_device_t* device);

uint8_t nrf24_status(nrf24_device_t* device);

uint8_t nrf24_set_idle(nrf24_device_t* device);
uint8_t nrf24_set_tx_mode(nrf24_device_t* device);
uint8_t nrf24_set_txpower(nrf24_device_t* device, uint8_t level);

uint8_t nrf24_set_maclen(nrf24_device_t* device, uint8_t maclen);
uint8_t nrf24_set_src_mac(nrf24_device_t* device, uint8_t* mac, uint8_t size);
uint8_t nrf24_set_dst_mac(nrf24_device_t* device, uint8_t* mac, uint8_t size);

void nrf24_startConstCarrier(nrf24_device_t* device, uint8_t level, uint8_t channel);
void nrf24_stopConstCarrier(nrf24_device_t* device);

/* Configure the radio (rate in Mbps: 1 or 2). */
void nrf24_configure(
    nrf24_device_t* device,
    uint8_t rate,
    uint8_t* srcmac,
    uint8_t* dstmac,
    uint8_t maclen,
    uint8_t channel,
    bool noack,
    bool disable_aa);

/* Reliable presence test: write a value to RF_CH and read it back. */
bool nrf24_check_connected(nrf24_device_t* device);

#ifdef __cplusplus
}
#endif
