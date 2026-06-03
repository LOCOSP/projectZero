#include "nrf24.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"

#define TAG "nrf24"

/* nRF24L01+ tolerates up to 10 MHz SPI; 8 MHz keeps a margin for the shared bus
 * and jumper wiring while letting channel hops complete quickly during sweeps. */
#define NRF24_SPI_CLOCK_HZ (8 * 1000 * 1000)

bool nrf24_init(nrf24_device_t* device) {
    if (device->initialized) return true;

    /* CE pin as push-pull output, held low (radio idle). */
    gpio_config_t ce_cfg = {
        .pin_bit_mask = (1ULL << device->ce_pin),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&ce_cfg);
    gpio_set_level(device->ce_pin, 0);

    /* The SD card driver may already own the bus. If it is not yet
     * initialized, set it up here (matching the SD pin map so both devices
     * share SCK/MOSI/MISO). ESP_ERR_INVALID_STATE means it is already up. */
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = device->mosi_pin,
        .miso_io_num = device->miso_pin,
        .sclk_io_num = device->sck_pin,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 64,
    };
    esp_err_t ret = spi_bus_initialize(device->host, &bus_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "spi_bus_initialize failed: %s", esp_err_to_name(ret));
        return false;
    }

    spi_device_interface_config_t dev_cfg = {
        .clock_speed_hz = NRF24_SPI_CLOCK_HZ,
        .mode = 0,
        .spics_io_num = device->cs_pin,
        .queue_size = 1,
        .command_bits = 0,
        .address_bits = 0,
    };
    ret = spi_bus_add_device(device->host, &dev_cfg, &device->spi);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "spi_bus_add_device failed: %s", esp_err_to_name(ret));
        return false;
    }

    device->initialized = true;
    return true;
}

void nrf24_deinit(nrf24_device_t* device) {
    if (!device->initialized) return;

    gpio_set_level(device->ce_pin, 0);

    if (device->spi) {
        spi_bus_remove_device(device->spi);
        device->spi = NULL;
    }

    /* Leave the SPI bus initialized; it is shared with the SD card driver. */
    gpio_reset_pin(device->ce_pin);

    device->initialized = false;
}

void nrf24_spi_trx(
    nrf24_device_t* device,
    uint8_t* tx,
    uint8_t* rx,
    uint8_t size,
    uint32_t timeout) {
    (void)timeout;
    if (!device->initialized || device->spi == NULL || size == 0) return;

    uint8_t local_rx[33];
    bool use_local = (rx == NULL);
    if (use_local && size > sizeof(local_rx)) size = sizeof(local_rx);

    spi_transaction_t t = {
        .length = (size_t)size * 8,
        .rxlength = (size_t)size * 8,
        .tx_buffer = tx,
        .rx_buffer = use_local ? local_rx : rx,
    };
    esp_err_t ret = spi_device_polling_transmit(device->spi, &t);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "spi trx failed: %s", esp_err_to_name(ret));
    }
}

uint8_t nrf24_write_reg(nrf24_device_t* device, uint8_t reg, uint8_t data) {
    uint8_t tx[2] = {W_REGISTER | (REGISTER_MASK & reg), data};
    uint8_t rx[2] = {0};
    nrf24_spi_trx(device, tx, rx, 2, nrf24_TIMEOUT);
    return rx[0];
}

uint8_t nrf24_write_buf_reg(nrf24_device_t* device, uint8_t reg, uint8_t* data, uint8_t size) {
    uint8_t tx[33];
    uint8_t rx[33];
    if (size > 32) size = 32;
    memset(rx, 0, size + 1);
    tx[0] = W_REGISTER | (REGISTER_MASK & reg);
    memcpy(&tx[1], data, size);
    nrf24_spi_trx(device, tx, rx, size + 1, nrf24_TIMEOUT);
    return rx[0];
}

uint8_t nrf24_read_reg(nrf24_device_t* device, uint8_t reg, uint8_t* data, uint8_t size) {
    uint8_t tx[33];
    uint8_t rx[33];
    if (size > 32) size = 32;
    memset(rx, 0, size + 1);
    tx[0] = R_REGISTER | (REGISTER_MASK & reg);
    memset(&tx[1], 0, size);
    nrf24_spi_trx(device, tx, rx, size + 1, nrf24_TIMEOUT);
    memcpy(data, &rx[1], size);
    return rx[0];
}

uint8_t nrf24_flush_rx(nrf24_device_t* device) {
    uint8_t tx[] = {FLUSH_RX};
    uint8_t rx[] = {0};
    nrf24_spi_trx(device, tx, rx, 1, nrf24_TIMEOUT);
    return rx[0];
}

uint8_t nrf24_flush_tx(nrf24_device_t* device) {
    uint8_t tx[] = {FLUSH_TX};
    uint8_t rx[] = {0};
    nrf24_spi_trx(device, tx, rx, 1, nrf24_TIMEOUT);
    return rx[0];
}

uint8_t nrf24_status(nrf24_device_t* device) {
    uint8_t status = 0;
    uint8_t tx[] = {R_REGISTER | (REGISTER_MASK & REG_STATUS)};
    nrf24_spi_trx(device, tx, &status, 1, nrf24_TIMEOUT);
    return status;
}

uint8_t nrf24_set_txpower(nrf24_device_t* device, uint8_t level) {
    uint8_t setup = 0;
    nrf24_read_reg(device, REG_RF_SETUP, &setup, 1);
    setup = (setup & 0xF8) | level;
    nrf24_write_reg(device, REG_RF_SETUP, setup);
    return setup;
}

uint8_t nrf24_set_maclen(nrf24_device_t* device, uint8_t maclen) {
    if (maclen < 2) maclen = 2;
    if (maclen > 5) maclen = 5;
    return nrf24_write_reg(device, REG_SETUP_AW, maclen - 2);
}

uint8_t nrf24_set_src_mac(nrf24_device_t* device, uint8_t* mac, uint8_t size) {
    uint8_t clearmac[] = {0, 0, 0, 0, 0};
    nrf24_set_maclen(device, size);
    nrf24_write_buf_reg(device, REG_RX_ADDR_P0, clearmac, 5);
    return nrf24_write_buf_reg(device, REG_RX_ADDR_P0, mac, size);
}

uint8_t nrf24_set_dst_mac(nrf24_device_t* device, uint8_t* mac, uint8_t size) {
    uint8_t clearmac[] = {0, 0, 0, 0, 0};
    nrf24_set_maclen(device, size);
    nrf24_write_buf_reg(device, REG_TX_ADDR, clearmac, 5);
    return nrf24_write_buf_reg(device, REG_TX_ADDR, mac, size);
}

uint8_t nrf24_set_idle(nrf24_device_t* device) {
    uint8_t cfg = 0;
    nrf24_read_reg(device, REG_CONFIG, &cfg, 1);
    cfg &= 0xfc; /* clear bottom two bits to power down the radio */
    uint8_t status = nrf24_write_reg(device, REG_CONFIG, cfg);
    gpio_set_level(device->ce_pin, 0);
    return status;
}

uint8_t nrf24_set_tx_mode(nrf24_device_t* device) {
    uint8_t cfg = 0;
    gpio_set_level(device->ce_pin, 0);
    nrf24_write_reg(device, REG_STATUS, 0x30);
    nrf24_read_reg(device, REG_CONFIG, &cfg, 1);
    cfg &= 0xfe; /* disable PRIM_RX */
    cfg |= 0x02; /* PWR_UP */
    uint8_t status = nrf24_write_reg(device, REG_CONFIG, cfg);
    gpio_set_level(device->ce_pin, 1);
    return status;
}

void nrf24_startConstCarrier(nrf24_device_t* device, uint8_t level, uint8_t channel) {
    nrf24_set_tx_mode(device);

    nrf24_write_reg(device, REG_RF_CH, channel);

    uint8_t setup = nrf24_set_txpower(device, level);
    /* Force 2 Mbps (RF_DR_HIGH=1, RF_DR_LOW=0), matching the proven RF24 setup,
     * and enable the unmodulated constant carrier with PLL locked. */
    setup |= (1 << 3);            /* RF_DR_HIGH -> 2 Mbps */
    setup &= ~(1 << 5);           /* RF_DR_LOW cleared */
    setup |= NRF24_CONT_WAVE | NRF24_PLL_LOCK;
    nrf24_write_reg(device, REG_RF_SETUP, setup);

    nrf24_write_reg(device, REG_EN_AA, 0x00);

    uint8_t config = 0;
    nrf24_read_reg(device, REG_CONFIG, &config, 1);
    config &= ~NRF24_EN_CRC;
    nrf24_write_reg(device, REG_CONFIG, config);

    uint8_t tx[33];
    tx[0] = W_TX_PAYLOAD;
    memset(&tx[1], 0xFF, 32);
    nrf24_spi_trx(device, tx, NULL, 33, nrf24_TIMEOUT);

    nrf24_set_tx_mode(device);
}

void nrf24_stopConstCarrier(nrf24_device_t* device) {
    uint8_t setup = 0;
    nrf24_read_reg(device, REG_RF_SETUP, &setup, 1);
    setup &= ~(NRF24_CONT_WAVE | NRF24_PLL_LOCK);
    nrf24_write_reg(device, REG_RF_SETUP, setup);

    uint8_t config = 0;
    nrf24_read_reg(device, REG_CONFIG, &config, 1);
    config |= NRF24_EN_CRC;
    nrf24_write_reg(device, REG_CONFIG, config);

    gpio_set_level(device->ce_pin, 0);
}

void nrf24_configure(
    nrf24_device_t* device,
    uint8_t rate,
    uint8_t* srcmac,
    uint8_t* dstmac,
    uint8_t maclen,
    uint8_t channel,
    bool noack,
    bool disable_aa) {
    if (channel > 125) channel = 125;
    if (rate == 2)
        rate = 8; /* 2Mbps */
    else
        rate = 0; /* 1Mbps */

    nrf24_write_reg(device, REG_CONFIG, 0x00); /* stop nRF */
    nrf24_set_idle(device);
    nrf24_write_reg(device, REG_STATUS, 0x1c); /* clear interrupts */
    if (disable_aa)
        nrf24_write_reg(device, REG_EN_AA, 0x00);
    else
        nrf24_write_reg(device, REG_EN_AA, 0x1F);

    nrf24_write_reg(device, REG_DYNPD, 0x3F);
    if (noack) {
        nrf24_write_reg(device, REG_FEATURE, 0x05);
    } else {
        nrf24_write_reg(device, REG_CONFIG, 0x0C);
        nrf24_write_reg(device, REG_FEATURE, 0x07);
        nrf24_write_reg(device, REG_SETUP_RETR, 0x1f);
    }

    nrf24_set_idle(device);
    nrf24_flush_rx(device);
    nrf24_flush_tx(device);

    if (maclen) nrf24_set_maclen(device, maclen);
    if (srcmac) nrf24_set_src_mac(device, srcmac, maclen);
    if (dstmac) nrf24_set_dst_mac(device, dstmac, maclen);

    nrf24_write_reg(device, REG_RF_CH, channel);
    nrf24_write_reg(device, REG_RF_SETUP, rate);
    vTaskDelay(pdMS_TO_TICKS(200));
}

bool nrf24_check_connected(nrf24_device_t* device) {
    if (!device->initialized) return false;

    /* Write a couple of distinctive channel values and read them back. A
     * present, powered module echoes them; an absent one returns 0x00/0xFF. */
    const uint8_t probes[] = {0x0A, 0x55, 0x2E};
    for (size_t i = 0; i < sizeof(probes); i++) {
        nrf24_write_reg(device, REG_RF_CH, probes[i]);
        uint8_t readback = 0xAB;
        nrf24_read_reg(device, REG_RF_CH, &readback, 1);
        if (readback != probes[i]) {
            return false;
        }
    }
    return true;
}
