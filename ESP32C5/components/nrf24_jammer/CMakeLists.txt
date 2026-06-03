idf_component_register(SRCS "nrf24.c" "nrf24_jammer.c"
                    INCLUDE_DIRS "include"
                    REQUIRES driver esp_driver_spi esp_driver_gpio esp_timer)
