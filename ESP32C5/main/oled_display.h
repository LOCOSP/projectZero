#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Detected display type after auto-probing I2C buses.
 */
typedef enum {
    DISPLAY_NONE = 0,       /**< No display found on any I2C bus          */
    DISPLAY_SSD1306,        /**< SSD1306 0.96" OLED 128x64 (GPIO 25/26)  */
    DISPLAY_SH1107,         /**< SH1107 1.3"  OLED 128x64 (GPIO 8/9)    */
    DISPLAY_UNIT_LCD,       /**< M5 Unit LCD 1.14" ST7789 (GPIO 8/9)     */
} display_type_t;

/**
 * Auto-detect and initialise the connected display.
 *
 * Probes two I2C buses in sequence:
 *   1. GPIO 25/26, addr 0x3C → SSD1306 (via esp_lcd + LVGL)
 *   2. GPIO 8/9,   addr 0x3C → SH1107  (raw I2C framebuffer)
 *   3. GPIO 8/9,   addr 0x3E → Unit LCD (I2C command interface)
 *
 * Must be called after PSRAM init. Shows "Monster !" splash on success.
 */
void oled_display_init(void);

/**
 * Return the display type detected during init.
 */
display_type_t oled_display_get_type(void);

/**
 * Update the display with two lines of text (thread-safe).
 * Lines 3 and 4 are cleared. Backward-compatible shortcut.
 */
void oled_display_update(const char *line1, const char *line2);

/**
 * Update all four lines of the display (thread-safe).
 * Pass NULL to keep any line's previous content.
 * SSD1306: auto-scrolls long text via LVGL.
 * SH1107 / Unit LCD: truncates with "..." if too long.
 */
void oled_display_update_full(const char *line1, const char *line2,
                              const char *line3, const char *line4);

/**
 * Clear all four lines of the display.
 */
void oled_display_clear(void);

#ifdef __cplusplus
}
#endif
