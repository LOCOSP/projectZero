#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize I2C bus, SSD1306 panel, and LVGL for the 0.96" OLED display.
 * Must be called after PSRAM init. Starts the LVGL timer task.
 */
void oled_display_init(void);

/**
 * Update the OLED display with two lines of text (thread-safe).
 * Lines 3 and 4 are cleared. Backward-compatible shortcut.
 * @param line1  Top line – command/mode name (may be NULL to keep previous)
 * @param line2  Second line – SSID / parameter (may be NULL or "" to clear)
 */
void oled_display_update(const char *line1, const char *line2);

/**
 * Update all four lines of the OLED display (thread-safe).
 * Pass NULL to keep any line's previous content.
 * @param line1  Title / command name (clipped at 16 chars)
 * @param line2  Target / SSID (auto-scrolls if >16 chars)
 * @param line3  Detail info (auto-scrolls if >16 chars)
 * @param line4  Status footer (clipped at 16 chars)
 */
void oled_display_update_full(const char *line1, const char *line2,
                              const char *line3, const char *line4);

/**
 * Clear all four lines of the OLED display.
 */
void oled_display_clear(void);

#ifdef __cplusplus
}
#endif
