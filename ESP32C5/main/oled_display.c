/*
 * Multi-display module - SSD1306 / SH1107 / M5 Unit LCD
 *
 * Auto-detects which display is connected by probing two I2C buses:
 *   Bus A (GPIO 25/26):  SSD1306 0.96" 128x64  -> esp_lcd + LVGL 9
 *   Bus B (GPIO 8/9):    SH1107 1.3"  128x64   -> raw I2C framebuffer + 5x7 font
 *                         M5 Unit LCD 1.14"      -> I2C command interface + 5x7 font
 *
 * Public API is identical for all display types.
 */

#include "oled_display.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/lock.h>
#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_timer.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "driver/i2c_master.h"

#include "lvgl.h"

static const char *TAG = "display";

/* ====================================================================== */
/*                     I2C  /  HW  CONFIGURATION                          */
/* ====================================================================== */

/* --- Bus A: SSD1306 board (0.96" OLED) --- */
#define BUS_A_SDA               25
#define BUS_A_SCL               26
#define SSD1306_I2C_ADDR        0x3C
#define SSD1306_I2C_FREQ_HZ     (400 * 1000)

/* --- Bus B: SH1107 / Unit LCD board --- */
#define BUS_B_SDA               8
#define BUS_B_SCL               9
#define SH1107_I2C_ADDR         0x3C
#define SH1107_I2C_FREQ_HZ      100000
#define UNIT_LCD_I2C_ADDR       0x3E
#define UNIT_LCD_I2C_FREQ_HZ     400000

/* --- Common display parameters --- */
#define OLED_H_RES              128
#define OLED_V_RES               64
#define OLED_PAGES              (OLED_V_RES / 8)
#define I2C_TIMEOUT_MS          100
#define I2C_DATA_CHUNK          16

/* --- Unit LCD parameters --- */
#define UNIT_LCD_WIDTH          135
#define UNIT_LCD_HEIGHT         240
#define UNIT_LCD_TEXT_SCALE       2
#define UNIT_LCD_ROTATION         0

/* --- SH1107 rotation (1 = 90 CW, 0 = 90 CCW) --- */
#define SH1107_ROTATE_90_CW       1

/* --- LVGL tunables (SSD1306 only) --- */
#define LVGL_TICK_PERIOD_MS       5
#define LVGL_TASK_STACK_SIZE      (4 * 1024)
#define LVGL_TASK_PRIORITY        2
#define LVGL_PALETTE_SIZE         8
#define LVGL_TASK_MAX_DELAY_MS    500
#define LVGL_TASK_MIN_DELAY_MS    (1000 / CONFIG_FREERTOS_HZ)

/* --- SH1107 max chars per line (128 px / 6 px per glyph) --- */
#define SH1107_MAX_CHARS        21
/* --- Unit LCD max chars per line (135 px / 12 px per glyph) --- */
#define UNIT_LCD_MAX_CHARS      11

/* ====================================================================== */
/*                        5x7  ASCII  FONT                                */
/* ====================================================================== */

static const uint8_t font5x7[95][5] = {
    /* 0x20 ' ' */ {0x00,0x00,0x00,0x00,0x00},
    /* 0x21 '!' */ {0x00,0x00,0x5F,0x00,0x00},
    /* 0x22 '"' */ {0x00,0x07,0x00,0x07,0x00},
    /* 0x23 '#' */ {0x14,0x7F,0x14,0x7F,0x14},
    /* 0x24 '$' */ {0x24,0x2A,0x7F,0x2A,0x12},
    /* 0x25 '%' */ {0x23,0x13,0x08,0x64,0x62},
    /* 0x26 '&' */ {0x36,0x49,0x55,0x22,0x50},
    /* 0x27     */ {0x00,0x05,0x03,0x00,0x00},
    /* 0x28 '(' */ {0x00,0x1C,0x22,0x41,0x00},
    /* 0x29 ')' */ {0x00,0x41,0x22,0x1C,0x00},
    /* 0x2A '*' */ {0x14,0x08,0x3E,0x08,0x14},
    /* 0x2B '+' */ {0x08,0x08,0x3E,0x08,0x08},
    /* 0x2C ',' */ {0x00,0x50,0x30,0x00,0x00},
    /* 0x2D '-' */ {0x08,0x08,0x08,0x08,0x08},
    /* 0x2E '.' */ {0x00,0x60,0x60,0x00,0x00},
    /* 0x2F '/' */ {0x20,0x10,0x08,0x04,0x02},
    /* 0x30 '0' */ {0x3E,0x51,0x49,0x45,0x3E},
    /* 0x31 '1' */ {0x00,0x42,0x7F,0x40,0x00},
    /* 0x32 '2' */ {0x42,0x61,0x51,0x49,0x46},
    /* 0x33 '3' */ {0x21,0x41,0x45,0x4B,0x31},
    /* 0x34 '4' */ {0x18,0x14,0x12,0x7F,0x10},
    /* 0x35 '5' */ {0x27,0x45,0x45,0x45,0x39},
    /* 0x36 '6' */ {0x3C,0x4A,0x49,0x49,0x30},
    /* 0x37 '7' */ {0x01,0x71,0x09,0x05,0x03},
    /* 0x38 '8' */ {0x36,0x49,0x49,0x49,0x36},
    /* 0x39 '9' */ {0x06,0x49,0x49,0x29,0x1E},
    /* 0x3A ':' */ {0x00,0x36,0x36,0x00,0x00},
    /* 0x3B ';' */ {0x00,0x56,0x36,0x00,0x00},
    /* 0x3C '<' */ {0x08,0x14,0x22,0x41,0x00},
    /* 0x3D '=' */ {0x14,0x14,0x14,0x14,0x14},
    /* 0x3E '>' */ {0x00,0x41,0x22,0x14,0x08},
    /* 0x3F '?' */ {0x02,0x01,0x51,0x09,0x06},
    /* 0x40 '@' */ {0x32,0x49,0x79,0x41,0x3E},
    /* 0x41 'A' */ {0x7E,0x11,0x11,0x11,0x7E},
    /* 0x42 'B' */ {0x7F,0x49,0x49,0x49,0x36},
    /* 0x43 'C' */ {0x3E,0x41,0x41,0x41,0x22},
    /* 0x44 'D' */ {0x7F,0x41,0x41,0x22,0x1C},
    /* 0x45 'E' */ {0x7F,0x49,0x49,0x49,0x41},
    /* 0x46 'F' */ {0x7F,0x09,0x09,0x09,0x01},
    /* 0x47 'G' */ {0x3E,0x41,0x49,0x49,0x7A},
    /* 0x48 'H' */ {0x7F,0x08,0x08,0x08,0x7F},
    /* 0x49 'I' */ {0x00,0x41,0x7F,0x41,0x00},
    /* 0x4A 'J' */ {0x20,0x40,0x41,0x3F,0x01},
    /* 0x4B 'K' */ {0x7F,0x08,0x14,0x22,0x41},
    /* 0x4C 'L' */ {0x7F,0x40,0x40,0x40,0x40},
    /* 0x4D 'M' */ {0x7F,0x02,0x0C,0x02,0x7F},
    /* 0x4E 'N' */ {0x7F,0x04,0x08,0x10,0x7F},
    /* 0x4F 'O' */ {0x3E,0x41,0x41,0x41,0x3E},
    /* 0x50 'P' */ {0x7F,0x09,0x09,0x09,0x06},
    /* 0x51 'Q' */ {0x3E,0x41,0x51,0x21,0x5E},
    /* 0x52 'R' */ {0x7F,0x09,0x19,0x29,0x46},
    /* 0x53 'S' */ {0x46,0x49,0x49,0x49,0x31},
    /* 0x54 'T' */ {0x01,0x01,0x7F,0x01,0x01},
    /* 0x55 'U' */ {0x3F,0x40,0x40,0x40,0x3F},
    /* 0x56 'V' */ {0x1F,0x20,0x40,0x20,0x1F},
    /* 0x57 'W' */ {0x3F,0x40,0x38,0x40,0x3F},
    /* 0x58 'X' */ {0x63,0x14,0x08,0x14,0x63},
    /* 0x59 'Y' */ {0x07,0x08,0x70,0x08,0x07},
    /* 0x5A 'Z' */ {0x61,0x51,0x49,0x45,0x43},
    /* 0x5B '[' */ {0x00,0x7F,0x41,0x41,0x00},
    /* 0x5C     */ {0x02,0x04,0x08,0x10,0x20},
    /* 0x5D ']' */ {0x00,0x41,0x41,0x7F,0x00},
    /* 0x5E '^' */ {0x04,0x02,0x01,0x02,0x04},
    /* 0x5F '_' */ {0x40,0x40,0x40,0x40,0x40},
    /* 0x60 '`' */ {0x00,0x01,0x02,0x04,0x00},
    /* 0x61 'a' */ {0x20,0x54,0x54,0x54,0x78},
    /* 0x62 'b' */ {0x7F,0x48,0x44,0x44,0x38},
    /* 0x63 'c' */ {0x38,0x44,0x44,0x44,0x20},
    /* 0x64 'd' */ {0x38,0x44,0x44,0x48,0x7F},
    /* 0x65 'e' */ {0x38,0x54,0x54,0x54,0x18},
    /* 0x66 'f' */ {0x08,0x7E,0x09,0x01,0x02},
    /* 0x67 'g' */ {0x0C,0x52,0x52,0x52,0x3E},
    /* 0x68 'h' */ {0x7F,0x08,0x04,0x04,0x78},
    /* 0x69 'i' */ {0x00,0x44,0x7D,0x40,0x00},
    /* 0x6A 'j' */ {0x20,0x40,0x44,0x3D,0x00},
    /* 0x6B 'k' */ {0x7F,0x10,0x28,0x44,0x00},
    /* 0x6C 'l' */ {0x00,0x41,0x7F,0x40,0x00},
    /* 0x6D 'm' */ {0x7C,0x04,0x18,0x04,0x78},
    /* 0x6E 'n' */ {0x7C,0x08,0x04,0x04,0x78},
    /* 0x6F 'o' */ {0x38,0x44,0x44,0x44,0x38},
    /* 0x70 'p' */ {0x7C,0x14,0x14,0x14,0x08},
    /* 0x71 'q' */ {0x08,0x14,0x14,0x18,0x7C},
    /* 0x72 'r' */ {0x7C,0x08,0x04,0x04,0x08},
    /* 0x73 's' */ {0x48,0x54,0x54,0x54,0x20},
    /* 0x74 't' */ {0x04,0x3F,0x44,0x40,0x20},
    /* 0x75 'u' */ {0x3C,0x40,0x40,0x20,0x7C},
    /* 0x76 'v' */ {0x1C,0x20,0x40,0x20,0x1C},
    /* 0x77 'w' */ {0x3C,0x40,0x30,0x40,0x3C},
    /* 0x78 'x' */ {0x44,0x28,0x10,0x28,0x44},
    /* 0x79 'y' */ {0x0C,0x50,0x50,0x50,0x3C},
    /* 0x7A 'z' */ {0x44,0x64,0x54,0x4C,0x44},
    /* 0x7B '{' */ {0x00,0x08,0x36,0x41,0x00},
    /* 0x7C '|' */ {0x00,0x00,0x7F,0x00,0x00},
    /* 0x7D '}' */ {0x00,0x41,0x36,0x08,0x00},
    /* 0x7E '~' */ {0x10,0x08,0x08,0x10,0x08},
};

static const uint8_t *font_get_glyph(char ch)
{
    static const uint8_t fallback[5] = {0x02,0x01,0x51,0x09,0x06};
    if (ch < 0x20 || ch > 0x7E) return fallback;
    return font5x7[ch - 0x20];
}

/* ====================================================================== */
/*                          SHARED  STATE                                 */
/* ====================================================================== */

static display_type_t       s_display_type = DISPLAY_NONE;
static _lock_t              s_api_lock;

static i2c_master_bus_handle_t  s_i2c_bus_b   = NULL;
static i2c_master_dev_handle_t  s_sh1107_dev  = NULL;
static i2c_master_dev_handle_t  s_ulcd_dev    = NULL;

static lv_display_t *s_lv_display   = NULL;
static lv_obj_t     *s_lv_line[4]   = {NULL};

static uint8_t ssd1306_buf[OLED_H_RES * OLED_V_RES / 8];
static uint8_t sh1107_fb[OLED_PAGES][OLED_H_RES];
static char s_line_cache[4][64];

/* ====================================================================== */
/*              SSD1306  DRIVER  (esp_lcd + LVGL 9)                       */
/* ====================================================================== */

static void ssd1306_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map)
{
    esp_lcd_panel_handle_t panel = lv_display_get_user_data(disp);
    px_map += LVGL_PALETTE_SIZE;

    uint16_t hor_res = lv_display_get_physical_horizontal_resolution(disp);
    int x1 = area->x1, x2 = area->x2, y1 = area->y1, y2 = area->y2;

    for (int y = y1; y <= y2; y++) {
        for (int x = x1; x <= x2; x++) {
            bool chroma = (px_map[(hor_res >> 3) * y + (x >> 3)] & (1 << (7 - (x % 8))));
            uint8_t *buf = ssd1306_buf + hor_res * (y >> 3) + x;
            if (chroma) *buf |=  (1 << (y % 8));
            else        *buf &= ~(1 << (y % 8));
        }
    }
    esp_lcd_panel_draw_bitmap(panel, x1, y1, x2 + 1, y2 + 1, ssd1306_buf);
}

static bool ssd1306_flush_ready_cb(esp_lcd_panel_io_handle_t io,
                                   esp_lcd_panel_io_event_data_t *edata,
                                   void *user_ctx)
{
    lv_display_flush_ready((lv_display_t *)user_ctx);
    return false;
}

static void lvgl_tick_cb(void *arg) { lv_tick_inc(LVGL_TICK_PERIOD_MS); }

static void lvgl_task(void *arg)
{
    ESP_LOGI(TAG, "LVGL task started");
    uint32_t ms = 0;
    while (1) {
        _lock_acquire(&s_api_lock);
        ms = lv_timer_handler();
        _lock_release(&s_api_lock);
        ms = MAX(ms, LVGL_TASK_MIN_DELAY_MS);
        ms = MIN(ms, LVGL_TASK_MAX_DELAY_MS);
        usleep(1000 * ms);
    }
}

static void ssd1306_build_ui(lv_display_t *disp)
{
    lv_obj_t *scr = lv_display_get_screen_active(disp);
    lv_obj_set_style_bg_color(scr, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(scr, 0, 0);

    static const int y_pos[4] = {0, 14, 28, 48};
    static const lv_label_long_mode_t modes[4] = {
        LV_LABEL_LONG_CLIP,
        LV_LABEL_LONG_SCROLL_CIRCULAR,
        LV_LABEL_LONG_SCROLL_CIRCULAR,
        LV_LABEL_LONG_CLIP,
    };

    for (int i = 0; i < 4; i++) {
        s_lv_line[i] = lv_label_create(scr);
        lv_label_set_long_mode(s_lv_line[i], modes[i]);
        lv_obj_set_width(s_lv_line[i], OLED_H_RES);
        lv_obj_set_style_text_font(s_lv_line[i], &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(s_lv_line[i], lv_color_white(), 0);
        lv_obj_align(s_lv_line[i], LV_ALIGN_TOP_LEFT, 0, y_pos[i]);
        lv_label_set_text(s_lv_line[i], "");
    }
}

static void ssd1306_show_monster_splash(void)
{
    if (!s_lv_display) return;

    _lock_acquire(&s_api_lock);
    lv_obj_t *scr = lv_display_get_screen_active(s_lv_display);
    lv_obj_t *splash = lv_label_create(scr);
    lv_obj_set_style_text_font(splash, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_color(splash, lv_color_white(), 0);
    lv_label_set_text(splash, "Monster !");
    lv_obj_center(splash);
    _lock_release(&s_api_lock);

    vTaskDelay(pdMS_TO_TICKS(1000));

    _lock_acquire(&s_api_lock);
    lv_obj_delete(splash);
    _lock_release(&s_api_lock);
}

static bool ssd1306_init(void)
{
    ESP_LOGI(TAG, "Probing SSD1306 on SDA=%d SCL=%d addr=0x%02X",
             BUS_A_SDA, BUS_A_SCL, SSD1306_I2C_ADDR);

    i2c_master_bus_handle_t bus = NULL;
    i2c_master_bus_config_t bus_cfg = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .i2c_port = I2C_NUM_0,
        .sda_io_num = BUS_A_SDA,
        .scl_io_num = BUS_A_SCL,
        .flags.enable_internal_pullup = true,
    };
    if (i2c_new_master_bus(&bus_cfg, &bus) != ESP_OK) return false;

    if (i2c_master_probe(bus, SSD1306_I2C_ADDR, I2C_TIMEOUT_MS) != ESP_OK) {
        i2c_del_master_bus(bus);
        return false;
    }

    esp_lcd_panel_io_handle_t io = NULL;
    esp_lcd_panel_io_i2c_config_t io_cfg = {
        .dev_addr = SSD1306_I2C_ADDR,
        .scl_speed_hz = SSD1306_I2C_FREQ_HZ,
        .control_phase_bytes = 1,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .dc_bit_offset = 6,
    };
    if (esp_lcd_new_panel_io_i2c(bus, &io_cfg, &io) != ESP_OK) {
        i2c_del_master_bus(bus);
        return false;
    }

    esp_lcd_panel_handle_t panel = NULL;
    esp_lcd_panel_ssd1306_config_t ssd_cfg = { .height = OLED_V_RES };
    esp_lcd_panel_dev_config_t dev_cfg = {
        .bits_per_pixel = 1,
        .reset_gpio_num = -1,
        .vendor_config = &ssd_cfg,
    };
    if (esp_lcd_new_panel_ssd1306(io, &dev_cfg, &panel) != ESP_OK ||
        esp_lcd_panel_reset(panel) != ESP_OK ||
        esp_lcd_panel_init(panel)  != ESP_OK ||
        esp_lcd_panel_disp_on_off(panel, true) != ESP_OK) {
        i2c_del_master_bus(bus);
        return false;
    }

    lv_init();
    s_lv_display = lv_display_create(OLED_H_RES, OLED_V_RES);
    lv_display_set_user_data(s_lv_display, panel);

    size_t buf_sz = OLED_H_RES * OLED_V_RES / 8 + LVGL_PALETTE_SIZE;
    void *draw_buf = heap_caps_calloc(1, buf_sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!draw_buf) draw_buf = heap_caps_calloc(1, buf_sz, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    assert(draw_buf);

    lv_display_set_color_format(s_lv_display, LV_COLOR_FORMAT_I1);
    lv_display_set_buffers(s_lv_display, draw_buf, NULL, buf_sz, LV_DISPLAY_RENDER_MODE_FULL);
    lv_display_set_flush_cb(s_lv_display, ssd1306_flush_cb);

    const esp_lcd_panel_io_callbacks_t cbs = { .on_color_trans_done = ssd1306_flush_ready_cb };
    esp_lcd_panel_io_register_event_callbacks(io, &cbs, s_lv_display);

    const esp_timer_create_args_t tick_args = { .callback = &lvgl_tick_cb, .name = "lvgl_tick" };
    esp_timer_handle_t tick_timer = NULL;
    ESP_ERROR_CHECK(esp_timer_create(&tick_args, &tick_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(tick_timer, LVGL_TICK_PERIOD_MS * 1000));
    xTaskCreate(lvgl_task, "LVGL", LVGL_TASK_STACK_SIZE, NULL, LVGL_TASK_PRIORITY, NULL);

    _lock_acquire(&s_api_lock);
    ssd1306_build_ui(s_lv_display);
    _lock_release(&s_api_lock);

    ESP_LOGI(TAG, "SSD1306 ready (128x64) on GPIO %d/%d", BUS_A_SDA, BUS_A_SCL);
    return true;
}

static void ssd1306_update(const char *lines[4])
{
    _lock_acquire(&s_api_lock);
    for (int i = 0; i < 4; i++) {
        if (lines[i] && s_lv_line[i])
            lv_label_set_text(s_lv_line[i], lines[i]);
    }
    _lock_release(&s_api_lock);
}

/* ====================================================================== */
/*                SH1107  DRIVER  (raw I2C framebuffer)                   */
/* ====================================================================== */

static esp_err_t sh1107_cmd(uint8_t cmd)
{
    uint8_t tx[2] = {0x00, cmd};
    return i2c_master_transmit(s_sh1107_dev, tx, sizeof(tx), I2C_TIMEOUT_MS);
}

static esp_err_t sh1107_cmd_arg(uint8_t cmd, uint8_t arg)
{
    uint8_t tx[3] = {0x00, cmd, arg};
    return i2c_master_transmit(s_sh1107_dev, tx, sizeof(tx), I2C_TIMEOUT_MS);
}

static esp_err_t sh1107_data(const uint8_t *data, size_t len)
{
    uint8_t tx[1 + I2C_DATA_CHUNK];
    tx[0] = 0x40;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > I2C_DATA_CHUNK) chunk = I2C_DATA_CHUNK;
        memcpy(&tx[1], data + off, chunk);
        esp_err_t err = i2c_master_transmit(s_sh1107_dev, tx, 1 + chunk, I2C_TIMEOUT_MS);
        if (err != ESP_OK) return err;
        off += chunk;
    }
    return ESP_OK;
}

static esp_err_t sh1107_set_page_col(uint8_t page, uint8_t col)
{
    esp_err_t e;
    e = sh1107_cmd((uint8_t)(0xB0 | (page & 0x0F)));       if (e) return e;
    e = sh1107_cmd((uint8_t)(0x00 | (col & 0x0F)));         if (e) return e;
    return sh1107_cmd((uint8_t)(0x10 | ((col >> 4) & 0x0F)));
}

static esp_err_t sh1107_flush(void)
{
    for (uint8_t p = 0; p < OLED_PAGES; p++) {
        esp_err_t e = sh1107_set_page_col(p, 0);
        if (e) return e;
        e = sh1107_data(sh1107_fb[p], OLED_H_RES);
        if (e) return e;
    }
    return ESP_OK;
}

static void sh1107_fb_clear(void) { memset(sh1107_fb, 0, sizeof(sh1107_fb)); }

static void sh1107_set_pixel(int x, int y)
{
    if (x < 0 || y < 0 || x >= OLED_H_RES || y >= OLED_V_RES) return;
    sh1107_fb[y / 8][x] |= (uint8_t)(1 << (y & 7));
}

static void sh1107_set_pixel_rot90(int lx, int ly)
{
    if (lx < 0 || ly < 0 || lx >= OLED_V_RES || ly >= OLED_H_RES) return;
#if SH1107_ROTATE_90_CW
    int px = (OLED_H_RES - 1) - ly;
    int py = lx;
#else
    int px = ly;
    int py = (OLED_V_RES - 1) - lx;
#endif
    sh1107_set_pixel(px, py);
}

static void sh1107_draw_char_rot(char ch, int cx, int cy)
{
    const uint8_t *g = font_get_glyph(ch);
    for (int col = 0; col < 5; col++) {
        uint8_t bits = g[col];
        for (int row = 0; row < 7; row++) {
            if (bits & (1 << row))
                sh1107_set_pixel_rot90(cx + col, cy + row);
        }
    }
}

static int truncate_text(const char *src, char *dst, size_t dst_sz, int max_chars)
{
    if (!src) { dst[0] = '\0'; return 0; }
    int len = (int)strlen(src);
    if (len <= max_chars) {
        snprintf(dst, dst_sz, "%s", src);
        return len;
    }
    if (max_chars > 3) {
        int cut = max_chars - 3;
        memcpy(dst, src, cut);
        dst[cut] = '.'; dst[cut+1] = '.'; dst[cut+2] = '.'; dst[cut+3] = '\0';
        return max_chars;
    }
    snprintf(dst, dst_sz, "%.*s", max_chars, src);
    return max_chars;
}

static void sh1107_draw_line_centre(const char *text, int line_y, int max_chars)
{
    if (!text || !text[0]) return;
    char buf[64];
    int len = truncate_text(text, buf, sizeof(buf), max_chars);
    int pixel_w = len * 6;
    int start_x = (OLED_V_RES - pixel_w) / 2;
    if (start_x < 0) start_x = 0;
    for (int i = 0; i < len; i++)
        sh1107_draw_char_rot(buf[i], start_x + i * 6, line_y);
}

static void sh1107_draw_line_left(const char *text, int line_y, int max_chars)
{
    if (!text || !text[0]) return;
    char buf[64];
    int len = truncate_text(text, buf, sizeof(buf), max_chars);
    for (int i = 0; i < len; i++)
        sh1107_draw_char_rot(buf[i], 1 + i * 6, line_y);
}

static void sh1107_draw_monster(void)
{
    sh1107_fb_clear();
    sh1107_draw_line_centre("Monster !", (OLED_H_RES - 7) / 2, SH1107_MAX_CHARS);
    sh1107_flush();
}

static void sh1107_update(const char *lines[4])
{
    sh1107_fb_clear();
    static const int line_y[4] = {4, 36, 66, 114};
    for (int i = 0; i < 4; i++) {
        if (lines[i] && lines[i][0])
            sh1107_draw_line_left(lines[i], line_y[i], SH1107_MAX_CHARS);
    }
    sh1107_flush();
}

static bool sh1107_init(void)
{
    ESP_LOGI(TAG, "Probing SH1107 on SDA=%d SCL=%d addr=0x%02X",
             BUS_B_SDA, BUS_B_SCL, SH1107_I2C_ADDR);

    if (!s_i2c_bus_b) {
        i2c_master_bus_config_t cfg = {
            .clk_source = I2C_CLK_SRC_DEFAULT,
            .i2c_port = I2C_NUM_0,
            .sda_io_num = BUS_B_SDA,
            .scl_io_num = BUS_B_SCL,
            .glitch_ignore_cnt = 7,
            .flags.enable_internal_pullup = true,
        };
        if (i2c_new_master_bus(&cfg, &s_i2c_bus_b) != ESP_OK) return false;
    }

    if (i2c_master_probe(s_i2c_bus_b, SH1107_I2C_ADDR, I2C_TIMEOUT_MS) != ESP_OK)
        return false;

    i2c_device_config_t dev = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = SH1107_I2C_ADDR,
        .scl_speed_hz = SH1107_I2C_FREQ_HZ,
    };
    if (i2c_master_bus_add_device(s_i2c_bus_b, &dev, &s_sh1107_dev) != ESP_OK)
        return false;

    vTaskDelay(pdMS_TO_TICKS(50));

    typedef struct { uint8_t cmd; int16_t arg; } icmd_t;
    static const icmd_t seq[] = {
        {0xAE, -1},
        {0xA8, 0x3F},
        {0x20, 0x00},
        {0xB0, -1},
        {0xAD, 0x81},
        {0xD5, 0x50},
        {0xD9, 0x22},
        {0xDB, 0x35},
        {0x81, 0x7F},
        {0xDC, 0x00},
        {0xD3, 0x60},
        {0xA0, -1},
        {0xC0, -1},
        {0xA4, -1},
        {0xA6, -1},
        {0xAF, -1},
    };

    for (size_t i = 0; i < sizeof(seq)/sizeof(seq[0]); i++) {
        esp_err_t e = (seq[i].arg >= 0) ? sh1107_cmd_arg(seq[i].cmd, (uint8_t)seq[i].arg)
                                         : sh1107_cmd(seq[i].cmd);
        if (e != ESP_OK) {
            i2c_master_bus_rm_device(s_sh1107_dev);
            s_sh1107_dev = NULL;
            return false;
        }
    }

    vTaskDelay(pdMS_TO_TICKS(120));
    sh1107_fb_clear();
    if (sh1107_flush() != ESP_OK) {
        i2c_master_bus_rm_device(s_sh1107_dev);
        s_sh1107_dev = NULL;
        return false;
    }

    ESP_LOGI(TAG, "SH1107 ready (128x64 rotated) on GPIO %d/%d", BUS_B_SDA, BUS_B_SCL);
    return true;
}

/* ====================================================================== */
/*            UNIT  LCD  DRIVER  (M5 Unit LCD 1.14" ST7789V2)             */
/* ====================================================================== */

static esp_err_t ulcd_send(const uint8_t *payload, size_t len)
{
    return i2c_master_transmit(s_ulcd_dev, payload, len, I2C_TIMEOUT_MS);
}

static esp_err_t ulcd_fill_rect(uint8_t x1, uint8_t y1, uint8_t x2, uint8_t y2, uint16_t c)
{
    uint8_t cmd[7] = {0x6A, x1, y1, x2, y2, (uint8_t)(c >> 8), (uint8_t)(c & 0xFF)};
    return ulcd_send(cmd, sizeof(cmd));
}

static esp_err_t ulcd_clear(uint16_t color)
{
    return ulcd_fill_rect(0, 0, UNIT_LCD_WIDTH - 1, UNIT_LCD_HEIGHT - 1, color);
}

static void ulcd_draw_char(char ch, int cx, int cy, int scale, uint16_t fg)
{
    const uint8_t *g = font_get_glyph(ch);
    for (int col = 0; col < 5; col++) {
        uint8_t bits = g[col];
        for (int row = 0; row < 7; row++) {
            if (!(bits & (1 << row))) continue;
            int px = cx + col * scale;
            int py = cy + row * scale;
            if (px >= UNIT_LCD_WIDTH || py >= UNIT_LCD_HEIGHT) continue;
            int x2 = px + scale - 1;
            int y2 = py + scale - 1;
            if (x2 >= UNIT_LCD_WIDTH)  x2 = UNIT_LCD_WIDTH - 1;
            if (y2 >= UNIT_LCD_HEIGHT) y2 = UNIT_LCD_HEIGHT - 1;
            ulcd_fill_rect((uint8_t)px, (uint8_t)py, (uint8_t)x2, (uint8_t)y2, fg);
        }
    }
}

static void ulcd_draw_text(const char *text, int x, int y, int scale, int max_chars, uint16_t fg)
{
    if (!text || !text[0]) return;
    char buf[64];
    int len = truncate_text(text, buf, sizeof(buf), max_chars);
    int spacing = scale;
    for (int i = 0; i < len; i++)
        ulcd_draw_char(buf[i], x + i * (5 * scale + spacing), y, scale, fg);
}

static void ulcd_draw_monster(void)
{
    const int scale = UNIT_LCD_TEXT_SCALE;
    const char *text = "Monster !";
    int len = (int)strlen(text);
    int char_w = 5 * scale + scale;
    int text_w = len * char_w - scale;
    int text_h = 7 * scale;
    int sx = (UNIT_LCD_WIDTH  - text_w) / 2;
    int sy = (UNIT_LCD_HEIGHT - text_h) / 2;
    if (sx < 0) sx = 0;
    if (sy < 0) sy = 0;
    ulcd_clear(0x0000);
    ulcd_draw_text(text, sx, sy, scale, 20, 0xFFFF);
}

static void ulcd_update(const char *lines[4])
{
    ulcd_clear(0x0000);
    static const int line_y[4] = {10, 70, 130, 210};
    for (int i = 0; i < 4; i++) {
        if (lines[i] && lines[i][0])
            ulcd_draw_text(lines[i], 4, line_y[i],
                           UNIT_LCD_TEXT_SCALE, UNIT_LCD_MAX_CHARS, 0xFFFF);
    }
}

static bool ulcd_init(void)
{
    ESP_LOGI(TAG, "Probing Unit LCD on SDA=%d SCL=%d addr=0x%02X",
             BUS_B_SDA, BUS_B_SCL, UNIT_LCD_I2C_ADDR);

    if (!s_i2c_bus_b) {
        i2c_master_bus_config_t cfg = {
            .clk_source = I2C_CLK_SRC_DEFAULT,
            .i2c_port = I2C_NUM_0,
            .sda_io_num = BUS_B_SDA,
            .scl_io_num = BUS_B_SCL,
            .glitch_ignore_cnt = 7,
            .flags.enable_internal_pullup = true,
        };
        if (i2c_new_master_bus(&cfg, &s_i2c_bus_b) != ESP_OK) return false;
    }

    if (i2c_master_probe(s_i2c_bus_b, UNIT_LCD_I2C_ADDR, I2C_TIMEOUT_MS) != ESP_OK)
        return false;

    i2c_device_config_t dev = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = UNIT_LCD_I2C_ADDR,
        .scl_speed_hz = UNIT_LCD_I2C_FREQ_HZ,
    };
    if (i2c_master_bus_add_device(s_i2c_bus_b, &dev, &s_ulcd_dev) != ESP_OK)
        return false;

    uint8_t reset_cmd = 0x30;
    if (ulcd_send(&reset_cmd, 1) != ESP_OK) goto fail;
    vTaskDelay(pdMS_TO_TICKS(120));

    uint8_t rot_cmd[2] = {0x36, UNIT_LCD_ROTATION};
    if (ulcd_send(rot_cmd, sizeof(rot_cmd)) != ESP_OK) goto fail;

    uint8_t on_cmd = 0x29;
    if (ulcd_send(&on_cmd, 1) != ESP_OK) goto fail;

    if (ulcd_clear(0x0000) != ESP_OK) goto fail;

    ESP_LOGI(TAG, "Unit LCD ready (%dx%d) on GPIO %d/%d",
             UNIT_LCD_WIDTH, UNIT_LCD_HEIGHT, BUS_B_SDA, BUS_B_SCL);
    return true;

fail:
    i2c_master_bus_rm_device(s_ulcd_dev);
    s_ulcd_dev = NULL;
    return false;
}

/* ====================================================================== */
/*                          PUBLIC  API                                   */
/* ====================================================================== */

void oled_display_init(void)
{
    if (ssd1306_init()) {
        s_display_type = DISPLAY_SSD1306;
        ESP_LOGI(TAG, "Display: SSD1306 OLED at 0x%02X (GPIO %d/%d)",
                 SSD1306_I2C_ADDR, BUS_A_SDA, BUS_A_SCL);
        ssd1306_show_monster_splash();
        return;
    }

    if (sh1107_init()) {
        s_display_type = DISPLAY_SH1107;
        ESP_LOGI(TAG, "Display: SH1107 OLED at 0x%02X (GPIO %d/%d)",
                 SH1107_I2C_ADDR, BUS_B_SDA, BUS_B_SCL);
        sh1107_draw_monster();
        vTaskDelay(pdMS_TO_TICKS(1000));
        return;
    }

    if (ulcd_init()) {
        s_display_type = DISPLAY_UNIT_LCD;
        ESP_LOGI(TAG, "Display: M5 Unit LCD at 0x%02X (GPIO %d/%d)",
                 UNIT_LCD_I2C_ADDR, BUS_B_SDA, BUS_B_SCL);
        ulcd_draw_monster();
        vTaskDelay(pdMS_TO_TICKS(1000));
        return;
    }

    s_display_type = DISPLAY_NONE;
    if (s_i2c_bus_b) {
        i2c_del_master_bus(s_i2c_bus_b);
        s_i2c_bus_b = NULL;
    }
    ESP_LOGW(TAG, "No display detected (probed 0x%02X on %d/%d, 0x%02X+0x%02X on %d/%d)",
             SSD1306_I2C_ADDR, BUS_A_SDA, BUS_A_SCL,
             SH1107_I2C_ADDR, UNIT_LCD_I2C_ADDR, BUS_B_SDA, BUS_B_SCL);
}

display_type_t oled_display_get_type(void)
{
    return s_display_type;
}

void oled_display_update(const char *line1, const char *line2)
{
    oled_display_update_full(line1, line2, "", "");
}

void oled_display_update_full(const char *line1, const char *line2,
                              const char *line3, const char *line4)
{
    const char *lines[4] = {line1, line2, line3, line4};

    switch (s_display_type) {
    case DISPLAY_SSD1306:
        ssd1306_update(lines);
        break;

    case DISPLAY_SH1107:
    case DISPLAY_UNIT_LCD:
        {
            bool changed = false;
            for (int i = 0; i < 4; i++) {
                if (lines[i] && strcmp(s_line_cache[i], lines[i]) != 0) {
                    changed = true;
                    snprintf(s_line_cache[i], sizeof(s_line_cache[i]), "%s", lines[i]);
                }
            }
            if (changed) {
                const char *cached[4] = {s_line_cache[0], s_line_cache[1],
                                         s_line_cache[2], s_line_cache[3]};
                _lock_acquire(&s_api_lock);
                if (s_display_type == DISPLAY_SH1107)
                    sh1107_update(cached);
                else
                    ulcd_update(cached);
                _lock_release(&s_api_lock);
            }
        }
        break;

    default:
        break;
    }
}

void oled_display_clear(void)
{
    oled_display_update_full("", "", "", "");
}
