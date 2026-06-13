#include "zig_recon.h"

#include <limits.h>
#include <string.h>
#include "esp_check.h"
#include "esp_bit_defs.h"
#include "esp_ieee802154.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#define ZIG_RECON_TAG "zig_recon"
#define ZIG_RECON_QUEUE_DEPTH 32
#define ZIG_RECON_MAX_FRAME_LEN 128
#define ZIG_RECON_DEFAULT_DWELL_MS 250
#define ZIG_RECON_TASK_STACK 4096
#define ZIG_RECON_TASK_PRIO 5
#define ZIG_RECON_NO_RSSI INT8_MIN
#define ZIG_RECON_PAN_UNKNOWN 0xffff

typedef struct {
    uint8_t len;
    uint8_t data[ZIG_RECON_MAX_FRAME_LEN];
    uint8_t channel;
    int8_t rssi;
    uint8_t lqi;
    uint64_t timestamp;
} zig_recon_rx_frame_t;

typedef struct {
    uint8_t frame_type;
    uint8_t mac_header_len;
    uint16_t dst_pan;
    uint16_t src_pan;
    uint16_t src_short;
    uint64_t src_ext;
    bool has_dst_pan;
    bool has_src_pan;
    bool has_src_short;
    bool has_src_ext;
    bool pan_compression;
    const uint8_t *payload;
    uint8_t payload_len;
} zig_recon_mac_info_t;

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static QueueHandle_t s_rx_queue;
static TaskHandle_t s_task;
static volatile bool s_active;
static bool s_enabled;
static uint8_t s_current_channel = ZIG_RECON_MIN_CHANNEL;
static uint16_t s_dwell_ms = ZIG_RECON_DEFAULT_DWELL_MS;
static uint32_t s_channel_mask = ZIG_RECON_ALL_CHANNELS_MASK;
static uint32_t s_packets_total;
static uint32_t s_dropped_frames;
static zig_recon_pan_t s_pans[ZIG_RECON_MAX_PANS];
static uint16_t s_pan_count;
static zig_recon_node_t s_nodes[ZIG_RECON_MAX_NODES];
static uint16_t s_node_count;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static uint32_t normalize_channel_mask(uint32_t mask)
{
    mask &= ZIG_RECON_ALL_CHANNELS_MASK;
    return mask ? mask : ZIG_RECON_ALL_CHANNELS_MASK;
}

static uint8_t first_channel(uint32_t mask)
{
    for (uint8_t ch = ZIG_RECON_MIN_CHANNEL; ch <= ZIG_RECON_MAX_CHANNEL; ch++) {
        if (mask & (1UL << ch)) {
            return ch;
        }
    }
    return ZIG_RECON_MIN_CHANNEL;
}

static uint8_t next_channel(uint8_t current, uint32_t mask)
{
    for (uint8_t step = 1; step <= 16; step++) {
        uint8_t ch = (uint8_t)(ZIG_RECON_MIN_CHANNEL + ((current - ZIG_RECON_MIN_CHANNEL + step) % 16));
        if (mask & (1UL << ch)) {
            return ch;
        }
    }
    return first_channel(mask);
}

static uint16_t get_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint64_t get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | p[i];
    }
    return v;
}

static bool read_short_addr(const uint8_t *payload, uint8_t len, uint8_t *pos, uint16_t *out)
{
    if ((uint16_t)*pos + 2 > len) {
        return false;
    }
    *out = get_le16(&payload[*pos]);
    *pos += 2;
    return true;
}

static bool read_ext_addr(const uint8_t *payload, uint8_t len, uint8_t *pos, uint64_t *out)
{
    if ((uint16_t)*pos + 8 > len) {
        return false;
    }
    *out = get_le64(&payload[*pos]);
    *pos += 8;
    return true;
}

static bool parse_mac(const uint8_t *frame, zig_recon_mac_info_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!frame || frame[0] < 3) {
        return false;
    }

    const uint8_t len = frame[0];
    const uint8_t *mhr = &frame[1];
    const uint16_t fcf = get_le16(mhr);
    const bool seq_suppressed = (fcf & BIT(8)) != 0;
    const uint8_t dst_mode = (uint8_t)((fcf >> 10) & 0x3);
    const uint8_t src_mode = (uint8_t)((fcf >> 14) & 0x3);

    out->frame_type = (uint8_t)(fcf & 0x7);
    out->pan_compression = (fcf & BIT(6)) != 0;

    uint8_t pos = 2;
    if (!seq_suppressed) {
        pos++;
    }
    if (pos > len) {
        return false;
    }

    if (dst_mode != 0) {
        if (!read_short_addr(mhr, len, &pos, &out->dst_pan)) {
            return false;
        }
        out->has_dst_pan = true;
        if (dst_mode == 2) {
            uint16_t ignored;
            if (!read_short_addr(mhr, len, &pos, &ignored)) {
                return false;
            }
        } else if (dst_mode == 3) {
            uint64_t ignored;
            if (!read_ext_addr(mhr, len, &pos, &ignored)) {
                return false;
            }
        } else {
            return false;
        }
    }

    if (src_mode != 0) {
        if (out->pan_compression && out->has_dst_pan) {
            out->src_pan = out->dst_pan;
            out->has_src_pan = true;
        } else {
            if (!read_short_addr(mhr, len, &pos, &out->src_pan)) {
                return false;
            }
            out->has_src_pan = true;
        }

        if (src_mode == 2) {
            if (!read_short_addr(mhr, len, &pos, &out->src_short)) {
                return false;
            }
            out->has_src_short = true;
        } else if (src_mode == 3) {
            if (!read_ext_addr(mhr, len, &pos, &out->src_ext)) {
                return false;
            }
            out->has_src_ext = true;
        } else {
            return false;
        }
    }

    if (pos > len) {
        return false;
    }
    out->mac_header_len = pos;
    out->payload = &mhr[pos];
    out->payload_len = (uint8_t)(len - pos);
    return true;
}

static uint16_t select_pan_id(const zig_recon_mac_info_t *mac)
{
    if (mac->has_src_pan && mac->src_pan != ZIG_RECON_PAN_UNKNOWN) {
        return mac->src_pan;
    }
    if (mac->has_dst_pan && mac->dst_pan != ZIG_RECON_PAN_UNKNOWN) {
        return mac->dst_pan;
    }
    if (mac->has_src_pan) {
        return mac->src_pan;
    }
    if (mac->has_dst_pan) {
        return mac->dst_pan;
    }
    return ZIG_RECON_PAN_UNKNOWN;
}

static bool payload_looks_zigbee(const zig_recon_mac_info_t *mac)
{
    if (!mac->payload || mac->payload_len < 2) {
        return false;
    }
    const uint16_t nwk_fcf = get_le16(mac->payload);
    const uint8_t nwk_frame_type = (uint8_t)(nwk_fcf & 0x3);
    const uint8_t protocol_version = (uint8_t)((nwk_fcf >> 2) & 0xf);
    return protocol_version == 2 && nwk_frame_type <= 3;
}

static bool payload_looks_thread(const zig_recon_mac_info_t *mac)
{
    if (!mac->payload || mac->payload_len == 0) {
        return false;
    }
    const uint8_t dispatch = mac->payload[0];
    if ((dispatch & 0xe0) == 0x60) { /* LOWPAN_IPHC */
        return true;
    }
    if ((dispatch & 0xc0) == 0x80) { /* LOWPAN_MESH */
        return true;
    }
    if (dispatch == 0x41 || dispatch == 0x42) { /* Fragment headers often seen with 6LoWPAN. */
        return true;
    }
    return false;
}

static bool payload_contains_be16(const uint8_t *payload, uint8_t len, uint16_t value)
{
    if (!payload || len < 2) {
        return false;
    }
    const uint8_t hi = (uint8_t)(value >> 8);
    const uint8_t lo = (uint8_t)(value & 0xff);
    for (uint8_t i = 0; i + 1 < len; i++) {
        if (payload[i] == hi && payload[i + 1] == lo) {
            return true;
        }
    }
    return false;
}

static bool payload_contains_ascii(const uint8_t *payload, uint8_t len, const char *needle)
{
    if (!payload || !needle) {
        return false;
    }
    const size_t needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > len) {
        return false;
    }
    for (uint8_t i = 0; i + needle_len <= len; i++) {
        if (memcmp(&payload[i], needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool payload_looks_matter_thread(const zig_recon_mac_info_t *mac)
{
    if (!payload_looks_thread(mac)) {
        return false;
    }

    /*
     * Matter over Thread is not a distinct 802.15.4 PHY/MAC protocol. This is
     * only a best-effort hint for rare cases where upper-layer bytes are still
     * visible in a 6LoWPAN-looking payload.
     */
    return payload_contains_be16(mac->payload, mac->payload_len, 5540) || /* Matter UDP */
           payload_contains_be16(mac->payload, mac->payload_len, 5683) || /* CoAP */
           payload_contains_be16(mac->payload, mac->payload_len, 5353) || /* mDNS/DNS-SD */
           payload_contains_ascii(mac->payload, mac->payload_len, "_matter") ||
           payload_contains_ascii(mac->payload, mac->payload_len, "_meshcop");
}

static zig_recon_pan_t *find_or_add_pan(uint16_t pan_id)
{
    for (uint16_t i = 0; i < s_pan_count; i++) {
        if (s_pans[i].pan_id == pan_id) {
            return &s_pans[i];
        }
    }
    if (s_pan_count >= ZIG_RECON_MAX_PANS) {
        s_dropped_frames++;
        return NULL;
    }
    zig_recon_pan_t *pan = &s_pans[s_pan_count++];
    memset(pan, 0, sizeof(*pan));
    pan->pan_id = pan_id;
    pan->proto = ZIG_RECON_PROTO_IEEE802154;
    pan->confidence = ZIG_RECON_CONFIDENCE_UNKNOWN;
    pan->best_rssi = ZIG_RECON_NO_RSSI;
    pan->last_rssi = ZIG_RECON_NO_RSSI;
    return pan;
}

static zig_recon_node_t *find_or_add_node(uint16_t pan_id, const zig_recon_mac_info_t *mac)
{
    if (!mac->has_src_short && !mac->has_src_ext) {
        return NULL;
    }
    if (mac->has_src_short && mac->src_short >= 0xfffe) {
        return NULL;
    }

    for (uint16_t i = 0; i < s_node_count; i++) {
        zig_recon_node_t *node = &s_nodes[i];
        if (node->pan_id != pan_id) {
            continue;
        }
        if (mac->has_src_short && node->short_addr == mac->src_short) {
            return node;
        }
        if (mac->has_src_ext && node->has_ext_addr && node->ext_addr == mac->src_ext) {
            return node;
        }
    }

    if (s_node_count >= ZIG_RECON_MAX_NODES) {
        s_dropped_frames++;
        return NULL;
    }

    zig_recon_node_t *node = &s_nodes[s_node_count++];
    memset(node, 0, sizeof(*node));
    node->pan_id = pan_id;
    node->short_addr = mac->has_src_short ? mac->src_short : ZIG_RECON_PAN_UNKNOWN;
    node->has_short_addr = mac->has_src_short;
    node->ext_addr = mac->src_ext;
    node->has_ext_addr = mac->has_src_ext;
    node->role = (mac->has_src_short && mac->src_short == 0x0000)
        ? ZIG_RECON_ROLE_COORDINATOR
        : ZIG_RECON_ROLE_UNKNOWN;
    return node;
}

static void update_proto_guess(zig_recon_pan_t *pan, const zig_recon_mac_info_t *mac)
{
    if (payload_looks_zigbee(mac)) {
        pan->proto = ZIG_RECON_PROTO_ZIGBEE;
        pan->confidence = ZIG_RECON_CONFIDENCE_PROBABLE;
    } else if (pan->proto != ZIG_RECON_PROTO_ZIGBEE && payload_looks_matter_thread(mac)) {
        pan->proto = ZIG_RECON_PROTO_MATTER_THREAD;
        pan->confidence = ZIG_RECON_CONFIDENCE_PROBABLE;
    } else if (pan->proto != ZIG_RECON_PROTO_ZIGBEE && payload_looks_thread(mac)) {
        if (pan->proto != ZIG_RECON_PROTO_MATTER_THREAD) {
            pan->proto = ZIG_RECON_PROTO_THREAD;
            pan->confidence = ZIG_RECON_CONFIDENCE_PROBABLE;
        }
    }
}

static void process_frame(const zig_recon_rx_frame_t *rx)
{
    zig_recon_mac_info_t mac;
    if (!parse_mac(rx->data, &mac)) {
        portENTER_CRITICAL(&s_lock);
        s_packets_total++;
        s_dropped_frames++;
        portEXIT_CRITICAL(&s_lock);
        return;
    }

    const uint32_t seen_ms = now_ms();
    const uint16_t pan_id = select_pan_id(&mac);

    portENTER_CRITICAL(&s_lock);
    s_packets_total++;

    zig_recon_pan_t *pan = find_or_add_pan(pan_id);
    if (pan) {
        pan->packets++;
        pan->channel_mask |= (1UL << rx->channel);
        pan->last_rssi = rx->rssi;
        if (pan->best_rssi == ZIG_RECON_NO_RSSI || rx->rssi > pan->best_rssi) {
            pan->best_rssi = rx->rssi;
        }
        pan->last_seen_ms = seen_ms;
        if (pan_id != ZIG_RECON_PAN_UNKNOWN) {
            update_proto_guess(pan, &mac);
        }

        zig_recon_node_t *node = find_or_add_node(pan_id, &mac);
        if (node) {
            if (node->packets == 0) {
                pan->nodes++;
            }
            node->packets++;
            node->last_rssi = rx->rssi;
            node->last_seen_ms = seen_ms;
        }
    }
    portEXIT_CRITICAL(&s_lock);
}

static void zig_recon_task(void *arg)
{
    (void)arg;
    int64_t next_hop_us = esp_timer_get_time();
    uint8_t channel = first_channel(s_channel_mask);

    while (s_active) {
        const int64_t now = esp_timer_get_time();
        if (now >= next_hop_us) {
            esp_ieee802154_set_channel(channel);
            esp_ieee802154_receive();
            portENTER_CRITICAL(&s_lock);
            s_current_channel = channel;
            portEXIT_CRITICAL(&s_lock);
            channel = next_channel(channel, s_channel_mask);
            next_hop_us = now + ((int64_t)s_dwell_ms * 1000);
        }

        zig_recon_rx_frame_t rx;
        if (xQueueReceive(s_rx_queue, &rx, pdMS_TO_TICKS(20)) == pdTRUE) {
            process_frame(&rx);
        }
    }

    s_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t zig_recon_start(const zig_recon_config_t *config)
{
    if (s_active) {
        return ESP_ERR_INVALID_STATE;
    }

    s_channel_mask = normalize_channel_mask(config ? config->channel_mask : 0);
    s_dwell_ms = (config && config->dwell_ms) ? config->dwell_ms : ZIG_RECON_DEFAULT_DWELL_MS;
    if (s_dwell_ms < 50) {
        s_dwell_ms = 50;
    }

    zig_recon_clear();

    if (!s_rx_queue) {
        s_rx_queue = xQueueCreate(ZIG_RECON_QUEUE_DEPTH, sizeof(zig_recon_rx_frame_t));
        ESP_RETURN_ON_FALSE(s_rx_queue != NULL, ESP_ERR_NO_MEM, ZIG_RECON_TAG, "rx queue alloc failed");
    }

    esp_err_t ret = esp_ieee802154_enable();
    ESP_RETURN_ON_ERROR(ret, ZIG_RECON_TAG, "ieee802154 enable failed");
    s_enabled = true;

    s_current_channel = first_channel(s_channel_mask);
    ESP_GOTO_ON_ERROR(esp_ieee802154_set_channel(s_current_channel), fail, ZIG_RECON_TAG, "set channel failed");
    ESP_GOTO_ON_ERROR(esp_ieee802154_set_promiscuous(true), fail, ZIG_RECON_TAG, "promisc failed");
    ESP_GOTO_ON_ERROR(esp_ieee802154_set_rx_when_idle(true), fail, ZIG_RECON_TAG, "rx idle failed");
    ESP_GOTO_ON_ERROR(esp_ieee802154_receive(), fail, ZIG_RECON_TAG, "receive failed");

    s_active = true;
    if (xTaskCreate(zig_recon_task, "zig_recon", ZIG_RECON_TASK_STACK, NULL,
                    ZIG_RECON_TASK_PRIO, &s_task) != pdPASS) {
        s_active = false;
        ret = ESP_ERR_NO_MEM;
        goto fail;
    }

    return ESP_OK;

fail:
    s_active = false;
    esp_ieee802154_set_rx_when_idle(false);
    esp_ieee802154_set_promiscuous(false);
    esp_ieee802154_sleep();
    if (s_enabled) {
        esp_ieee802154_disable();
        s_enabled = false;
    }
    if (s_rx_queue) {
        vQueueDelete(s_rx_queue);
        s_rx_queue = NULL;
    }
    return ret;
}

void zig_recon_stop(void)
{
    if (!s_active && !s_enabled) {
        return;
    }

    s_active = false;
    esp_ieee802154_set_rx_when_idle(false);
    esp_ieee802154_set_promiscuous(false);
    esp_ieee802154_sleep();

    for (int i = 0; i < 20 && s_task != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (s_task != NULL) {
        vTaskDelete(s_task);
        s_task = NULL;
    }

    if (s_enabled) {
        esp_ieee802154_disable();
        s_enabled = false;
    }

    if (s_rx_queue) {
        xQueueReset(s_rx_queue);
        vQueueDelete(s_rx_queue);
        s_rx_queue = NULL;
    }
}

bool zig_recon_is_active(void)
{
    return s_active;
}

void zig_recon_clear(void)
{
    portENTER_CRITICAL(&s_lock);
    s_packets_total = 0;
    s_dropped_frames = 0;
    s_pan_count = 0;
    s_node_count = 0;
    memset(s_pans, 0, sizeof(s_pans));
    memset(s_nodes, 0, sizeof(s_nodes));
    portEXIT_CRITICAL(&s_lock);
    if (s_rx_queue) {
        xQueueReset(s_rx_queue);
    }
}

void zig_recon_get_snapshot(zig_recon_snapshot_t *out)
{
    if (!out) {
        return;
    }
    portENTER_CRITICAL(&s_lock);
    memset(out, 0, sizeof(*out));
    out->active = s_active;
    out->current_channel = s_current_channel;
    out->dwell_ms = s_dwell_ms;
    out->channel_mask = s_channel_mask;
    out->packets_total = s_packets_total;
    out->dropped_frames = s_dropped_frames;
    out->pan_count = s_pan_count;
    out->node_count = s_node_count;
    memcpy(out->pans, s_pans, sizeof(s_pans));
    memcpy(out->nodes, s_nodes, sizeof(s_nodes));
    portEXIT_CRITICAL(&s_lock);
}

const char *zig_recon_proto_name(zig_recon_proto_t proto)
{
    switch (proto) {
    case ZIG_RECON_PROTO_IEEE802154: return "802.15.4";
    case ZIG_RECON_PROTO_ZIGBEE: return "Zigbee";
    case ZIG_RECON_PROTO_THREAD: return "Thread";
    case ZIG_RECON_PROTO_MATTER_THREAD: return "Matter/Thread";
    default: return "Unknown";
    }
}

const char *zig_recon_proto_token(zig_recon_proto_t proto)
{
    switch (proto) {
    case ZIG_RECON_PROTO_IEEE802154: return "ieee802154";
    case ZIG_RECON_PROTO_ZIGBEE: return "zigbee";
    case ZIG_RECON_PROTO_THREAD: return "thread";
    case ZIG_RECON_PROTO_MATTER_THREAD: return "matter_thread";
    default: return "unknown";
    }
}

const char *zig_recon_confidence_token(zig_recon_confidence_t confidence)
{
    switch (confidence) {
    case ZIG_RECON_CONFIDENCE_CONFIRMED: return "confirmed";
    case ZIG_RECON_CONFIDENCE_PROBABLE: return "probable";
    default: return "unknown";
    }
}

const char *zig_recon_role_name(zig_recon_role_t role)
{
    switch (role) {
    case ZIG_RECON_ROLE_COORDINATOR: return "Coordinator";
    case ZIG_RECON_ROLE_ROUTER: return "Router";
    case ZIG_RECON_ROLE_END_DEVICE: return "End Device";
    default: return "Unknown";
    }
}

const char *zig_recon_role_token(zig_recon_role_t role)
{
    switch (role) {
    case ZIG_RECON_ROLE_COORDINATOR: return "coordinator";
    case ZIG_RECON_ROLE_ROUTER: return "router";
    case ZIG_RECON_ROLE_END_DEVICE: return "end_device";
    default: return "unknown";
    }
}

void IRAM_ATTR esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info)
{
    if (s_active && s_rx_queue && frame && frame[0] > 0) {
        zig_recon_rx_frame_t rx = {0};
        uint8_t len = (uint8_t)(frame[0] + 1);
        if (len > ZIG_RECON_MAX_FRAME_LEN) {
            len = ZIG_RECON_MAX_FRAME_LEN;
        }
        rx.len = len;
        memcpy(rx.data, frame, len);
        if (frame_info) {
            rx.channel = frame_info->channel;
            rx.rssi = frame_info->rssi;
            rx.lqi = frame_info->lqi;
            rx.timestamp = frame_info->timestamp;
        } else {
            rx.channel = s_current_channel;
            rx.rssi = ZIG_RECON_NO_RSSI;
        }

        BaseType_t woken = pdFALSE;
        if (xQueueSendFromISR(s_rx_queue, &rx, &woken) != pdTRUE) {
            portENTER_CRITICAL_ISR(&s_lock);
            s_dropped_frames++;
            portEXIT_CRITICAL_ISR(&s_lock);
        }
        if (woken == pdTRUE) {
            portYIELD_FROM_ISR();
        }
    }

    if (frame) {
        esp_ieee802154_receive_handle_done(frame);
    }
}
