#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZIG_RECON_MIN_CHANNEL 11
#define ZIG_RECON_MAX_CHANNEL 26
#define ZIG_RECON_ALL_CHANNELS_MASK 0x07FFF800UL
#define ZIG_RECON_MAX_PANS 32
#define ZIG_RECON_MAX_NODES 128

typedef enum {
    ZIG_RECON_PROTO_UNKNOWN = 0,
    ZIG_RECON_PROTO_IEEE802154,
    ZIG_RECON_PROTO_ZIGBEE,
    ZIG_RECON_PROTO_THREAD,
    ZIG_RECON_PROTO_MATTER_THREAD,
} zig_recon_proto_t;

typedef enum {
    ZIG_RECON_CONFIDENCE_UNKNOWN = 0,
    ZIG_RECON_CONFIDENCE_PROBABLE,
    ZIG_RECON_CONFIDENCE_CONFIRMED,
} zig_recon_confidence_t;

typedef enum {
    ZIG_RECON_ROLE_UNKNOWN = 0,
    ZIG_RECON_ROLE_COORDINATOR,
    ZIG_RECON_ROLE_ROUTER,
    ZIG_RECON_ROLE_END_DEVICE,
} zig_recon_role_t;

typedef struct {
    uint32_t channel_mask;   /* Bits 11..26. 0 means all channels. */
    uint16_t dwell_ms;       /* 0 means default. */
} zig_recon_config_t;

typedef struct {
    uint16_t pan_id;
    zig_recon_proto_t proto;
    zig_recon_confidence_t confidence;
    uint32_t channel_mask;
    uint32_t packets;
    uint16_t nodes;
    int8_t best_rssi;
    int8_t last_rssi;
    uint32_t last_seen_ms;
} zig_recon_pan_t;

typedef struct {
    uint16_t pan_id;
    uint16_t short_addr;
    bool has_short_addr;
    uint64_t ext_addr;
    bool has_ext_addr;
    zig_recon_role_t role;
    uint32_t packets;
    int8_t last_rssi;
    uint32_t last_seen_ms;
} zig_recon_node_t;

typedef struct {
    bool active;
    uint8_t current_channel;
    uint16_t dwell_ms;
    uint32_t channel_mask;
    uint32_t packets_total;
    uint32_t dropped_frames;
    uint16_t pan_count;
    uint16_t node_count;
    zig_recon_pan_t pans[ZIG_RECON_MAX_PANS];
    zig_recon_node_t nodes[ZIG_RECON_MAX_NODES];
} zig_recon_snapshot_t;

esp_err_t zig_recon_start(const zig_recon_config_t *config);
void zig_recon_stop(void);
bool zig_recon_is_active(void);
void zig_recon_clear(void);
void zig_recon_get_snapshot(zig_recon_snapshot_t *out);

const char *zig_recon_proto_name(zig_recon_proto_t proto);
const char *zig_recon_proto_token(zig_recon_proto_t proto);
const char *zig_recon_confidence_token(zig_recon_confidence_t confidence);
const char *zig_recon_role_name(zig_recon_role_t role);
const char *zig_recon_role_token(zig_recon_role_t role);

#ifdef __cplusplus
}
#endif
