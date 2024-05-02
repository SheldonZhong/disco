#pragma once

#include "lib.h"
#include "kv.h"

// define {{{
#define SST_VLEN_TS ((0x10000u)) // tomb stone
#define SST_VLEN_MASK ((0xffffu)) // real vlen == vlen & 0xffff
#define SST_MAX_BLKSZ  ((PGSZ))
#define SST_MAX_KVSZ   ((SST_MAX_BLKSZ - (sizeof(u16))))
#define SST_MAX_PAGEID ((UINT16_MAX - 1))
#define MSST_NR_RUNS   ((16)) // up to 16 runs
// TODO: why does it not align with SSTY_RANK?

// meanings in a hex dump
// 8x stale
// 4x tombstone
// 2x tail
// cx stale and ts
// ax stale and tail
// 6x ts and tail
// ex stale ts and tail
#define SSTY_STALE     ((0x80u)) // has been updated in newer runs
#define SSTY_TOMBSTONE ((0x40u))
#define SSTY_TAIL      ((0x20u)) // the last kv record in the page
#define SSTY_RANK      ((0x1fu))
#define SSTY_INVALID   ((0xffu))
// }}} define

struct msstz_cfg {
  u32 major_switch; // 1 or 2
  u32 major_trigger; // <16
  u32 estimate_safe; // to avoid overflow
  u32 pages_accept; // force compaction with enough data
  u16 max_pages; // <65500; maximum number of 4KB pages
  bool ckeys; // generate ckeys for faster remix rebuild
  bool tags; // generate hash tags for fast point lookup
  bool bt_bloom;
  bool leaf_bloom;
  bool dbits;
  bool inc_rebuild;
};

// TODO: rename this
struct msst_stats {
  u64 ssty_sz;
  u64 meta_sz;
  u64 data_sz;
  u32 totkv;
  u32 totsz;
  u32 valid;
  u32 nr_runs;
};

struct t_build_cfg {
  char * const dirname;
  u64 seq;
  u32 run;
  u16 max_pages; // <= 65520
  bool del;
  bool ckeys;
  bool lcp; // use lcp+1 or full key for anchor keys
  bool bt_bloom;
  bool leaf_bloom;
};

extern const struct msstz_cfg msstz_cfg_default;

// mm {{{
extern const struct kvmap_mm kvmap_mm_ts;
// }}} mm

// kv {{{
  u8
sst_tag(const u32 hash32);

  extern size_t
sst_kv_vi128_estimate(const struct kv * const kv);

  extern u8 *
sst_kv_vi128_encode(u8 * ptr, const struct kv * const kv);

  extern size_t
sst_kv_size(const struct kv * const kv);

  extern struct kv *
sst_kv_vi128_decode(const u8 * ptr, struct kv * const out);

  extern struct kv *
sst_kvref_dup2_kv(const struct kvref * const kvref, struct kv * const out);
// }}} kv

