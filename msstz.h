#pragma once
#include "lib.h"
#include "msstv.h"
#include "ctypes.h"

// msstz {{{
struct msstz;

// use cfg=NULL for default cfg
  extern struct msstz *
msstz_open(const char * const dirname, const u64 cache_size_mb, const struct msstz_cfg * const cfg);

  extern void
msstz_destroy(struct msstz * const z);

// return number of bytes written since opened
  extern u64
msstz_stat_writes(struct msstz * const z);

  extern u64
msstz_stat_reads(struct msstz * const z);

  extern u64
msstz_version(struct msstz * const z);

  extern struct msstv *
msstz_getv(struct msstz * const z);

  extern void
msstz_putv(struct msstz * const z, struct msstv * const v);

typedef void (*msstz_range_cb)(void * priv, const bool accepted, const struct kv * k0, const struct kv * kz);

  extern void
msstz_comp(struct msstz * const z, const struct kvmap_api * const api1, void * const map1,
    const u32 nr_workers, const u32 co_per_worker, const u64 max_reject);
// }}} msstz

