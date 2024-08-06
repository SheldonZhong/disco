/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

#include "blkio.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

// mm {{{

  extern struct kv *
kvmap_mm_in_ts(struct kv * const kv, void * const priv);

  extern struct kv *
kvmap_mm_out_ts(struct kv * const kv, struct kv * const out);
// }}} mm

// sst {{{
struct sst;

  extern struct sst *
sst_open(const char * const dirname, const u64 seq, const u32 run);

  extern const struct sst_meta *
sst_meta(struct sst * const sst);

  extern void
sst_rcache(struct sst * const sst, struct rcache * const rc);

  extern struct kv *
sst_get(struct sst * const map, const struct kref * const key, struct kv * const out);

  extern bool
sst_probe(struct sst* const map, const struct kref * const key);

  extern struct kv *
sst_first_key(const struct sst * const map, struct kv * const out);

  extern struct kv *
sst_last_key(const struct sst * const map, struct kv * const out);

  extern void
sst_destroy(struct sst * const map);

  extern void
sst_dump(struct sst * const sst, const char * const fn);

  extern void
sst_fprint(struct sst * const map, FILE * const out);

struct sst_iter;

  extern struct sst_iter *
sst_iter_create(struct sst * const sst);

  extern bool
sst_iter_ts(struct sst_iter * const iter);

  extern void
sst_iter_seek(struct sst_iter * const iter, const struct kref * const key);

  extern void
sst_iter_seek_null(struct sst_iter * const iter);

  extern bool
sst_iter_valid(struct sst_iter * const iter);

  extern struct kv *
sst_iter_peek(struct sst_iter * const iter, struct kv * const out);

  extern bool
sst_iter_kref(struct sst_iter * const iter, struct kref * const kref);

  extern bool
sst_iter_kvref(struct sst_iter * const iter, struct kvref * const kvref);

  extern u64
sst_iter_retain(struct sst_iter * const iter);

  extern void
sst_iter_release(struct sst_iter * const iter, const u64 opaque);

  extern void
sst_iter_skip1(struct sst_iter * const iter);

  extern void
sst_iter_skip(struct sst_iter * const iter, const u32 nr);

  extern struct kv *
sst_iter_next(struct sst_iter * const iter, struct kv * const out);

  extern void
sst_iter_park(struct sst_iter * const iter);

  u64
sst_iter_retain(struct sst_iter * const iter);

  void
sst_iter_release(struct sst_iter * const iter, const u64 opaque);

  extern void
sst_iter_destroy(struct sst_iter * const iter);
// }}} sst

// build-sst {{{
// api contains sorted keys and supports iter_next().
// all keys in the map_api will be added to the sstable.
  extern u64
sst_build(const char * const dirname, struct miter * const miter,
    const u64 seq, const u32 run, const u16 max_pages,
    const bool del, const bool ckeys,
    const bool bloom, const bool leaf_bloom,
    const struct kv * const k0, const struct kv * const kz);

  extern u64
sst_build_at(const int dfd, struct miter * const miter,
    const struct t_build_cfg * const cfg,
    const struct kv * const k0, const struct kv * const kz);
// }}} build-sst

// msstx {{{
// msst (multi-sst)
struct msst;
struct msstx_iter;

// msstx
  extern struct msst *
msstx_open(const char * const dirname, const u64 seq, const u32 nr_runs);

  extern struct msst *
msstx_open_at_reuse(const int dfd, const u64 seq, const u32 nr_runs, struct msst * const msst0, const u32 nrun0);

  extern struct msst *
msstx_open_at(const int dfd, const u64 seq, const u32 nr_runs);

  extern void
msst_rcache(struct msst * const msst, struct rcache * const rc);

  extern void
msst_add_refcnt(struct msst * const msst);

  extern u32
msst_accu_nkv_at(const struct msst * const msst, const u32 i);

  extern u32
msst_nkv_at(const struct msst * const msst, const u32 i);

  extern u32
msst_nr_pages_at(const struct msst * const msst, const u32 i);

  extern void
msst_stats(const struct msst * const msst, struct msst_stats * const stats);

  extern void
msstx_destroy(struct msst * const msst);

  extern struct msstx_iter *
msstx_iter_create(struct msst * const msst);

  extern struct kv *
msstx_get(struct msst * const msst, const struct kref * const key, struct kv * const out);

  extern bool
msstx_probe(struct msst * const msst, const struct kref * const key);

  extern bool
msstx_iter_valid(struct msstx_iter * const iter);

  extern void
msstx_iter_seek(struct msstx_iter * const iter, const struct kref * const key);

  extern void
msstx_iter_seek_null(struct msstx_iter * const iter);

  extern struct kv *
msstx_iter_peek(struct msstx_iter * const iter, struct kv * const out);

  extern bool
msstx_iter_kref(struct msstx_iter * const iter, struct kref * const kref);

  extern bool
msstx_iter_kvref(struct msstx_iter * const iter, struct kvref * const kvref);

  extern u64
msstx_iter_retain(struct msstx_iter * const iter);

  extern void
msstx_iter_release(struct msstx_iter * const iter, const u64 opaque);

  extern void
msstx_iter_skip1(struct msstx_iter * const iter);

  extern void
msstx_iter_skip(struct msstx_iter * const iter, const u32 nr);

  extern struct kv *
msstx_iter_next(struct msstx_iter * const iter, struct kv * const out);

  extern void
msstx_iter_park(struct msstx_iter * const iter);

  extern void
msstx_iter_destroy(struct msstx_iter * const iter);
// }}} msstx

// ssty {{{
struct ssty;

  extern void
ssty_destroy(struct ssty * const ssty);

  extern void
ssty_dump(struct ssty * const ssty, const char * const filename);

  extern void
ssty_fprint(struct ssty * const ssty, FILE * const fout);
// }}} ssty

// mssty {{{
struct mssty_ref;
struct mssty_iter;

  extern struct msst *
mssty_create_at(const int dfd);

  extern bool
mssty_open_y_at(const int dfd, struct msst * const msst);

  extern struct msst *
mssty_open(const char * const dirname, const u64 seq, const u32 nr_runs);

  extern struct msst *
mssty_open_at(const int dfd, const u64 seq, const u32 nr_runs);

  extern struct mssty_iter *
mssty_iter_new();

  extern void
mssty_destroy(struct msst * const msst);

  extern void
mssty_drop(struct msst * const msst);

  extern void
mssty_drop_lazy(struct msst * const msst);

  extern u64
mssty_get_magic(const struct msst * const msst);

  extern void
mssty_fprint(struct msst * const msst, FILE * const fout);

  extern struct mssty_ref *
mssty_ref(struct msst * const msst);

  extern struct msst *
mssty_unref(struct mssty_ref * const ref);

  extern struct mssty_iter *
mssty_iter_create(struct mssty_ref * const ref);

  extern void
mssty_iter_init(struct mssty_iter * const iter, struct msst * const msst);

  extern bool
mssty_iter_valid(struct mssty_iter * const iter);

  extern void
mssty_iter_seek(struct mssty_iter * const iter, const struct kref * const key);

  extern void
mssty_iter_seek_null(struct mssty_iter * const iter);

  extern void
mssty_iter_seek_near(struct mssty_iter * const iter, const struct kref * const key, const bool bsearch_keys);

  extern struct kv *
mssty_iter_peek(struct mssty_iter * const iter, struct kv * const out);

  extern bool
mssty_iter_kref(struct mssty_iter * const iter, struct kref * const kref);

  extern bool
mssty_iter_kvref(struct mssty_iter * const iter, struct kvref * const kvref);

  extern u64
mssty_iter_retain(struct mssty_iter * const iter);

  extern void
mssty_iter_release(struct mssty_iter * const iter, const u64 opaque);

  extern void
mssty_iter_skip1(struct mssty_iter * const iter);

  extern void
mssty_iter_skip(struct mssty_iter * const iter, const u32 nr);

  extern struct kv *
mssty_iter_next(struct mssty_iter * const iter, struct kv * const out);

  extern void
mssty_iter_park(struct mssty_iter * const iter);

  extern void
mssty_iter_destroy(struct mssty_iter * const iter);

// ts iter: ignore a key if its newest version is a tombstone
  extern bool
mssty_iter_ts(struct mssty_iter * const iter);

  extern void
mssty_iter_seek_ts(struct mssty_iter * const iter, const struct kref * const key);

  extern void
mssty_iter_skip1_ts(struct mssty_iter * const iter);

  extern void
mssty_iter_skip_ts(struct mssty_iter * const iter, const u32 nr);

  extern struct kv *
mssty_iter_next_ts(struct mssty_iter * const iter, struct kv * const out);

// dup iter: return all versions, including old keys and tombstones
  extern struct kv *
mssty_iter_peek_dup(struct mssty_iter * const iter, struct kv * const out);

  extern void
mssty_iter_skip1_dup(struct mssty_iter * const iter);

  extern void
mssty_iter_skip_dup(struct mssty_iter * const iter, const u32 nr);

  extern struct kv *
mssty_iter_next_dup(struct mssty_iter * const iter, struct kv * const out);

  extern bool
mssty_iter_kref_dup(struct mssty_iter * const iter, struct kref * const kref);

  extern bool
mssty_iter_kvref_dup(struct mssty_iter * const iter, struct kvref * const kvref);

// mssty_get can return tombstone
  extern struct kv *
mssty_get(struct mssty_ref * const ref, const struct kref * const key, struct kv * const out);

// mssty_probe can return tombstone
  extern bool
mssty_probe(struct mssty_ref * const ref, const struct kref * const key);

// return NULL for tomestone
  extern struct kv *
mssty_get_ts(struct mssty_ref * const ref, const struct kref * const key, struct kv * const out);

// return false for tomestone
  extern bool
mssty_probe_ts(struct mssty_ref * const ref, const struct kref * const key);

  extern bool
mssty_get_value_ts(struct mssty_ref * const ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out);

  extern struct kv *
mssty_first_key(const struct msst * const msst, struct kv * const out);

  extern struct kv *
mssty_last_key(const struct msst * const msst, struct kv * const out);

  extern void
mssty_dump(struct msst * const msst, const char * const fn);
// }}} mssty

// build-ssty {{{
// build extended metadata based on a set of sstables.
// y0 and run0 are optional for speeding up the sorting
  extern u32
ssty_build(const char * const dirname, struct msst * const msst,
    const u64 seq, const u32 run, struct msst * const y0, const u32 run0, const bool tags, const bool dbits);

  extern u32
ssty_build_at(const int dfd, struct msst * const msstx1,
    const u64 seq, const u32 nr_runs, struct msst * const mssty0,
    const u32 run0, const bool gen_tags, const bool gen_dbits,
    const bool inc_rebuild, const u8 * merge_list, const u64 hist_size);

  extern struct msst *
ssty_build_at_reuse(const int dfd, struct rcache * const rc,
    const u64 seq, const u32 nr_runs, struct msst * const mssty0,
    const u32 run0, const bool gen_tags, const bool gen_dbits,
    const bool inc_rebuild, const u8 * merge_list, const u64 hist_size, u64 * ysz);

  extern void
mssty_miter_major(struct msst * const msst, struct miter * const miter);

  extern void
mssty_miter_partial(struct msst * const msst, struct miter * const miter, const u32 bestrun);

  u64
mssty_comp_est_ssty(const u64 nkeys, const float run);
// }}} build-ssty

// api {{{
extern const struct kvmap_api kvmap_api_sst;
extern const struct kvmap_api kvmap_api_msstx;
extern const struct kvmap_api kvmap_api_mssty;
extern const struct kvmap_api kvmap_api_mssty_ts;
// }}} api

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
