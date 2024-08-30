#pragma once

#include "common.h"
#include "blkio.h"

// bt {{{
  extern u64
bt_build(const char * const dirname, struct miter * const miter,
    const u64 seq, const u32 run, const u16 max_pages,
    const bool del, const bool ckeys,
    const bool bt_bloom, const bool leaf_bloom,
    const struct kv * const k0, const struct kv * const kz);

  extern u64
bt_build_at(const int dfd, struct miter * const miter,
    const struct t_build_cfg * const cfg,
    const struct kv * const k0, const struct kv * const kz);

struct bt;

  extern u32
bt_nr_pages(struct bt * const bt);

  extern void
bt_rcache(struct bt * const bt, struct rcache * const rc);

  extern struct bt *
bt_open(const char * const dirname, const u64 seq, const u32 run);

  extern void
bt_destroy(struct bt * const bt);

  extern void
bt_fprint(struct bt * const bt, FILE * const out);

struct bt_ptr;
struct bt_iter;

  extern struct bt_iter *
bt_iter_create(struct bt * const bt);

  extern bool
bt_iter_valid(const struct bt_iter * const iter);

  extern void
bt_iter_seek(struct bt_iter * const iter, const struct kref * const key);

  extern void
bt_iter_seek_null(struct bt_iter * const iter);

  extern bool
bt_iter_ts(struct bt_iter * const iter);

  extern struct kv *
bt_iter_peek(struct bt_iter * const iter, struct kv * const out);

  extern bool
bt_iter_kref(struct bt_iter * const iter, struct kref * const kref);

  extern bool
bt_iter_kvref(struct bt_iter * const iter, struct kvref * const kvref);

  extern u64
bt_iter_retain(struct bt_iter * const iter);

  extern void
bt_iter_release(struct bt_iter * const iter, const u64 opaque);

  extern void
bt_iter_skip1(struct bt_iter * const iter);

  extern void
bt_iter_skip(struct bt_iter * const iter, const u32 nr);

  extern struct kv *
bt_iter_next(struct bt_iter * const iter, struct kv * const out);

  extern void
bt_iter_park(struct bt_iter * const iter);

  extern void
bt_iter_destroy(struct bt_iter * const iter);

  extern struct kv *
bt_get(struct bt * const bt, const struct kref * const key, struct kv * const out);

  extern bool
bt_probe(struct bt * const bt, const struct kref * const key);

  extern struct kv *
bt_first_key(struct bt * const bt, struct kv * const out);

  extern struct kv *
bt_last_key(struct bt * const bt, struct kv * const out);
// }}} bt

// mbtx {{{
// msst (multi-sst)
struct mbt;
struct mbtx_ref;
struct mbtx_iter;

  extern struct mbt *
mbtx_open_at(const int dfd, const u64 seq, const u32 nr_runs);

// mbtx
  extern struct mbt *
mbtx_open(const char * const dirname, const u64 seq, const u32 nrun);

  extern struct mbt *
mbtd_open_at(const int dfd, const u64 seq, const u32 nr_runs);

  extern u32
mbtx_nr_pages(struct mbt * const mbt);

  extern void
mbtx_rcache(struct mbt * const mbt, struct rcache * const rc);

  extern void
mbtx_destroy(struct mbt * const mbt);

  extern void
mbtx_fprint(struct mbt * const mbt, FILE * const fout);

  extern struct kv *
mbtd_first_key(struct mbt * const mbt, struct kv * const out);

  extern struct kv *
mbtd_last_key(struct mbt * const mbt, struct kv * const out);

  extern void
mbtx_drop(struct mbt * const mbt);

  extern void
mbtx_drop_lazy(struct mbt * const mbt);

  extern struct mbtx_iter *
mbtx_iter_create(struct mbtx_ref * const ref);

  extern struct mbtx_ref *
mbtx_ref(struct mbt * const mbt);

  extern struct mbt *
mbtx_unref(struct mbtx_ref * const ref);

  extern struct mbtx_iter *
mbtx_iter_new();

  extern void
mbtx_iter_init(struct mbtx_iter * const iter, struct mbt * const mbt);

  extern bool
mbtx_iter_ts(struct mbtx_iter * const iter);

  extern struct kv *
mbtx_get(struct mbtx_ref * const ref, const struct kref * const key, struct kv * const out);

  extern struct kv *
mbtx_get_ts(struct mbtx_ref * const ref, const struct kref * const key, struct kv * const out);

  extern bool
mbtx_get_value_ts(struct mbtx_ref * const ref, const struct kref * key, void * const vbuf_out, u32 * const vlen_out);

  extern bool
mbtx_probe(struct mbtx_ref * const ref, const struct kref * const key);

  extern bool
mbtx_probe_ts(struct mbtx_ref * const ref, const struct kref * const key);

  extern bool
mbtx_iter_valid(struct mbtx_iter * const iter);

  extern void
mbtx_iter_seek(struct mbtx_iter * const iter, const struct kref * const key);

  extern void
mbtx_iter_seek_null(struct mbtx_iter * const iter);

  extern struct kv *
mbtx_iter_peek(struct mbtx_iter * const iter, struct kv * const out);

  extern bool
mbtx_iter_kref(struct mbtx_iter * const iter, struct kref * const kref);

  extern bool
mbtx_iter_kvref(struct mbtx_iter * const iter, struct kvref * const kvref);

  extern u64
mbtx_iter_retain(struct mbtx_iter * const iter);

  extern void
mbtx_iter_release(struct mbtx_iter * const iter, const u64 opaque);

  extern void
mbtx_iter_skip1(struct mbtx_iter * const iter);

  extern void
mbtx_iter_skip(struct mbtx_iter * const iter, const u32 nr);

  extern struct kv *
mbtx_iter_next(struct mbtx_iter * const iter, struct kv * const out);

  extern void
mbtx_iter_park(struct mbtx_iter * const iter);

  extern void
mbtx_iter_destroy(struct mbtx_iter * const iter);

  extern void
mbtd_stats(const struct mbt * const mbt, struct msst_stats * const stats);

  extern void
mbtx_stats(const struct mbt * const mbt, struct msst_stats * const stats);

  extern struct mbt *
mbtd_create_at(const int dfd);

  extern void
mbtd_destroy(struct mbt * const mbt);

  extern void
mbtd_drop_lazy(struct mbt * const mbt);

  extern void
mbtd_drop(struct mbt * const mbt);

  extern struct mbt *
dummy_build_at_reuse(const int dfd, struct rcache * const rc,
    struct msstz_ytask * task, struct msstz_cfg * zcfg, u64 * ysz);
// }}} mbtx

// remix {{{
struct remix;

  extern u32
remix_build(const char * const dirname, struct mbt * const x1,
            const u64 seq, const u32 nr_runs, struct mbt * const y0,
            const u32 nr_reuse, const bool gen_tags, const bool gen_dbits,
            const bool inc_rebuild, const u8 * merge_hist, const u64 hist_size);

  extern struct mbt *
mbty_create_at(const int dfd);

  extern u32
remix_build_at(const int dfd, struct mbt * const x1,
               const u64 seq, const u32 nr_runs,
               struct mbt * const y0, const u32 nr_reuse,
               const bool gen_tags, const bool gen_dbits,
               const bool inc_rebuild, const u8 * merge_hist, const u64 hist_size);

  extern struct mbt *
remix_build_at_reuse(const int dfd, struct rcache * const rc,
    struct msstz_ytask * task, struct msstz_cfg * zcfg, u64 * ysz);

  void
mbt_miter_partial(struct mbt * const mbty, struct miter * const miter, const u32 bestrun);

  extern void
remix_destroy(struct remix * const remix);

  extern void
remix_fprint(struct remix * const remix, FILE * const out);

  extern void
remix_dump(struct remix * const remix, const char * const filename);
// }}} remix

// mbty {{{
struct mbty_ref;
struct mbty_iter;

  extern struct mbt *
mbty_open(const char * const dirname, const u64 seq, const u32 nr_runs);

  extern struct mbt *
mbty_open_at(const int dfd, const u64 seq, const u32 nr_runs);

  extern bool
mbty_open_y_at(const int dfd, struct mbt * const mbt);

  extern void
mbt_add_refcnt(struct mbt * mbt);

  extern u32
mbty_nr_pages(struct mbt * const mbt);

  extern void
mbty_rcache(struct mbt * const mbt, struct rcache * const rc);

  extern void
mbty_destroy(struct mbt * const mbt);

  extern void
mbty_fprint(struct mbt * const mbt, FILE * const fout);

  extern void
mbty_stats(const struct mbt * const mbt, struct msst_stats * const stats);

  extern u32
mbt_accu_nkv_at(const struct mbt * const mbt, const u32 i);

  extern u32
mbt_nkv_at(const struct mbt * const mbt, const u32 i);

  extern u32
mbt_nr_pages_at(const struct mbt * const mbt, const u32 i);

  extern u32
mbt_accu_nkv_at(const struct mbt * const mbt, const u32 i);

  extern u64
mbty_comp_est_remix(const u64 nkeys, const float run);

  extern struct mbty_ref *
mbty_ref(struct mbt * const mbt);

  extern struct mbt *
mbty_unref(struct mbty_ref * const ref);

  extern struct mbty_iter *
mbty_iter_create(struct mbty_ref * const ref);

  extern struct mbty_iter *
mbty_iter_new();

  extern void
mbty_iter_init(struct mbty_iter * const iter, struct mbt * const mbt);

  extern bool
mbty_iter_valid(const struct mbty_iter * const iter);

  extern void
mbty_iter_seek(struct mbty_iter * const iter, const struct kref * const key);

  extern void
mbty_iter_seek_null(struct mbty_iter * const iter);

  extern void
mbty_iter_seek_near(struct mbty_iter * const iter, const struct kref * const key, const bool bsearch_keys);

  extern struct kv *
mbty_iter_peek(struct mbty_iter * const iter, struct kv * const out);

  extern bool
mbty_iter_kref(struct mbty_iter * const iter, struct kref * const kref);

  extern bool
mbty_iter_kvref(struct mbty_iter * const iter, struct kvref * const kvref);

  extern u64
mbty_iter_retain(struct mbty_iter * const iter);

  extern void
mbty_iter_release(struct mbty_iter * const iter, const u64 opaque);

  extern void
mbty_iter_skip1(struct mbty_iter * const iter);

  extern void
mbty_iter_skip(struct mbty_iter * const iter, const u32 nr);

  extern struct kv *
mbty_iter_next(struct mbty_iter * const iter, struct kv * const out);

  extern void
mbty_iter_park(struct mbty_iter * const iter);

  extern void
mbty_iter_destroy(struct mbty_iter * const iter);

  extern void
mbty_drop(struct mbt * const mbt);

  extern void
mbty_drop_lazy(struct mbt * const mbt);

  extern u64
mbt_get_magic(const struct mbt * const mbt);

// ts iter: ignore a key if its newest version is a tombstone
  extern bool
mbty_iter_ts(struct mbty_iter * const iter);

  extern void
mbty_iter_seek_ts(struct mbty_iter * const iter, const struct kref * const key);

  extern void
mbty_iter_skip1_ts(struct mbty_iter * const iter);

  extern void
mbty_iter_skip_ts(struct mbty_iter * const iter, const u32 nr);

  extern struct kv *
mbty_iter_next_ts(struct mbty_iter * const iter, struct kv * const out);

// dup iter: return all versions, including old keys and tombstones
  extern struct kv *
mbty_iter_peek_dup(struct mbty_iter * const iter, struct kv * const out);

  extern void
mbty_iter_skip1_dup(struct mbty_iter * const iter);

  extern void
mbty_iter_skip_dup(struct mbty_iter * const iter, const u32 nr);

  extern struct kv *
mbty_iter_next_dup(struct mbty_iter * const iter, struct kv * const out);

  extern bool
mbty_iter_kref_dup(struct mbty_iter * const iter, struct kref * const kref);

  extern bool
mbty_iter_kvref_dup(struct mbty_iter * const iter, struct kvref * const kvref);

// mbty_get can return tombstone
  extern struct kv *
mbty_get(struct mbty_ref * const ref, const struct kref * const key, struct kv * const out);

// mbty_probe can return tombstone
  extern bool
mbty_probe(struct mbty_ref * const ref, const struct kref * const key);

// return NULL for tomestone
  extern struct kv *
mbty_get_ts(struct mbty_ref * const ref, const struct kref * const key, struct kv * const out);

// return false for tomestone
  extern bool
mbty_probe_ts(struct mbty_ref * const ref, const struct kref * const key);

  extern bool
mbty_get_value_ts(struct mbty_ref * const ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out);

  extern struct kv *
mbty_first_key(struct mbt * const mbt, struct kv * const out);

  extern struct kv *
mbty_last_key(struct mbt * const mbt, struct kv * const out);

  extern void
mbty_dump(struct mbt * const mbt, const char * const fn);
// }}} mbty

// {{{ findex - full index
struct mbtf_ref;
struct mbtf_iter;

  extern void
mbtf_rcache(struct mbt * const mbt, struct rcache * const rc);

  extern struct mbt *
mbtf_open_at(const int dfd, const u64 seq, const u32 nr_runs);

  extern struct mbt *
mbtf_create_at(const int dfd);

  extern void
mbtf_destroy(struct mbt * const mbt);

  extern struct kv *
mbtf_first_key(struct mbt * const mbt, struct kv * const out);

  extern struct kv *
mbtf_last_key(struct mbt * const mbt, struct kv * const out);

  extern void
mbtf_drop(struct mbt * const mbt);

  extern void
mbtf_drop_lazy(struct mbt * const mbt);

  extern struct kv *
mbtf_get(struct mbtf_ref * const ref, const struct kref * const key, struct kv * const out);

  extern struct kv *
mbtf_get_ts(struct mbtf_ref * const ref, const struct kref * const key, struct kv * const out);

  extern bool
mbtf_get_value_ts(struct mbtf_ref * const ref, const struct kref * key, void * const vbuf_out, u32 * const vlen_out);

  extern bool
mbtf_probe(struct mbtf_ref * const ref, const struct kref * const key);

  extern bool
mbtf_probe_ts(struct mbtf_ref * const ref, const struct kref * const key);

  extern void
mbtf_iter_seek_null(struct mbtf_iter * const iter);

  extern struct mbtf_iter *
mbtf_iter_new();

  extern struct mbtf_iter *
mbtf_iter_create(struct mbtf_ref * const ref);

  extern bool
mbtf_iter_valid(const struct mbtf_iter * const iter);

  extern void
mbtf_fprint(struct mbt * const mbt, FILE * const fout);

  extern void
mbtf_stats(const struct mbt * const mbt, struct msst_stats * const stats);

  extern struct mbt *
findex_build_at_reuse(const int dfd, struct rcache * const rc,
    struct msstz_ytask * task, struct msstz_cfg * zcfg, u64 * ysz);

  extern void
mbtf_iter_init(struct mbtf_iter * const iter, struct mbt * const mbt);

  extern void
mbtf_iter_park(struct mbtf_iter * const iter);

  extern void
mbtf_iter_destroy(struct mbtf_iter * const iter);

  extern struct mbtf_ref *
mbtf_ref(struct mbt * const mbt);

  extern struct mbt *
mbtf_unref(struct mbtf_ref * const ref);

  extern void
mbtf_iter_seek(struct mbtf_iter * const iter, const struct kref * const key);

  extern struct kv *
mbtf_iter_peek(struct mbtf_iter * const iter, struct kv * const out);

  extern bool
mbtf_iter_kref(struct mbtf_iter * const iter, struct kref * const kref);

  extern bool
mbtf_iter_kvref(struct mbtf_iter * const iter, struct kvref * const kvref);

  extern u64
mbtf_iter_retain(struct mbtf_iter * const iter);

  extern bool
mbtf_iter_ts(struct mbtf_iter * const iter);

  extern void
mbtf_iter_skip1(struct mbtf_iter * const iter);

  extern void
mbtf_iter_release(struct mbtf_iter * const iter, const u64 opaque);

  extern void
mbtf_iter_skip(struct mbtf_iter * const iter, const u32 nr);

  extern struct kv *
mbtf_iter_next(struct mbtf_iter * const iter, struct kv * const out);
// }}}

// api {{{
extern const struct kvmap_api kvmap_api_bt;
extern const struct kvmap_api kvmap_api_mbtx;
extern const struct kvmap_api kvmap_api_mbty;
extern const struct kvmap_api kvmap_api_mbty_ts;
extern const struct kvmap_api kvmap_api_mbtf;
// }}} api

// vim:fdm=marker
