#include "lib.h"
#include "blkio.h"
#include "kv.h"

// msstv {{{
struct msstv;
struct msstv_iter;
struct msstv_ref;

extern const struct fs_api * const vzfs;

  extern struct msstv *
msstv_create(const u64 nslots, const u64 version);

  extern void
msstv_append(struct msstv * const v, void * const msst, const struct kv * const anchor);

  extern void
msstv_rcache(struct msstv * const v, struct rcache * const rc);

  extern u64
msstv_get_version(const struct msstv * const msstv);

  extern u64
msstv_get_nr(const struct msstv * const msstv);

  extern void
msstv_add_reader(struct msstv * const msstv);

  extern void
msstv_drop_reader(struct msstv * const msstv);

  extern struct msstv *
msstv_next(const struct msstv * const msstv);

  extern void
msstv_destroy(struct msstv * const v);

  extern struct msstv *
msstv_open(const char * const dirname, const char * const filename);

  extern bool
msstv_save(struct msstv * const v, const int dfd);

  extern struct msstv *
msstv_open_at(const int dfd, const char * const filename);

  extern struct msstv *
msstv_open_version(const char * const dirname, const u64 version);

  extern struct msstv *
msstv_create_v0(const int dfd);

  extern struct msstv_ref *
msstv_ref(struct msstv * const v);

  extern struct msstv *
msstv_unref(struct msstv_ref * const ref);

  extern struct kv *
msstv_get(struct msstv_ref * const ref, const struct kref * const key, struct kv * const out);

  extern bool
msstv_probe(struct msstv_ref * const ref, const struct kref * const key);

// return NULL for tomestone
  extern struct kv *
msstv_get_ts(struct msstv_ref * const ref, const struct kref * const key, struct kv * const out);

// return false for tomestone
  extern bool
msstv_probe_ts(struct msstv_ref * const ref, const struct kref * const key);

  extern bool
msstv_get_value_ts(struct msstv_ref * const ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out);

  extern struct msstv_iter *
msstv_iter_create(struct msstv_ref * const ref);

  extern bool
msstv_iter_valid(struct msstv_iter * const vi);

  extern void
msstv_iter_seek(struct msstv_iter * const vi, const struct kref * const key);

  extern struct kv *
msstv_iter_peek(struct msstv_iter * const vi, struct kv * const out);

  extern bool
msstv_iter_kref(struct msstv_iter * const vi, struct kref * const kref);

  extern bool
msstv_iter_kvref(struct msstv_iter * const vi, struct kvref * const kvref);

  extern u64
msstv_iter_retain(struct msstv_iter * const vi);

  extern void
msstv_iter_release(struct msstv_iter * const vi, const u64 opaque);

  extern void
msstv_iter_skip1(struct msstv_iter * const vi);

  extern void
msstv_iter_skip(struct msstv_iter * const vi, const u32 nr);

  extern struct kv *
msstv_iter_next(struct msstv_iter * const vi, struct kv * const out);

  extern void
msstv_iter_park(struct msstv_iter * const vi);

  extern bool
msstv_iter_ts(struct msstv_iter * const vi);

  extern void
msstv_iter_seek_ts(struct msstv_iter * const vi, const struct kref * const key);

  extern void
msstv_iter_skip1_ts(struct msstv_iter * const vi);

  extern void
msstv_iter_skip_ts(struct msstv_iter * const vi, const u32 nr);

  extern struct kv *
msstv_iter_next_ts(struct msstv_iter * const vi, struct kv * const out);

  extern void
msstv_fprint(struct msstv * const v, FILE * const out);

  extern void
msstv_iter_destroy(struct msstv_iter * const vi);

  extern u64
msstv_max_seq(const struct msstv * const v);

  extern u64
msstv_gc(struct msstv * const v);

  extern const struct kv *
msstv_get_anchor(const struct msstv * const v, const u64 ipart);

  extern const struct kv *
msstv_get_kz(const struct msstv * const v, const u64 ipart);

  extern void *
msstv_get_msst(const struct msstv * const v, const u64 ipart);

  extern u64
msstv_gc_prepare(struct msstv * const v, u64 ** const vseq, u64 ** const vall);

  void
msstv_set_next(struct msstv * const v, struct msstv * const next);

  void
msstv_mark_rej(struct msstv * const v, const u64 ipart, const bool rej);

// UNSAFE!
// return the anchors of msstv terminated with NULL
// the returned pointer should be freed after use
// must use when holding a msstv
// anchor->vlen: 0: accepted; 1: rejected
  extern struct kv **
msstv_anchors(struct msstv * const v);
// }}} msstv

// {{{ api
extern const struct kvmap_api kvmap_api_msstv;
extern const struct kvmap_api kvmap_api_msstv_ts;
// }}} api

