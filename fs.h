#include "common.h"
#include "blkio.h"
#include "kv.h"

/*

// {{{ msstv needs

  extern void
msst_rcache(void * const msst, struct rcache * const rc);

  extern void *
msstx_open_at(const int dfd, const u64 seq, const u32 nr_runs);

  extern void
msstx_destroy(void * const msst);

  extern void *
mssty_open_at(const int dfd, const u64 seq, const u32 nr_runs);

  extern bool
mssty_open_y_at(const int dfd, void * const msst);

  extern void
mssty_destroy(void * const msst);

  extern struct kv *
mssty_first_key(const void * const msst, struct kv * const out);

  extern struct kv *
mssty_last_key(const void * const msst, struct kv * const out);

  extern void
msst_add_refcnt(void * const msst);

  extern void
mssty_drop_lazy(void * const msst);

  extern void
mssty_drop(void * const msst);

  extern u64
mssty_get_magic(const void * const msst);

  extern void *
mssty_iter_new();

  extern bool
mssty_iter_valid(void * const y_iter);

  extern struct kv *
mssty_get(void * const y_ref, const struct kref * const key, struct kv * const out);

  extern struct kv *
mssty_get_ts(void * const y_ref, const struct kref * const key, struct kv * const out);

  extern bool
mssty_get_value_ts(void * const y_ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out);

  extern bool
mssty_probe(void * const y_ref, const struct kref * const key);

  extern bool
mssty_probe_ts(void * const y_ref, const struct kref * const key);

  extern void
mssty_iter_init(void * const y_iter, void * const msst);

  extern void
mssty_iter_park(void * const y_iter);

  extern void
mssty_iter_seek(void * const y_iter, const struct kref * const key);

  extern struct kv *
mssty_iter_peek(void * const y_iter, struct kv * const out);

  extern bool
mssty_iter_kref(void * const y_iter, struct kref * const kref);

  extern bool
mssty_iter_kvref(void * const y_iter, struct kvref * const kvref);

  extern u64
mssty_iter_retain(void * const y_iter);

  extern void
mssty_iter_skip1(void * const y_iter);

  extern void
mssty_fprint(void * const msst, FILE * const fout);

  extern bool
mssty_iter_ts(void * const y_iter);

  extern void
mssty_iter_seek_null(void * const y_iter);

  extern u32
ssty_build_at(const int dfd, void * const msstx1,
    const u64 seq, const u32 nr_runs, void * const mssty0, const u32 run0, const bool gen_tags);

// }}} msstv needs

// {{{ msstz needs
struct msst_stats {
  u64 ssty_sz;
  u64 meta_sz;
  u64 data_sz;
  u32 totkv;
  u32 totsz;
  u32 valid;
  u32 nr_runs;
};

struct sst_build_cfg {
  u64 seq;
  u32 run;
  u16 max_pages; // <= 65520
  bool del;
  bool ckeys;
};

  extern void
msst_stats(const void * const msst, struct msst_stats * const stats);

  extern void *
msstx_open_at_reuse(const int dfd, const u64 seq, const u32 nr_runs, void * const msst0, const u32 nrun0);

  extern u64
sst_build_at(const int dfd, struct miter * const miter,
    const struct sst_build_cfg * const cfg,
    const struct kv * const k0, const struct kv * const kz);

  extern u32
msst_accu_nkv_at(const void * const msst, const u32 i);

  u64
mssty_comp_est_ssty(const u64 nkeys, const float run);

  extern u32
msst_nkv_at(const void * const msst, const u32 i);

  extern void
mssty_miter_major(void * const msst, struct miter * const miter);

  extern void
mssty_miter_partial(void * const msst, struct miter * const miter, const u32 bestrun);
// }}} msstz needs
*/

struct fs_api {
  void (* mt_rcache) (void * const msst, struct rcache * const rc);
  void * (* x_open_at) (const int dfd, const u64 seq, const u32 nr_runs);
  void (* x_destroy) (void * const msst);
  void * (* y_open_at) (const int dfd, const u64 seq, const u32 nr_runs);
  bool (* y_open_y_at) (const int dfd, void * const msst);
  void (*y_destroy) (void * const msst);
  struct kv * (* y_first_key) (const void * const msst, struct kv * const out);
  struct kv * (* y_last_key) (const void * const msst, struct kv * const out);
  void (* mt_add_refcnt) (void * const msst);
  void (* y_drop_lazy) (void * const msst);
  void (* y_drop) (void * const msst);
  u64 (* y_get_magic) (const void * const msst);
  void * (* y_iter_new) ();
  bool (* y_iter_valid) (void * const y_iter);
  struct kv * (* y_get) (void * const y_ref, const struct kref * const key, struct kv * const out);
  struct kv * (* y_get_ts) (void * const y_ref, const struct kref * const key, struct kv * const out);
  bool (* y_get_value_ts) (void * const y_ref, const struct kref * const key, void * const vbuf_out, u32 * const vlen_out);
  bool (* y_probe) (void * const y_ref, const struct kref * const key);
  bool (* y_probe_ts) (void * const y_ref, const struct kref * const key);
  void (* y_iter_init) (void * const y_iter, void * const msst);
  void (* y_iter_park) (void * const y_iter);
  void (* y_iter_seek) (void * const y_iter, const struct kref * const key);
  struct kv * (* y_iter_peek) (void * const y_iter, struct kv * const out);
  bool (* y_iter_kref) (void * const y_iter, struct kref * const kref);
  bool (* y_iter_kvref) (void * const y_iter, struct kvref * const kvref);
  u64 (* y_iter_retain) (void * const y_iter);
  void (* y_iter_skip1) (void * const y_iter);
  void (* y_fprint) (void * const msst, FILE * const fout);
  bool (* y_iter_ts) (void * const y_iter);
  void (* y_iter_seek_null) (void * const y_iter);
  u32 (* y_build_at) (const int dfd, void * const msstx1,
    const u64 seq, const u32 nr_runs, void * const mssty0,
    const u32 run0, const bool gen_tags, const bool gen_dbits,
    const bool inc_rebuild, const u8 * merge_hist, const u64 hist_size);
  void (* mt_stats) (const void * const msst, struct msst_stats * const stats);
  void * (*x_open_at_reuse) (const int dfd, const u64 seq, const u32 nr_runs, void * const msst0, const u32 nrun0);
  u64 (* t_build_at) (const int dfd, struct miter * const miter, const struct t_build_cfg * const cfg,
    const struct kv * const k0, const struct kv * const kz);
  u32 (* mt_accu_nkv_at) (const void * const msst, const u32 i);
  u64 (* y_comp_est_y) (const u64 nkeys, const float run);
  u32 (* mt_nkv_at) (const void * const msst, const u32 i);
  u32 (* mt_nr_pages_at) (const void * const msst, const u32 i);
  void (* y_miter_major) (void * const msst, struct miter * const miter);
  void (* y_miter_partial) (void * const msst, struct miter * const miter, const u32 bestrun);
  const char * const x_suffix;
  const char * const y_suffix;
};

extern const struct fs_api sst_fs;
extern const struct fs_api bt_fs;

  const struct fs_api *
get_fs(const char * name);

// vim:fdm=marker
