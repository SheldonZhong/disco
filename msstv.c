#define _GNU_SOURCE

#include "msstv.h"
#include "kv.h"
#include "ctypes.h"
#include "fs.h"
#include "logger.h"

const struct fs_api * const vzfs = &bt_fs;

// msstv {{{
struct msstv { // similar to a version in leveldb
  u64 version;
  u64 nr; // number of partitions
  u64 nslots; // assert(nr <= nslots)
  struct msstv * next; // to older msstvs
  au64 rdrcnt; // active readers; updated concurrently
  struct rcache * rc; // rcache

  struct msstv_part {
    struct kv * anchor; // magic in anchor->priv; anchor->vlen == 1 for rejected partition
    void * msst; // mssty
  } es[0];
};

struct msstv_iter {
  struct msstv * v;
  u64 nr;
  u64 i; // select mssty
  void * iter;
};

struct msstv_ref { // ref is iter
  struct msstv_iter vi;
};

  inline void
msstv_rcache(struct msstv * const v, struct rcache * const rc)
{
  v->rc = rc;
  for (u64 i = 0; i < v->nr; i++)
    vzfs->mt_rcache(v->es[i].msst, rc);
}

  u64
msstv_get_nr(const struct msstv * const msstv)
{
  return msstv->nr;
}

  u64
msstv_get_version(const struct msstv * const msstv)
{
  return msstv->version;
}

  struct msstv *
msstv_next(const struct msstv * const msstv)
{
  return msstv->next;
}

  void
msstv_add_reader(struct msstv * const msstv)
{
  atomic_fetch_add_explicit(&msstv->rdrcnt, 1, MO_ACQUIRE);
}

  void
msstv_drop_reader(struct msstv * const msstv)
{
  debug_assert(msstv->rdrcnt);
  atomic_fetch_sub_explicit(&msstv->rdrcnt, 1, MO_RELEASE);
}

// for debugging now
  struct msstv *
msstv_create(const u64 nslots, const u64 version)
{
  // msstv does not record nslots
  // caller need to do it right
  struct msstv * const v = calloc(1, sizeof(*v) + (sizeof(v->es[0]) * nslots));
  v->version = version;
  v->nslots = nslots;
  // v->next is maintained externally
  return v;
}

// create empty store
  struct msstv *
msstv_create_v0(const int dfd)
{
  // msstx nr_runs = 0
  void * const msst = vzfs->x_open_at(dfd, 0, 0);
  if (!msst)
    return NULL;

  if (!vzfs->y_build_at(dfd, msst, 0, 0, NULL, 0, false, false, false, NULL, 0)) {
    vzfs->x_destroy(msst);
    return NULL;
  }

  if (!vzfs->y_open_y_at(dfd, msst)) {
    vzfs->x_destroy(msst);
    return NULL;
  }
  // void * const mssty = mssty_open_at(dfd, 0, 0);

  // msstv
  struct msstv * const v = msstv_create(1, 1); // version = 1
  if (v == NULL) {
    vzfs->y_destroy(msst);
    return NULL;
  }
  msstv_append(v, msst, kv_null());
  return v;
}

// anchor can be NULL for auto detection; for new partitions only
// a private copy of the anchor will be duplicated if not NULL
  void
msstv_append(struct msstv * const v, void * const msst, const struct kv * const anchor)
{
  debug_assert(msst);
  debug_assert(v->nr < v->nslots);

  struct msstv_part * const e = &(v->es[v->nr]);
  if (v->nr && (anchor == NULL)) { // auto generate anchor
    struct kv * const first = vzfs->y_first_key(msst, NULL); // malloced
    debug_assert(first); // major compaction should never generate an empty mssty
    struct kv * const plast = vzfs->y_last_key(v->es[v->nr-1].msst, NULL); // malloced; might be NULL
    if (plast) {
      first->klen = kv_key_lcp(plast, first) + 1;
      //kv_update_hash(first);
      free(plast);
    }
    e->anchor = first;
  } else {
    debug_assert(anchor);
    e->anchor = kv_dup_key(anchor);
  }

  vzfs->mt_add_refcnt(msst);
  // save magic in anchor->priv; anchor->hash is not saved
  e->anchor->priv = vzfs->y_get_magic(msst);
  e->msst = msst;
  v->nr++;
}

// save to a file
  bool
msstv_save(struct msstv * const v, const int dfd)
{
  char fn[24];
  sprintf(fn, "%lu.ver", v->version);
  int fd = openat(dfd, fn, O_CREAT|O_WRONLY|O_TRUNC, 00644);
  if (fd < 0)
    return false;

  FILE * const fout = fdopen(fd, "w");
  if (fout == NULL)
    return false;
  setvbuf(fout, NULL, _IOFBF, 1lu << 16); // 64kB
  fwrite(&(v->version), sizeof(v->version), 1, fout);
  fwrite(&(v->nr), sizeof(v->nr), 1, fout);
  char bufz[8] = {};
  for (u64 i = 0; i < v->nr; i++) {
    const u64 keysize = key_size(v->es[i].anchor);
    fwrite(v->es[i].anchor, keysize, 1, fout);
    const u64 size = bits_round_up(keysize, 3);
    if (size > keysize)
      fwrite(bufz, size - keysize, 1, fout);
  }
  fclose(fout);
  return true;
}

// open version and open all msstys
  struct msstv *
msstv_open_at(const int dfd, const char * const filename)
{
  const int fd = openat(dfd, filename, O_RDONLY);
  if (fd < 0)
    return NULL;

  const u64 filesz = fdsize(fd);
  if (filesz < (sizeof(u64) * 2 + sizeof(struct kv))) {
    close(fd);
    return NULL;
  }

  u8 * const buf = malloc(filesz);
  const ssize_t nread = pread(fd, buf, filesz, 0);
  if (filesz != (u64)nread) {
    free(buf);
    close(fd);
    return NULL;
  }
  close(fd);

  const u64 v1 = ((const u64 *)buf)[0];
  const u64 nr = ((const u64 *)buf)[1];
  debug_assert(nr);

  logger_printf("%s version %lu partitions %lu\n", __func__, v1, nr);

  // open msstys
  struct msstv * const v = msstv_create(nr, v1);
  u8 * cursor = buf + (sizeof(u64) * 2);
  for (u64 i = 0; i < nr; i++) {
    struct kv * const anchor = (typeof(anchor))cursor;
    const u64 magic = anchor->priv;
    // rc: msstz_open sets rc later; compaction sets rc manually
    void * const mssty = vzfs->y_open_at(dfd, magic / 100lu, (u32)(magic % 100lu));
    if (!mssty) {
      msstv_destroy(v);
      free(buf);
      return NULL;
    }

    logger_printf("%s opening %lu-th parition\n", __func__, i);

    msstv_append(v, mssty, anchor);
    cursor += (bits_round_up(key_size(anchor), 3));
  }

  debug_assert((u64)(cursor - buf) == filesz);
  free(buf);
  return v;
}

  struct msstv *
msstv_open(const char * const dirname, const char * const filename)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return NULL;
  struct msstv * const v = msstv_open_at(dfd, filename);
  close(dfd);
  return v;
}

  struct msstv *
msstv_open_version(const char * const dirname, const u64 version)
{
  char filename[32];
  sprintf(filename, "%lu.ver", version);
  return msstv_open(dirname, filename);
}

  static void
msstv_destroy_lazy(struct msstv * const v)
{
  for (u64 i = 0; i < v->nr; i++) {
    // mssty can be shared by mutliple versions
    void * const msst = v->es[i].msst;
    vzfs->y_drop_lazy(msst);

    free(v->es[i].anchor);
  }
  free(v);
}

// it does not free the msstys
  void
msstv_destroy(struct msstv * const v)
{
  for (u64 i = 0; i < v->nr; i++) {
    // mssty can be shared by mutliple versions
    void * const msst = v->es[i].msst;
    vzfs->y_drop(msst);

    free(v->es[i].anchor);
  }
  free(v);
}

  struct msstv_ref *
msstv_ref(struct msstv * const v)
{
  struct msstv_iter * const vi = calloc(1, sizeof(*vi));
  vi->v = v;
  vi->nr = v->nr;
  vi->i = v->nr; // invalid
  vi->iter = vzfs->y_iter_new();
  return (struct msstv_ref *)vi;
}

  struct msstv *
msstv_unref(struct msstv_ref * const ref)
{
  struct msstv * const v = ref->vi.v;
  free(ref->vi.iter);
  free(ref);
  return v;
}

  static u64
msstv_search_le(struct msstv * const v, const struct kref * const key)
{
  u64 l = 0;
  u64 r = v->nr;
  while ((l + 1) < r) {
    const u64 m = (l + r) >> 1;
    const int cmp = kref_kv_compare(key, v->es[m].anchor);
    if (cmp < 0)
      r = m; // m always > 0
    else if (cmp > 0)
      l = m;
    else
      return m;
  }
  return l;
}

  static void
msstv_read_prepare(struct msstv_ref * const ref, const struct kref * const key)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  const u64 i = msstv_search_le(vi->v, key);
  debug_assert(i < vi->nr);
  if (i != vi->i) {
    vzfs->y_iter_init(vi->iter, vi->v->es[i].msst);
    vi->i = i;
  }
}

  struct kv *
msstv_get(struct msstv_ref * const ref, const struct kref * const key, struct kv * const out)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  msstv_read_prepare(ref, key);
  struct kv * const ret = vzfs->y_get(vi->iter, key, out);
  vzfs->y_iter_park(vi->iter);
  return ret;
}

  bool
msstv_probe(struct msstv_ref * const ref, const struct kref * const key)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  msstv_read_prepare(ref, key);
  const bool r = vzfs->y_probe(vi->iter, key);
  vzfs->y_iter_park(vi->iter);
  return r;
}

  struct kv *
msstv_get_ts(struct msstv_ref * const ref, const struct kref * const key, struct kv * const out)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  msstv_read_prepare(ref, key);
  struct kv * const ret = vzfs->y_get_ts(vi->iter, key, out);
  vzfs->y_iter_park(vi->iter);
  return ret;
}

  bool
msstv_probe_ts(struct msstv_ref * const ref, const struct kref * const key)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  msstv_read_prepare(ref, key);
  const bool r = vzfs->y_probe_ts(vi->iter, key);
  vzfs->y_iter_park(vi->iter);
  return r;
}

  bool
msstv_get_value_ts(struct msstv_ref * const ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  msstv_read_prepare(ref, key);
  const bool r = vzfs->y_get_value_ts(vi->iter, key, vbuf_out, vlen_out);
  vzfs->y_iter_park(vi->iter);
  return r;
}

  static bool
msstv_iter_valid_i(struct msstv_iter * const vi)
{
  return (vi->i < vi->nr);
}

  bool
msstv_iter_valid(struct msstv_iter * const vi)
{
  debug_assert((vi->i < vi->nr) ? vzfs->y_iter_valid(vi->iter) : true);
  return msstv_iter_valid_i(vi);
}

  struct msstv_iter *
msstv_iter_create(struct msstv_ref * const ref)
{
  // invalid the old states
  ref->vi.i = ref->vi.nr;
  // reuse ref
  return (struct msstv_iter *)ref;
}

  void
msstv_iter_destroy(struct msstv_iter * const vi)
{
  if (msstv_iter_valid(vi))
    vzfs->y_iter_park(vi->iter);
}

  void
msstv_iter_seek(struct msstv_iter * const vi, const struct kref * const key)
{
  struct msstv * const v = vi->v;
  const u64 i0 = msstv_search_le(v, key);
  debug_assert(i0 < vi->nr);
  if (i0 != vi->i) {
    if (msstv_iter_valid(vi))
      vzfs->y_iter_park(vi->iter);
    vi->i = i0;
    vzfs->y_iter_init(vi->iter, v->es[i0].msst);
  }

  do {
    vzfs->y_iter_seek(vi->iter, key);
    if (vzfs->y_iter_valid(vi->iter))
      return;

    vzfs->y_iter_park(vi->iter);
    vi->i++;
    if (!msstv_iter_valid_i(vi))
      return;
    vzfs->y_iter_init(vi->iter, v->es[vi->i].msst);
  } while (true);
}

  struct kv *
msstv_iter_peek(struct msstv_iter * const vi, struct kv * const out)
{
  if (!msstv_iter_valid(vi))
    return NULL;
  return vzfs->y_iter_peek(vi->iter, out);
}

  bool
msstv_iter_kref(struct msstv_iter * const vi, struct kref * const kref)
{
  if (!msstv_iter_valid(vi))
    return false;
  return vzfs->y_iter_kref(vi->iter, kref);
}

  bool
msstv_iter_kvref(struct msstv_iter * const vi, struct kvref * const kvref)
{
  if (!msstv_iter_valid(vi))
    return false;
  return vzfs->y_iter_kvref(vi->iter, kvref);
}

  inline u64
msstv_iter_retain(struct msstv_iter * const vi)
{
  debug_assert(msstv_iter_valid(vi));
  return vzfs->y_iter_retain(vi->iter);
}

  inline void
msstv_iter_release(struct msstv_iter * const vi, const u64 opaque)
{
  const u8 * blk = (const u8 *)opaque;
  struct rcache * const rc = vi->v->rc;
  debug_assert(blk && (((u64)blk) & 0xffflu) == 0);
  if (rc)
    rcache_release(rc, blk);
}

  void
msstv_iter_skip1(struct msstv_iter * const vi)
{
  debug_assert(msstv_iter_valid(vi));
  void * const iter = vi->iter;
  vzfs->y_iter_skip1(iter);
  while (unlikely(!vzfs->y_iter_valid(iter))) { // next partition
    vzfs->y_iter_park(iter);
    vi->i++;
    if (msstv_iter_valid_i(vi)) {
      vzfs->y_iter_init(iter, vi->v->es[vi->i].msst);
      vzfs->y_iter_seek_null(iter);
    } else { // invalid
      return;
    }
  }
}

  void
msstv_iter_skip(struct msstv_iter * const vi, const u32 nr)
{
  if (!msstv_iter_valid(vi))
    return;
  for (u32 i = 0; i < nr; i++) {
    msstv_iter_skip1(vi);
  }
}

  struct kv *
msstv_iter_next(struct msstv_iter * const vi, struct kv * const out)
{
  struct kv * const ret = msstv_iter_peek(vi, out);
  if (msstv_iter_valid(vi))
    msstv_iter_skip1(vi);
  return ret;
}

  inline bool
msstv_iter_ts(struct msstv_iter * const vi)
{
  // assume vi is valid
  debug_assert(msstv_iter_valid(vi));
  return vzfs->y_iter_ts(vi->iter);
}

  void
msstv_iter_seek_ts(struct msstv_iter * const vi, const struct kref * const key)
{
  msstv_iter_seek(vi, key);
  while (msstv_iter_valid(vi) && msstv_iter_ts(vi))
    msstv_iter_skip1(vi);
}

  void
msstv_iter_skip1_ts(struct msstv_iter * const vi)
{
  if (!msstv_iter_valid(vi))
    return;

  msstv_iter_skip1(vi);
  while (msstv_iter_valid(vi) && msstv_iter_ts(vi))
    msstv_iter_skip1(vi);
}

  void
msstv_iter_skip_ts(struct msstv_iter * const vi, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!msstv_iter_valid(vi))
      return;

    msstv_iter_skip1(vi);
    while (msstv_iter_valid(vi) && msstv_iter_ts(vi))
      msstv_iter_skip1(vi);
  }
}

  struct kv *
msstv_iter_next_ts(struct msstv_iter * const vi, struct kv * const out)
{
  struct kv * const ret = msstv_iter_peek(vi, out);
  msstv_iter_skip1_ts(vi);
  return ret;
}

  void
msstv_iter_park(struct msstv_iter * const vi)
{
  if (msstv_iter_valid(vi))
    vzfs->y_iter_park(vi->iter);
  vi->i = vi->nr;
}

  void
msstv_fprint(struct msstv * const v, FILE * const out)
{
  fprintf(out, "%s v %lu nr %lu refcnt %lu rcache %s\n",
      __func__, v->version, v->nr, atomic_load_explicit(&v->rdrcnt, MO_CONSUME), v->rc ? "ON" : "OFF");

  for (u64 i = 0; i < v->nr; i++) {
    void * const msst = v->es[i].msst;
    vzfs->y_fprint(msst, out);
    const u64 magic = v->es[i].anchor->priv;
    fprintf(out, "%s [%3lu %6.3lu]", __func__, i, magic);
    kv_print(v->es[i].anchor, "sn", out);
  }
}

  void
msstv_mark_rej(struct msstv * const v, const u64 ipart, const bool rej)
{
  // the vlen is consumed in xdb reject
  // 1: rej; 0: ok
  v->es[ipart].anchor->vlen = rej ? 1 : 0;
}

  struct kv **
msstv_anchors(struct msstv * const v)
{
  struct kv ** const ret = malloc(sizeof(ret[0]) * (v->nr+1));
  for (u64 i = 0; i < v->nr; i++)
    ret[i] = v->es[i].anchor;
  ret[v->nr] = NULL;
  return ret;
}

  u64
msstv_max_seq(const struct msstv * const v)
{
  u64 seq = 0;
  for (u64 i = 0; i < v->nr; i++) {
    const u64 magic = v->es[i].anchor->priv;
    const u64 seq1 = magic / 100;
    if (seq < seq1)
      seq = seq1;
  }
  return seq;
}

  const struct kv *
msstv_get_kz(const struct msstv * const v, const u64 ipart)
{
  return ((ipart + 1) < v->nr) ? v->es[ipart + 1].anchor : NULL;
}

  const struct kv *
msstv_get_anchor(const struct msstv * const v, const u64 ipart)
{
  return v->es[ipart].anchor;
}

  void *
msstv_get_msst(const struct msstv * const v, const u64 ipart)
{
  return v->es[ipart].msst;
}

  u64
msstv_gc(struct msstv * const v)
{
  u64 nv = 0;
  // gc the tail, one at a time
  while (v->next) {
    struct msstv ** pv = &(v->next);
    // seek to &plast
    while ((*pv)->next)
      pv = &((*pv)->next);
    // stop if there is no next version, or the oldest version has version > 0

    struct msstv * const last = *pv;
    debug_assert(last->next == NULL);
    if (atomic_load_explicit(&last->rdrcnt, MO_CONSUME)) {
      break;
    } else { // do gc
      *pv = NULL; // remove from the list
      msstv_destroy_lazy(last);
      nv++;
    }
  }

  return nv;
}

  void
msstv_set_next(struct msstv * const v, struct msstv * const next)
{
  v->next = next;
}

  u64
msstv_gc_prepare(struct msstv * const hv, u64 ** const vseq_out, u64 ** const vall_out)
{
  // count nr
  u64 nr = 0;
  struct msstv * v = hv;
  while (v) {
    nr += v->nr;
    v = v->next;
  }
  // collect live seq numbers
  cpu_cfence();
  // array of all live seqs
  u64 * const vseq = malloc(sizeof(*vseq) * nr);
  // array of all live magics (live ssty)
  u64 * const vall = malloc(sizeof(*vall) * nr);
  u64 nr1 = 0;
  v = hv; // start over to collect seqs
  debug_assert(v);
  do {
    for (u64 i = 0; i < v->nr; i++) {
      const u64 magic = v->es[i].anchor->priv;
      vseq[nr1] = magic / 100;
      vall[nr1] = magic;
      nr1++;
    }
    v = v->next;
  } while (v);
  debug_assert(nr1 == nr);
  // it's ok to have duplicates
  qsort_u64(vseq, nr);
  qsort_u64(vall, nr);

  *vseq_out = vseq;
  *vall_out = vall;

  return nr;
}

// }}} msstv

// {{{ api
const struct kvmap_api kvmap_api_msstv = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)msstv_get,
  .probe = (void *)msstv_probe,
  .iter_create = (void *)msstv_iter_create,
  .iter_seek = (void *)msstv_iter_seek,
  .iter_valid = (void *)msstv_iter_valid,
  .iter_peek = (void *)msstv_iter_peek,
  .iter_kref = (void *)msstv_iter_kref,
  .iter_kvref = (void *)msstv_iter_kvref,
  .iter_retain = (void *)msstv_iter_retain,
  .iter_release = (void *)msstv_iter_release,
  .iter_skip1 = (void *)msstv_iter_skip1,
  .iter_skip = (void *)msstv_iter_skip,
  .iter_next = (void *)msstv_iter_next,
  .iter_park = (void *)msstv_iter_park,
  .iter_destroy = (void *)msstv_iter_destroy,
  .ref = (void *)msstv_ref,
  .unref = (void *)msstv_unref,
  .destroy = (void *)msstv_destroy,
  .fprint = (void *)msstv_fprint,
};

const struct kvmap_api kvmap_api_msstv_ts = { // xdb
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)msstv_get_ts,
  .probe = (void *)msstv_probe_ts,
  .iter_create = (void *)msstv_iter_create,
  .iter_seek = (void *)msstv_iter_seek_ts,
  .iter_valid = (void *)msstv_iter_valid,
  .iter_peek = (void *)msstv_iter_peek,
  .iter_kref = (void *)msstv_iter_kref,
  .iter_kvref = (void *)msstv_iter_kvref,
  .iter_retain = (void *)msstv_iter_retain,
  .iter_release = (void *)msstv_iter_release,
  .iter_skip1 = (void *)msstv_iter_skip1_ts,
  .iter_skip = (void *)msstv_iter_skip_ts,
  .iter_next = (void *)msstv_iter_next_ts,
  .iter_park = (void *)msstv_iter_park,
  .iter_destroy = (void *)msstv_iter_destroy,
  .ref = (void *)msstv_ref,
  .unref = (void *)msstv_unref,
  .destroy = (void *)msstv_destroy,
  .fprint = (void *)msstv_fprint,
};

  static void *
msstv_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  (void)mm;
  if ((!strcmp(name, "msstv")) || (!strcmp(name, "msstv_ts"))) {
    return msstv_open(args[0], args[1]);
  } else {
    return NULL;
  }
}

// alternatively, call the register function from main()
__attribute__((constructor))
  static void
sst_kvmap_api_init(void)
{
  kvmap_api_register(2, "msstv", "<dirname> <filename>", msstv_kvmap_api_create, &kvmap_api_msstv);
  kvmap_api_register(2, "msstv_ts", "<dirname> <filename>", msstv_kvmap_api_create, &kvmap_api_msstv_ts);
}

// }}} api

// vim:fdm=marker
