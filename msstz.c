#include "common.h"
#include "msstz.h"
#include <dirent.h>
#include "fs.h"
#include "logger.h"

// msstz {{{

// msst zoo
struct msstz {
  struct msstv * volatile hv; // the newest version
  au64 seq; // next available seq
  char * dirname;

  // compaction parameters
  struct msstz_cfg cfg;
  struct rcache * rc; // read-only cache

  double t0;
  int dfd;
  u64 stat_time; // time spent in comp()
  u64 stat_writes; // total bytes written to sstx&ssty
  u64 stat_reads; // total bytes read through rcache

  u64 padding1[7];
  rwlock head_lock; // writer: compaction, gc
};

  static void
msstz_head_sync(const int dfd, const u64 version)
{
  char basefn[24];
  sprintf(basefn, "./%lu.ver", version);

  unlinkat(dfd, "HEAD", 0);
  symlinkat(basefn, dfd, "HEAD");
  return;
}

  struct msstz *
msstz_open(const char * const dirname, const struct msstz_cfg * const cfg)
{
  // get the dir
  int dfd = open(dirname, O_RDONLY | O_DIRECTORY);
  if (dfd < 0) {
    mkdir(dirname, 00777);
    dfd = open(dirname, O_RDONLY | O_DIRECTORY);
  }
  if (dfd < 0)
    return NULL;

  // get a version
  struct msstv * hv = msstv_open_at(dfd, "HEAD");
  if (hv == NULL) {
    logger_printf("%s open HEAD failed, now trying to create new v0\n", __func__);
    hv = msstv_create_v0(dfd);
  }
  if (hv == NULL) {
    close(dfd);
    logger_printf("%s create v0 failed\n", __func__);
    return NULL;
  }

  // after creation, rdrcnt is already 0
  // atomic_store_explicit(&hv->rdrcnt, 0, MO_RELAXED);
  // use a new seq
  const u64 seq0 = msstv_max_seq(hv) + 1;

  struct msstz * const z = yalloc(sizeof(*z));
  debug_assert(z);
  memset(z, 0, sizeof(*z));
  if (cfg->cache_size_mb)
    z->rc = rcache_create(cfg->cache_size_mb, 16);

  z->seq = seq0;
  z->hv = hv;
  msstv_rcache(hv, z->rc);

  z->dirname = strdup(dirname);
  debug_assert(z->dirname);

  z->cfg = cfg ? *cfg : msstz_cfg_default;
  z->dfd = dfd;

  z->t0 = time_sec();

  rwlock_init(&(z->head_lock));
  char ts[64];
  time_stamp(ts, 64);
  logger_printf("%s time %s v %lu seq %lu cache %lu\n", __func__,
      ts, msstz_version(z), seq0, cfg->cache_size_mb);

  /*
  for (u64 i = 0; i < hv->nr; i++) {
    const u64 magic = hv->es[i].anchor->priv;
    logger_printf("%s [%3lu] %5lu\n", __func__, i, magic);
  }
  */
  return z;
}

  inline u64
msstz_stat_writes(struct msstz * const z)
{
  return z->stat_writes;
}

  inline u64
msstz_stat_reads(struct msstz * const z)
{
  return z->stat_reads;
}

  inline u64
msstz_version(struct msstz * const z)
{
  return msstv_get_version(z->hv);
}

// free unused versions and delete unused files
// currently the first analyze worker do the gc
  static void
msstz_gc(struct msstz * const z)
{
  const u64 t0 = time_nsec();
  //const double t0 = time_sec();
  struct msstv * const hv = z->hv;
  debug_assert(hv);
  const u64 nv = msstv_gc(hv);
  u64 hv_ver = msstv_get_version(hv);
  const u64 nc = z->rc ? rcache_close_flush(z->rc) : 0;

  u64 * vseq, * vall;
  const u64 nr = msstv_gc_prepare(hv, &vseq, &vall);
  const u64 maxseq = vseq[nr-1];
  // search file in dir
  DIR * const dir = opendir(z->dirname); // don't directly use the dfd
  if (!dir) {
    logger_printf("%s opendir() failed\n", __func__);
    exit(0);
  }

  u64 nu = 0;
  do {
    struct dirent * const ent = readdir(dir);
    if (!ent)
      break;
    char * dot = strchr(ent->d_name, '.');
    // has dot and is .sst* or (.btx or .remix)
    if (!dot)
      continue;

    if (!memcmp(dot, ".ver", 4)) {
      if (a2u64(ent->d_name) < hv_ver)
        unlinkat(z->dfd, ent->d_name, 0);
      continue;
    }

    if ((strcmp(dot, vzfs->x_suffix) != 0) && (strcmp(dot, vzfs->y_suffix) != 0)) {
      continue;
    }
    const u64 magic = a2u64(ent->d_name);
    const u64 seq = magic / 100;

    if (seq > maxseq)
      continue;

    if (strcmp(dot, vzfs->x_suffix) == 0) {
      if (bsearch_u64(seq, vseq, nr))
        continue;
    } else if (strcmp(dot, vzfs->y_suffix) == 0) {
      if (bsearch_u64(magic, vall, nr))
        continue;
    } else {
      debug_die();
    }
    // now delete
    unlinkat(z->dfd, ent->d_name, 0);
    //logger_printf("%s unlink %s\n", __func__, ent->d_name);
    nu++;
  } while (true);

  free(vseq);
  free(vall);
  closedir(dir);
  logger_printf("%s gc dt-ms %lu free-v %lu close %lu unlink %lu\n", __func__, time_diff_nsec(t0)/1000000, nv, nc, nu);
}

  inline struct msstv *
msstz_getv(struct msstz * const z)
{
  rwlock_lock_read(&(z->head_lock));
  struct msstv * const v = z->hv;
  msstv_add_reader(v);
  rwlock_unlock_read(&(z->head_lock));
  return v;
}

  inline void
msstz_putv(struct msstz * const z, struct msstv * const v)
{
  (void)z;
  msstv_drop_reader(v);
}

  void
msstz_destroy(struct msstz * const z)
{
  struct msstv * iter = z->hv;
  debug_assert(iter);
  msstz_gc(z);
  logger_printf("%s hv %lu comp_time %lu writes %lu reads %lu\n", __func__,
      msstv_get_version(iter), z->stat_time, z->stat_writes, z->stat_reads);
  while (iter) {
    struct msstv * next = msstv_next(iter);
    msstv_destroy(iter);
    iter = next;
  }
  if (z->rc)
    rcache_destroy(z->rc);

  free(z->dirname);
  close(z->dfd);
  free(z);
}
// }}} msstz

// msstz-comp {{{

// struct {{{
// yq allows different threads to build sstys; very useful for sequential loading
struct msstz_yq {
  au64 pseq; // producer seq
  au64 cseq; // consumer seq
  spinlock lock;
  u32 padding;
  struct msstz_ytask tasks[0];
};

// global compaction information
struct msstz_comp_info {
  struct msstz * z;
  struct msstv * v0; // the old version
  au64 seqx; // to assign analysis/compaction tasks to threads
  struct msstz_yq * yq;
  u64 n0; // total number of v0 partitions
  au64 nx; // when nx == n0, the yq has all the tasks
  u32 nr_workers;
  u32 co_per_worker;
  const struct kvmap_api * api1; // memtable api
  void * map1; // memtable map
  au64 totsz;
  au64 stat_writes; // total bytes written to sstx&ssty
  au64 stat_reads; // total bytes read through rcache
  au64 stat_minor;
  au64 stat_partial;
  au64 stat_major;
  au64 stat_append;
  au64 time_analyze;
  au64 time_comp_x;
  au64 time_comp_y;
  u64 t0;
  u64 dta;
  u64 dtc;
  struct msstz_comp_part {
    u64 idx;
    u64 newsz; // size of new data in the memtable
    u32 bestrun; // how many existing (can be linked) tables to keep in the old partition
    float ratio; // write_size over read_size; newsz / totsz; the higher the better
  } parts[0];
};
// }}} struct

// y {{{
  static struct msstz_yq *
msstz_yq_create(const u64 nslots)
{
  struct msstz_yq * const yq = malloc(sizeof(*yq) + (sizeof(yq->tasks[0]) * nslots));
  yq->pseq = 0;
  yq->cseq = 0;
  spinlock_init(&yq->lock);
  return yq;
}

  static struct msstz_ytask *
msstz_yq_append(struct msstz_yq * const yq, void * const mssty1, const u64 seq1, const u32 run1,
    void * const mssty0, const u32 run0, const u64 ipart, const u64 isub, const struct kv * const anchor,
    u8 * const merge_hist, u64 hist_size, const char * const comp_str)
{
  u8 * build_history = NULL;
  if (hist_size) {
    build_history = malloc(hist_size);
    memcpy(build_history, merge_hist, hist_size);
  }
  spinlock_lock(&yq->lock);
  const u64 i = yq->pseq++;
  struct msstz_ytask * const task = &yq->tasks[i];
  task->y1 = mssty1; // not NULL only when append
  task->y0 = mssty0;
  task->seq1 = seq1;
  task->run1 = run1;
  task->run0 = run0;
  task->ipart = ipart;
  task->isub = isub;
  task->anchor = anchor;
  task->t_build_history = build_history;
  task->hist_size = hist_size;
  strcpy(task->comp_str, comp_str);
  spinlock_unlock(&yq->lock);
  return &yq->tasks[i];
}

// return true when a task is found and executed
  static bool
msstz_yq_consume(struct msstz_comp_info * const ci)
{
  struct msstz_yq * const yq = ci->yq;
  struct msstz * const z = ci->z;
  spinlock_lock(&yq->lock);
  if (yq->cseq == yq->pseq) {
    // no task
    spinlock_unlock(&yq->lock);
    return false;
  }
  // claim a task with lock
  const u64 id = yq->cseq++;
  spinlock_unlock(&yq->lock);

  struct msstz_ytask * const task = &(yq->tasks[id]);
  // already done (only once for the store-append)
  if (task->y1)
    return true;

  // open a msstx and call ssty_build
  const u64 t0 = time_nsec();
  u64 ysz = 0;
  void * const msst = vzfs->y_build_at_reuse(z->dfd, z->rc, task, &z->cfg, &ysz);
  ci->stat_writes += ysz;

  task->y1 = msst; // done; the new partition is now loaded and ready to use
  if (task->t_build_history)
    free(task->t_build_history);

  const u64 dt = time_diff_nsec(t0);
  //const struct ssty_meta * const ym = msst->ssty->meta;
  struct msst_stats stats;
  vzfs->mt_stats(msst, &stats);
  logger_printf("%s dt-ms %lu ssty-build %lu %02u ysz %lu xkv %u xsz %u valid %u\n",
      __func__, dt / 1000000, task->seq1, task->run1,
      ysz, stats.totkv, stats.totsz, stats.valid);
  logger_printf("%s %s compaction, run0 %d run1 %u, rate %lf Mbps\n",
      __func__, task->comp_str, task->run0, task->run1, (((double)stats.totsz / 1024 / 1024) / ((double)dt / 1e9)));
  return true;
}
// }}} y

// x {{{
// compaction driver on one partition; it may create multiple partitions
// create ssts synchronously; queue build-ssty tasks in yq
// seq0 and run0 indicate the existing (can be linked) tables in the target partition
  static void
msstz_comp_ssts(struct msstz_comp_info * const ci, const u64 ipart, struct miter * const miter,
    const struct kv * const k0, const struct kv * const kz, const u64 seq0, const u32 run0, const bool split,
    void * const mssty0, const bool is_append, const char * const comp_str)
{
  struct msstz * const z = ci->z;
  // tmp anchor
  struct kv * const tmp = malloc(sizeof(struct kv) + SST_MAX_KVSZ); // just a buffer
  u64 seq = seq0;
  u32 run = run0;
  u32 np = 0;
  debug_assert(run < MSST_NR_RUNS);

  if (is_append) {
    msstz_yq_append(ci->yq, mssty0, seq, run, NULL, 0, ipart, 0, k0, NULL, 0, comp_str);
    // only mssty0, ipart, and k0 will be used
    np++;
    seq = z->seq++;
    run = 0;
  }

  if ((split == false)) {
    // don't record for major and append
    // TODO: also skip for minor compactions
    miter_start_recording(miter);
  }
  // a compaction may create new partitions, each with several new tables
  do {
    const u64 t0 = time_nsec();

    const struct t_build_cfg cfg = {.seq = seq, .run = run,
      .max_pages = z->cfg.max_pages, .del = split, .ckeys = z->cfg.ckeys};
    const u64 sizex = vzfs->t_build_at(z->dfd, miter, &cfg, NULL, kz);
    // TODO: what if it generates multiple runs?
    const u64 dt = time_diff_nsec(t0);
    ci->stat_writes += sizex;
    logger_printf("%s dt-ms %lu sst-build %lu-%02u %lu\n", __func__, dt / 1000000, seq, run, sizex);
    run++;

    struct kv * const tmpz = miter_peek(miter, tmp); // the current unconsumed key

    // the entire partition is done
    const bool donez = (tmpz == NULL) || (kz && (kv_compare(tmpz, kz) >= 0));

    // the current partition must close; will switch to a new partition
    const bool done1 = split ? (run >= z->cfg.major_switch) : false;
    if (donez || done1) { // close current mssty
      if (np == 0) { // on the original partition; use y0, run0, and k0
        u8 * history = NULL;
        u64 hist_size = 0;
        miter_stop_recording(miter, &history, &hist_size);
        if (history != NULL) {
          debug_assert(hist_size > 0);
        }
        msstz_yq_append(ci->yq, NULL, seq, run, mssty0, run0, ipart, np, k0, history, hist_size, comp_str);
      } else { // a new partition: reuse nothing, generate anchor
        msstz_yq_append(ci->yq, NULL, seq, run, NULL, 0, ipart, np, NULL, NULL, 0, comp_str);
      }
      np++;

      if (donez) { // the end
        break;
      } else if (split) { // done1: next partition
        seq = z->seq++;
        run = 0;
      } else if (run >= MSST_NR_RUNS) {
        // it is acceptable to have tables above major_trigger; the actual threshold is MSST_NR_RUNS
        debug_die();
      }
    }
  } while (true);
  debug_assert(split || (np == 1)); // only split can return more than one partition
  free(tmp);
  logger_printf("%s np %u seq0 %lu run0 %u seq %lu run %u\n", __func__, np, seq0, run0, seq, run);
}

  static void
msstz_comp_link(const int dfd, const u64 seq0, const u64 seq1, const u32 nr_runs)
{
  debug_assert(seq0 < seq1);
  char fn0[24];
  char fn1[24];

  for (u32 i = 0; i < nr_runs; i++) {
    sprintf(fn0, "%03lu%s", seq0 * 100lu + i, vzfs->x_suffix);
    sprintf(fn1, "%03lu%s", seq1 * 100lu + i, vzfs->x_suffix);
    unlinkat(dfd, fn1, 0);
    int s = linkat(dfd, fn0, dfd, fn1, 0);
    debug_assert(s == 0);
  }
}
// }}} x

// v {{{
  static int
msstz_cmp_ytask(const void * p1, const void * p2)
{
  const struct msstz_ytask * const t1 = p1;
  const struct msstz_ytask * const t2 = p2;
  if (t1->ipart < t2->ipart) {
    return -1;
  } else if (t1->ipart > t2->ipart) {
    return 1;
  } else if (t1->isub < t2->isub) {
    return -1;
  } else if (t1->isub > t2->isub) {
    return 1;
  } else {
    debug_die();
    return 0;
  }
}

  static void
msstz_comp_harvest(struct msstz_comp_info * const ci)
{
  struct msstz_yq * const yq = ci->yq;
  debug_assert(yq->pseq == yq->cseq);
  debug_assert(yq->pseq >= ci->n0);
  const u64 nr = yq->pseq;
  struct msstv * const v0 = ci->v0;

  // sort yq
  qsort(yq->tasks, nr, sizeof(yq->tasks[0]), msstz_cmp_ytask);

  u64 ssty_sz = 0; // total ssty file size
  u64 meta_sz = 0; // total sst metadata size
  u64 data_sz = 0; // total data size (pages)
  const u64 v0_ver = msstv_get_version(v0);
  struct msstv * const v1 = msstv_create(nr, v0_ver + 1); // no resizing

  // collect new partitions and create v1
  for (u64 i = 0; i < nr; i++) {
    struct msstz_ytask * const t = &yq->tasks[i];
    msstv_append(v1, t->y1, t->anchor);
    // ipart is actually i, can we assume?
    msstv_mark_rej(v0, t->ipart, t->seq1 == UINT64_MAX);

    // count sizes
    void * const msst = t->y1;
    struct msst_stats stats;
    vzfs->mt_stats(msst, &stats);
    ssty_sz += stats.ssty_sz;
    meta_sz += stats.meta_sz;
    data_sz += stats.data_sz;
  }

  struct msstz * const z = ci->z;
  logger_printf("%s v %lu nr %lu ssty-size %lu sst-meta-size %lu sst-data-size %lu\n",
      __func__, msstv_get_version(v1), nr, ssty_sz, meta_sz, data_sz);

  msstv_rcache(v1, z->rc);
  msstv_set_next(v1, v0);
  // finalize the new version v1
  msstv_save(v1, z->dfd);
  msstz_head_sync(z->dfd, msstv_get_version(v1));

  // add the new version to z
  rwlock_lock_write(&(z->head_lock));
  z->hv = v1;
  rwlock_unlock_write(&(z->head_lock));
}
// }}} v

// analyze {{{
  static inline u64
msstz_comp_runsz(struct msstz * const z)
{
  return (PGSZ - 256) * z->cfg.max_pages;
}

  static inline u32
msstz_comp_bestrun(struct msstz_comp_part * const cpart, const void * const msst,
    struct msstz * const z, const u64 newnr)
{
  // calculate wa[i] if start from run[i]
  // 0: fully rewrite with real deletion
  // 1 to nr_runs-1: partial merge
  // nr_runs: minor compaction (wa == 1)

  struct msst_stats stats;
  vzfs->mt_stats(msst, &stats);
  const u32 nr_runs = stats.nr_runs;
  debug_assert(vzfs->mt_accu_nkv_at(msst, nr_runs) == 0);

  struct { u64 wx, wy; float nrun1, wa, bonus, score; } f[MSST_NR_RUNS+1];

  const u64 avg_sz = stats.totsz / stats.totkv;
  // wx: data write size
  f[0].wx = cpart->newsz + ((u64)stats.valid * avg_sz); // major
  for (u32 i = 1; i <= nr_runs; i++)
    f[i].wx = cpart->newsz + ((u64)vzfs->mt_accu_nkv_at(msst, i)* avg_sz); // major

  // nrun1: final run
  // penalty = nrun1
  const float runsz = (float)msstz_comp_runsz(z);
  for (u32 i = 0; i <= nr_runs; i++)
    f[i].nrun1 = ((float)f[i].wx / runsz) + (float)i;

  // wy: ysize
  f[0].wy = vzfs->y_comp_est_y(newnr + stats.valid, fminf(f[0].nrun1, (float)z->cfg.major_trigger));
  u64 totkvi = 0;
  for (u32 i = 1; i <= nr_runs; i++) {
    totkvi += vzfs->mt_nkv_at(msst, i-1);
    f[i].wy = vzfs->y_comp_est_y(newnr + totkvi + vzfs->mt_accu_nkv_at(msst, i), f[i].nrun1);
  }
  // wa: write amp.
  for (u32 i = 0; i <= nr_runs; i++)
    f[i].wa = (float)(f[i].wx + f[i].wy) / (float)cpart->newsz;

  // bonus: based on how effective it can reduce runs
  for (u32 i = 0; i <= nr_runs; i++)
    f[i].bonus = f[nr_runs].nrun1 - f[i].nrun1;

  // adjust major bonus: large bonus when split is necessary
  if (f[nr_runs].nrun1 > (float)z->cfg.major_trigger)
    f[0].bonus += (f[0].nrun1 - (float)z->cfg.major_switch);

  // adjust minor bonus; +1
  f[nr_runs].bonus += 1.0f;

  u32 bestrun = 0; // major by default
  for (u32 i = 0; i <= nr_runs; i++) {
    // score: lower is better
    //const float score = (f[i].wa + sqrtf(f[i].nrun1 + 1.0f)) / (f[i].bonus + 4.0f);
    const float score = (f[i].wa + (f[i].nrun1 * 0.75f)) / (f[i].bonus + 4.0f);
    f[i].score = score;
    if ((i < z->cfg.major_trigger) && (f[i].nrun1 < (float)z->cfg.estimate_safe) && (f[i].score < f[bestrun].score))
      bestrun = i;
  }
  debug_assert(bestrun < z->cfg.major_trigger);

  // log some details of the compaction
  for (u32 i = 0; i <= nr_runs; i++) {
    const u64 sz = (i < nr_runs) ? vzfs->mt_nr_pages_at(msst, i) * PGSZ : cpart->newsz;
    const float pct = ((float)sz) * 100.0f / (float)(z->cfg.max_pages * PGSZ);
    logger_printf("%c[%c%x] sz %9lu %6.2f%% wx %6lu wy %6lu nrun1 %4.1f wa %4.1f bonus %4.1f score %5.2f\n",
        (i == bestrun ? '>':' '), (i == nr_runs ? '*' : ' '), i,
        sz, pct, f[i].wx, f[i].wy, f[i].nrun1, f[i].wa, f[i].bonus, f[i].score);
  }

  logger_printf("%s magic0 %lu totkv0 %u valid0 %u newnr %lu newsz %lu minor %.1f major %.1f bestrun %u ratio %.3f\n",
      __func__, vzfs->y_get_magic(msst), stats.totkv, stats.valid,
      newnr, cpart->newsz, f[nr_runs].nrun1, f[0].nrun1, bestrun, cpart->ratio);
  return bestrun;
}

// bestrun:
// 0: major, rewrite everything
// < nrun0 (nrun0 < MSST_NR_RUNS): partial, rewrite a few tables
// == nrun0: minor, no rewritting
// == MSST_NR_RUNS: store-append: the last partition and new data > existing keys
  static u64
msstz_comp_analyze(struct msstz_comp_info * const ci, const u64 ipart)
{
  const u64 t0 = time_nsec();
  const struct msstv * const v0 = ci->v0;
  // struct msstv_part * const part = &(ci->v0->es[ipart]);
  const void * const msst = msstv_get_msst(v0, ipart);
  // k0 kz
  const struct kv * const k0 = msstv_get_anchor(v0, ipart);
  debug_assert(k0);
  // kz == NULL for the last partition
  const struct kv * const kz = msstv_get_kz(v0, ipart);
  const struct kvmap_api * const api = ci->api1;
  void * const map = ci->map1;
  struct msst_stats stats;
  vzfs->mt_stats(msst, &stats);

  void * const ref = kvmap_ref(api, map);
  void * const iter = api->iter_create(ref);
  u64 newsz = 0;
  u64 newnr = 0;
  struct kv * kz_inp = NULL;
  if (kz) { // not the last partition; search where to stop
    struct kref krefz = {.ptr = kz->kv, .len = kz->klen, .hash32 = kv_crc32c(kz->kv, kz->klen)};
    api->iter_seek(iter, &krefz);
    api->iter_inp(iter, kvmap_inp_steal_kv, &kz_inp);
  }

  // check if new key has no overlap
  struct kv * const sst_kz = vzfs->y_last_key(msst, NULL); // free soon
  struct kv * map_k0 = NULL;

  // start from k0
  struct kref kref0 = {.ptr = k0->kv, .len = k0->klen, .hash32 = kv_crc32c(k0->kv, k0->klen)};
  api->iter_seek(iter, &kref0);
  api->iter_inp(iter, kvmap_inp_steal_kv, &map_k0);
  const bool overlap = sst_kz && map_k0 && (kv_compare(sst_kz, map_k0) >= 0);
  free(sst_kz);

  const u32 sample_skip = 8;
  const u32 sample_mask = sample_skip-1;
  while (api->iter_valid(iter)) {
    struct kv * kv_inp = NULL;
    api->iter_inp(iter, kvmap_inp_steal_kv, &kv_inp);
    if (kv_inp == kz_inp)
      break;
    if ((newnr & sample_mask) == 0)
      newsz += (sst_kv_vi128_estimate(kv_inp) + sizeof(u16));

    newnr++;
    api->iter_skip1(iter);
  }
  newsz *= sample_skip;
  api->iter_destroy(iter);
  kvmap_unref(api, ref);

  struct msstz_comp_part * const cpart = &(ci->parts[ipart]);
  cpart->newsz = newsz;

  // const struct ssty_meta * const meta = msst->ssty->meta;
  const u32 nr_runs = stats.nr_runs;

  struct msstz * const z = ci->z;
  // MAJOR: no existing data at all
  if (stats.valid == 0) { // this also avoids divide-by-zero below
    cpart->ratio = (float)newsz;
    cpart->bestrun = 0;
    logger_printf("%s newsz %lu direct-major\n", __func__, newsz);
    return time_diff_nsec(t0);
  }

  // REJECT empty input
  if (newnr == 0) {
    cpart->ratio = 0.0f;
    cpart->bestrun = z->cfg.major_trigger; // reject
    return time_diff_nsec(t0);
  }

  const u64 runsz = msstz_comp_runsz(z);
  // APPEND: not too small, store-wide append, partition has some data
  if (!overlap && !kz && nr_runs > 1 && newsz > runsz) {
    cpart->ratio = (float)newsz; // worth doing
    cpart->bestrun = MSST_NR_RUNS;
    logger_printf("%s newsz %lu store-append\n", __func__, newsz);
    return time_diff_nsec(t0);
  }

  debug_assert(stats.totsz && newsz);
  cpart->ratio = (float)newsz / (float)(stats.totsz);
  cpart->bestrun = msstz_comp_bestrun(cpart, msst, z, newnr); // bestrun is determined

  return time_diff_nsec(t0);
}

  static void *
msstz_analyze_worker(void * const ptr)
{
  struct msstz_comp_info * const ci = (typeof(ci))ptr;
  const u64 n = msstv_get_nr(ci->v0);
  do {
    const u64 i = ci->seqx++;
    if (i == 0)
      msstz_gc(ci->z);
    if (i >= n)
      return NULL;

    ci->parts[i].idx = i; // assign idx
    ci->time_analyze += msstz_comp_analyze(ci, i);
    ci->totsz += ci->parts[i].newsz;
  } while (true);
}
// }}} analyze

// part {{{
// do compaction in a partition; bestrun decides what to do
  static u64
msstz_comp_part(struct msstz_comp_info * const ci, const u64 ipart)
{
  const u64 t0 = time_nsec();
  struct msstz * const z = ci->z;
  const struct msstv * const v0 = ci->v0;
  void * const mssty0 = msstv_get_msst(v0, ipart);
  struct msstz_comp_part * const cpart = &(ci->parts[ipart]);
  const struct kv * const k0 = msstv_get_anchor(v0, ipart);
  debug_assert(k0);

  struct msst_stats stats;
  vzfs->mt_stats(mssty0, &stats);
  const u64 magic0 = k0->priv;
  const u64 seq0 = magic0 / 100lu; // seq of the old partition
  const u32 nrun0 = stats.nr_runs; // seq of the old partition

  if (cpart->bestrun == z->cfg.major_trigger) {
    // marked as rejected by msstz_comp()
    // reject: send to yqueue as completed; use seq = UINT64_MAX for real rejections or seq0 for newsz == 0
    msstz_yq_append(ci->yq, mssty0, cpart->newsz ? UINT64_MAX : seq0, nrun0, NULL, 0, ipart, 0, k0, NULL, 0, "major");
    // {y0, seq, ipart, k0} will be used later
    ci->nx++;
    return 0;
  }

  const u32 bestrun = cpart->bestrun;
  const bool is_append = (bestrun == MSST_NR_RUNS);
  const bool is_minor = (bestrun == nrun0);
  const bool is_major = (bestrun == 0);

  debug_assert(bestrun < z->cfg.major_trigger || is_append);
  // k0 kz
  // kz == NULL for the last partition
  const struct kv * const kz = msstv_get_kz(v0, ipart);

  // need a new seq unless it's a minor compaction
  // start with a different seq unless it's a minor compaction
  const u64 seq1 = (is_minor || is_append) ? seq0 : (z->seq++);

  struct miter * const miter = miter_create();

  char comp_str[8];
  if (is_append) {
    sprintf(comp_str, "append");
    ci->stat_append++;
  } else if (is_minor) {
    sprintf(comp_str, "minor");
    ci->stat_minor++;
  } else {
    // major or partial
    // hard link unchanged files
    msstz_comp_link(z->dfd, seq0, seq1, bestrun);
    if (is_major) { // full
      vzfs->y_miter_major(mssty0, miter);
      ci->stat_major++;
      sprintf(comp_str, "major");
    } else { // partial
      vzfs->y_miter_partial(mssty0, miter, bestrun);
      ci->stat_partial++;
      sprintf(comp_str, "partial");
    }
  }

  // add the memtable
  miter_add(miter, ci->api1, ci->map1);
  struct kref kref0 = {.ptr = k0->kv, .len = k0->klen, .hash32 = kv_crc32c(k0->kv, k0->klen)};
  miter_seek(miter, &kref0);

  const u32 comprun = is_append ? nrun0 : bestrun;
  // allow split (and gc tombstones) when: major or append
  const bool split = is_major || is_append;
  msstz_comp_ssts(ci, ipart, miter, k0, kz, seq1, comprun, split, mssty0, is_append, comp_str);
  miter_destroy(miter);
  ci->nx++; // done with one partition's x
  return time_diff_nsec(t0);
}
// }}} part

// driver {{{
  static void
msstz_comp_worker_func(struct msstz_comp_info * const ci)
{
  const u64 n = msstv_get_nr(ci->v0);
  struct coq * const coq = coq_current();
  // x loop
  do {
    const u64 i = ci->seqx++;
    if (i >= n)
      break;

    ci->time_comp_x += msstz_comp_part(ci, i);

    const u64 t0 = time_nsec();
    if (msstz_yq_consume(ci))
      ci->time_comp_y += time_diff_nsec(t0);
  } while (true);

  // process all ssty_build
  struct msstz_yq * const yq = ci->yq;
  while ((ci->nx < ci->n0) || (yq->cseq < yq->pseq)) {
    const u64 t0 = time_nsec();
    const bool r = msstz_yq_consume(ci);
    if (r) {
      ci->time_comp_y += time_diff_nsec(t0);
    } else if (coq) {
      coq_idle(coq);
    } else {
      usleep(1);
    }
  }
}

  static void
msstz_comp_worker_coq_co(void)
{
  void * const priv = co_priv();
  debug_assert(priv);
  msstz_comp_worker_func(priv);
}

// thread
  static void *
msstz_comp_worker(void * const ptr)
{
  // TODO: maybe get back this stats
  // ssty_build_ckeys_reads = 0;
  rcache_thread_stat_reset();
  struct msstz_comp_info * const ci = (typeof(ci))ptr;
  const u32 nco = ci->co_per_worker;
  if (nco > 1) {
    struct coq * const coq = coq_create_auto(nco << 1);
    coq_install(coq);
    u64 hostrsp = 0;
    for (u64 i = 0; i < nco; i++) {
      struct co * const co = co_create(PGSZ * 7, msstz_comp_worker_coq_co, ptr, &hostrsp);
      corq_enqueue(coq, co);
    }
    coq_run(coq);
    coq_uninstall();
    coq_destroy_auto(coq);
  } else {
    msstz_comp_worker_func(ci);
  }
  // ci->stat_reads += ssty_build_ckeys_reads;
  ci->stat_reads += (rcache_thread_stat_reads() * PGSZ);
  return NULL;
}

// for sorting tasks based on their sizes
  static int
msstz_cmp_ratio(const void * p1, const void * p2)
{
  const float r1 = ((const struct msstz_comp_part *)p1)->ratio;
  const float r2 = ((const struct msstz_comp_part *)p2)->ratio;
  debug_assert(isfinite(r1));
  debug_assert(isfinite(r2));
  if (r1 < r2) {
    return -1;
  } else if (r1 > r2) {
    return 1;
  } else {
    return 0;
  }
}

  static int
msstz_cmp_idx(const void * p1, const void * p2)
{
  const u64 * const v1 = &(((const struct msstz_comp_part *)p1)->idx);
  const u64 * const v2 = &(((const struct msstz_comp_part *)p2)->idx);
  return compare_u64(v1, v2);
}

  static u64
msstz_comp_reject(struct msstz_comp_info * const ci, const u64 max_reject)
{
  const u64 nr = msstv_get_nr(ci->v0);
  qsort(ci->parts, nr, sizeof(ci->parts[0]), msstz_cmp_ratio);

  // reject keys
  u64 rejsz = 0;
  u64 nrej = 0;
  struct msstz * const z = ci->z;
  const u64 size_accept = PGSZ * z->cfg.pages_accept;
  logger_printf("%s ratio min %.3f max %.3f\n", __func__, ci->parts[0].ratio, ci->parts[nr-1].ratio);
  for (u64 i = 0; i < nr; i++) {
    struct msstz_comp_part * const cp = &(ci->parts[i]);
    // no more rejections
    if ((cp->newsz > size_accept) || ((rejsz + cp->newsz) > max_reject) || cp->ratio > 0.1f) {
      logger_printf("%s i %lu/%lu (newsz %lu > %lu) || ((rejsz %lu + newsz %lu) > max_reject %lu) || (ratio %.3f > 0.1)\n",
          __func__, i, nr, cp->newsz, size_accept, rejsz, cp->newsz, max_reject, cp->ratio);
      break;
    }
    rejsz += cp->newsz;
    nrej++;
    cp->bestrun = z->cfg.major_trigger; // reject
  }
  logger_printf("%s reject size %lu/%lu np %lu/%lu\n", __func__, rejsz, ci->totsz, nrej, nr);

  // resume idx order
  qsort(ci->parts, nr, sizeof(ci->parts[0]), msstz_cmp_idx);
  return nrej;
}

  static void
msstz_comp_stat(struct msstz_comp_info * const ci)
{
  struct msstz * const z = ci->z;
  const u64 dt = time_diff_nsec(ci->t0);
  const u64 dw = ci->stat_writes;
  const u64 dr = ci->stat_reads;
  z->stat_time += dt;
  z->stat_writes += dw;
  z->stat_reads += dr;
  const u64 ta = ci->time_analyze;
  const u64 tx = ci->time_comp_x;
  const u64 ty = ci->time_comp_y;
  logger_printf("%s dt-s %.6lf dw-mb %lu mbps %lu dr-mb %lu mbps %lu append %lu major %lu partial %lu minor %lu\n",
      __func__, ((double)dt) * 1e-9, dw>>20, (dw<<10)/dt, dr>>20, (dr<<10)/dt,
      ci->stat_append, ci->stat_major, ci->stat_partial, ci->stat_minor);
  logger_printf("%s n0 %lu dta %lu/%lu %3lu%% dtc (%lu+%lu)/%lu %3lu%%\n",
      __func__, ci->n0, ta/1000000, ci->dta/1000000, ta*100lu/ci->dta,
      tx/1000000, ty/1000000, ci->dtc/1000000, (tx+ty)*100lu/ci->dtc);
}

// comp is not thread safe
// p_min_write: 0 to 100, minimum percentage of data that must be written down
  void
msstz_comp(struct msstz * const z, const struct kvmap_api * const api1, void * const map1,
    const u32 nr_workers, const u32 co_per_worker, const u64 max_reject)
{
  struct msstv * const v0 = msstz_getv(z);
  const u64 nr = msstv_get_nr(v0);
  struct msstz_comp_info * const ci = calloc(1, sizeof(*ci) + (nr * sizeof(ci->parts[0])));
  ci->t0 = time_nsec();
  ci->z = z;
  ci->v0 = v0;
  ci->n0 = nr;
  ci->api1 = api1;
  ci->map1 = map1;
  ci->nr_workers = nr_workers;
  ci->co_per_worker = co_per_worker;

  // concurrent analysis + GC by seq==0
  ci->dta = thread_fork_join(nr_workers, msstz_analyze_worker, false, ci);
  const u64 nrej = msstz_comp_reject(ci, max_reject);
  if (nrej < nr) {
    ci->seqx = 0; // restart from 0
    ci->yq = msstz_yq_create((nr + 64) << 3); // large enough for adding new partitions
    ci->dtc = thread_fork_join(nr_workers, msstz_comp_worker, false, ci);
    msstz_comp_harvest(ci);
    free(ci->yq);
  } else {
    ci->dtc = 1; // avoid divide by zero
  }

  msstz_putv(z, v0);
  msstz_comp_stat(ci);
  free(ci);
}
// }}} driver

// }}} msstz-comp

// vim:fdm=marker
