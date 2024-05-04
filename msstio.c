
#define _GNU_SOURCE

#include "lib.h"
#include "kv.h"
#include "wh.h"
#include "bt.h"
#include "sst.h"
#include "fs.h"

#include <getopt.h>

#define CONFIG_SIZE ((256))

u64 build_seed = 1;
u8 * levels1 = NULL;
u8 * levels2 = NULL;
u64 max_key_idx = 0;
u64 nr_insert = 0;
u64 nkv = 0;

struct msstio_meta {
  char * name;
  char * value;
};

static struct msstio_meta config[CONFIG_SIZE] = {
  {
    .name = NULL,
  },
};

  static void
config_put(const char * const name, const char * const value)
{
  u32 pos = 0;
  while (config[pos].name != NULL) {
    if (strcmp(name, config[pos].name) == 0) {
      // already exists
      free(config[pos].value);
      config[pos].value = strdup(value);
      return;
    }
    pos++;
  }

  config[pos].name = strdup(name);
  config[pos].value = strdup(value);

  config[pos+1].name = NULL;
}

  static void
config_put_bool(const char * const name, const bool val)
{
  if (val) {
    config_put(name, "true");
  } else {
    config_put(name, "false");
  }
}

  static void
config_put_u64(const char * const name, const u64 val)
{
  char buff[128];
  sprintf(buff, "%lu", val);
  config_put(name, buff);
}

  static void
config_put_double(const char * const name, const double val)
{
  char buff[128];
  sprintf(buff, "%f", val);
  config_put(name, buff);
}

  static void
config_put_u32(const char * const name, const u32 val)
{
  char buff[128];
  sprintf(buff, "%u", val);
  config_put(name, buff);
}

  static void
config_dump(const char * const fn)
{
  FILE * dump = fopen(fn, "w");

  u32 pos = 0;
  while (config[pos].name != NULL) {
    fprintf(dump, "%s = %s\n", config[pos].name, config[pos].value);
    pos++;
  }

  fclose(dump);
}

  static void
config_free()
{
  u32 pos = 0;
  while (config[pos].name != NULL) {
    free(config[pos].name);
    free(config[pos].value);
    pos++;
  }
}

struct runs_build_fs {
  char name[16];
  char name_x[16];
  char name_y[16];
  char name_y_dup[16];
  typeof(bt_build)* build_run_f;
  void * (*open_run_f)(const char * const, const u64, const u32);
  // set rcache for mbt and msst
  void (*set_rcache)(void *, struct rcache *);
  const struct kvmap_api * run_api;
  struct kv * (* run_last_key)(void *, struct kv *); // not in api

  void * (*x_open_f)(const char * const, const u64, const u32);
  const struct kvmap_api * x_api;
  typeof(remix_build)* y_build_f;

  void * (*y_open_f)(const char * const, const u64, const u32);
  const struct kvmap_api * y_api;
  struct kv * (* y_last_key)(void *, struct kv *); // not in api
  void (*y_dump)(void *, const char *);
};

struct test_info {
  char * dirname;
  struct rgen * rgen;
  char * rgen_str;
  struct runs_build_fs * fs;
  char * mode; // existing, non-existing, mixed
  u64 num_ops;
  u32 seq;
  u32 nway;
  u32 vlen;
  bool tags;
  bool dbits;
  bool is_empty;
  bool bt_bloom;
  bool leaf_bloom;
};

  static const char *
ok_str(const bool ok)
{
  return ok ? TERMCLR(32)"OK"TERMCLR(0) : TERMCLR(31)"ERROR?"TERMCLR(0);
}

  static void
set_value_tag(struct kv * const curr, void * const priv)
{
  *(u8 *)(kv_vptr(curr)) = *(u8 *)priv;
}

  static void
check_run(const char * const dirname, const u64 seq, const u32 way,
           const u32 nset, const u32 omitted, const struct kv * const end,
           const struct runs_build_fs * const fs)
{
  const u8 tag = ((u8)'A') + (u8)way;
  // check
  void * const run = fs->open_run_f(dirname, seq, way);
  debug_assert(run);
  // XXX: we know that sst/bt don't need ref/unref
  void * const iter = fs->run_api->iter_create(run);
  debug_assert(iter);
  fs->run_api->iter_seek(iter, kref_null());
  u32 nskip = 0;
  struct kvref kvref;
  while (fs->run_api->iter_valid(iter)) {
    fs->run_api->iter_kvref(iter, &kvref);
    // when tag equals to this way, this is skipped?
    // count how many keys in this sst has the tag
    // this kvref is from the sst, so the tag is actually copied
    if (kvref.vptr[0] == tag)
      nskip++;
    fs->run_api->iter_skip1(iter);
  }
  fs->run_api->iter_destroy(iter);

  // compare the number of keys in sst and the levels encoding
  u32 nprobe = 0;
  for (u64 i = 0; i < nkv; i++) {
    if ((levels1[i] == way) || (levels2[i] == way)) {
      const bool r = kvmap_kv_probe(fs->run_api, run, kvss[i]);
      // when probe is false, the key should be greater than end key
      debug_assert(r || kv_compare(kvss[i], end) >= 0);
      if (r)
        nprobe++;
      // indicating that some are not in the sst
      // by deduction, nprobe + omitted == nset,
      // omitted record the number of false probes
    }
  }
  debug_assert(omitted == 0); // might break sometime?
  const bool ok = (nset == (nskip + omitted)) && (nskip == nprobe);
  if (!ok) {
    fs->run_api->fprint(run, stdout);
    printf("run %lu %u nset %u found-by-skip %u found-by-probe %u omitted %u %s\n",
        seq, way, nset, nskip, nprobe, omitted, ok_str(ok));
  }
  fs->run_api->destroy(run);
}

  static u64
build_run(const char * const dirname, const u64 seq, const u32 way,
          const bool bt_bloom, const bool leaf_bloom,
          const struct runs_build_fs * const fs)
{
  // x_api is not actually x's api but api for building x
  const struct kvmap_api * const x_api = &kvmap_api_wormhole;
  struct wormhole * const map = wormhole_create(&kvmap_mm_ts);
  struct kv * const end = malloc(sizeof(*end) + PGSZ);
  debug_assert(map);

  // tag marks which run it belongs to
  u8 tag = ((u8)'A') + (u8)way; // const tag; omit const for inpw
  void * const ref = kvmap_ref(x_api, map);
  u32 nset = 0;
  for (u64 i = 0; i < nkv; i++) {
    // wenshao: if equal to either one of the levels put it to the sst
    if ((levels1[i] == way) || (levels2[i] == way)) {
      kvmap_kv_put(x_api, ref, kvss[i]);
      kvmap_kv_inpw(x_api, ref, kvss[i], set_value_tag, &tag);
      nset++;
    }
  }
  kvmap_unref(x_api, ref);
  struct miter * const miter = miter_create();
  debug_assert(miter);
  miter_add(miter, x_api, map);
  miter_seek(miter, kref_null());
  // gen sst
  const u64 tx0 = time_nsec();
  fs->build_run_f(dirname, miter, seq, way, 65500, false, (way & 1) == 0,
      bt_bloom, leaf_bloom, NULL, NULL);
  const u64 dtx0 = time_diff_nsec(tx0);
  if (miter_valid(miter))
    miter_peek(miter, end);
  // we are counting how many keys remaining
  // ideally there should not be any key remaining
  // just verifying
  u32 omitted = 0;
  while (miter_valid(miter)) {
    miter_skip1(miter);
    omitted++;
  }
  // nset - omitted is the number of keys in sst
  // nset is the number of keys in wormhole api
  // omitted should usually be zero
  if (omitted)
    printf(TERMCLR(35)"build-x dt %lu used %u omitted %u\n"TERMCLR(0), dtx0, nset - omitted, omitted);
  miter_destroy(miter);
  x_api->clean(map);
  x_api->destroy(map);

  check_run(dirname, seq, way, nset, omitted, end, fs);
  free(end);
  return nset;
}

  static void
mssty_check_seek_near(struct mssty_iter * const iter, const u32 nway)
{
  mssty_iter_seek(iter, kref_null());
  struct kv * const tmp = malloc(1 << 17);
  u64 x = 0;
  u64 lt = 0;
  u64 eq = 0;
  u64 gt = 0;
  while (x < nkv) {
    const bool hit = (levels1[x] < nway) || (levels2[x] < nway);
    const struct kref kref = kv_kref(kvss[x]);
    mssty_iter_seek_near(iter, &kref, random_u64() & 1);
    if (mssty_iter_valid(iter)) {
      struct kv * const ret = mssty_iter_peek(iter, tmp);
      const int cmp = kv_compare(kvss[x], ret);
      if (cmp < 0) {
        if (hit) {
          printf("should hit at %lu but seek to > key (this can be false alarm with omitted keys)\n", x);
          kv_print(ret, "sn", stdout);
          kv_print(kvss[x], "sn", stdout);
          break;
        }
        lt++;
      } else if (cmp == 0) {
        if (!hit) {
          printf("BUG! should mismatch at %lu but seek to == key\n", x);
          kv_print(ret, "sn", stdout);
          kv_print(kvss[x], "sn", stdout);
          break;
        }
        eq++;
      } else {
        gt++;
      }
    } else {
      printf("seek_near: iter became invalid at %lu/%lu\n", x, nkv);
      kv_print(kvss[x], "sn", stdout);
      break;
    }
    x += (random_u64() & 0x3f);
  }
  printf("check_seek_near done: %lu %lu %lu==0 last:\n", lt, eq, gt);
  free(tmp);
}

// only checks y but not x
  static void
check_tables(const char * const dirname, const u64 seq, const u32 nway,
        const u64 uniq, const bool is_empty, const struct runs_build_fs * const fs)
{
  // check y
  const u64 magic = seq * 100lu + nway;
  struct kv * const tmp = malloc(1 << 17);
  tmp->hash = 0;

  // use the y api to open it
  const struct kvmap_api * const y_api = fs->y_api;
  struct msst * const y_map = fs->y_open_f(dirname, magic/100lu, (u32)(magic%100lu));
  debug_assert(y_map);

  void * const ref = kvmap_ref(y_api, y_map);
  struct mssty_iter * const iter = y_api->iter_create(ref);
  u64 y_found = 0;
  kvmap_kv_iter_seek(y_api, iter, kv_null());
  while (y_api->iter_valid(iter)) {
    (void)y_api->iter_next(iter, tmp);
    y_found++;
  }
  // uniq is the total set, how are omitted keys included here?
  // it seems like if omitted != 0 uniq != y_found
  printf("found in y scanned=%lu %s\n",
          y_found, ok_str(uniq == y_found));

  if (y_found) {
    struct kv * const last = fs->y_last_key(y_map, NULL);
    const bool last_match = kv_match(tmp, last);
    // assume the last keys from api and the scan be the same
    if (!last_match) {
      kv_print(tmp, "xn", stdout);
      kv_print(last, "xn", stdout);
    }
    free(last);
    // seek near (mssty only)
    if (fs->y_api == &kvmap_api_mssty)
      mssty_check_seek_near(iter, nway);
  } else if (!is_empty) {
    printf("check mssty %lu: empty\n", magic);
  }

  y_api->iter_destroy(iter);
  kvmap_unref(y_api, ref);

  // dump
  char dumpname[128];
  sprintf(dumpname, "%s/%lu.m%sy.txt", dirname, magic, fs->name);
  fs->y_dump(y_map, dumpname);
  y_api->destroy(y_map);
  free(tmp);
}

// put inserted keys to the front
// so inserted key should be smaller
  static struct kv **
kv_sort_on_inserted(const u32 nway)
{
  struct kv ** kvtt = malloc(nkv * sizeof(*kvtt));
  u64 idx = 0;
  for (u64 i = 0; i < nkv; i++) {
    if ((levels1[i] < nway) || (levels2[i] < nway)) {
      // inserted keys
      kvtt[idx++] = kvss[i];
    }
  }

  debug_assert(idx == nr_insert);
  shuffle_u64((u64 *)kvtt, idx);

  struct kv ** not_inserted = kvtt + nr_insert;

  for (u64 i = 0; i < nkv; i++) {
    if ((levels1[i] >= nway) && (levels2[i] >= nway)) {
      kvtt[idx++] = kvss[i];
    }
  }

  debug_assert(idx == nkv);
  shuffle_u64((u64 *)not_inserted, nkv - nr_insert);

  return kvtt;
}

// build the sst and indexes, and check the correctness
// build x
  static void
build_tables(const char * const dirname, const u64 seq, const u32 nway,
        const u32 vlen, const bool tags, const bool dbits,
        const bool is_empty, const bool bt_bloom, const bool leaf_bloom,
        const struct runs_build_fs * const fs)
{
  srandom_u64(build_seed);
  u64 totset = 0;
  u64 uniq = 0;
  nr_insert = 0;
  max_key_idx = nkv; // invalid
  for (u64 i = 0; i < nkv; i++) {
    // wenshao: if either levels is smaller than nway,
    // the key is actually inserted and unique
    levels1[i] = (u8)(random_u64() % (nway * 2));
    levels2[i] = (u8)(random_u64() % (nway * 2));
    if ((levels1[i] < nway) || (levels2[i] < nway)) {
      max_key_idx = i;
      uniq++;
      nr_insert++;
    }

    kvss[i]->vlen = vlen;
  }

  // build all ssts
  for (u32 way = 0; way < nway; way++) {
    totset += build_run(dirname, seq, way, bt_bloom, leaf_bloom, fs);
  }

  // after building each sst, now open it as msst
  void * const msst = fs->x_open_f(dirname, seq, nway);
  debug_assert(msst);
  // build ssty
  // the remix index
  const u64 ty0 = time_nsec();
  if (fs->y_build_f)
    fs->y_build_f(dirname, msst, seq, nway, NULL, 0, tags, dbits, true, NULL, 0);
  const u64 dty0 = time_diff_nsec(ty0);

  fs->x_api->destroy(msst);

  printf(TERMCLR(33)"%s %s dt %lu seq=%lu nway=%u uniq=%lu totset=%lu dup=%lu, nkv=%lu\n"TERMCLR(0),
      fs->name, __func__, dty0, seq, nway, uniq, totset, totset - uniq, nkv);

  if (fs->y_open_f)
    check_tables(dirname, seq, nway, uniq, is_empty, fs);
  // TODO: add more checks
}

  static struct rgen *
rgen_new(const char * const rgen_str, const u64 max)
{
  struct rgen * rgen = NULL;
  if (rgen_str == NULL) {
    fprintf(stderr, "Required option -r <rgen_str>\n");
    exit(1);
  } else if (strcmp(rgen_str, "unizipf") == 0) {
    rgen = rgen_new_unizipf(0, max, 100);
  } else if (strcmp(rgen_str, "uniform") == 0) {
    rgen = rgen_new_uniform(0, max);
  } else if (strcmp(rgen_str, "zipfian") == 0) {
    rgen = rgen_new_zipfian(0, max);
  } else {
    fprintf(stderr, "rgen %s not supported\n", rgen_str);
    exit(1);
  }
  return rgen;
}

  static double
do_point_search(const struct kvmap_api * const api,
    void * const map, const u64 nway,
    const char * const rgen_str, struct rgen * const rgen,
    const bool probe_only, const u64 num_ops, const char * const mode)
{
  struct rgen * rgen1 = NULL;
  struct kv ** kvs = NULL;

  struct kv ** to_free = NULL;
  struct rgen * rgen_to_free = NULL;

  if (strcmp(mode, "mixed") == 0) {
    rgen1 = rgen;
    kvs = kvss;
    shuffle_u64((u64 *)kvs, nkv);
  } else {
    kvs = kv_sort_on_inserted(nway);
    to_free = kvs;
    u64 nr = 0;
    if (strcmp(mode, "existing") == 0) {
      nr = nr_insert;
      // sort kvtt and initialize rgen1 to select existing keys
    } else if (strcmp(mode, "non-existing") == 0) {
      nr = nkv - nr_insert;
      kvs += nr_insert;
    } else {
      fprintf(stderr, "No appropriate rgen given\n");
      return 0.0;
    }

    rgen1 = rgen_new(rgen_str, nr-1);
    rgen_to_free = rgen1;
  }
  debug_assert(rgen1 != NULL);

  void * const ref = kvmap_ref(api, map);
  struct kv * const tmp = malloc(1 << 20);

  config_put_bool("probe_only", probe_only);
  config_put_u64("num_ops", num_ops);
  config_put_u64("nkv", nkv);

  const u64 t0 = time_nsec();

  for (u64 i = 0; i < num_ops; i++) {
    const u64 idx = rgen_next(rgen1);
    if (probe_only) {
      bool e = kvmap_kv_probe(api, ref, kvs[idx]);
      if (strcmp(mode, "existing") == 0) {
        debug_assert(e == true);
      } else if (strcmp(mode, "non-existing") == 0) {
        debug_assert(e == false);
      }
    } else {
      kvmap_kv_get(api, ref, kvs[idx], tmp);
    }
  }
  const u64 dt = time_diff_nsec(t0);
  const double mops = ((double)num_ops) * 1e3 / ((double)dt);
  if (probe_only) {
    printf(" probe %.3lf\n", mops);
  } else {
    printf(" get %.3lf\n", mops);
  }

  if (to_free != NULL) {
    free(to_free);
  }

  if (rgen_to_free != NULL) {
    free(rgen_to_free);
  }
  free(tmp);
  kvmap_unref(api, ref);
  return mops;
}

  static double
do_range_search(const struct kvmap_api * const api,
    void * const map, const u64 nway, struct rgen * const rgen,
    const char * const mode, const char * const rgen_str,
    const u32 nskip, const u32 nnext, const bool peek, const u64 num_ops)
{
  struct rgen * rgen1 = NULL;
  struct kv ** kvs = NULL;

  struct kv ** to_free = NULL;
  struct rgen * rgen_to_free = NULL;

  void * const ref = kvmap_ref(api, map);
  void * const iter = api->iter_create(ref);
  struct kv * const tmp = malloc(1 << 20);

  config_put_u32("nskip", nskip);
  config_put_u32("nnext", nnext);
  config_put_bool("peek", peek);
  config_put_u64("num_ops", num_ops);
  config_put_u64("nkv", nkv);

  if (strcmp(mode, "mixed") == 0) {
    rgen1 = rgen;
    kvs = kvss;
    shuffle_u64((u64 *)kvs, nkv);
  } else {
    kvs = kv_sort_on_inserted(nway);
    to_free = kvs;
    u64 nr = 0;
    if (strcmp(mode, "existing") == 0) {
      nr = nr_insert;
      // sort kvtt and initialize rgen1 to select existing keys
    } else if (strcmp(mode, "non-existing") == 0) {
      nr = nkv - nr_insert;
      kvs += nr_insert;
    } else {
      fprintf(stderr, "No appropriate rgen given\n");
      return 0.0;
    }

    rgen1 = rgen_new(rgen_str, nr-1);
    rgen_to_free = rgen1;
  }

  const u64 t0 = time_nsec();
  debug_perf_switch();
  for (u64 i = 0; i < num_ops; i++) {
    // cpu_prefetch0(kvss[i+1]);
    // cpu_prefetch0(((const u8 *)kvss[i+1])+64);
    const u64 idx = rgen_next(rgen);
    kvmap_kv_iter_seek(api, iter, kvss[idx]);
    if (nnext) { // nnext > 0: do next
      for (u32 j = 0; j < nnext; j++)
        api->iter_next(iter, tmp);
    } else if (nskip) { // nnext == 0: do skip and peek
      api->iter_skip(iter, nskip);
      api->iter_peek(iter, tmp);
    } else if (peek) {
      api->iter_peek(iter, tmp);
    }
    // both are zero, and do peek do a pure seek
  }
  const u64 dt = time_diff_nsec(t0);
  const double mops = ((double)num_ops) * 1e3 / ((double)dt);
  if (nnext)
    printf(" seek-next%u %.3lf\n", nnext, mops);
  else
    printf(" seek-skip%u-peek %.3lf\n", nskip, mops);

  if (to_free != NULL) {
    free(to_free);
  }

  if (rgen_to_free != NULL) {
    free(rgen_to_free);
  }
  free(tmp);
  api->iter_destroy(iter);
  kvmap_unref(api, ref);
  return mops;
}

  static void
test_probe_io(char * const dirname, char * const api_str,
    const u64 seq, const u32 nway, const u64 num_ops,
    const char * const mode, const char * const rgen_str,
    struct rgen * const rgen, const struct runs_build_fs * const fs)
{
  config_put("operation", "probe");
  printf(TERMCLR(35)"%s %s magic=%lu%02u nkv=%lu\n"TERMCLR(0),
      __func__, api_str, seq, nway, nkv);
  char buf1[10];
  char buf2[10];
  sprintf(buf1, "%lu", seq);
  sprintf(buf2, "%u", nway);
  // should new an api with rcache
  char * argv[5] = {"api", api_str, dirname, buf1, buf2};
  const struct kvmap_api * api = NULL;
  void * map = NULL;
  // mm is ignored by msstx/mssty
  kvmap_api_helper(5, argv, NULL, &api, &map);
  debug_assert(api);
  debug_assert(map);

  srandom_u64(time_nsec());

  struct rcache * rc = rcache_create(256, 12);

  // use tiemstamp for the dump filename
  char buff[512];
  char ts[64];
  time_stamp2(ts, 64);
  sprintf(buff, "rcache-%s.trace", ts);
  rcache_set_dump_file(rc, buff);

  config_put("trace_file", buff);

  fs->set_rcache(map, rc);

  double mops = 0;
  const bool probe_only = true;
  mops = do_point_search(api, map, nway, rgen_str, rgen, probe_only, num_ops, mode);
  config_put_double("mops", mops);

  api->destroy(map);

  rcache_destroy(rc);
  sprintf(buff, "rcache-%s.meta", ts);
  config_dump(buff);
}

  static void
test_seek_io(char * const dirname, char * const api_str,
    const u64 seq, const u32 nway, const u64 num_ops,
    const char * const mode, const char * const rgen_str,
    const bool dbits, struct rgen * const rgen,
    const struct runs_build_fs * const fs)
{
  config_put("operation", "seek");
  // first build it without rcache
  // then run read workload with rcache and the trace
  printf(TERMCLR(35)"%s %s magic=%lu%02u nkv=%lu\n"TERMCLR(0),
      __func__, api_str, seq, nway, nkv);
  char buf1[10];
  char buf2[10];
  sprintf(buf1, "%lu", seq);
  sprintf(buf2, "%u", nway);
  // should new an api with rcache
  char * argv[5] = {"api", api_str, dirname, buf1, buf2};
  const struct kvmap_api * api = NULL;
  void * map = NULL;
  // mm is ignored by msstx/mssty
  kvmap_api_helper(5, argv, NULL, &api, &map);
  debug_assert(api);
  debug_assert(map);

  srandom_u64(time_nsec());

  config_put("fs_name", fs->name);
  config_put_u64("seq", seq);
  config_put_u32("nway", nway);
  config_put_bool("dbits", dbits);

  struct rcache * rc = rcache_create(256, 12);

  // use tiemstamp for the dump filename
  char buff[512];
  char ts[64];
  time_stamp2(ts, 64);
  sprintf(buff, "rcache-%s.trace", ts);
  rcache_set_dump_file(rc, buff);

  config_put("trace_file", buff);

  fs->set_rcache(map, rc);

  // pure seek
  double mops = 0;
  mops = do_range_search(api, map, nway, rgen, mode, rgen_str, 0, 0, false, num_ops);
  config_put_double("mops", mops);
  // We don't care about long range queries for now.
  // They (w/ w/o dbits) will be pretty similar since long range queries
  // need to access almost all runs. We might need special techniques.
  // seek + 50 skips
  // do_range_search(api, map, nway, rgen, mode, rgen_str, 50, 0, false, num_ops);
  // seek + 50 nexts
  // do_range_search(api, map, nway, rgen, mode, rgen_str, 0, 50, false, num_ops);

  const u32 xpages = mbtx_nr_pages(map);
  const u32 totpages = mbty_nr_pages(map);
  printf("x pages %u remix pages %u\n", xpages, totpages - xpages);

  config_put_u32("xpages", xpages);
  config_put_u32("totpages", totpages);

  api->destroy(map);

  rcache_destroy(rc);

  sprintf(buff, "rcache-%s.meta", ts);
  config_dump(buff);
}

// new bt* no remix I/O
struct runs_build_fs bt_fs_test = {
  .name = "bt",
  .name_x = "mbtx",
  .name_y = "mbty",
  .name_y_dup = "mbty_dup",
  .build_run_f = bt_build,
  .open_run_f = (void *)bt_open,
  .set_rcache = (void *)mbtx_rcache,
  .run_api = &kvmap_api_bt,
  .run_last_key = (void *)bt_last_key,
  .x_open_f = (void *)mbtx_open,
  .x_api = &kvmap_api_mbtx,
  .y_build_f = (void *)remix_build,
  .y_open_f = (void *)mbty_open,
  .y_api = &kvmap_api_mbty,
  .y_last_key = (void *)mbty_last_key,
  .y_dump = (void *)mbty_dump,
};

// new bt, rcache includes remix's I/O*
struct runs_build_fs bt_rc_fs = {
  .name = "bt_rc",
  .name_x = "mbtx",
  .name_y = "mbty",
  .name_y_dup = "mbty_dup",
  .build_run_f = bt_build,
  .open_run_f = (void *)bt_open,
  .set_rcache = (void *)mbty_rcache,
  .run_api = &kvmap_api_bt,
  .run_last_key = (void *)bt_last_key,
  .x_open_f = (void *)mbtx_open,
  .x_api = &kvmap_api_mbtx,
  .y_build_f = (void *)remix_build,
  .y_open_f = (void *)mbty_open,
  .y_api = &kvmap_api_mbty,
  .y_last_key = (void *)mbty_last_key,
  .y_dump = (void *)mbty_dump,
};

// multiple table index
struct runs_build_fs mbtx_fs = {
  .name = "mbtx",
  .name_x = "mbtx",
  .name_y = "mbtx",
  .name_y_dup = "mbtx_dup", // this is invalid
  .build_run_f = bt_build,
  .open_run_f = (void *)bt_open,
  .set_rcache = (void *)mbtx_rcache,
  .run_api = &kvmap_api_bt,
  .run_last_key = (void *)bt_last_key,
  .x_open_f = (void *)mbtx_open,
  .x_api = &kvmap_api_mbtx,
  .y_build_f = NULL,
  .y_open_f = NULL,
  .y_api = NULL,
  .y_last_key = NULL,
  .y_dump = NULL,
};

// old sst*
struct runs_build_fs sst_fs_test = {
  .name = "sst",
  .name_x = "msstx",
  .name_y = "mssty",
  .name_y_dup = "mssty_dup",
  .build_run_f = sst_build,
  .open_run_f = (void *)sst_open,
  .set_rcache = (void *)msst_rcache,
  .run_api = &kvmap_api_sst,
  .run_last_key = (void *)sst_last_key,
  .x_open_f = (void *)msstx_open,
  .x_api = &kvmap_api_msstx,
  .y_build_f = (void *)ssty_build,
  .y_open_f = (void *)mssty_open,
  .y_api = &kvmap_api_mssty,
  .y_last_key = (void *)mssty_last_key,
  .y_dump = (void *)mssty_dump,
};

  static void
build_and_test(struct test_info * ti)
{
  build_tables(ti->dirname, ti->nway, ti->nway, ti->vlen, ti->tags,
      ti->dbits, ti->is_empty, ti->bt_bloom, ti->leaf_bloom, ti->fs);

  config_put("dirname", ti->dirname);
  config_put("fs_name", ti->fs->name);
  config_put("fs_name_x", ti->fs->name_x);
  config_put("fs_name_y", ti->fs->name_y);
  // fs
  config_put_u64("num_ops", ti->num_ops);
  config_put_u64("seq", ti->seq);
  config_put_u32("nway", ti->nway);
  config_put_u32("vlen", ti->vlen);
  config_put_bool("tags", ti->tags);
  config_put_bool("dbits", ti->dbits);
  config_put_bool("is_empty", ti->is_empty);
  config_put_bool("bt_bloom", ti->bt_bloom);
  config_put_bool("leaf_bloom", ti->leaf_bloom);
  config_put("mode", ti->mode);

  test_probe_io(ti->dirname, ti->fs->name_y, ti->nway, ti->nway,
      ti->num_ops, ti->mode, ti->rgen_str, ti->rgen, ti->fs);
  test_seek_io(ti->dirname, ti->fs->name_y, ti->nway, ti->nway,
      ti->num_ops, ti->mode, ti->rgen_str, ti->dbits, ti->rgen, ti->fs);
}

// a few variables: range, nrkv, nkv, nops
// nrkv is inherent in the KV file
// range is set for the actual dataset size
// nkv seems to have the same semantics
// nops should control how many operations / how long we run
// only do the range query and collect I/O traces from rcache
  int
main(int argc, char ** argv)
{
  if (argc <= 1) {
    fprintf(stderr, "Usage: -k <keyfile> -v <vlen> -r <rgen_str> -n <nkv> -m <mode> -q <num_operations>\n");
    exit(1);
  }

  int * vlens = malloc(32 * sizeof(*vlens));
  for (int i = 0; i < 32; i++)
    vlens[i] = -1;

  char * rgen_str = NULL;
  struct rgen * rgen = NULL;

  int opt;
  u64 num_ops = 0;
  char * mode = NULL;
  while ((opt = getopt(argc, argv, "k:v:r:n:m:q:")) != -1) {
    switch (opt) {
      case 'k':
        if (kv_load(optarg) == false) {
          fprintf(stderr, "Key file %s load error\n", optarg);
          exit(1);
        }
        nkv = kvnr;
        char * bname = basename(optarg);
        config_put("key_file", bname);
        break;
      case 'v':
        {
          char * values = optarg;
          u32 i = 0;
          printf("value lengths: ");
          for (i = 0, values = optarg; ; i++, values = NULL) {
            char * value = strtok(values, ",");
            if (value == NULL || i >= 32)
              break;

            const u32 vlen = a2u32(value);
            const u32 vlen1 = vlen < sizeof(u8) ? sizeof(u8) : vlen;
            vlens[i] = vlen1;
            printf("%u ", vlen1);
          }
          printf("\n");
          break;
        }
      case 'r':
        rgen_str = strdup(optarg);
        break;
      case 'n':
        nkv = a2u64(optarg);
        if (nkv > kvnr) {
          printf("nkv force to be %lu\n", kvnr);
          nkv = kvnr;
        }
        break;
      case 'm':
        mode = strdup(optarg);
        break;
      case 'q':
        num_ops = a2u64(optarg);
        break;
      default:
        fprintf(stderr, "Unknown argument\n");
        exit(1);
        break;
    }
  }

  if (kvss == NULL) {
    fprintf(stderr, "Required option -k <key file>\n");
    exit(1);
  }

  shuffle_u64((u64 *)kvss, kvnr);

  if (vlens[0] < 0) {
    fprintf(stderr, "Required option -v <value lengths>\n");
    exit(1);
  }

  if (mode == NULL) {
    mode = strdup("mixed");
  }

  rgen = rgen_new(rgen_str, nkv-1);
  config_put("rgen", rgen_str);

  levels1 = malloc(nkv);
  levels2 = malloc(nkv);
  char dirname[256];
  sprintf(dirname, "/tmp/mssttest-%s", getlogin());
  mkdir(dirname, 00777);
  const u32 maxnway = 16;

  build_seed = time_nsec();
  printf("build_seed %lu\n", build_seed);


  // const u32 vlens[] = {100, 125, 250, 500, 1000, 2000, 4000};
  for (u32 i = 0; vlens[i] >= 0; i++) {
    for (u32 nway = 1; nway <= maxnway; nway <<= 1) {
      struct test_info ti = {
        .dirname  = dirname,
        .rgen     = rgen,
        .rgen_str = rgen_str,
        .fs       = &bt_rc_fs,
        .mode     = mode,
        .seq      = nway,
        .nway     = nway,
        .num_ops  = num_ops,
        .vlen      = vlens[i],
        .tags       = false,
        .dbits      = false,
        .is_empty   = false,
        .bt_bloom   = false,
        .leaf_bloom = false,
      };
      // compare the I/O of bloom filters and dbits, and remix

      // remix
      build_and_test(&ti);

      // remix + dbits
      ti.dbits = true;
      build_and_test(&ti);

      // only has merging iterators
      ti.fs = &mbtx_fs;
      build_and_test(&ti);

      // merging iterators with bt bloom filters
      ti.bt_bloom = true;
      build_and_test(&ti);

      // merging iterators with leaf bloom filters
      // ti.bt_bloom = false;
      // ti.leaf_bloom = true;
      // build_and_test(&ti);
    }
  }

  if (mode != NULL) {
    free(mode);
  }
  free(rgen_str);
  free(vlens);
  free(rgen);
  config_free();
}

