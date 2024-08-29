#define _GNU_SOURCE

#include "lib.h"
#include "kv.h"
#include "pkeys.h"
#include "bt.h"
#include "logger.h"

// define {{{
#define FLUSH_THRE_SEGMENT_NKEYS ((64))

#if defined(__linux__)
#define BT_OPEN_FLAGS ((O_RDONLY))
#define REMIX_OPEN_FLAGS ((O_RDONLY))
#else
#define BT_OPEN_FLAGS ((O_RDONLY))
#define REMIX_OPEN_FLAGS ((O_RDONLY))
#endif
// }}} define

// btenc {{{
// on closing each page, it builds the bloom filter
struct bfenc {
  u8 * buff;
  u8 * ptr;
  u32 * bf_offs;
  u32 written;
  u32 buff_size;
  u16 max_pageid;
  u16 cur_pageid;
};

  static struct bfenc *
bfenc_create(const u16 max_pageid)
{
  struct bfenc * bfenc = malloc(sizeof(*bfenc));
  bfenc->written = 0;
  bfenc->buff_size = PGSZ * 8;
  bfenc->max_pageid = max_pageid;
  bfenc->cur_pageid = 0;
  bfenc->buff = malloc(bfenc->buff_size);
  bfenc->ptr = bfenc->buff;
  bfenc->bf_offs = malloc(sizeof(bfenc->bf_offs[0]) * max_pageid);

  return bfenc;
}

  static void
bfenc_destroy(struct bfenc * const bfenc)
{
  free(bfenc->buff);
  free(bfenc->bf_offs);
  free(bfenc);
}

  static void
bfenc_try_append(struct bfenc * const bfenc, const struct bf * const bf)
{
  const u64 bf_size = bf_ser_byte(bf);
  const u32 written = bfenc->written;
  const u32 boundary = bits_round_up(written, PGBITS);
  u8 * const ptr = bfenc->ptr;
  if ((boundary > written) && ((written + bf_size) > boundary)) {
    // needs a new page, add paddings
    memset(ptr, 0, boundary - written);
    bfenc->written = boundary;
    bfenc->ptr += (boundary - written);
  }

  if ((written + bf_size) >= bfenc->buff_size) {
    bfenc->buff_size = bfenc->buff_size * 2;
    bfenc->buff = realloc(bfenc->buff, bfenc->buff_size);
    bfenc->ptr = bfenc->buff + bfenc->written;
  }
}

  static void
bfenc_append(struct bfenc * const bfenc, const struct bf * const bf)
{
  bfenc_try_append(bfenc, bf);
  const u64 bf_size = bf_ser_byte(bf);
  const u32 written = bfenc->written;
  const u32 bound = bits_round_up(written, PGBITS);
  const u32 boundary = written == bound ? bound + PGSZ : bound;
  debug_assert((bfenc->written + bf_size) <= boundary);
  (void)boundary;

  memcpy(bfenc->ptr, bf, bf_size);
  bfenc->written = bfenc->written + bf_size;
  bfenc->ptr += bf_size;

  // build the <pageid> : <bf_offset> mapping
  bfenc->bf_offs[bfenc->cur_pageid] = written;
  bfenc->cur_pageid++;
}

  static void
bfenc_finish(struct bfenc * const bfenc)
{
  const u32 written = bfenc->written;
  const u32 boundary = bits_round_up(written, PGBITS);
  u8 * const ptr = bfenc->ptr;
  memset(ptr, 0, boundary - written);
  bfenc->written = boundary;
  bfenc->ptr = bfenc->buff + bfenc->written;
}

struct bthdr { // the header structure in every bt page
  u16 nkeys; // number of keys
  u16 offs[0];
};

struct btenc {
  u32 nr_pages; // number of closed pages
  u32 max_leaf_pages;
  struct wring * wring;
  struct kv ** anchors; // for encoding internal nodes later

  struct bfenc * bfenc;

  u8 * bufptr; // from wring
  struct bthdr * hdr;
  u8 * data; // first kv
  u8 * cursor; // data_size = cursor-data
  u32 metasz;
  u32 datasz;
  u32 last_page_size; // the last pages's total size

  u32 nr_kvs; // all kv (normal + ts)
  u32 nr_tss; // tombstones
};

// all-zero for an empty B+-tree;
struct btmeta { // BT_PGSZ defined in sst.c
  u32 depth; // == number of non-leaf levels
  u32 nr_leaf; // valid pageid < nr_leaf; no valid page when nr_leaf == root == 0
  u32 root; // root page id, which is nr_pages-1
  u32 nr_kvs; // number of all kvs including tombstones
  u32 root_size; // the size of the root node; may be cached and pinned separately
  u32 btbf_size;
  u32 blbf_size;
};

  static u32
btmeta_nr_pages(const struct btmeta * const meta)
{
  const u32 nr_pages = meta->nr_leaf ? (meta->root + 1) : 0;
  return nr_pages;
}

  static size_t
btmeta_bt_size(const struct btmeta * const meta)
{
  return btmeta_nr_pages(meta) * PGSZ;
}

  static size_t
btmeta_bf_size(const struct btmeta * const meta)
{
  return meta->btbf_size + meta->blbf_size;
}

  static size_t
btmeta_mmap_size(const struct btmeta * const meta)
{
  return btmeta_bt_size(meta) + btmeta_bf_size(meta);
}

  static void
btenc_acquire_buffer(struct btenc * const enc)
{
  enc->bufptr = wring_acquire(enc->wring);
  enc->hdr = (void *)enc->bufptr;
  enc->hdr->nkeys = 0;
  enc->data = enc->bufptr + PGSZ;
  enc->cursor = enc->data;

  enc->metasz = (u32)sizeof(enc->hdr->nkeys);
  enc->datasz = 0;
}

  static struct btenc *
btenc_create(const int fd, const u32 max_leaf_pages)
{
  struct btenc * const enc = calloc(1, sizeof(*enc));
  if (enc == NULL)
    return NULL;

  enc->max_leaf_pages = max_leaf_pages; // const
  enc->wring = wring_create(fd, PGSZ << 1, 16); // doubled buffer size
  enc->anchors = calloc(enc->max_leaf_pages * 2, sizeof(enc->anchors[0]));

  btenc_acquire_buffer(enc);

  enc->bfenc = bfenc_create(max_leaf_pages);
  return enc;
}

  static void
btenc_close_page(struct btenc * const enc, const bool leaf)
{
  if (enc->hdr->nkeys == 0)
    return;
  debug_assert((enc->metasz << 1) <= PGSZ); // hdr and hdrenc should not overlap

  // copy bm
  struct bthdr * const hdr = enc->hdr;
  struct bthdr * const hdr1 = (typeof(hdr1))(enc->data - enc->metasz);
  hdr1->nkeys = hdr->nkeys;

  const u8 * const data = enc->data;

  struct bf * bf = bf_create(10, hdr->nkeys);
  for (u32 i = 0; i < hdr->nkeys; i++) {
    const u16 off = hdr->offs[i];
    hdr1->offs[i] = off + (u16)enc->metasz;
    const u8 * ptr = data + off;
    u32 klen, vlen;
    ptr = vi128_decode_u32(ptr, &klen);
    ptr = vi128_decode_u32(ptr, &vlen);
    u64 hash = byte_hash64(ptr, klen);
    bf_add(bf, hash);
  }

  if (leaf)
    bfenc_append(enc->bfenc, bf);

  bf_destroy(bf);

  // zero padding
  const u32 total_size = enc->metasz + enc->datasz;
  debug_assert(total_size <= PGSZ);
  memset(enc->cursor, 0, PGSZ - total_size);

  const u64 file_off = PGSZ * enc->nr_pages;
  const size_t buf_off = (size_t)(((u8 *)hdr1) - enc->bufptr);
  debug_assert(buf_off + enc->metasz == PGSZ);

  wring_write_partial(enc->wring, file_off, enc->bufptr, buf_off, PGSZ);
  enc->last_page_size = total_size;
  btenc_acquire_buffer(enc);
  enc->nr_pages++; // closed
}

// the input kv must not be oversize
// true: the kv has been added
// false: the sst is full and should be closed; meanwhile the input kv is not consumed
// the caller must always maintain a copy of the previously inserted kv (use kv_null() for the first kv)
// the lcp only applies to anchor keys in bt
  static bool
btenc_append(struct btenc * const enc, const struct kv * const kv,
    const struct kv * const prev, const bool internal, const bool lcp)
{
  debug_assert(kv_compare(kv, prev) > 0 || kv->klen == 0 || lcp == false); // the input must be sorted
  const u32 newsz = (u32)(sizeof(enc->hdr->offs[0]) + sst_kv_vi128_estimate(kv));

  if ((enc->metasz + enc->datasz + newsz) > PGSZ) { // close the current page
    // if it is an internal node, it is not a leaf
    btenc_close_page(enc, !internal);
    if (internal == false && enc->nr_pages == enc->max_leaf_pages) // full
      return false;
  }

  // can append
  debug_assert(newsz + sizeof(enc->hdr->nkeys) <= PGSZ);
  debug_assert(internal || enc->nr_pages < enc->max_leaf_pages);

  struct bthdr * const hdr = enc->hdr;
  if (hdr->nkeys == 0) { // need a new anchor key
    debug_assert(enc->data == enc->cursor);
    const bool use_lcp = (internal == false) && lcp;
    const u32 alen = prev->klen ? (use_lcp ? (kv_key_lcp(prev, kv) + 1) : kv->klen) : 0;
    debug_assert(alen <= kv->klen);
    struct kv * const anchor = kv_dup_key_prefix_extra(kv, alen, sizeof(u32));
    anchor->vlen = sizeof(u32);
    *(u32 *)kv_vptr(anchor) = enc->nr_pages; // page id
    enc->anchors[enc->nr_pages] = anchor;
  }

  // append
  hdr->offs[hdr->nkeys++] = (u16)(enc->cursor - enc->data);
  enc->cursor = sst_kv_vi128_encode(enc->cursor, kv);

  enc->metasz = (u32)(sizeof(hdr->nkeys) + (sizeof(hdr->offs[0]) * hdr->nkeys));
  enc->datasz = (u32)(enc->cursor - enc->data);
  debug_assert((enc->metasz + enc->datasz) <= PGSZ);

  if (internal == false) {
    enc->nr_kvs++;
    if (kv->vlen == SST_VLEN_TS)
      enc->nr_tss++;
  }
  return true;
}

// return the total number of pages in the tree
// the root node is at ret-1; the tree does not exist if ret == 0
  static u32
btenc_finish(struct btenc * const enc, struct btmeta * const out)
{
  btenc_close_page(enc, /* leaf */ true);
  debug_assert(enc->hdr->nkeys == 0);
  debug_assert(enc->data == enc->cursor);

  const u32 nr_leaf = enc->nr_pages;
  debug_assert(nr_leaf <= enc->max_leaf_pages);
  u16 depth = 0;
  u32 a0 = 0;
  u32 na = nr_leaf; // number of anchors to add
  struct kv ** anchors = enc->anchors;

  while (na > 1) {
    struct kv * const prev = malloc(PGSZ);
    kv_dup2(kv_null(), prev);
    for (u32 i = 0; i < na; i++) {
      const struct kv * const curr = anchors[a0 + i];
      const bool r = btenc_append(enc, curr, prev, true, false);
      // fatal error
      if (!r)
        debug_die();

      kv_dup2(curr, prev);
    }
    btenc_close_page(enc, /* leaf */ false);
    depth++;
    a0 += na;
    na = enc->nr_pages - a0;
    free(prev);
  }
  wring_flush(enc->wring);
  const u32 nr_all = enc->nr_pages;
  debug_assert((nr_leaf < nr_all) || (nr_leaf == nr_all && nr_leaf <= 1));
  debug_assert((nr_all == 0) == (enc->last_page_size == 0));

  out->depth = depth;
  out->nr_leaf = (u16)nr_leaf;
  out->root = nr_all ? (nr_all - 1) : 0;
  out->nr_kvs = enc->nr_kvs;
  out->root_size = enc->last_page_size;
  return nr_all;
}

  static void
btenc_destroy(struct btenc * const enc)
{
  bfenc_destroy(enc->bfenc);
  wring_destroy(enc->wring);
  // anchors
  struct kv ** const anchors = enc->anchors;
  for (u32 i = 0; i < enc->nr_pages; i++) {
    debug_assert(anchors[i]);
    free(anchors[i]);
  }
  debug_assert(anchors[enc->nr_pages] == NULL);
  free(anchors);
  free(enc);
}

  u64
bt_build_at(const int dfd, struct miter * const miter,
    const struct t_build_cfg * const cfg,
    const struct kv * const k0, const struct kv * const kz)
{
  char fn[24];
  const u64 magic = cfg->seq * 100lu + cfg->run;
  sprintf(fn, "%03lu.btx", magic);
  const int fdout = openat(dfd, fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  if (fdout < 0)
    return 0;

  debug_assert(cfg->max_pages <= SST_MAX_PAGEID);
  struct btenc * const enc = btenc_create(fdout, cfg->max_pages);
  debug_assert(enc);

  struct kv * const prev = malloc(sizeof(*prev) + PGSZ);
  kv_dup2(kv_null(), prev);
  struct kv * const tmp = malloc(sizeof(*tmp) + PGSZ);

  if (k0)
    miter_kv_seek(miter, k0);

  u64 hashes_size = PGSZ / sizeof(u64);
  u64 * hashes = malloc(sizeof(*hashes) * hashes_size);
  u64 hashes_idx = 0;

  while (miter_valid(miter)) {
    // key in tmp
    struct kv * curr = miter_peek(miter, tmp);
    debug_assert(curr);

    // if del is true then skip all tombstones and stale keys
    if (cfg->del) {
      while (curr && (curr->vlen == SST_VLEN_TS)) {
        miter_skip_unique(miter);
        curr = miter_peek(miter, tmp);
      }
    }

    // check for termination
    if ((curr == NULL) || (kz && (kv_compare(curr, kz) >= 0)))
      break;

    // only record unique keys hashes
    if (cfg->bt_bloom && (prev == NULL || kv_compare(curr, prev) != 0)) {
      const u64 hash = kv_hash64(curr);
      hashes[hashes_idx++] = hash;
      if (hashes_idx >= hashes_size) {
        hashes_size <<= 1;
        hashes = realloc(hashes, sizeof(*hashes) * hashes_size);
      }
    }

    if (!btenc_append(enc, curr, prev, false, cfg->lcp))
      break;

    kv_dup2_key(curr, prev);
    miter_skip_unique(miter);
  }

  struct btmeta meta = {};
  const u64 nr_pages = btenc_finish(enc, &meta);
  const u64 pages_size = nr_pages * PGSZ;

  lseek(fdout, (off_t)pages_size, SEEK_SET);

  if (cfg->bt_bloom) {
    debug_assert(hashes_idx > 0 || nr_pages == 0);
    struct bf * bf = bf_create(10, hashes_idx);
    for (u64 i = 0; i < hashes_idx; i++) {
      bf_add(bf, hashes[i]);
    }
    const u64 bf_size = bf_ser_byte(bf);
    write(fdout, bf, bf_size);
    const u64 aligned_bf_size = bits_round_up(bf_size, PGBITS);
    void * paddings = calloc(1, PGSZ);
    write(fdout, paddings, aligned_bf_size - bf_size);
    meta.btbf_size = aligned_bf_size;
    free(paddings);
    bf_destroy(bf);
  } else if (cfg->leaf_bloom) {
    struct bfenc * bfenc = enc->bfenc;
    debug_assert(meta.nr_leaf == bfenc->cur_pageid);
    bfenc_finish(bfenc);
    write(fdout, bfenc->buff, bfenc->written);
    meta.blbf_size = bfenc->written;
    write(fdout, bfenc->bf_offs, bfenc->cur_pageid * sizeof(bfenc->bf_offs[0]));
  }
  free(hashes);
  write(fdout, &meta, sizeof(meta));
  fdatasync(fdout);
  close(fdout);

  btenc_destroy(enc); // fdout closed by btenc
  free(prev);
  free(tmp);
  return pages_size + meta.btbf_size + meta.blbf_size + sizeof(meta);
}

  u64
bt_build(const char * const dirname, struct miter * const miter,
    const u64 seq, const u32 run, const u16 max_pages,
    const bool del, const bool lcp,
    const bool bt_bloom, const bool leaf_bloom,
    const struct kv * const k0, const struct kv * const kz)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return 0;

  const struct t_build_cfg cfg = {.seq = seq, .run = run,
    .max_pages = max_pages, .del = del, .lcp = lcp,
    .bt_bloom = bt_bloom, .leaf_bloom = leaf_bloom};
  const u64 ret = bt_build_at(dfd, miter, &cfg, k0, kz);
  close(dfd);
  return ret;
}
// }}} btenc

// bt {{{
// b-tree Bloom filters
// in-memory representation of on disk Bloom filters
// read-only
struct btbf {
  // same layout as the bf in lib.c
  u64 nr_probe;
  u64 nbits;
  u64 nbytes;
  u64 ones;
  // the start of the on disk Bloom filters
  // Bloom filters start at nr_pages * PGSZ
  u32 bf_offset;
  u32 bf_size;
  u32 nqueries;
  u32 nfps; // false positives
  u32 nfns; // false negatives
  u32 ntps; // true positives
  u32 ntns; // true negatives
  bool print_stats;
};

struct bt {
  struct rcache * rc; // optional
  int fd; // rc uses the fd
  u32 refcnt;
  struct btbf * btbf;
  struct blbf * blbf;
  struct btmeta meta;
  u8 * mem; // pointer to the mmap area
  u8 * root_dup; // optional: only when root is small and internal
  bool pinned;
};

  static struct btbf *
btbf_create(const struct bt * const bt, const struct btmeta * const meta)
{
  u64 alloc_sz;
  struct btbf * bf = pages_alloc_best(sizeof(*bf), false, &alloc_sz);
  debug_assert(alloc_sz == PGSZ);
  const size_t bf_offset = btmeta_bt_size(meta);
  const int read_size = pread(bt->fd, bf, alloc_sz, bf_offset);
  debug_assert(read_size > 0);
  bf->bf_offset = bf_offset;
  bf->bf_size = btmeta_bf_size(meta);
  bf->print_stats = false;
  return bf;
}

  static void
btbf_destroy(struct btbf * const bf)
{
  if (bf->nbits != 0 && bf->print_stats == true) {
    printf("bloom filter initialized nr_probe: %lu, bits: %lu, ones %lu, rate :%f%%\n",
            bf->nr_probe, bf->nbits, bf->ones,
            (double)bf->ones / (double)bf->nbits * 100.0);
  }
  if (bf->nqueries != 0 && bf->print_stats == true) {
    printf("Bloom stats: queries: %u TP: %u TN: %u FP: %u FN: %u, FPR %f%%\n",
        bf->nqueries, bf->ntps, bf->ntns, bf->nfps, bf->nfns,
        (double)bf->nfps / (double)(bf->nfps + bf->ntns) * 100.0);
  }
  pages_unmap(bf, PGSZ);
}

// b-tree leaf bloom filters
// in-memory representation of on disk per leaf bloom filters
struct blbf {
  void * buff;
  u64 alloc_sz;
  u32 * bf_offs; // pageid to bf_offset mappings, cached in-memory
  u32 nr_leaf;
  u32 bfs_offset;
  u32 bf_offs_offset;
  // stats
  u32 bf_offset;
  u32 bf_size;
  u32 nqueries;
  u32 nfps; // false positives
  u32 nfns; // false negatives
  u32 ntps; // true positives
  u32 ntns; // true negatives
};

  static struct blbf *
blbf_create(const struct bt * const bt, const struct btmeta * const meta)
{
  struct blbf * bf = calloc(1, sizeof(*bf));

  bf->bfs_offset = btmeta_bt_size(meta);
  const size_t offs_offset = bf->bfs_offset + btmeta_bf_size(meta);
  bf->bf_offs_offset = offs_offset;
  const u64 nr_leaf = meta->nr_leaf;
  bf->nr_leaf = nr_leaf;

  void * const buff = pages_alloc_best(nr_leaf * sizeof(*(bf->bf_offs)) + btmeta_bf_size(meta), false, &bf->alloc_sz);
  const int read_size = pread(bt->fd, buff, bf->alloc_sz, bf->bfs_offset);
  debug_assert(read_size > 0);
  bf->bf_offs = buff + btmeta_bf_size(meta);
  bf->buff = buff;

  return bf;
}

  static void
blbf_destroy(struct blbf * bf)
{
  if (bf->nqueries != 0) {
    printf("Leaf Bloom total stats: queries: %u TP: %u TN: %u FP: %u FN: %u, FPR %f%%\n",
        bf->nqueries, bf->ntps, bf->ntns, bf->nfps, bf->nfns,
        (double)bf->nfps / (double)bf->nqueries * 100.0);
  }
  pages_unmap(bf->buff, bf->alloc_sz);
  free(bf);
}

// Wenshao: init needs metadata
  static bool
bt_init(const int fd, const struct btmeta * const meta, struct bt * const bt, const bool pinned)
{
  const size_t map_size = btmeta_mmap_size(meta);

  u8 * mem = NULL;
  if (pinned) {
    u64 alloc_size = 0;
    if (map_size) {
      mem = pages_alloc_best(map_size, false, &alloc_size);
      if (alloc_size < map_size || mem == NULL) {
        return false;
      }
    }
    const size_t read_size = pread(fd, mem, map_size, 0);
    if (read_size != map_size) {
      return false;
    }
  } else {
    // mem will not be accessed once rcache has been installed
    // Hugepages make replacement hard; some file systems don't support hugepages
    //MAP_HUGETLB|MAP_HUGE_2MB
    mem = map_size ? mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0) : NULL;
    if (mem == MAP_FAILED)
      return false;
    if (map_size) {
      if (posix_madvise(mem, map_size, POSIX_MADV_RANDOM)) {
        logger_printf("%s madvise failed\n", __func__);
      }
    }
  }
  debug_assert(mem || meta->nr_leaf == 0);

  bt->rc = NULL;
  bt->fd = fd; // keep fd open
  bt->refcnt = 1;
  bt->meta = *meta;
  bt->mem = mem;
  bt->pinned = pinned;
  const size_t bt_size = btmeta_bt_size(meta);
  if (meta->depth && meta->root_size < 2040) {
    debug_assert(bt_size >= (PGSZ << 1)); // at least two pages
    const size_t root_off = bt_size - PGSZ;
    u64 alloc_sz;
    u8 * const root_dup = pages_alloc_best(meta->root_size, false, &alloc_sz);
    debug_assert(alloc_sz == PGSZ);
    const int read_size = pread(fd, root_dup, alloc_sz, (off_t)root_off);
    debug_assert(read_size > 0);
    bt->root_dup = root_dup;
  } else {
    bt->root_dup = NULL;
  }

  bt->btbf = NULL;
  bt->blbf = NULL;
  // one of them must be 0
  debug_assert((meta->btbf_size == 0) || (meta->blbf_size == 0));
  if (meta->btbf_size != 0)
    bt->btbf = btbf_create(bt, meta);
  else if (meta->blbf_size != 0) {
    bt->blbf = blbf_create(bt, meta);
  }

  return true;
}

  static bool
bt_init_at(const int dfd, const u64 seq, const u32 run, struct bt * const bt)
{
  char fn[24];
  const u64 magic = seq * 100lu + run;
  sprintf(fn, "%03lu.btx", magic);
  const int fd = openat(dfd, fn, BT_OPEN_FLAGS);
  if (fd < 0)
    return false;

  if (posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM)) {
    logger_printf("%s fadvise failed\n", __func__);
  }

  const size_t fsize = fdsize(fd);
  if (fsize < sizeof(struct btmeta) || fsize >= UINT32_MAX) {
    close(fd);
    return false;
  }
  u64 alloc_sz;
  struct btmeta * meta = pages_alloc_best(sizeof(*meta), false, &alloc_sz);
  debug_assert(alloc_sz == PGSZ);
  const size_t meta_off = fsize - sizeof(*meta);
  const int read_size = pread(fd, meta, alloc_sz, (off_t)meta_off);
  debug_assert((read_size > 0) && (read_size == sizeof(*meta)));

  const bool s = bt_init(fd, meta, bt, false);

  size_t expected_size = btmeta_bt_size(meta) + btmeta_bf_size(meta) + sizeof(*meta);

  // leaf bloom filters have extra index
  if (meta->blbf_size != 0) {
    expected_size += (meta->nr_leaf * sizeof(u32));
  }
  pages_unmap(meta, alloc_sz);
  debug_assert(fsize == expected_size);
  return s ? fsize == expected_size : s;
}

  inline u32
bt_nr_pages(struct bt * const bt)
{
  return btmeta_nr_pages(&(bt->meta));
}

  inline void
bt_rcache(struct bt * const bt, struct rcache * const rc)
{
  bt->rc = rc;
}

  static struct bt *
bt_open_at(const int dfd, const u64 seq, const u32 run)
{
  struct bt * const bt = yalloc(sizeof(*bt));
  if (bt == NULL)
    return NULL;
  if (bt_init_at(dfd, seq, run, bt)) {
    return bt;
  } else {
    free(bt);
    return NULL;
  }
}

  struct bt *
bt_open(const char * const dirname, const u64 seq, const u32 run)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return NULL;
  struct bt * const bt = bt_open_at(dfd, seq, run);
  close(dfd);
  return bt;
}

// access data blocks from here
  static inline const u8 *
bt_page_acquire(const struct bt * const bt, const u32 pageid)
{
  if (bt->rc) {
    const u8 * const ptr = rcache_acquire(bt->rc, bt->fd, pageid);
    debug_assert(ptr);
    return ptr;
  } else {
    return bt->mem + (PGSZ * pageid);
  }
}

  static inline u64
bt_page_retain(struct rcache * const rc, const u8 * page)
{
  debug_assert(page && (((u64)page) & (PGSZ - 1)) == 0);
  if (rc)
    rcache_retain(rc, page);
  return (u64)page;
}

  static inline void
bt_page_release(struct rcache * const rc, const u8 * page)
{
  debug_assert(page && (((u64)page) & (PGSZ - 1)) == 0);
  if (rc)
    rcache_release(rc, page);
}

  static void
bt_deinit(struct bt * const bt)
{
  if (bt->refcnt == 1) {
    debug_assert(bt->mem || bt->meta.nr_leaf == 0);
    if (bt->mem) {
      if (bt->pinned) {
        pages_unmap((void *)bt->mem, btmeta_mmap_size(&bt->meta));
      } else {
        munmap((void *)bt->mem, btmeta_mmap_size(&bt->meta));
      }
    }
    if (bt->rc)
      rcache_close(bt->rc, bt->fd);
    else
      close(bt->fd);
    if (bt->btbf)
      btbf_destroy(bt->btbf);
    if (bt->blbf)
      blbf_destroy(bt->blbf);

    pages_unmap(bt->root_dup, PGSZ);
  } else {
    bt->refcnt--;
  }
}

  static void
bt_deinit_lazy(struct bt * const bt)
{
  if (bt->refcnt == 1) {
    debug_assert(bt->mem || bt->meta.nr_leaf == 0);
    if (bt->mem)
      munmap((void *)bt->mem, btmeta_mmap_size(&bt->meta));
    if (bt->rc)
      rcache_close_lazy(bt->rc, bt->fd);
    else
      close(bt->fd);
    pages_unmap(bt->root_dup, PGSZ);
  } else {
    bt->refcnt--;
  }
}

  void
bt_destroy(struct bt * const bt)
{
  bt_deinit(bt);
  free(bt);
}

  void
bt_fprint(struct bt * const bt, FILE * const out)
{
  const struct btmeta * const m = &bt->meta;
  fprintf(out, "%s depth %hu nr_leaf %hu root %u nr_kvs %u\n",
      __func__, m->depth, m->nr_leaf, m->root, m->nr_kvs);
}

  static u16
bt_page_nkeys(const u8 * const page)
{
  const struct bthdr * const hdr = (typeof(hdr))page;
  debug_assert(hdr->nkeys); // no empty pages
  return hdr->nkeys;
}

  static inline const u8 *
bt_page_vi128(const u8 * const page, const u32 id)
{
  const struct bthdr * const hdr = (typeof(hdr))page;
  debug_assert(id < hdr->nkeys);
  return page + hdr->offs[id];
}

// seek on an internal node for lower-equal
// for internal nodes only
// return child pageid
  static u32
bt_page_seek_internal(const u8 * const page, const struct kref * const key)
{
  struct kvref kvref;
  const u32 nkeys = bt_page_nkeys(page);
  u32 l = 0;
  u32 r = nkeys;
  while ((l + 1) < r) {
    const u32 m = (l + r) >> 1;
    kv128_decode_kvref(bt_page_vi128(page, m), &kvref);
    const int cmp = kref_kvref_compare(key, &kvref);
    debug_assert(kvref.hdr.vlen == sizeof(u32));
    if (cmp < 0) // search-key < [m]
      r = m;
    else if (cmp > 0) // search-key > [m]
      l = m;
    else
      return *(const u32 *)kvref.vptr;
  }
  kv128_decode_kvref(bt_page_vi128(page, l), &kvref);
  return *(const u32 *)kvref.vptr;
}

// return a leaf node id; return 0 when nr_leaf == 0
  static u16
bt_seek_pageid(const struct bt * const bt, const struct kref * const key)
{
  u32 pageid = bt->meta.root;
  u32 depth = bt->meta.depth;

  if (depth && bt->root_dup) {
    const u32 child = bt_page_seek_internal(bt->root_dup, key);
    debug_assert(child < bt->meta.root);
    pageid = child;
    depth--;
  }

  while (depth) {
    debug_assert(pageid <= bt->meta.root);
    const u8 * const page = bt_page_acquire(bt, pageid);
    const u32 child = bt_page_seek_internal(page, key);
    debug_assert(child < pageid);
    pageid = child;
    bt_page_release(bt->rc, page);
    depth--;
  }

  debug_assert(pageid < bt->meta.nr_leaf || bt->meta.nr_leaf == 0);
  return (u16)pageid;
}

struct bt_ptr {
  u16 pageid; // xth 4kb-block in the table
  u16 keyid; // xth key in the block // MAX == invalid
};

struct bt_iter { // 32 bytes
  struct bt * bt;
  u8 rank;
  u8 padding;
  u16 nr_leaf;
  struct bt_ptr ptr;
  u32 klen;
  u32 vlen;
  const u8 * kvdata;
};

// points to the first key; invalid for empty bt
  static inline void
bt_iter_init(struct bt_iter * const iter, struct bt * const bt, const u8 rank)
{
  debug_assert(rank < MSST_NR_RUNS || rank == UINT8_MAX);
  iter->bt = bt;
  iter->rank = rank;
  iter->nr_leaf = bt->meta.nr_leaf;
  iter->ptr.pageid = iter->nr_leaf; // invalid
  iter->ptr.keyid = 0;
  // klen, vlen are ignored
  iter->kvdata = NULL;
}

  struct bt_iter *
bt_iter_create(struct bt * const bt)
{
  struct bt_iter * const iter = calloc(1, sizeof(*iter));
  if (iter)
    bt_iter_init(iter, bt, 0);
  return iter;
}

// the iter is pointing to a valid position
  inline bool
bt_iter_valid(const struct bt_iter * const iter)
{
  return iter->ptr.pageid < iter->nr_leaf;
}

// the iter is valid AND the kv-pair is accessible
  static inline bool
bt_iter_active(struct bt_iter * const iter)
{
  return bt_iter_valid(iter) && iter->kvdata;
}

  static int
bt_iter_compare(struct bt_iter * const i1, struct bt_iter * const i2)
{
  debug_assert(bt_iter_active(i1) && bt_iter_active(i2));
  const u32 len = i1->klen < i2->klen ? i1->klen : i2->klen;
  const int cmp = memcmp(i1->kvdata, i2->kvdata, len);
  return cmp ? cmp : (((int)i1->klen) - ((int)i2->klen));
}

// i1 must be valid
// key can be NULL
  static int
bt_iter_compare_kref(struct bt_iter * const i1, const struct kref * const key)
{
  debug_assert(bt_iter_active(i1) && key);
  const u32 len = (i1->klen < key->len) ? i1->klen : key->len;
  const int cmp = memcmp(i1->kvdata, key->ptr, len);
  if (cmp != 0) {
    return cmp;
  } else {
    return ((int)i1->klen) - ((int)key->len);
  }
}

  static inline bool
bt_iter_match_kref(struct bt_iter * const i1, const struct kref * const key)
{
  debug_assert(bt_iter_active(i1) && key);
  return (i1->klen == key->len) && (!memcmp(i1->kvdata, key->ptr, i1->klen));
}

  static inline const u8 *
bt_iter_page_addr(struct bt_iter * const iter)
{
  debug_assert(iter->kvdata);
  const u64 addr = ((u64)iter->kvdata) >> PGBITS << PGBITS;
  return (const u8 *)addr;
}

  static inline const struct bthdr *
bt_iter_page_bthdr(struct bt_iter * const iter)
{
  return (const struct bthdr *)bt_iter_page_addr(iter);
}

  static inline void
bt_iter_page_release(struct bt_iter * const iter)
{
  if (iter->kvdata) {
    // get page address
    const u8 * const page = bt_iter_page_addr(iter);
    bt_page_release(iter->bt->rc, page);
    iter->kvdata = NULL;
  }
}

// iter has ptr.keyid
// get klen, vlen, and kvdata
  static void
bt_iter_decode_kv(struct bt_iter * const iter, const u8 * const page)
{
  const u8 * const ptr = bt_page_vi128(page, iter->ptr.keyid); // keyid checked inside
  iter->kvdata = vi128_decode_u32(vi128_decode_u32(ptr, &iter->klen), &iter->vlen);
}

// reuse the kvdata and keyid
  static void
bt_iter_fix_kv_reuse(struct bt_iter * const iter)
{
  debug_assert(iter->kvdata);
  const u8 * const page = bt_iter_page_addr(iter);
  bt_iter_decode_kv(iter, page);
}

  static void
bt_iter_set_ptr(struct bt_iter * const iter, const struct bt_ptr ptr)
{
  debug_assert(ptr.pageid <= iter->nr_leaf); // must be a valid ptr
  if (iter->kvdata && (iter->ptr.pageid == ptr.pageid)) {
    iter->ptr.keyid = ptr.keyid;
    bt_iter_fix_kv_reuse(iter);
  } else {
    bt_iter_page_release(iter);
    iter->ptr = ptr;
  }
}

// make kvdata current with the iter; acquire page
// also used by mssty
  static void
bt_iter_fix_kv(struct bt_iter * const iter)
{
  debug_assert(bt_iter_valid(iter));
  if (iter->kvdata)
    return;

  const u8 * const page = bt_page_acquire(iter->bt, iter->ptr.pageid);
  bt_iter_decode_kv(iter, page);
}

// iter already has bt and ptr.pageid
// seek on a leaf node for >= key (greater-equal)
  static bool
bt_page_seek_leaf(struct bt_iter * const iter, const struct kref * const key)
{
  debug_assert(iter->kvdata == NULL);
  const u8 * const page = bt_page_acquire(iter->bt, iter->ptr.pageid);
  const u32 nkeys = bt_page_nkeys(page);
  u32 l = 0;
  u32 r = nkeys;
  while (l < r) {
    const u32 m = (l + r) >> 1;
    iter->ptr.keyid = (u16)m;
    bt_iter_decode_kv(iter, page);
    const int cmp = bt_iter_compare_kref(iter, key);
    if (cmp < 0)
      l = m + 1;
    else if (cmp > 0)
      r = m;
    else
      return true; // match
  }

  if (l < nkeys) { // target in the current page
    iter->ptr.keyid = (u16)l;
    bt_iter_decode_kv(iter, page);
  } else { // the first key of the next page or EOF
    iter->kvdata = NULL;
    bt_page_release(iter->bt->rc, page);
    iter->ptr.pageid++;
    iter->ptr.keyid = 0;
  }
  return false;
}

  void
bt_iter_seek(struct bt_iter * const iter, const struct kref * const key)
{
  bt_iter_page_release(iter);
  iter->ptr.pageid = bt_seek_pageid(iter->bt, key);
  if (bt_iter_valid(iter))
    bt_page_seek_leaf(iter, key);
}

  inline void
bt_iter_seek_null(struct bt_iter * const iter)
{
  bt_iter_page_release(iter);
  iter->ptr.pageid = 0;
  iter->ptr.keyid = 0;
}

// for remix; the first anchor must be klen=0
  static bool
bt_page_seek_leaf_le(struct bt_iter * const iter, const struct kref * const key)
{
  debug_assert(iter->kvdata == NULL);
  const u8 * const page = bt_page_acquire(iter->bt, iter->ptr.pageid);
  const u32 nkeys = bt_page_nkeys(page);
  u32 l = 0;
  u32 r = nkeys;
  while ((l + 1) < r) {
    const u32 m = (l + r) >> 1;
    iter->ptr.keyid = (u16)m;
    bt_iter_decode_kv(iter, page);
    const int cmp = bt_iter_compare_kref(iter, key);
    if (cmp < 0)
      l = m;
    else if (cmp > 0)
      r = m;
    else
      return true; // match
  }
  debug_assert(l < nkeys);
  iter->ptr.keyid = (u16)l;
  bt_iter_decode_kv(iter, page);
  return false;
}

// for remix; the first anchor must be klen=0
// return false when the bt is empty
  static bool
bt_iter_seek_le(struct bt_iter * const iter, const struct kref * const key)
{
  bt_iter_page_release(iter);
  iter->ptr.pageid = bt_seek_pageid(iter->bt, key);
  // assert key >= first key in the page
  if (bt_iter_valid(iter)) {
    bt_page_seek_leaf_le(iter, key);
    return true;
  } else {
    return false;
  }
}

// test if iter points to a tombstone
  inline bool
bt_iter_ts(struct bt_iter * const iter)
{
  debug_assert(bt_iter_valid(iter));
  bt_iter_fix_kv(iter);
  return iter->vlen == SST_VLEN_TS;
}

  struct kv *
bt_iter_peek(struct bt_iter * const iter, struct kv * const out)
{
  if (!bt_iter_valid(iter))
    return NULL;

  bt_iter_fix_kv(iter);
  const u32 kvlen = iter->klen + (iter->vlen & SST_VLEN_MASK);
  struct kv * const ret = out ? out : malloc(sizeof(*ret) + kvlen);
  ret->klen = iter->klen;
  ret->vlen = iter->vlen;
  memcpy(ret->kv, iter->kvdata, kvlen);
  return ret;
}

  static const u8 *
bt_iter_vptr(struct bt_iter * const iter)
{
  debug_assert(bt_iter_active(iter));
  return iter->kvdata + iter->klen;
}

  bool
bt_iter_kref(struct bt_iter * const iter, struct kref * const kref)
{
  if (!bt_iter_valid(iter))
    return false;

  bt_iter_fix_kv(iter);
  kref_ref_raw(kref, iter->kvdata, iter->klen); // no hash32
  return true;
}

  bool
bt_iter_kvref(struct bt_iter * const iter, struct kvref * const kvref)
{
  if (!bt_iter_valid(iter))
    return false;

  bt_iter_fix_kv(iter);
  kvref->hdr.klen = iter->klen;
  kvref->hdr.vlen = iter->vlen;
  //kvref->hdr.hash = 0; // XXX
  kvref->kptr = iter->kvdata;
  kvref->vptr = iter->kvdata + iter->klen;
  return true;
}

  inline u64
bt_iter_retain(struct bt_iter * const iter)
{
  return bt_page_retain(iter->bt->rc, bt_iter_page_addr(iter));
}

  inline void
bt_iter_release(struct bt_iter * const iter, const u64 opaque)
{
  bt_page_release(iter->bt->rc, (const u8 *)opaque);
}

  void
bt_iter_skip1(struct bt_iter * const iter)
{
  debug_assert(bt_iter_valid(iter));
  struct bt_ptr * const pptr = &iter->ptr;

  bt_iter_fix_kv(iter);
  const struct bthdr * const hdr = bt_iter_page_bthdr(iter);
  pptr->keyid++;
  if (pptr->keyid >= hdr->nkeys) {
    bt_iter_page_release(iter); // discard kvdata
    pptr->pageid++;
    pptr->keyid = 0;
  } else if (iter->kvdata) {
    bt_iter_fix_kv_reuse(iter);
  }
}

  void
bt_iter_skip(struct bt_iter * const iter, const u32 nr)
{
  debug_assert(bt_iter_valid(iter));
  struct bt_ptr * const pptr = &iter->ptr;

  u32 todo = nr;
  do {
    bt_iter_fix_kv(iter);
    const struct bthdr * const hdr = bt_iter_page_bthdr(iter);
    const u32 ncap = hdr->nkeys - pptr->keyid;
    if (todo < ncap) {
      pptr->keyid += (u16)todo;
      if (iter->kvdata)
        bt_iter_fix_kv_reuse(iter);
      return; // done
    }
    bt_iter_page_release(iter); // discard kvdata
    pptr->pageid++;
    pptr->keyid = 0;
    if (pptr->pageid >= iter->nr_leaf)
      return; // invalid
    todo -= ncap;
  } while (todo);
}

  struct kv *
bt_iter_next(struct bt_iter * const iter, struct kv * const out)
{
  struct kv * const ret = bt_iter_peek(iter, out);
  if (bt_iter_valid(iter))
    bt_iter_skip1(iter);
  return ret;
}

  void
bt_iter_park(struct bt_iter * const iter)
{
  // release the page
  bt_iter_page_release(iter);
}

  void
bt_iter_destroy(struct bt_iter * const iter)
{
  bt_iter_park(iter);
  free(iter);
}

  static bool
btbf_lookup(const struct bt * const bt, const struct kref * key)
{
  struct btbf * bf = bt->btbf;
  if (bf == NULL) {
    return true;
  }

  bf->nqueries++;

  // calculate the bits then the page offset
  const u64 hash64 = kref_hash64(key);
  u64 t = hash64;
  const u64 inc = bf_inc(hash64);
  const u64 bits = bf->nbits;
  for (u64 i = 0; i < bf->nr_probe; i++) {
    const u64 idx = t % bits;

    const u64 off_idx = idx + (8 * (bf_header_size() + bf->bf_offset));
    // (size << 3) >> 6 == size >> 3
    const u64 u64_idx = (off_idx >> 6);
    const u32 pageid = u64_idx >> 9;
    // assuming the header is 8 byte aligned.
    const u8 * const page = (typeof(page))bt_page_acquire(bt, pageid);
    const u64 * const u64page = (typeof(u64page))page;

    /*
     *      page index | u64 index |bit index
     * ---- ---- ---- -|--- ---- --|-- ----|
     */

    // bitmap_test()
    bool hit = (u64page[(u64_idx & 0x1fflu)] & (1lu << (off_idx & 0x3flu))) != 0;

    bt_page_release(bt->rc, page);
    if (hit == false) {
      bf->ntns++;
      return false;
    }

    t += inc;
  }
  return true;
}

  static void
btbf_log_metrics(const struct bt * const bt, const bool predict, const bool result)
{
  if (bt->btbf == NULL) {
    return;
  }

  if (predict == result) {
    if (result == true) {
      bt->btbf->ntps++;
    } else {
      bt->btbf->ntns++;
    }
  } else {
    if (predict == false) {
      // bloom says no, but actual result is yes: a false negative
      bt->btbf->nfns++;
    } else {
      bt->btbf->nfps++;
    }
  }
}

  static bool
blbf_lookup(const struct bt * bt, const u32 pageid, const struct kref * const key)
{
  struct blbf * blbf = bt->blbf;
  if (blbf == NULL) {
    return true;
  }

  blbf->nqueries++;

  debug_assert(pageid < blbf->nr_leaf);
  const u32 bf_offset = blbf->bfs_offset + blbf->bf_offs[pageid];
  const u32 bf_page = bf_offset >> PGBITS;
  const u8 * const page = bt_page_acquire(bt, bf_page);
  // get offset in the page
  const u32 page_offset = bf_offset & ((1 << PGBITS) - 1);
  struct bf * bf = (void *)page + page_offset;

  struct bf_header {
    u64 nrprobe;
    u64 nbits;
    u64 nbytes;
    u64 ones;
  };

  struct bf_header * hdr = (void *)bf;
  // making sure bf_test is safe
  debug_assert((page_offset + sizeof(*hdr) + hdr->nbytes) <= PGSZ);
  (void)hdr;

  const u64 hash = byte_hash64(key->ptr, key->len);
  bool r = bf_test(bf, hash);
  bt_page_release(bt->rc, page);
  return r;
}

  static void
blbf_log_metrics(const struct bt * bt, const bool predict, const bool result)
{
  if (bt->blbf == NULL)
    return;

  if (predict == result) {
    if (result == true) {
      bt->blbf->ntps++;
    } else {
      bt->blbf->ntns++;
    }
  } else {
    if (predict == false) {
      // bloom says no, but actual result is yes: a false negative
      bt->blbf->nfns++;
    } else {
      bt->blbf->nfps++;
    }
  }
}

  static bool
bt_iter_match(struct bt_iter * const iter, const struct kref * const key)
{
  struct bt * bt = iter->bt;
  if (bt->meta.nr_leaf == 0)
    return false;

  // first way: check bloom filters before we go into the index
  const bool might_exist = btbf_lookup(bt, key);
  if (might_exist == false) {
    return false;
  }

  iter->nr_leaf = bt->meta.nr_leaf;
  iter->ptr.pageid = bt_seek_pageid(bt, key);
  iter->kvdata = NULL;

  // second way: check the bloom filter after we are in at a leaf node
  // save one I/O to the actual leaf block
  const bool might_exist1 = blbf_lookup(bt, iter->ptr.pageid, key);
  if (might_exist1 == false) {
    return false;
  }

  const bool match = bt_page_seek_leaf(iter, key);
  btbf_log_metrics(bt, might_exist, match);
  blbf_log_metrics(bt, might_exist1, match);
  return match;
}

  struct kv *
bt_get(struct bt * const bt, const struct kref * const key, struct kv * const out)
{
  struct bt_iter iter;
  iter.bt = bt;
  const bool match = bt_iter_match(&iter, key);
  struct kv * const ret = match ? bt_iter_peek(&iter, out) : NULL;
  bt_iter_park(&iter);
  return ret;
}

  bool
bt_probe(struct bt * const bt, const struct kref * const key)
{
  struct bt_iter iter;
  iter.bt = bt;
  const bool match = bt_iter_match(&iter, key);
  bt_iter_park(&iter);
  return match;
}

  struct kv *
bt_first_key(struct bt * const bt, struct kv * const out)
{
  if (bt->meta.nr_leaf == 0)
    return NULL;

  struct bt_iter iter;
  iter.bt = bt;
  iter.nr_leaf = bt->meta.nr_leaf;
  iter.ptr.pageid = 0;
  iter.ptr.keyid = 0;
  iter.kvdata = NULL;
  bt_iter_fix_kv(&iter);
  iter.vlen = 0; // hide the value

  struct kv * const ret = bt_iter_peek(&iter, out);
  bt_iter_park(&iter);
  return ret;
}

  struct kv *
bt_last_key(struct bt * const bt, struct kv * const out)
{
  if (bt->meta.nr_leaf == 0)
    return NULL;

  struct bt_iter iter;
  iter.bt = bt;
  iter.nr_leaf = bt->meta.nr_leaf;
  iter.ptr.pageid = iter.nr_leaf - 1;

  const u8 * const page = bt_page_acquire(bt, iter.ptr.pageid);
  const u16 nkeys = bt_page_nkeys(page);
  iter.ptr.keyid = nkeys - 1;
  bt_iter_decode_kv(&iter, page);
  iter.vlen = 0; // hide the value

  struct kv * const ret = bt_iter_peek(&iter, out);
  bt_iter_park(&iter);
  return ret;
}
// }}} bt

// mbt {{{
struct mbt {
  u64 seq;
  u32 nr_runs;
  u32 refcnt; // not atomic: -- in mbtz_gc(); ++ in append-to-v; no race condition
  union {
    struct remix * remix; // optional
    struct dummy * dummy;
    struct findex * findex;
  };
  // mbt is both x and y, if it has remix, it's y
  struct rcache * rc;
  struct bt bts[MSST_NR_RUNS];
};
// }}} mbt

// mbtx {{{
struct mbtx_iter {
  struct mbt * mbt;
  u32 nr_runs;
  // minheap
  struct bt_iter * mh[MSST_NR_RUNS+1];
  struct bt_iter iters[MSST_NR_RUNS];
};

  struct mbt *
mbtx_open_at_reuse(const int dfd, const u64 seq, const u32 nr_runs, struct mbt * const mbt0, const u32 nrun0)
{
  if (nr_runs > MSST_NR_RUNS)
    return NULL;
  struct mbt * const mbt = calloc(1, sizeof(*mbt));
  if (mbt == NULL)
    return NULL;

  debug_assert(nrun0 <= nr_runs);
  for (u32 i = 0; i < nrun0; i++) {
    debug_assert(mbt0->bts[i].refcnt == 1);
    mbt->bts[i] = mbt0->bts[i];
    // only increment the old's refcnt
    mbt0->bts[i].refcnt++;
  }

  u64 nr_keys = 0;
  u64 nr_pages = 0;

  for (u32 i = 0; i < nrun0; i++) {
    struct btmeta * meta = &mbt->bts[i].meta;
    nr_keys += meta->nr_kvs;
    nr_pages += meta->root;

    logger_printf("%s btmeta: run %u nr_kv %u depth %u nr_leaf %u root %u\n", __func__, i,
        meta->nr_kvs, meta->depth, meta->nr_leaf, meta->root);
  }

  logger_printf("%s seq %lu nr_runs %u\n", __func__, seq, nr_runs);
  for (u32 i = nrun0; i < nr_runs; i++) {
    // it uses pread to open a bt file
    if (!bt_init_at(dfd, seq, i, &(mbt->bts[i]))) {
      // error
      for (u64 j = 0; j < i; j++)
        bt_deinit(&(mbt->bts[j]));

      free(mbt);
      return NULL;
    }
    struct btmeta * meta = &mbt->bts[i].meta;
    nr_keys += meta->nr_kvs;
    nr_pages += meta->root;

    logger_printf("%s btmeta: run %u nr_kv %u depth %u nr_leaf %u root %u\n", __func__, i,
        meta->nr_kvs, meta->depth, meta->nr_leaf, meta->root);
  }
  logger_printf("%s summary nr_keys %lu nr_pages %lu\n", __func__, nr_keys, nr_pages);
  mbt->seq = seq;
  mbt->nr_runs = nr_runs;
  return mbt;
}

  inline void
mbt_add_refcnt(struct mbt * mbt)
{
  mbt->refcnt++;
}

  struct mbt *
mbtx_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  return mbtx_open_at_reuse(dfd, seq, nr_runs, NULL, 0);
}

  inline struct mbt *
mbtx_open(const char * const dirname, const u64 seq, const u32 nr_runs)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return NULL;
  struct mbt * const mbt = mbtx_open_at_reuse(dfd, seq, nr_runs, NULL, 0);
  close(dfd);
  return mbt;
}

  inline u32
mbtx_nr_pages(struct mbt * const mbt)
{
  u32 nr_pages = 0;
  for (u32 i = 0; i < mbt->nr_runs; i++)
    nr_pages += bt_nr_pages(&(mbt->bts[i]));
  return nr_pages;
}

  inline void
mbtx_rcache(struct mbt * const mbt, struct rcache * const rc)
{
  mbt->rc = rc;
  for (u32 i = 0; i < mbt->nr_runs; i++)
    bt_rcache(&(mbt->bts[i]), rc);
}

  static void
mbtx_destroy_lazy(struct mbt * const mbt)
{
  debug_assert(mbt->remix == NULL);
  for (u32 i = 0; i < mbt->nr_runs; i++)
    bt_deinit_lazy(&(mbt->bts[i]));
  free(mbt);
}

  void
mbtx_destroy(struct mbt * const mbt)
{
  debug_assert(mbt->remix == NULL);
  for (u32 i = 0; i < mbt->nr_runs; i++)
    bt_deinit(&(mbt->bts[i]));
  free(mbt);
}

  void
mbtx_drop(struct mbt * const mbt)
{
  if (mbt->refcnt == 1) {
    mbtx_destroy(mbt);
  } else {
    mbt->refcnt--;
  }
}

  void
mbtx_drop_lazy(struct mbt * const mbt)
{
  if (mbt->refcnt == 1) {
    mbtx_destroy_lazy(mbt);
  } else {
    mbt->refcnt--;
  }
}

  void
mbtx_fprint(struct mbt * const mbt, FILE * const fout)
{
  const u32 nr_runs = mbt->nr_runs;
  fprintf(fout, "%s seq %lu nr_runs %u\n", __func__, mbt->seq, nr_runs);
  for (u32 i = 0; i < nr_runs; i++)
    bt_fprint(&(mbt->bts[i]), fout);
}

  static struct kv *
mbtx_first_key(struct mbt * const mbt, struct kv * const out)
{
  if (mbt->nr_runs == 0) {
    return NULL;
  }

  struct kv * const tmp = malloc(sizeof(*tmp) + SST_MAX_KVSZ);
  struct kv * const min = bt_first_key(&(mbt->bts[0]), out);

  for (u32 i = 0; i < mbt->nr_runs; i++) {
    struct kv * const curr = bt_first_key(&(mbt->bts[i]), tmp);
    if (kv_compare(curr, min) < 0) {
      kv_dup2(curr, min);
    }
  }

  free(tmp);
  return min;
}

  static struct kv *
mbtx_last_key(struct mbt * const mbt, struct kv * const out)
{
  if (mbt->nr_runs == 0) {
    return NULL;
  }

  struct kv * const tmp = malloc(sizeof(*tmp) + SST_MAX_KVSZ);
  struct kv * const max = bt_last_key(&(mbt->bts[0]), out);

  for (u32 i = 0; i < mbt->nr_runs; i++) {
    struct kv * const curr = bt_last_key(&(mbt->bts[i]), tmp);
    if (kv_compare(curr, max) > 0) {
      kv_dup2(curr, max);
    }
  }

  free(tmp);
  return max;
}

  struct mbtx_iter *
mbtx_iter_create(struct mbtx_ref * const ref)
{
  return (struct mbtx_iter *)ref;
}

  struct mbtx_iter *
mbtx_iter_new()
{
  struct mbtx_iter * const iter = malloc(sizeof(*iter));
  return iter;
}

  void
mbtx_iter_init(struct mbtx_iter * const iter, struct mbt * const mbt)
{
  iter->mbt = mbt;
  iter->nr_runs = mbt->nr_runs;
  for (u32 i = 0; i < mbt->nr_runs; i++) {
    bt_iter_init(&(iter->iters[i]), &(mbt->bts[i]), (u8)i);
    iter->mh[i+1] = &(iter->iters[i]);
  }
}

  inline bool
mbtx_iter_ts(struct mbtx_iter * const iter)
{
  struct bt_iter * bt_iter = iter->mh[1];
  debug_assert(bt_iter_valid(bt_iter));
  bt_iter_fix_kv(bt_iter);
  return bt_iter->vlen == SST_VLEN_TS;
}

  static struct bt_iter *
mbtx_iter_match(struct mbtx_iter * const iter, const struct kref * const key, const bool hide_ts)
{
  struct mbt * mbt = iter->mbt;

  for (u32 i = mbt->nr_runs-1; i < mbt->nr_runs; i--) {
    struct bt_iter * bt_iter = &(iter->iters[i]);
    const bool match = bt_iter_match(bt_iter, key);
    if (match) {
      if (hide_ts && bt_iter_ts(bt_iter)) {
        return NULL;
      }
      return bt_iter;
    }
  }
  return NULL;
}

  static struct kv *
mbtx_get_internal(struct mbtx_ref * const ref, const struct kref * const key,
    struct kv * const out, const bool hide_ts)
{
  struct mbtx_iter * const iter = (typeof(iter))ref;
  struct bt_iter * const iter1 = mbtx_iter_match(iter, key, hide_ts);
  if (iter1) {
    struct kv * const ret = bt_iter_peek(iter1, out);
    mbtx_iter_park(iter);
    return ret;
  } else {
    return NULL;
  }
}

  struct kv *
mbtx_get(struct mbtx_ref * const ref, const struct kref * const key, struct kv * const out)
{
  return mbtx_get_internal(ref, key, out, false);
}

  struct kv *
mbtx_get_ts(struct mbtx_ref * const ref, const struct kref * const key, struct kv * const out)
{
  return mbtx_get_internal(ref, key, out, true);
}

  bool
mbtx_get_value_ts(struct mbtx_ref * const ref, const struct kref * key, void * const vbuf_out, u32 * const vlen_out)
{
  struct mbtx_iter * const iter = (typeof(iter))ref;
  struct bt_iter * const iter1 = mbtx_iter_match(iter, key, true);
  if (iter1) {
    memcpy(vbuf_out, iter1->kvdata + iter1->klen, iter1->vlen);
    *vlen_out = iter1->vlen;
    mbtx_iter_park(iter);
    return true;
  } else {
    return false;
  }
}

  static bool
mbtx_probe_internal(struct mbtx_ref * const ref, const struct kref * const key, const bool hide_ts)
{
  struct mbtx_iter * const iter = (typeof(iter))ref;
  struct bt_iter * const iter1 = mbtx_iter_match(iter, key, hide_ts);
  if (iter1) {
    mbtx_iter_park(iter);
    return true;
  } else {
    return false;
  }
}

  bool
mbtx_probe(struct mbtx_ref * const ref, const struct kref * const key)
{
  return mbtx_probe_internal(ref, key, false);
}

  bool
mbtx_probe_ts(struct mbtx_ref * const ref, const struct kref * const key)
{
  return mbtx_probe_internal(ref, key, true);
}

// mh {{{
  static void
mbtx_mh_swap(struct mbtx_iter * const iter, const u32 cidx)
{
  debug_assert(cidx > 1);
  struct bt_iter * const tmp = iter->mh[cidx];
  iter->mh[cidx] = iter->mh[cidx>>1];
  iter->mh[cidx>>1] = tmp;
}

  static bool
mbtx_mh_should_swap(struct bt_iter * const sp, struct bt_iter * const sc)
{
  debug_assert(sp != sc);
  debug_assert(sp->rank != sc->rank);
  if (!bt_iter_valid(sp))
    return true;
  if (!bt_iter_valid(sc))
    return false;

  const int c = bt_iter_compare(sp, sc);
  if (c > 0)
    return true;
  else if (c < 0)
    return false;
  return sp->rank < sc->rank; // high rank == high priority
}

  static void
mbtx_mh_uphead(struct mbtx_iter * const iter, u32 idx)
{
  while (idx > 1) {
    struct bt_iter * const sp = iter->mh[idx >> 1];
    struct bt_iter * const sc = iter->mh[idx];
    if (!bt_iter_valid(sc))
      return;
    if (mbtx_mh_should_swap(sp, sc))
      mbtx_mh_swap(iter, idx);
    else
      return;
    idx >>= 1;
  }
}

  static void
mbtx_mh_downheap(struct mbtx_iter * const iter, u32 idx)
{
  const u32 nr_runs = iter->nr_runs;
  while ((idx<<1) <= nr_runs) {
    struct bt_iter * sl = iter->mh[idx<<1];
    u32 idxs = idx << 1;
    if ((idx<<1) < nr_runs) { // has sr
      struct bt_iter * sr = iter->mh[(idx<<1) + 1];
      if (mbtx_mh_should_swap(sl, sr))
        idxs++;
    }

    if (mbtx_mh_should_swap(iter->mh[idx], iter->mh[idxs]))
      mbtx_mh_swap(iter, idxs);
    else
      return;
    idx = idxs;
  }
}
// }}} mh

  bool
mbtx_iter_valid(struct mbtx_iter * const iter)
{
  return iter->nr_runs && bt_iter_valid(iter->mh[1]);
}

  static inline bool
mbtx_iter_valid_1(struct mbtx_iter * const iter)
{
  return iter->nr_runs != 0;
}

  void
mbtx_iter_seek(struct mbtx_iter * const iter, const struct kref * const key)
{
  const u32 nr_runs = iter->nr_runs;
  for (u32 i = 1; i <= nr_runs; i++) {
    struct bt_iter * const iter1 = iter->mh[i];
    bt_iter_seek(iter1, key);
    if (bt_iter_valid(iter1))
      bt_iter_fix_kv(iter1);
  }
  for (u32 i = 2; i <= nr_runs; i++)
    mbtx_mh_uphead(iter, i);
}

  void
mbtx_iter_seek_null(struct mbtx_iter * const iter)
{
  const u32 nr_runs = iter->nr_runs;
  for (u32 i = 1; i <= nr_runs; i++) {
    struct bt_iter * const iter1 = iter->mh[i];
    bt_iter_seek_null(iter1);
    if (bt_iter_valid(iter1))
      bt_iter_fix_kv(iter1);
  }
  for (u32 i = 2; i <= nr_runs; i++)
    mbtx_mh_uphead(iter, i);
}

  struct mbtx_ref *
mbtx_ref(struct mbt * const mbt)
{
  struct mbtx_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;

  mbtx_iter_init(iter, mbt);
  return (struct mbtx_ref *)iter;
}

  struct mbt *
mbtx_unref(struct mbtx_ref * const ref)
{
  struct mbtx_iter * const iter = (typeof(iter))ref;
  struct mbt * const mbt = iter->mbt;
  mbtx_iter_park(iter);
  free(iter);
  return mbt;
}

  struct kv *
mbtx_iter_peek(struct mbtx_iter * const iter, struct kv * const out)
{
  if (!mbtx_iter_valid_1(iter))
    return NULL;
  return bt_iter_peek(iter->mh[1], out);
}

  bool
mbtx_iter_kref(struct mbtx_iter * const iter, struct kref * const kref)
{
  if (!mbtx_iter_valid_1(iter))
    return false;

  return bt_iter_kref(iter->mh[1], kref);
}

  bool
mbtx_iter_kvref(struct mbtx_iter * const iter, struct kvref * const kvref)
{
  if (!mbtx_iter_valid_1(iter))
    return false;

  return bt_iter_kvref(iter->mh[1], kvref);
}

  inline u64
mbtx_iter_retain(struct mbtx_iter * const iter)
{
  return bt_iter_retain(iter->mh[1]);
}

  inline void
mbtx_iter_release(struct mbtx_iter * const iter, const u64 opaque)
{
  // all should use the same rcache
  bt_page_release(iter->mbt->rc, (const u8 *)opaque);
}

  void
mbtx_iter_skip1(struct mbtx_iter * const iter)
{
  if (!mbtx_iter_valid(iter))
    return;
  struct bt_iter * const iter1 = iter->mh[1];
  bt_iter_skip1(iter1);
  if (bt_iter_valid(iter1))
    bt_iter_fix_kv(iter1);
  mbtx_mh_downheap(iter, 1);
}

  void
mbtx_iter_skip(struct mbtx_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!mbtx_iter_valid(iter))
      return;
    struct bt_iter * const iter1 = iter->mh[1];
    bt_iter_skip1(iter1);
    if (bt_iter_valid(iter1))
      bt_iter_fix_kv(iter1);
    mbtx_mh_downheap(iter, 1);
  }
}

  struct kv *
mbtx_iter_next(struct mbtx_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mbtx_iter_peek(iter, out);
  mbtx_iter_skip1(iter);
  return ret;
}

  void
mbtx_iter_park(struct mbtx_iter * const iter)
{
  const u32 nr_runs = iter->nr_runs;
  for (u32 i = 0; i < nr_runs; i++)
    bt_iter_park(&(iter->iters[i]));
}

  void
mbtx_iter_destroy(struct mbtx_iter * const iter)
{
  mbtx_iter_park(iter);
}

struct dummy {
  struct kv * first_key;
  struct kv * last_key;
};

struct findex {
  struct bt bt;
  struct kv * first_key;
  struct kv * last_key;
};

// TODO: separate out x_stats from dummy_stats
  void
mbtx_stats(const struct mbt * const mbt, struct msst_stats * const stats)
{
  memset(stats, 0, sizeof(*stats));
  for (u32 i = 0; i < mbt->nr_runs; i++) {
    const struct bt * const bt = &(mbt->bts[i]);
    stats->data_sz += (PGSZ * bt->meta.nr_leaf);
    stats->meta_sz += sizeof(bt->meta);
    stats->totkv += bt->meta.nr_kvs;
    const struct btmeta * const meta = &bt->meta;
    stats->totsz +=
      (PGSZ * (meta->root + 1)) + meta->btbf_size + meta->blbf_size + sizeof(*meta);
  }
  stats->nr_runs = mbt->nr_runs;
  stats->valid = stats->totkv;
  struct dummy * dummy = mbt->dummy;
  stats->ssty_sz = 0;
  if (dummy != NULL) {
    if (dummy->first_key) {
      stats->ssty_sz += (dummy->first_key->klen + sizeof(u32));
    }
    if (dummy->last_key) {
      stats->ssty_sz += (dummy->last_key->klen + sizeof(u32));
    }
  }
}

// TODO: this could be reduced by storing a kvmap_api in fs
  void
mbtx_miter_major(struct mbt * const mbt, struct miter * const miter)
{
  miter_add(miter, &kvmap_api_mbtx, mbt);
}
// }}} mbtx

// {{{ mbtx_dummy
  static struct dummy *
dummy_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  char fn[16];
  const u64 magic = seq * 100lu + nr_runs;
  sprintf(fn, "%03lu.dummy", magic);
  const int fd = openat(dfd, fn, O_RDONLY);
  if (fd < 0)
    return NULL;

  struct dummy * dummy = malloc(sizeof(*dummy));

  const size_t fsize = fdsize(fd);
  debug_assert(fsize >= (2 * sizeof(u32)));
  debug_assert(fsize < 2 * (SST_MAX_KVSZ + sizeof(u32)));

  void * const buff = malloc(fsize);
  u64 bytes_read = pread(fd, buff, fsize, 0);
  debug_assert(bytes_read >= (2 * sizeof(u32)));
  debug_assert(bytes_read < (2 * (sizeof(u32) + SST_MAX_KVSZ)));

  const u32 k0_len = *(u32*)(buff + fsize - (2 * sizeof(u32)));
  debug_assert(k0_len < SST_MAX_KVSZ);
  const u32 kz_len = *(u32*)(buff + fsize - sizeof(u32));
  debug_assert(kz_len < SST_MAX_KVSZ);

  struct kv * k0 = calloc(1, sizeof(*k0) + k0_len);
  memcpy(k0->kv, buff, k0_len);
  k0->klen = k0_len;

  struct kv * kz = calloc(1, sizeof(*kz) + kz_len);
  memcpy(kz->kv, buff + k0_len, kz_len);
  kz->klen = kz_len;

  dummy->first_key = k0;
  dummy->last_key = kz;

  free(buff);

  logger_printf("%s seq %lu nr_runs %u\n", __func__,
      seq, nr_runs);
  return dummy;
}

  static bool
mbtx_open_d_at(const int dfd, struct mbt * const mbt)
{
  debug_assert(mbt->dummy == NULL);
  struct dummy * const dummy = dummy_open_at(dfd, mbt->seq, mbt->nr_runs);
  mbt->dummy = dummy;
  return dummy != NULL;
}

// dummy has this format
// [key0] [keyz] [4: key0_len] [4: keyz_len]

  static u32
dummy_build_at(const int dfd, struct mbt * const x1)
{
  char fn[24];
  const u64 magic = mbt_get_magic(x1);
  sprintf(fn, "%03lu.dummy", magic);
  const int fdout = openat(dfd, fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  if (fdout < 0)
    return 0;

  struct kv * k0 = mbtx_first_key(x1, NULL);
  struct kv * kz = mbtx_last_key(x1, NULL);
  const u32 k0_len = k0 ? k0->klen : 0;
  const u32 kz_len = kz ? kz->klen : 0;

  u32 bytes_written = 0;

  if (k0) {
    write(fdout, k0->kv, k0_len);
    bytes_written += k0_len;
  }
  if (kz) {
    write(fdout, kz->kv, kz_len);
    bytes_written += kz_len;
  }

  write(fdout, &k0_len, sizeof(k0_len));
  bytes_written += sizeof(k0_len);
  write(fdout, &kz_len, sizeof(kz_len));
  bytes_written += sizeof(kz_len);

  fdatasync(fdout);
  close(fdout);

  free(k0);
  free(kz);
  return bytes_written;
}

  void
dummy_destroy(struct dummy * const dummy)
{
  free(dummy->first_key);
  free(dummy->last_key);
  free(dummy);
}

  struct mbt *
mbtd_create_at(const int dfd)
{
  struct mbt * mbt = mbtx_open_at(dfd, 0, 0);
  if (mbt == NULL) {
    return NULL;
  }

  if (dummy_build_at(dfd, mbt) == false) {
    mbtx_destroy(mbt);
    return NULL;
  }

  if (mbtx_open_d_at(dfd, mbt) == false) {
    mbtx_destroy(mbt);
    return NULL;
  }

  return mbt;
}

  static void
mbtd_destroy_lazy(struct mbt * const mbt)
{
  dummy_destroy(mbt->dummy);
  for (u32 i = 0; i < mbt->nr_runs; i++)
    bt_deinit_lazy(&(mbt->bts[i]));
  free(mbt);
}

  void
mbtd_drop(struct mbt * const mbt)
{
  if (mbt->refcnt == 1) {
    mbtd_destroy(mbt);
  } else {
    mbt->refcnt--;
  }
}

  void
mbtd_drop_lazy(struct mbt * const mbt)
{
  if (mbt->refcnt == 1) {
    mbtd_destroy_lazy(mbt);
  } else {
    mbt->refcnt--;
  }
}

  void
mbtd_destroy(struct mbt * const mbt)
{
  dummy_destroy(mbt->dummy);
  mbt->dummy = NULL;
  mbtx_destroy(mbt);
}

  struct kv *
mbtd_first_key(struct mbt * const mbt, struct kv * const out)
{
  debug_assert(mbt->dummy);
  return kv_dup2(mbt->dummy->first_key, out);
}

  struct kv *
mbtd_last_key(struct mbt * const mbt, struct kv * const out)
{
  debug_assert(mbt->dummy);
  return kv_dup2(mbt->dummy->last_key, out);
}

  struct mbt *
dummy_build_at_reuse(const int dfd, struct rcache * const rc,
    struct msstz_ytask * task, struct msstz_cfg * zcfg, u64 * ysz)
{
  (void)zcfg;
  struct mbt * mbt = mbtx_open_at_reuse(dfd, task->seq1, task->run1,
      task->y0, task->run0);

  mbtx_rcache(mbt, rc);
  u32 size = dummy_build_at(dfd, mbt);
  if (size == 0) {
    debug_die();
  }
  *ysz = size;

  if (mbtx_open_d_at(dfd, mbt) == false) {
    debug_die();
  }

  return mbt;
}

  struct mbt *
mbtd_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  struct mbt * const mbt = mbtx_open_at(dfd, seq, nr_runs);
  if (mbt == NULL)
    return NULL;

  if (mbtx_open_d_at(dfd, mbt) == false) {
    mbtx_destroy(mbt);
    return NULL;
  }

  return mbt;
}
// }}}

// remix {{{
struct remixmeta {
  struct btmeta btmeta;
  u32 nr_runs;
  u32 nr_keys; // all keys including ts and stale

  u32 first_key_off;
  u32 first_key_len;
  u32 last_key_off;
  u32 last_key_len;
  bool tags;
  bool dbits;
  u8 padding[6];

  struct {
    u32 valid_kv_up; // [i]: valid kvs from run[i] and above (ts=false and stale=false)
    u32 stale_kv_up; // [i]: stale kvs from run[i] and above (ts=false and stale=true)
    u32 valid_ts_up; // [i]: valid tss from run[i] and above (ts=true and stale=false)
    u32 stale_ts_up; // [i]: stale tss from run[i] and above (ts=true and stale=true)
  } stats[MSST_NR_RUNS];
};

struct remix {
  struct bt bt;
  struct remixmeta meta;
  struct kv * first_key;
  struct kv * last_key;
  u32 nr_runs;
  u32 fsize; // need this value to find the remixmeta
  bool tags;
  bool dbits;
  u8 padding[6];
};

  static struct remix *
remix_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  char fn[16];
  const u64 magic = seq * 100lu + nr_runs;
  sprintf(fn, "%03lu.remix", magic);
  const int fd = openat(dfd, fn, REMIX_OPEN_FLAGS);
  if (fd < 0)
    return NULL;

  struct remix * const remix = malloc(sizeof(*remix));
  const size_t fsize = fdsize(fd);
  debug_assert(fsize >= sizeof(struct remixmeta) && fsize < UINT32_MAX);
  u64 first_last_meta = bits_round_down(fsize, PGBITS);

  u64 alloc_sz;
  void * const buff = pages_alloc_best(sizeof(remix->meta), false, &alloc_sz);
  debug_assert(alloc_sz == PGSZ);
  const int read_size = pread(fd, buff, alloc_sz, (off_t)first_last_meta);
  debug_assert(read_size > 0);

  const size_t meta_off = read_size - sizeof(remix->meta);
  memcpy(&remix->meta, buff + meta_off, sizeof(remix->meta));
  debug_assert(remix->meta.nr_runs == nr_runs);

  struct kv * const first_key = calloc(1, sizeof(*first_key) + remix->meta.first_key_len);
  memcpy(first_key->kv, buff, (off_t)remix->meta.first_key_len);
  first_key->klen = remix->meta.first_key_len;
  remix->first_key = first_key;

  struct kv * const last_key = calloc(1, sizeof(*last_key) + remix->meta.last_key_len);
  memcpy(last_key->kv, buff + remix->meta.first_key_len, remix->meta.last_key_len);
  pages_unmap(buff, alloc_sz);
  last_key->klen = remix->meta.last_key_len;
  remix->last_key = last_key;

  const bool r = bt_init(fd, &remix->meta.btmeta, &remix->bt, true);
  if (!r) {
    free(first_key);
    free(last_key);

    close(fd);
    free(remix);
    return NULL;
  }
  remix->nr_runs = nr_runs;
  remix->fsize = (u32)fsize;
  remix->tags = remix->meta.tags;
  remix->dbits = remix->meta.dbits;

  logger_printf("%s seq %lu nr_runs %u nr_keys %u nr_pages %u\n", __func__,
                seq, nr_runs, remix->bt.meta.nr_kvs, remix->bt.meta.root);

  return remix;
}

  void
remix_destroy(struct remix * const remix)
{
  free(remix->first_key);
  free(remix->last_key);
  debug_assert(remix);
  bt_deinit(&remix->bt);
  free(remix);
}

  void
remix_fprint(struct remix * const remix, FILE * const out)
{
  bt_fprint(&remix->bt, out);
  fprintf(out, "%s nr_runs %u fsize %u\n", __func__, remix->nr_runs, remix->fsize);
}

/*
 * // to dump
 * struct remix * const remix = remix_open_at(dfd, seq, nr_runs);
 * sprintf(fn, "%03lu.remix.txt", magic);
 * remix_dump(remix, fn);
 * remix_destroy(remix);
 *
 * struct mbt * mbty = mbty_open_at(dfd, seq, nr_runs);
 * sprintf(fn, "%03lu.mbty.txt", magic);
 * mbty_dump(mbty, fn);
 * mbty_destroy(mbty);
 *
 * char dump_path[32];
 * sprintf(dump_path, "/tmp/%s.dump", fn);
 * logger_printf("%s dumping remix to %s\n", __func__, dump_path);
 * remix_dump(remix, dump_path);
 **/
  void
remix_dump(struct remix * const remix, const char * const filename)
{
  FILE * const fout = fopen(filename, "w");
  struct bt_iter * const iter = bt_iter_create(&remix->bt);
  struct kv * const kv = malloc(sizeof(*kv) + PGSZ);
  bt_iter_seek(iter, kref_null());
  u32 totkv = 0;
  while (bt_iter_valid(iter)) {
    bt_iter_peek(iter, kv);
    u8 * vptr = kv_vptr(kv);
    const u32 nkeys = *vptr;
    u32 vlen = 1 + (sizeof(struct bt_ptr) * remix->nr_runs) + nkeys;
    if (remix->tags) {
      vlen += nkeys;
    }
    if (remix->dbits) {
      vlen += (4 * nkeys);
      const u32 dk_vlen = vptr[vlen];
      vlen += (1 + 1 + dk_vlen);
    }
    debug_assert(kv->vlen == vlen);

    fprintf(fout, "%.*s %u:", kv->klen, kv->kv, nkeys);
    vptr++;

    const struct bt_ptr * const ptrs = (typeof(ptrs))vptr;
    for (u32 i = 0; i < remix->nr_runs; i++)
      fprintf(fout, " %hu:%hu", ptrs[i].pageid, ptrs[i].keyid);
    vptr += (sizeof(struct bt_ptr) * remix->nr_runs);

    for (u32 i = 0; i < nkeys; i++)
      fprintf(fout, " %02hhx", vptr[i]);

    fprintf(fout, "\n");
    totkv += nkeys;
    bt_iter_skip1(iter);
  }
  free(kv);
  bt_iter_destroy(iter);
  fprintf(fout, "totkv %u\n", totkv);
  fclose(fout);
}

  static struct kv *
remix_first_key(struct remix * const remix, struct kv * const out)
{
  return kv_dup2(remix->first_key, out);
}

  static struct kv *
remix_last_key(struct remix * const remix, struct kv * const out)
{
  return kv_dup2(remix->last_key, out);
}
// }}} remix

// mbty {{{

// open {{{
  struct mbt *
mbty_create_at(const int dfd)
{
  struct mbt * mbt = mbtx_open_at(dfd, 0, 0);
  if (mbt == NULL) {
    return NULL;
  }

  if (!remix_build_at(dfd, mbt, 0, 0, NULL, 0, false, false, false, NULL, 0)) {
    mbtx_destroy(mbt);
    return NULL;
  }

  if (!mbty_open_y_at(dfd, mbt)) {
    mbtx_destroy(mbt);
    return NULL;
  }

  return mbt;
}

  bool
mbty_open_y_at(const int dfd, struct mbt * const mbt)
{
  debug_assert(mbt->remix == NULL);
  struct remix * const remix = remix_open_at(dfd, mbt->seq, mbt->nr_runs);
  mbt->remix = remix;
  return remix != NULL;
}

// naming convention example: seq=123, nr_runs=8:
// dir/12300.btx, dir/12301.btx, ..., dir/12307.btx, dir/12308.remix
  struct mbt *
mbty_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  struct mbt * const mbt = mbtx_open_at(dfd, seq, nr_runs);
  if (mbt == NULL)
    return NULL;

  if (!mbty_open_y_at(dfd, mbt)) {
    mbtx_destroy(mbt);
    return NULL;
  }

  return mbt;
}

  struct mbt *
mbty_open(const char * const dirname, const u64 seq, const u32 nr_runs)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return NULL;

  struct mbt * const mbt = mbty_open_at(dfd, seq, nr_runs);
  close(dfd);
  return mbt;
}

  inline u32
mbty_nr_pages(struct mbt * const mbt)
{
  const u32 nr_pages_x = mbtx_nr_pages(mbt);
  u32 nr_pages_y = 0;
  if (mbt->remix)
    nr_pages_y = bt_nr_pages(&(mbt->remix->bt));
  return nr_pages_x + nr_pages_y;
}

  inline void
mbty_rcache(struct mbt * const mbt, struct rcache * const rc)
{
  mbtx_rcache(mbt, rc);
  if (mbt->remix != NULL) {
    bt_rcache(&(mbt->remix->bt), rc);
  }
}

  static void
mbty_destroy_lazy(struct mbt * const mbt)
{
  remix_destroy(mbt->remix);
  mbt->remix = NULL;
  mbtx_destroy_lazy(mbt);
}

  void
mbty_drop_lazy(struct mbt * const mbt)
{
  if (mbt->refcnt == 1) {
    mbty_destroy_lazy(mbt);
  } else {
    mbt->refcnt--;
  }
}

  void
mbty_destroy(struct mbt * const mbt)
{
  remix_destroy(mbt->remix);
  mbt->remix = NULL;
  mbtx_destroy(mbt);
}

  void
mbty_drop(struct mbt * const mbt)
{
  if (mbt->refcnt == 1) {
    mbty_destroy(mbt);
  } else {
    mbt->refcnt--;
  }
}

  u64
mbt_get_magic(const struct mbt * const mbt)
{
  const u64 magic = mbt->seq * 100lu + mbt->nr_runs;
  return magic;
}

  void
mbty_fprint(struct mbt * const mbt, FILE * const fout)
{
  const u32 nr_runs = mbt->nr_runs;
  fprintf(fout, "%s seq %lu nr_runs %u\n", __func__, mbt->seq, nr_runs);
  fprintf(fout, "remix bt: ");
  remix_fprint(mbt->remix, fout);
  for (u32 i = 0; i < nr_runs; i++)
    bt_fprint(&(mbt->bts[i]), fout);
}

  struct kv *
mbty_first_key(struct mbt * const mbt, struct kv * const out)
{
  debug_assert(mbt->remix);
  return remix_first_key(mbt->remix, out);
}

  struct kv *
mbty_last_key(struct mbt * const mbt, struct kv * const out)
{
  debug_assert(mbt->remix);
  return remix_last_key(mbt->remix, out);
}
// }}} open

// helpers {{{
struct mbty_iter { // valid if seg_iter is valid
  struct mbt * mbt;
  struct remix * remix; // a copy of mbt->remix
  u32 nr_runs; // const: a copy of remix->nr_runs

  u32 seg_index; // points to a key in the segment
  u32 seg_nkeys; // valid if seg_index < seg_nkeys
  bool tags;
  bool dbits;
  u8 padding[2];
  const u8 * seg_ranks; // remix_iter value ptr
  const u8 * seg_tags;
  // const u32 * pkeys;
  // struct dkey_ref dkey;

  struct pkeys pkeys;

  // iters
  struct bt_iter remix_iter; // points to the current segment
  struct bt_iter iters[MSST_NR_RUNS]; // iters to the runs
};

  u32
mbt_accu_nkv_at(const struct mbt * const mbt, const u32 i)
{
  const u32 nruns = mbt->nr_runs;
  u32 nkv = 0;
  for (u32 j = nruns - 1; j >= i && j < nruns; j--) {
    nkv += mbt->bts[j].meta.nr_kvs;
  }
  return nkv;
}

  u32
mbt_nkv_at(const struct mbt * const mbt, const u32 i)
{
  if (i >= mbt->nr_runs) {
    return 0;
  }
  return mbt->bts[i].meta.nr_kvs;
}

  u32
mbt_nr_pages_at(const struct mbt * const mbt, const u32 i)
{
  if (i >= mbt->nr_runs) {
    return 0;
  }
  return mbt->bts[i].meta.root + 1;
}

  void
mbty_stats(const struct mbt * const mbt, struct msst_stats * const stats)
{
  memset(stats, 0, sizeof(*stats));
  for (u32 i = 0; i < mbt->nr_runs; i++) {
    const struct bt * const bt = &(mbt->bts[i]);
    stats->data_sz += (PGSZ * bt->meta.nr_leaf);
    stats->meta_sz += sizeof(bt->meta);
    stats->totkv += bt->meta.nr_kvs;
    const struct btmeta * const meta = &bt->meta;
    stats->totsz +=
      (PGSZ * (meta->root + 1)) + meta->btbf_size + meta->blbf_size + sizeof(*meta);
  }
  stats->nr_runs = mbt->nr_runs;
  const struct remix * const remix = mbt->remix;
  if (remix != NULL) {
    debug_assert(mbt->nr_runs == remix->nr_runs);
    // TODO: after we added fsize in meta and totsz in remix
    // debug_assert(stats->totsz == remix->fsize);
    stats->ssty_sz = remix->fsize;
    // TODO: check valid count
    stats->valid = remix->meta.stats[0].valid_kv_up;
  }
}

  void
mbty_iter_init(struct mbty_iter * const iter, struct mbt * const mbt)
{
  debug_assert(mbt->remix);
  iter->mbt = mbt;
  struct remix * const remix = mbt->remix;
  iter->remix = remix;
  const u32 nr_runs = remix->nr_runs;
  iter->nr_runs = nr_runs;

  iter->seg_index = 0;
  iter->seg_nkeys = 0;
  iter->tags = remix->tags;
  iter->dbits = remix->dbits;
  iter->seg_ranks = NULL;

  bt_iter_init(&(iter->remix_iter), &(remix->bt), UINT8_MAX); // rank does not matter
  for (u32 i = 0; i < nr_runs; i++)
    bt_iter_init(&(iter->iters[i]), &(mbt->bts[i]), (u8)i);
}

  bool
mbty_iter_valid(const struct mbty_iter * const iter)
{
  const bool valid = iter->seg_nkeys != 0;
  debug_assert((!valid) || (iter->seg_ranks && iter->seg_nkeys && bt_iter_valid(&iter->remix_iter)));
  return valid;
}

// return true if any bt has kvdata
  static bool
mbty_iter_active(struct mbty_iter * const iter)
{
  if (bt_iter_active(&(iter->remix_iter)))
    return true;

  for (u32 i = 0; i < iter->nr_runs; i++)
    if (bt_iter_active(&(iter->iters[i])))
      return true;

  return false;
}

  static inline u8
mbty_iter_rankenc(struct mbty_iter * const iter)
{
  debug_assert(mbty_iter_valid(iter));
  return iter->seg_ranks[iter->seg_index];
}

  inline bool
mbty_iter_ts(struct mbty_iter * const iter)
{
  return (mbty_iter_rankenc(iter) & SSTY_TOMBSTONE) != 0;
}

  static inline bool
mbty_iter_stale(struct mbty_iter * const iter)
{
  return (mbty_iter_rankenc(iter) & SSTY_STALE) != 0;
}

  static inline u8
mbty_iter_rank(struct mbty_iter * const iter)
{
  return mbty_iter_rankenc(iter) & SSTY_RANK;
}

  static struct bt_iter *
mbty_iter_bt_iter(struct mbty_iter * const iter)
{
  return &(iter->iters[mbty_iter_rank(iter)]);
}

// bt_iter_skip1 with rankenc
// rankenc is used to distinguish if the key is the last key
  static void
mbty_bt_iter_skip1(struct bt_iter * const iter, const u8 rankenc)
{
  debug_assert((rankenc & SSTY_RANK) == iter->rank);
  debug_assert(bt_iter_valid(iter));
  struct bt_ptr * const pptr = &iter->ptr;

  if (rankenc & SSTY_TAIL) {
    bt_iter_park(iter); // discard iter->kvdata
    pptr->pageid++;
    pptr->keyid = 0;
  } else {
    pptr->keyid++;
    // it will read the page if the iter has kvdata
    if (iter->kvdata)
      bt_iter_fix_kv_reuse(iter);
  }
}

// for seek only
  static void
mbty_iter_sync_ptrs(struct mbty_iter * const iter)
{
  debug_assert(iter->seg_ranks);
  const struct bt_ptr * const ptrs = (typeof(ptrs))(bt_iter_vptr(&iter->remix_iter) + sizeof(u8));
  const u32 nr_runs = iter->nr_runs;
  for (u32 i = 0; i < nr_runs; i++)
    iter->iters[i].ptr = ptrs[i];
}

  static void
mbty_iter_fix_ptrs(struct mbty_iter * const iter)
{
  debug_assert(iter->seg_ranks);
  const struct bt_ptr * const ptrs = (typeof(ptrs))(bt_iter_vptr(&iter->remix_iter) + sizeof(u8));
  const u32 nr_runs = iter->nr_runs;
  for (u32 i = 0; i < nr_runs; i++) {
    bt_iter_set_ptr(&iter->iters[i], ptrs[i]);
  }
}

  static void
mbty_iter_sync_segment(struct mbty_iter * const iter)
{
  const u8 * const seg_vptr = bt_iter_vptr(&iter->remix_iter);
  iter->seg_index = 0;
  iter->seg_nkeys = seg_vptr[0]; // 1 byte
  iter->seg_ranks = seg_vptr + sizeof(u8) + (sizeof(struct bt_ptr) * iter->nr_runs);
}

  static void
mbty_iter_sync_tags(struct mbty_iter * const iter)
{
  if (iter->tags == false)
    return;
  const u8 * const seg_vptr = bt_iter_vptr(&iter->remix_iter);
  // assuming sync_segment has been called
  const u32 nkeys = iter->seg_nkeys;
  iter->seg_tags = seg_vptr + sizeof(u8) +
                            (sizeof(struct bt_ptr) * iter->nr_runs) +
                            nkeys;
}

  static void
mbty_iter_sync_pkeys(struct mbty_iter * const iter)
{
  if (iter->dbits == false)
    return;
  const u8 * const seg_vptr = bt_iter_vptr(&iter->remix_iter);
  const u32 nkeys = iter->seg_nkeys;
  const u8 * pkeys_ptr = seg_vptr + sizeof(u8) +
                                   (sizeof(struct bt_ptr) * iter->nr_runs) +
                                   nkeys + (iter->tags ? nkeys : 0);
  pkeys_deserialize(&iter->pkeys, nkeys, pkeys_ptr);
}

  struct mbty_iter *
mbty_iter_create(struct mbty_ref * const ref)
{
  // ref is already an iter
  // a ref must not be shared
  return (struct mbty_iter *)ref;
}

  struct mbty_iter *
mbty_iter_new()
{
  struct mbty_iter * const iter = malloc(sizeof(*iter));
  return iter;
}

  void
mbty_iter_park(struct mbty_iter * const iter)
{
  const u32 nr_runs = iter->nr_runs;
  iter->seg_nkeys = 0; // seg_ranks ignored
  bt_iter_park(&(iter->remix_iter));
  for (u32 i = 0; i < nr_runs; i++)
    bt_iter_park(&(iter->iters[i]));
}

  void
mbty_iter_destroy(struct mbty_iter * const iter)
{
  mbty_iter_park(iter);
}

// just for printing all the stats
  static void
mbty_iter_nkeys_stats(struct mbty_iter * const iter)
{
  struct bt_iter * const remix_iter = &iter->remix_iter;
  bt_iter_seek_null(remix_iter);

  const u32 sz = FLUSH_THRE_SEGMENT_NKEYS << 1;
  u32 * hist = calloc(sz, sizeof(hist[0]));
  u32 sum = 0;
  u32 cnt = 0;
  while (bt_iter_valid(remix_iter)) {
    bt_iter_fix_kv(remix_iter);
    const u8 * const seg_vptr = bt_iter_vptr(remix_iter);
    const u32 nkeys = seg_vptr[0];
    debug_assert(nkeys < sz);
    hist[nkeys]++;
    sum += nkeys;
    cnt++;
    bt_iter_skip1(remix_iter);
  }

  for (u32 i = 0; i < sz; i++) {
    if (hist[i] > 0) {
      printf("%u %u\n", i, hist[i]);
    }
  }
  printf("sum %u, cnt %u\n", sum, cnt);
  free(hist);
}
// }}} helpers

// dup {{{
// _dup iterator: return all versions, including old keys and tombstones
  struct kv *
mbty_iter_peek_dup(struct mbty_iter * const iter, struct kv * const out)
{
  if (!mbty_iter_valid(iter))
    return NULL;

  struct bt_iter * const iter1 = mbty_iter_bt_iter(iter);
  return bt_iter_peek(iter1, out);
}

  bool
mbty_iter_kref_dup(struct mbty_iter * const iter, struct kref * const kref)
{
  if (!mbty_iter_valid(iter))
    return false;

  struct bt_iter * const iter1 = mbty_iter_bt_iter(iter);
  return bt_iter_kref(iter1, kref);
}

  bool
mbty_iter_kvref_dup(struct mbty_iter * const iter, struct kvref * const kvref)
{
  if (!mbty_iter_valid(iter))
    return false;

  struct bt_iter * const iter1 = mbty_iter_bt_iter(iter);
  return bt_iter_kvref(iter1, kvref);
}

  void
mbty_iter_skip1_dup(struct mbty_iter * const iter)
{
  if (!mbty_iter_valid(iter))
    return;

  const u8 rankenc = iter->seg_ranks[iter->seg_index];
  const u8 rank = rankenc & SSTY_RANK;
  mbty_bt_iter_skip1(&(iter->iters[rank]), rankenc);
  iter->seg_index++;
  if (iter->seg_index < iter->seg_nkeys)
    return;

  // switch to the next segment or EOF
  struct bt_iter * const remix_iter = &(iter->remix_iter);
  bt_iter_skip1(remix_iter);
  if (bt_iter_valid(remix_iter)) {
    bt_iter_fix_kv(remix_iter);
    mbty_iter_sync_segment(iter);

    const struct bt_ptr * const ptrs = (typeof(ptrs))(bt_iter_vptr(&iter->remix_iter) + sizeof(u8));
    const u32 nr_runs = iter->nr_runs;
    for (u32 i = 0; i < nr_runs; i++) {
      debug_assert(iter->iters[i].ptr.pageid == ptrs[i].pageid);
      debug_assert(iter->iters[i].ptr.keyid == ptrs[i].keyid);
    }
    // assert iters ptrs match remix ptrs
    //mbty_iter_sync_ptrs(iter);
  } else {
    iter->seg_nkeys = 0;
    debug_assert(!mbty_iter_active(iter));
  }
}

  void
mbty_iter_skip_dup(struct mbty_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!mbty_iter_valid(iter))
      return;

    mbty_iter_skip1_dup(iter);
  }
}

  struct kv *
mbty_iter_next_dup(struct mbty_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mbty_iter_peek_dup(iter, out);
  mbty_iter_skip1_dup(iter);
  return ret;
}
// }}} dup

// peek {{{
  struct kv *
mbty_iter_peek(struct mbty_iter * const iter, struct kv * const out)
{
  if (!mbty_iter_valid(iter))
    return NULL;

  debug_assert(!mbty_iter_stale(iter));
  struct bt_iter * const iter1 = mbty_iter_bt_iter(iter);
  return bt_iter_peek(iter1, out);
}

// kvref non-stale keys
  bool
mbty_iter_kref(struct mbty_iter * const iter, struct kref * const kref)
{
  if (!mbty_iter_valid(iter))
    return false;

  debug_assert(!mbty_iter_stale(iter));
  struct bt_iter * const iter1 = mbty_iter_bt_iter(iter);
  return bt_iter_kref(iter1, kref);
}

// kvref non-stale keys
  bool
mbty_iter_kvref(struct mbty_iter * const iter, struct kvref * const kvref)
{
  if (!mbty_iter_valid(iter))
    return false;

  debug_assert(!mbty_iter_stale(iter));
  struct bt_iter * const iter1 = mbty_iter_bt_iter(iter);
  return bt_iter_kvref(iter1, kvref);
}

  u64
mbty_iter_retain(struct mbty_iter * const iter)
{
  debug_assert(mbty_iter_valid(iter));
  struct bt_iter * const iter1 = mbty_iter_bt_iter(iter);
  debug_assert(iter1->bt->rc == iter->remix->bt.rc);
  return bt_iter_retain(iter1);
}

  void
mbty_iter_release(struct mbty_iter * const iter, const u64 opaque)
{
  bt_page_release(iter->remix->bt.rc, (const u8 *)opaque);
}

  void
mbty_iter_seek_null(struct mbty_iter * const iter)
{
  mbty_iter_park(iter);
  bt_iter_seek_null(&iter->remix_iter);
  if (bt_iter_valid(&iter->remix_iter))
    bt_iter_fix_kv(&iter->remix_iter);
  mbty_iter_sync_segment(iter);
  mbty_iter_sync_ptrs(iter);
  if (iter->dbits == true) {
    mbty_iter_sync_pkeys(iter);
  }
}

  struct mbty_ref *
mbty_ref(struct mbt * const mbt)
{
  struct mbty_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;

  mbty_iter_init(iter, mbt);
  (void)mbty_iter_nkeys_stats;
  // mbty_iter_nkeys_stats(iter);
  return (struct mbty_ref *)iter;
}

  struct mbt *
mbty_unref(struct mbty_ref * const ref)
{
  struct mbty_iter * const iter = (typeof(iter))ref;
  struct mbt * const mbt = iter->mbt;
  mbty_iter_park(iter);
  free(iter);
  return mbt;
}
// }}} peek

// seek {{{
  void
mbty_iter_skip1(struct mbty_iter * const iter)
{
  mbty_iter_skip1_dup(iter);
  while (mbty_iter_valid(iter) && mbty_iter_stale(iter))
    mbty_iter_skip1_dup(iter);
}

  void
mbty_iter_skip(struct mbty_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!mbty_iter_valid(iter))
      return;

    mbty_iter_skip1(iter);
  }
}

  struct kv *
mbty_iter_next(struct mbty_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mbty_iter_peek(iter, out);
  mbty_iter_skip1(iter);
  return ret;
}

// similar to mssty_iter_seek_bisect with OPT enabled
// seek in the segment in [seg_index, seg_nkeys]
// the input iter must be valid but may not be active
  static u32
mbty_iter_segment_seek_opt(struct mbty_iter * const iter, const struct kref * const key)
{
  const u8 * const ranks = iter->seg_ranks;
  const u32 i0 = iter->seg_index;

  // if l points to a stale version, the key has already been skipped so l should move forward
  u32 l = i0;
  while ((l < iter->seg_nkeys) && (ranks[l] & SSTY_STALE))
    l++;

  // skip stale slots and placeholders
  // no underflow because the first key of each group is not stale
  u32 r = iter->seg_nkeys;
  debug_assert((ranks[0] & SSTY_STALE) == 0); // the first key is never stale
  while ((r > 1) && (ranks[r - 1] & SSTY_STALE))
    r--;

  while (l < r) {
    const u32 m = (l + r) >> 1;
    const u8 rankm = ranks[m] & SSTY_RANK;
    struct bt_iter * const iterm = &(iter->iters[rankm]);
    const struct bt_ptr ptr0 = iterm->ptr; // save the ptr

    // skip [i0,l), search in [l,r)
    for (u32 i = i0; i < r; i++) { // advance iterm
      const u8 rankenci = ranks[i];
      if ((rankenci & SSTY_RANK) == rankm) {
        if (i < l) { // [i0,l)
          mbty_bt_iter_skip1(iterm, rankenci);
        } else { // [l,r)
          bt_iter_fix_kv(iterm);
          const int cmp = bt_iter_compare_kref(iterm, key);
          if (cmp < 0) { // shrink forward
            mbty_bt_iter_skip1(iterm, rankenci);
            l = i + 1;
          } else if (cmp > 0) { // shrink backward
            r = i;
            break;
          } else { // match: must point to the non-stale version
            l = i;
            while (ranks[l] & SSTY_STALE)
              l--;
            r = i;
            break;
          }
        }
      }
    }
    bt_iter_set_ptr(iterm, ptr0); // recover iterm

    while ((l < iter->seg_nkeys) && (ranks[l] & SSTY_STALE))
      l++;

    while ((r > 1) && (ranks[r - 1] & SSTY_STALE))
      r--;
  }

  // now the iter is at the original position
  // the caller will determine what to do with l
  // 0 <= l <= seg_nkeys
  return l;
}

  static void
mbty_iter_segment_access(struct mbty_iter * iter, const u32 idx, struct kref * out)
{
  const u8 * const ranks = iter->seg_ranks;
  const u8 rank = ranks[idx] & SSTY_RANK;
  struct bt_iter * const biter = &(iter->iters[rank]);
  const struct bt_ptr ptr0 = biter->ptr;
  const u32 i0 = iter->seg_index;
  debug_assert(idx < iter->seg_nkeys);
  for (u32 i = i0; i < idx; i++) {
    const u8 rankenci = ranks[i];
    if ((rankenci & SSTY_RANK) == rank) {
      mbty_bt_iter_skip1(biter, rankenci);
    }
  }
  bt_iter_fix_kv(biter);
  out->len = biter->klen;
  out->ptr = biter->kvdata;
  bt_iter_set_ptr(biter, ptr0);
}

  static bool
mbty_iter_segment_probe_dbits(struct mbty_iter * const iter, const struct kref * const key)
{
  const u8 * const ranks = iter->seg_ranks;
  const u32 l0 = iter->seg_index;
  const u32 r0 = iter->seg_nkeys;
  u32 l = l0;
  while ((l < r0) && (ranks[l] & SSTY_STALE))
    l++;

  u32 r = r0;
  while ((r > 1) && (ranks[r - 1] & SSTY_STALE))
    r--;

  u32 pkey_pos = pkeys_match(&iter->pkeys, key, l, r);
  if (pkey_pos >= r) {
    return false;
  }

  // possibly a match, need to compare with the actual key
  while (ranks[pkey_pos] & SSTY_STALE)
    pkey_pos--;
  const u32 pos = pkey_pos;

  struct kref curr;
  mbty_iter_segment_access(iter, pos, &curr);
  if (key->len != curr.len) {
    return false;
  }
  const u32 len = key->len;
  const int cmp = memcmp(key->ptr, curr.ptr, (size_t)len);

  return (cmp == 0);
}

  static inline u32
mbty_iter_segment_seek_dbits(struct mbty_iter * const iter, const struct kref * const key)
{
  const u8 * const ranks = iter->seg_ranks;
  const u32 l0 = iter->seg_index;
  const u32 r0 = iter->seg_nkeys;

  u32 l = l0;
  while ((l < r0) && (ranks[l] & SSTY_STALE))
    l++;

  u32 r = r0;
  while ((r > 1) && (ranks[r - 1] & SSTY_STALE))
    r--;

  u32 pkey_pos = pkeys_find(&iter->pkeys, key, l, r);

  while (ranks[pkey_pos] & SSTY_STALE)
    pkey_pos--;
  const u32 pos = pkey_pos;

  struct kref curr;
  mbty_iter_segment_access(iter, pos, &curr);

  u32 ret_pos = pkeys_correct(&iter->pkeys, pos, key, &curr, l, r);

  while ((ret_pos < r0) && (ranks[ret_pos] & SSTY_STALE))
    ret_pos++;
  return ret_pos;
}

  void
mbty_iter_seek(struct mbty_iter * const iter, const struct kref * const key)
{
  mbty_iter_park(iter);
  // because it's a seek_le, seek to less than or equal to
  // and the first page is length zero (key_null), it succeeds anyways
  // only returns false when the bt is empty
  if (!bt_iter_seek_le(&iter->remix_iter, key))
    return;

  // points to [0]
  mbty_iter_sync_segment(iter);
  mbty_iter_sync_ptrs(iter);

  // hints
  // tags_off = iter->seg_ranks + iter->seg_nkeys;
  // dbits = tags_off + (iter->tags ? iter->seg_nkeys : 0)

  u32 i; // const
  if (iter->dbits == false) {
    i = mbty_iter_segment_seek_opt(iter, key);
  } else {
    mbty_iter_sync_pkeys(iter);
    i = mbty_iter_segment_seek_dbits(iter, key);
  }

  debug_assert(iter->seg_index <= i && i <= iter->seg_nkeys);
  mbty_iter_skip_dup(iter, i - iter->seg_index);
}
// }}} seek

// point {{{
  static struct bt_iter *
mbty_iter_match(struct mbty_iter * const iter, const struct kref * const key, const bool hide_ts)
{
  mbty_iter_seek(iter, key);
  if (mbty_iter_valid(iter)) {
    debug_assert(!mbty_iter_stale(iter));
    if ((!hide_ts) || (!mbty_iter_ts(iter))) {
      struct bt_iter * const iter1 = mbty_iter_bt_iter(iter);
      bt_iter_fix_kv(iter1);
      if (bt_iter_match_kref(iter1, key))
        return iter1;
    }
    // not found
    mbty_iter_park(iter);
  }

  return NULL;
}

// get at least one I/O
  static struct kv *
mbty_get_internal(struct mbty_ref * const ref, const struct kref * const key, struct kv * const out, const bool hide_ts)
{
  struct mbty_iter * const iter = (typeof(iter))ref;
  struct bt_iter * const iter1 = mbty_iter_match(iter, key, hide_ts);
  if (iter1) {
    struct kv * const ret = bt_iter_peek(iter1, out);
    mbty_iter_park(iter);
    return ret;
  } else {
    return NULL;
  }
}

  static bool
mbty_probe_internal(struct mbty_ref * const ref, const struct kref * const key, const bool hide_ts)
{
  struct mbty_iter * const iter = (typeof(iter))ref;
  mbty_iter_park(iter);
  if (!bt_iter_seek_le(&iter->remix_iter, key))
    return false;

  // points to [0]
  mbty_iter_sync_segment(iter);
  mbty_iter_sync_ptrs(iter);

  if (iter->dbits == true) {
    mbty_iter_sync_pkeys(iter);
    bool e = mbty_iter_segment_probe_dbits(iter, key);
    return e;
  }

  const u32 i = mbty_iter_segment_seek_opt(iter, key);

  debug_assert(iter->seg_index <= i && i <= iter->seg_nkeys);
  mbty_iter_skip_dup(iter, i - iter->seg_index);

  struct bt_iter * const iter1 = mbty_iter_match(iter, key, hide_ts);
  if (iter1) {
    mbty_iter_park(iter);
    return true;
  } else {
    return false;
  }
}
// mbty_get can return tombstone
  struct kv *
mbty_get(struct mbty_ref * const ref, const struct kref * const key, struct kv * const out)
{
  return mbty_get_internal(ref, key, out, false);
}

// mbty_probe can return tombstone
  bool
mbty_probe(struct mbty_ref * const ref, const struct kref * const key)
{
  return mbty_probe_internal(ref, key, false);
}

// return NULL for tomestone
  struct kv *
mbty_get_ts(struct mbty_ref * const ref, const struct kref * const key, struct kv * const out)
{
  return mbty_get_internal(ref, key, out, true);
}

// return false for tomestone
  bool
mbty_probe_ts(struct mbty_ref * const ref, const struct kref * const key)
{
  return mbty_probe_internal(ref, key, true);
}

  bool
mbty_get_value_ts(struct mbty_ref * const ref, const struct kref * key,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct mbty_iter * const iter = (typeof(iter))ref;
  struct bt_iter * const iter1 = mbty_iter_match(iter, key, true);
  if (iter1) {
    memcpy(vbuf_out, iter1->kvdata + iter1->klen, iter1->vlen);
    *vlen_out = iter1->vlen;
    mbty_iter_park(iter);
    return true;
  } else {
    return false;
  }
}
// }}} point

// ts {{{
// hide tomestones
  void
mbty_iter_seek_ts(struct mbty_iter * const iter, const struct kref * const key)
{
  mbty_iter_seek(iter, key);
  while (mbty_iter_valid(iter) && mbty_iter_ts(iter))
    mbty_iter_skip1(iter);
}

  void
mbty_iter_skip1_ts(struct mbty_iter * const iter)
{
  if (!mbty_iter_valid(iter))
    return;
  mbty_iter_skip1(iter);
  while (mbty_iter_valid(iter) && mbty_iter_ts(iter))
    mbty_iter_skip1(iter);
}

// skip nr valid keys (tomestones are transparent)
  void
mbty_iter_skip_ts(struct mbty_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!mbty_iter_valid(iter))
      return;
    mbty_iter_skip1(iter);
    while (mbty_iter_valid(iter) && mbty_iter_ts(iter))
      mbty_iter_skip1(iter);
  }
}

  struct kv *
mbty_iter_next_ts(struct mbty_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mbty_iter_peek(iter, out);
  mbty_iter_skip1_ts(iter);
  return ret;
}
// }}} ts

// dump {{{
  void
mbty_dump(struct mbt * const mbt, const char * const fn)
{
  const int fd = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  debug_assert(fd >= 0);
  void * const ref = mbty_ref(mbt);
  struct mbty_iter * const iter = mbty_iter_create(ref);

  struct kvref kvref;
  u32 n = 0;
  mbty_iter_seek(iter, kref_null());
  u32 seg_cnt = 0;
  struct kv * tmp = malloc(4096);
  while (mbty_iter_kvref_dup(iter, &kvref)) { // dump all the keys
    if (n) {
      struct kvref old_kvref;
      kvref_ref_kv(&old_kvref, tmp);
      debug_assert(kvref_kvref_compare(&old_kvref, &kvref) <= 0);
    }
    kvref_dup2_key(&kvref, tmp);
    if (iter->seg_index == 0) {
      mbty_iter_sync_segment(iter);
      struct bt_iter * remix = &iter->remix_iter;
      struct kref anchor;
      bt_iter_kref(remix, &anchor);
      dprintf(fd, "%4u--%2u %2u:%4u %.*s\n", seg_cnt++,
            iter->seg_nkeys, remix->ptr.keyid, remix->ptr.pageid,
            anchor.len, anchor.ptr);
      const u32 nkeys = iter->seg_nkeys;
      dprintf(fd, "ranks: ");
      for (u32 i = 0; i < nkeys; i++) {
        dprintf(fd, "%u", iter->seg_ranks[i]);
        if (i < (nkeys-1)) {
          dprintf(fd, ",");
        } else {
          dprintf(fd, "\n");
        }
      }
      if (mbt->remix->dbits) {
        mbty_iter_sync_pkeys(iter);
        pkeys_dprintf(&iter->pkeys, fd, iter->seg_nkeys);
      }
    }
    const u8 rankenc = mbty_iter_rankenc(iter);
    const bool stale = (rankenc & SSTY_STALE) != 0;
    const bool tsy = (rankenc & SSTY_TOMBSTONE) != 0;
    const bool tsx = (kvref.hdr.vlen & SST_VLEN_TS) != 0;
    const bool tail = (rankenc & SSTY_TAIL) != 0;
    const u8 rank = rankenc & SSTY_RANK;
    const bool ts_match = tsy == tsx;
    const struct bt_iter * bt_iter = mbty_iter_bt_iter(iter);
    dprintf(fd, "%7u %4u:%2u%c%x %3u:%5u %c%c%c %.*s (%u,%u)\n",
        n, iter->seg_index, iter->seg_nkeys, ts_match ? ' ' : 'E',
        rank, bt_iter->ptr.keyid, bt_iter->ptr.pageid, stale ? '#' : ' ', tsy ? 'X' : ' ', tail ? '|' : ' ',
        kvref.hdr.klen, kvref.kptr, kvref.hdr.klen, kvref.hdr.vlen & SST_VLEN_MASK);
    mbty_iter_skip1_dup(iter);
    n++;
  }
  free(tmp);
  mbty_iter_destroy(iter);
  mbty_unref(ref);
  fsync(fd);
  close(fd);
}

// }}} dump

// }}} mbty

// remix_build {{{

// struct {{{
struct remix_build_info {
  struct mbt * x1; // input: target tables
  struct mbt * y0; // input: the old remix or NULL
  bool tags; // generate hash tags
  bool dbits;
  u8 padding[2];
  int fd; // remix fd;
  // flush threshold try to flush when pending is greater than threshold
  u32 flush_thre_segment_nkeys; // >= number of runs
  u32 max_segment_nkeys; // >= flush_thre + number of runs
  u32 nr_reuse;  // input: number of runs to reuse in y0
  const u8 * merge_hist;
  u64 hist_size;
};

struct remixb2_meta {
  u32 x_keys_cnt;
  u32 build_seg_cnt;
  u32 upgrade_cnt;
  u32 chkopt_cnt;
  u32 try_insert_cnt;
  u32 try_insert_fails_dbits; // fail because of not sharing dbits
  u32 try_insert_fails_split; // fail because the segment needs to split
  u32 try_insert_success;
  u32 scan_cnt;
};

// remix_builder
// remixb: a special kind of iterator structure for building a REMIX
// There are two instances of remixb: remixb2 and remixbm
// A compaction always writes new tables sequentially (a sorted view),
// and the existing data are already sorted (another sorted view).
// remixb2 performs a two-way merge between the old and new data.
// remixb2 uses the key-value data. It uses binary searches to find merge points.

// If the input data does not qualify for a two-way merge, remixbm should be used.
// remixbm can be used to create a REMIX for any kind of inputs (e.g., overlapping).
// remixbm uses miter to perform multi-way merge.
// remixbm automatically uses ckeys if every input table contains ckeys.

struct remixb {
  u32 rankenc; // the current rankenc (rank and flags)
  u32 idx; // index on the full sorted view
  u32 nr_runs; // the target nr_runs
  u32 nr_pending; // pending keys in the buffer

  // copy from msstb
  u32 run0;
  u32 run1;
  u32 nkidx;
  u32 kidx0;

  struct kv * tmp0;
  struct kv * tmp1;

  struct mbt * x1; // the input mbt (build remix for x1)
  struct mbt * y0; // the old mbt; x1 and y0 share runs [0 to run0-1]

  struct btenc * enc;

  struct kv * anchor;
  u8 * ranks; // ranks buffer
  u8 * tags; // tags buffer

  struct pkf * pkf;

  const u8 * merge_hist;
  u64 hist_size;
  u64 hist_idx;

  struct bt_ptr ptrs[MSST_NR_RUNS];

  struct kv * key0; // a copy of the first key

  struct miter * miter;
  struct bt_iter * iters[MSST_NR_RUNS]; // for new tables

  // for remixb2
  struct mbty_iter iterb;
  struct kv * currb;
  struct mbty_iter iter0;

  u32 flush_thre_segment_nkeys;

  struct remixb2_meta meta;
};

  static inline bool
remixb_valid(struct remixb * const b)
{
  return b->rankenc != UINT32_MAX;
}

  static inline u32
remixb_rankenc(struct remixb * const b)
{
  return b->rankenc;
}
// }}} struct

// remixbm {{{
  static void
remixbm_sync_rank(struct remixb * const b)
{
  if (!miter_valid(b->miter)) {
    b->rankenc = UINT32_MAX;
    return;
  }

  const u32 rank = miter_rank(b->miter);
  debug_assert(rank < MSST_NR_RUNS);
  struct kvref cref;
  miter_kvref(b->miter, &cref);
  const bool stale = (cref.hdr.klen == b->tmp1->klen) && (!memcmp(cref.kptr, b->tmp1->kv, b->tmp1->klen));
  const bool ts = cref.hdr.vlen == SST_VLEN_TS;
  struct bt_iter * const iter = b->iters[rank];
  bt_iter_fix_kv(iter);
  const u16 nkeys = bt_iter_page_bthdr(iter)->nkeys;
  debug_assert(nkeys && (iter->ptr.keyid < nkeys));
  const bool tail = (iter->ptr.keyid + 1) == nkeys;
  b->rankenc = rank | (stale ? SSTY_STALE : 0u) | (ts ? SSTY_TOMBSTONE : 0u) | (tail ? SSTY_TAIL : 0u);

  if (!stale) { // save the previous unique key in tmp0, and copy the current key to tmp1
    struct kv * const xchg = b->tmp0;
    b->tmp0 = b->tmp1;
    b->tmp1 = xchg;
    kvref_dup2_key(&cref, b->tmp1);
  }
}

  static struct remixb *
remixbm_create(const struct remix_build_info * const bi)
{
  struct remixb * const b = calloc(1, sizeof(*b));
  b->nr_runs = bi->x1->nr_runs;
  b->x1 = bi->x1;
  // bi->y0 ignored
  // bi->nr_reuse ignored
  b->tmp0 = malloc(sizeof(*b->tmp0) + PGSZ);
  b->tmp1 = malloc(sizeof(*b->tmp1) + PGSZ);

  b->enc = btenc_create(bi->fd, SST_MAX_PAGEID);
  // assume a page big enough for all metadata
  b->anchor = malloc(sizeof(*b->anchor) + PGSZ);
  b->ranks = calloc(1, bi->max_segment_nkeys);
  if (bi->tags)
    b->tags = calloc(1, bi->max_segment_nkeys);

  if (bi->dbits) {
    b->pkf = pkf_create();
  }

  // TODO: this part is weird
  const struct kvmap_api * const api_build = &kvmap_api_bt;
  struct miter * const miter = miter_create();
  b->miter = miter;
  for (u32 i = 0; i < b->nr_runs; i++)
    b->iters[i] = miter_add(miter, api_build, &b->x1->bts[i]);

  miter_seek(miter, kref_null());
  if (miter_valid(miter)) {
    struct kvref kvref;
    miter_kvref(miter, &kvref);
    kvref_dup2_key(&kvref, b->tmp1);
    b->key0 = kv_dup_key(b->tmp1);
    b->tmp1->klen = !b->tmp1->klen; // let the first stale == false
  }
  remixbm_sync_rank(b);
  return b;
}

  static void
remixbm_skip1(struct remixb * const b)
{
  const u32 nkeys = b->nr_pending;
  if (nkeys == 0) {
    // save the anchor
    const u32 alen = b->idx ? (kv_key_lcp(b->tmp0, b->tmp1) + 1) : 0;
    debug_assert(!alen == !b->idx);
    debug_assert(alen <= b->tmp1->klen);
    kv_dup2_key_prefix(b->tmp1, b->anchor, alen);

    // save the ptrs
    for (u32 i = 0; i < b->nr_runs; i++)
      b->ptrs[i] = b->iters[i]->ptr;
  }

  // save the current rankenc (and tags)
  debug_assert(b->rankenc <= UINT8_MAX);
  b->ranks[nkeys] = (u8)b->rankenc;
  if (b->tags)
    b->tags[nkeys] = sst_tag(kv_crc32c(b->tmp1->kv, b->tmp1->klen));

  // tmp1 is the current key, it is updated in remixbm_sync_rank
  if (b->pkf) {
    pkf_append(b->pkf, b->tmp1);
  }

  b->nr_pending++;
  miter_skip1(b->miter);
  b->idx++;
  remixbm_sync_rank(b);
}

// the value layout
// +----------------------------+
// |    nkeys (1 byte)          |
// +----------------------------+
// | ptrs[:] (4 x nr_runs)      |
// +----------------------------+
// | run_selectors (1 x nkeys)  |
// +----------------------------+
// | tags (optional, 1 x nkeys) |
// +----------------------------+
// | pkeys and dkeys (optional) |
// +----------------------------+
// | pkeys (4 x nkeys)          |
// +----------------------------+
// | dkey.len (1 byte)          |
// +----------------------------+
// | dkey.tot1s (1 byte)        |
// +----------------------------+
// | dkey ( dkey.len )          |
// +----------------------------+
//
  static bool
remixbm_flush(struct remixb * const b)
{
  const u32 nkeys = b->nr_pending;
  if (nkeys == 0)
    return true;

  u8 * vptr = kv_vptr(b->anchor);
  const u8 * const vptr0 = vptr;

  // number of keys in this segment
  debug_assert(nkeys <= UINT8_MAX);
  *vptr = (u8)nkeys; // nkeys
  vptr++;

  // cursor positions
  const u32 ptrs_size = sizeof(b->ptrs[0]) * b->nr_runs;
  memcpy(vptr, &b->ptrs, ptrs_size);
  vptr += ptrs_size;

  // run selectors
  memcpy(vptr, b->ranks, nkeys);
  vptr += nkeys;

  // hash tags (optional)
  if (b->tags) {
    memcpy(vptr, b->tags, nkeys); // tags
    vptr += nkeys;
  }

  if (b->pkf) {
    // build the dkey and pkeys for this batch
    // pkf was filled by calling pkf_append
    // pkf_build extract the pkeys and dkey for this batch
    struct pkeys_ref pkeys;
    struct dkey_ref dkey;
    const u32 npkeys = pkf_build(b->pkf, &pkeys, &dkey);
    debug_assert(npkeys == nkeys);
    (void)npkeys;

    // now we have dkey and pkeys, encode them in the value
    memcpy(vptr, pkeys.ptr, pkeys.len);
    vptr += pkeys.len;
    debug_assert(dkey.len < 255);
    *(u8 *)vptr = dkey.len;
    vptr++;
    debug_assert(dkey.tot1s < 255);
    *(u8 *)vptr = dkey.tot1s;
    vptr++;
    memcpy(vptr, dkey.ptr, dkey.len);
    vptr += dkey.len;

    // we can now clear them since we got pkeys and dkey
    pkf_clear(b->pkf);
  }

  // b->anchor->vlen = 1u + ptrs_size + nkeys + (b->tags ? nkeys : 0);
  b->anchor->vlen = vptr - vptr0;

  b->nr_pending = 0;

  // the anchor key here is already lcp+1 for sparse index
  // we can skip getting lcp+1 in btenc when building internal keys
  return btenc_append(b->enc, b->anchor, b->anchor, false, false);
}

  static void
remixbm_destroy(struct remixb * const b)
{
  free(b->tmp0);
  free(b->tmp1);
  btenc_destroy(b->enc);
  free(b->anchor);
  free(b->ranks);
  if (b->tags) {
    free(b->tags); // can be NULL
  }
  free(b->key0);
  miter_destroy(b->miter);
  if (b->pkf) {
    pkf_destroy(b->pkf);
  }
  free(b);
}
// }}} remixbm

// overlap {{{
// check if tables at run0 to nr_runs overlap
  static bool
remix_build_overlap(struct mbt * const mbtx1, const u32 nr_reuse)
{
  const u32 nr_runs = mbtx1->nr_runs;
  struct kv * const last = malloc(sizeof(*last) + SST_MAX_KVSZ);
  struct kv * const tmp = malloc(sizeof(*last) + SST_MAX_KVSZ);
  last->klen = UINT32_MAX;
  bool overlap = false;
  for (u32 i = nr_reuse; i < nr_runs; i++) {
    if (mbtx1->bts[i].meta.nr_leaf == 0)
      continue;

    struct kv * const first = bt_first_key(&(mbtx1->bts[i]), tmp);
    if ((last->klen != UINT32_MAX) && (kv_compare(last, first) >= 0)) {
      overlap = true;
      break;
    }
    bt_last_key(&(mbtx1->bts[i]), last);
  }

  free(last);
  free(tmp);
  return overlap;
}
// }}} overlap

// build {{{
  static u32
remix_finish_meta(struct remix_build_info * bi, struct remixb * const b,
                  struct remixmeta * meta)
{
  const u32 nr_pages = btenc_finish(b->enc, &meta->btmeta);
  const u32 pages_size = nr_pages * PGSZ;
  lseek(bi->fd, pages_size, SEEK_SET);

  debug_assert(meta->nr_keys == b->idx);
  meta->nr_runs = b->nr_runs;
  meta->nr_keys = b->idx;

  const u32 first_key_off = (u32)pages_size;
  const u32 first_key_len = b->key0 ? b->key0->klen : 0;
  const u32 last_key_off = first_key_off + first_key_len;
  const u32 last_key_len = b->key0 ? b->tmp1->klen : 0;
  meta->first_key_off = first_key_off;
  meta->last_key_off = last_key_off;
  meta->first_key_len = first_key_len;
  meta->last_key_len = last_key_len;

  // write the two keys
  if (b->key0) { // non-empty remix
    write(bi->fd, b->key0->kv, first_key_len);
    write(bi->fd, b->tmp1->kv, last_key_len);
  }

  meta->tags = bi->tags;
  meta->dbits = bi->dbits;

  for (u32 i = b->nr_runs - 2; i < b->nr_runs; i--) {
    meta->stats[i].valid_kv_up += meta->stats[i + 1].valid_kv_up;
    meta->stats[i].stale_kv_up += meta->stats[i + 1].stale_kv_up;
    meta->stats[i].valid_ts_up += meta->stats[i + 1].valid_ts_up;
    meta->stats[i].stale_ts_up += meta->stats[i + 1].stale_ts_up;
  }
  write(bi->fd, meta, sizeof(*meta));

  fdatasync(bi->fd);
  close(bi->fd);

  debug_assert(first_key_len + last_key_len + sizeof(*meta) <= PGSZ);
  return pages_size + first_key_len + last_key_len + sizeof(*meta);
}

  static void
remixmeta_collect(struct remixmeta * const meta, const u32 rankenc)
{
  meta->nr_keys++;
  const u32 rank = rankenc & SSTY_RANK;
  switch (rankenc & (SSTY_STALE | SSTY_TOMBSTONE)) {
  case 0:
    meta->stats[rank].valid_kv_up++; break;
  case SSTY_STALE:
    meta->stats[rank].stale_kv_up++; break;
  case SSTY_TOMBSTONE:
    meta->stats[rank].valid_ts_up++; break;
  case (SSTY_STALE | SSTY_TOMBSTONE):
    meta->stats[rank].stale_ts_up++; break;
  default:
    debug_die();
    break;
  }
}

  static u32
remix_build_miter(struct remix_build_info * const bi)
{
  struct remixb * const b = remixbm_create(bi);
  if (!b)
    debug_die();

  u32 nr_pending = 0;
  struct remixmeta meta = {};
  // disable the logic when dbits is disabled
  bool finish_dbits = false;

  while (remixb_valid(b)) {
    const u32 rankenc = remixb_rankenc(b);
    debug_assert(rankenc < SSTY_INVALID);
    debug_assert((rankenc & SSTY_RANK) < b->nr_runs);
    debug_assert(nr_pending == b->nr_pending);
    remixmeta_collect(&meta, rankenc);

    // close the current segment
    if ((rankenc & SSTY_STALE) == 0) {
      if ((nr_pending >= bi->flush_thre_segment_nkeys) || (finish_dbits == true)) {
        nr_pending = 0;
        const bool r = remixbm_flush(b);
        if (!r)
          debug_die();

        finish_dbits = false;
      }
    }

    remixbm_skip1(b);
    if (b->pkf) {
      finish_dbits = pkf_check_finish(b->pkf);
    }

    nr_pending++;
  }

  // the final page
  debug_assert(nr_pending == b->nr_pending);
  remixbm_flush(b);
  debug_assert(b->nr_pending == 0);

  const u32 pages_size = remix_finish_meta(bi, b, &meta);
  remixbm_destroy(b);
  return pages_size;
}
// }}} build

// remixb2 {{{
  static void
remixb2_sync_mp(struct remixb * b)
{
  struct mbty_iter * const iterb = &b->iterb;

  do {
    if (b->run1 == b->nr_runs) {
      mbty_iter_park(iterb);
      // invalidate the iterator
      iterb->seg_nkeys = 0;
      // no more runs could be used
      return;
    } else if (bt_iter_valid(b->iters[b->run1])) {
      // the run1 and iter are still valid
      break;
    }
    b->run1++;
  } while (true);
  struct bt_iter * const iter1 = b->iters[b->run1];

  // this handles the case where the keys in iterb are used up
  if (iterb->seg_nkeys == 0) {
    bt_iter_fix_kv(iter1);
    return;
  }

  struct kref kref1;
  bt_iter_kref(iter1, &kref1);

  // use remix to position iterb to the insert point
  mbty_iter_seek(iterb, &kref1);
  // because of here, run0 stores nr_reuse
  // the y0 have some ranks that are greater than nr_reuse
  // this skip was used to skip high-rank keys, which is exactly what we want to do here.
  while (mbty_iter_valid(iterb) && (mbty_iter_rank(iterb) >= b->run0)) {
    mbty_iter_skip1_dup(iterb);
  }
}

// see if the local 2 way iterator is valid
  static bool
remixb2_valid(struct remixb * b)
{
  struct mbty_iter * const iter0 = &b->iter0;
  if (b->run1 == b->nr_runs) {
    return mbty_iter_valid(iter0);
  }
  struct bt_iter * const iter1 = b->iters[b->run1];

  if (mbty_iter_valid(iter0) || bt_iter_valid(iter1)) {
    return true;
  }

  return false;
}

  static int
remixb2_iter0_iter1_cmp(struct remixb * b)
{
  debug_assert(remixb2_valid(b));
  struct bt_iter * const iter1 = b->iters[b->run1];
  struct mbty_iter * const iter0 = &b->iter0;
  if ((b->run1 == b->nr_runs) || (bt_iter_valid(iter1) == false)) {
    // iter0 must be valid
    return -1;
  }
  // iter1 must be valid
  if (mbty_iter_valid(iter0) == false) {
    return 1;
  }
  // both must be valid now
  struct kvref key0, key1;
  bt_iter_kvref(iter1, &key1);
  mbty_iter_kvref_dup(iter0, &key0);
  return kvref_kvref_compare(&key0, &key1);
}

  static void
remixb2_sync_rank(struct remixb * b)
{
  if (!remixb2_valid(b)) {
    b->rankenc = UINT32_MAX;
    return;
  }

  u32 rank = 0;
  struct bt_iter * const iter1 = b->iters[b->run1];
  struct mbty_iter * const iter0 = &b->iter0;
  struct kvref cref;

  struct bt_iter * iter = NULL;

  if (remixb2_iter0_iter1_cmp(b) < 0) {
    mbty_iter_kvref_dup(iter0, &cref);
    rank = mbty_iter_rank(iter0);
    iter = mbty_iter_bt_iter(iter0);
  } else {
    bt_iter_kvref(iter1, &cref);
    rank = iter1->rank;
    iter = iter1;
  }
  debug_assert((rank & SSTY_RANK) < b->nr_runs);

  const bool stale = (cref.hdr.klen == b->tmp1->klen) && (!memcmp(cref.kptr, b->tmp1->kv, b->tmp1->klen));
  const bool ts = cref.hdr.vlen == SST_VLEN_TS;
  debug_assert(iter);
  bt_iter_fix_kv(iter);
  const u16 nkeys = bt_iter_page_bthdr(iter)->nkeys;
  debug_assert(nkeys && (iter->ptr.keyid < nkeys));
  const bool tail = (iter->ptr.keyid + 1) == nkeys;
  b->rankenc = rank | (stale ? SSTY_STALE : 0u) | (ts ? SSTY_TOMBSTONE : 0u) | (tail ? SSTY_TAIL : 0u);
  if (!stale) {
    // save previous unique key in tmp0, copy the current key to tmp1
    struct kv * const xchg = b->tmp0;
    b->tmp0 = b->tmp1;
    b->tmp1 = xchg;
    kvref_dup2_key(&cref, b->tmp1);
  }
}

  static void
remixb2_destroy(struct remixb * const b)
{
  free(b->tmp0);
  free(b->tmp1);
  btenc_destroy(b->enc);
  free(b->anchor);
  free(b->ranks);
  free(b->key0);
  free(b->currb);
  if (b->tags) {
    free(b->tags);
  }
  if (b->pkf) {
    pkf_destroy(b->pkf);
  }

  if (b->y0) {
    mbty_iter_destroy(&b->iterb);
    mbty_iter_destroy(&b->iter0);
  }

  for (u32 i = b->run0; i < b->nr_runs; i++) {
    bt_iter_destroy(b->iters[i]);
  }

  free(b);
}

  static struct remixb *
remixb2_create(struct remix_build_info * const bi)
{
  debug_assert(bi->x1);
  struct remixb * const b = calloc(1, sizeof(*b));
  if (b == NULL) {
    return NULL;
  }

  b->x1 = bi->x1;
  b->y0 = bi->y0;

  b->run0 = bi->nr_reuse;
  b->run1 = bi->nr_reuse;
  b->nr_runs = bi->x1->nr_runs;

  b->tmp0 = malloc(sizeof(*b->tmp0) + PGSZ);
  b->tmp1 = malloc(sizeof(*b->tmp1) + PGSZ);

  b->enc = btenc_create(bi->fd, SST_MAX_PAGEID);
  b->anchor = malloc(sizeof(*b->anchor) + PGSZ);
  b->ranks = calloc(1, bi->max_segment_nkeys);

  if (bi->tags) {
    b->tags = calloc(1, bi->max_segment_nkeys);
  }

  if (bi->dbits) {
    b->pkf = pkf_create();
  }

  b->flush_thre_segment_nkeys = bi->flush_thre_segment_nkeys;

  if (bi->nr_reuse) {
    debug_assert(bi->y0);
    // TODO: maybe fill these shortcuts
    // b->nkidx = mssty0->ssty->nkidx; // shortcut
    // b->ranks = mssty0->ssty->ranks; // shortcut

    mbty_iter_init(&(b->iterb), bi->y0);
    mbty_iter_seek(&(b->iterb), kref_null());
    mbty_iter_init(&(b->iter0), bi->y0);
    mbty_iter_seek(&(b->iter0), kref_null());
  }

  for (u32 i = bi->nr_reuse; i < bi->x1->nr_runs; i++) {
    b->iters[i] = bt_iter_create(&(b->x1->bts[i]));
    b->iters[i]->rank = (u8)i;
    bt_iter_seek_null(b->iters[i]);
  }

  b->currb = malloc(sizeof(*b->currb) + PGSZ);
  remixb2_sync_mp(b);

  if (remixb2_valid(b)) {
    struct mbty_iter * iter0 = &b->iter0;
    struct bt_iter * const iter1 = b->iters[b->run1];
    struct kvref cref;
    if (remixb2_iter0_iter1_cmp(b) < 0) {
      mbty_iter_kvref_dup(iter0, &cref);
    } else {
      bt_iter_kvref(iter1, &cref);
    }
    kvref_dup2_key(&cref, b->tmp1);
    b->key0 = kv_dup_key(b->tmp1);
    // make tmp1 update
    b->tmp1->klen = !b->tmp1->klen;
  }

  remixb2_sync_rank(b);

  return b;
}

// compare the remix_iter
  static int
mbty_iter_cmp_segs(const struct mbty_iter * const itera, const struct mbty_iter * const iterb)
{
  debug_assert(itera->seg_nkeys != 0 && iterb->seg_nkeys != 0);

  const struct bt_ptr * const pptra = &itera->remix_iter.ptr;
  const struct bt_ptr * const pptrb = &iterb->remix_iter.ptr;

  // first see if they are in the same remix page in the B+-tree
  if (pptra->pageid != pptrb->pageid) {
    return (int)pptra->pageid - (int)pptrb->pageid;
  }

  // see if they are at the same remix key (segment)
  return (int)pptra->keyid - (int)pptrb->keyid;
}

  static void
remixb2_save_ptrs(struct remixb * b)
{
  // save pointers
  for (u32 i = 0; i < b->run0; i++) {
    b->ptrs[i] = b->iter0.iters[i].ptr;
  }

  for (u32 i = b->run0; i < b->nr_runs; i++) {
    b->ptrs[i] = b->iters[i]->ptr;
  }
}

  static void
remixb2_skip1(struct remixb * b)
{
  struct mbty_iter * const iter0 = &b->iter0;

  const u32 nkeys = b->nr_pending;
  if (nkeys == 0) {
    const u32 alen = b->idx ? (kv_key_lcp(b->tmp0, b->tmp1) + 1) : 0;
    debug_assert(!alen == !b->idx);
    debug_assert(alen <= b->tmp1->klen);
    kv_dup2_key_prefix(b->tmp1, b->anchor, alen);

    remixb2_save_ptrs(b);
  }

  // save the current rankenc (and tags)
  debug_assert(b->rankenc <= UINT8_MAX);
  b->ranks[nkeys] = (u8)b->rankenc;
  if (b->tags)
    b->tags[nkeys] = sst_tag(kv_crc32c(b->tmp1->kv, b->tmp1->klen));

  // tmp1 is the current key, it is updated in remixb2_sync_rank
  if (b->pkf) {
    pkf_append(b->pkf, b->tmp1);
  }

  b->nr_pending++;

  b->idx++;

  // miter_skip1
  if (remixb2_iter0_iter1_cmp(b) < 0) {
    mbty_iter_skip1_dup(iter0);
  } else {
    struct bt_iter * const iter1 = b->iters[b->run1];
    bt_iter_skip1(iter1);
    b->meta.x_keys_cnt++;
  }
  remixb2_sync_mp(b);
  remixb2_sync_rank(b);
}

// update tmp1 to point to the last key in the segment
  static void
remixb2_build_save_last(struct remixb * const b)
{
  // TODO: could this be optimized to only be called from entering build_miter?
  struct mbty_iter * iter0 = &b->iter0;
  for (u32 i = 0; i < iter0->nr_runs; i++)
    bt_iter_park(&(iter0->iters[i]));
  // when enter, tmp1 stores the first key in this segment
  // tmp0 stores the last key in the last segment
  struct kref seg_last;
  mbty_iter_segment_access(iter0, iter0->seg_nkeys-1, &seg_last);

  struct kv * const xchg = b->tmp0;
  b->tmp0 = b->tmp1;
  b->tmp1 = xchg;
  kref_dup2_key(&seg_last, b->tmp1);
  // after it returns, tmp1 stores the last key in this segment
  // tmp0 stores the first key in this segment.
  // a followup call to sync_rank should make tmp0 and tmp1 ready
}

// there is no new keys in the segment
// only need to add new runs' ptrs
// it does not move iter1 and iterb (mp)
  static void
remixb2_build_upgrade(struct remixb * const b, struct remixmeta * const meta)
{
  b->meta.upgrade_cnt++;
  struct mbty_iter * iter0 = &b->iter0;
  struct bt_iter * const remix_iter = &(iter0->remix_iter);
  debug_assert(bt_iter_valid(remix_iter));
  bt_iter_fix_kv(remix_iter);
  mbty_iter_sync_ptrs(iter0);

  // pointers are new
  remixb2_save_ptrs(b);
  const u32 alen = b->idx ? (kv_key_lcp(b->tmp0, b->tmp1) + 1) : 0;
  debug_assert(!alen == !b->idx);
  debug_assert(alen <= b->tmp1->klen);
  kv_dup2_key_prefix(b->tmp1, b->anchor, alen);

  remixb2_build_save_last(b);

  u8 * vptr = kv_vptr(b->anchor);
  const u8 * const vptr0 = vptr;
  const u32 nkeys = iter0->seg_nkeys;

  // nkeys does not change
  *vptr = (u8)nkeys;
  vptr++;

  // cursor position
  const u32 ptrs_size = sizeof(b->ptrs[0]) * b->nr_runs;
  memcpy(vptr, &b->ptrs, ptrs_size);
  vptr += ptrs_size;

  struct kvref old_anchor;
  bt_iter_kvref(remix_iter, &old_anchor);

  // after cursors everything should be the same
  const u32 skip_length = sizeof(u8) + (sizeof(struct bt_ptr) * iter0->nr_runs);
  const u8 * const src_ptr = old_anchor.vptr + skip_length;

  // run selectors
  const u8 * const ranks_ptr = src_ptr;
  for (u32 i = 0; i < nkeys; i++) {
    const u32 rankenc = ranks_ptr[i];
    remixmeta_collect(meta, rankenc);
  }
  b->idx += nkeys;

  memcpy(vptr, src_ptr, old_anchor.hdr.vlen - skip_length);
  vptr += (old_anchor.hdr.vlen - skip_length);
  b->anchor->vlen = vptr - vptr0;
  btenc_append(b->enc, b->anchor, b->anchor, false, false);
  bt_iter_skip1(remix_iter);
  if (bt_iter_valid(remix_iter)) {
    bt_iter_fix_kv(remix_iter);
    mbty_iter_sync_segment(iter0);
    mbty_iter_fix_ptrs(iter0);
  } else {
    iter0->seg_nkeys = 0;
  }
  remixb2_sync_mp(b);
  remixb2_sync_rank(b);
}

// check if the next key from the new runs is greater than or equal to
// the next anchor in remix, if yes, then we can do optimized rebuild
  static bool
remixb2_build_chkopt(struct remixb * const b)
{
  b->meta.chkopt_cnt++;
  // TODO: can check multiple keys, and we see if they can be inserted
  // TODO: remove and merge try_insert to chkopt
  struct kref next;
  struct bt_iter * const iter1 = b->iters[b->run1];
  const struct bt_ptr curr_ptr = iter1->ptr;
  bt_iter_skip1(iter1);
  if (bt_iter_valid(iter1) == false) {
    if ((b->run1 + 1) >= b->nr_runs) {
      // if there is no next, then there is only one key
      // put iter1 back
      bt_iter_set_ptr(iter1, curr_ptr);
      bt_iter_fix_kv(iter1);
      return true;
    } else {
      struct bt_iter * const next_iter1 = b->iters[b->run1+1];
      bt_iter_seek_null(next_iter1);
      bt_iter_kref(next_iter1, &next);
    }
  } else {
    bt_iter_kref(iter1, &next);
  }

  struct bt_iter * const remix = &b->iter0.remix_iter;
  const struct bt_ptr remix_ptr = remix->ptr;
  bt_iter_skip1(remix);
  bool optimized_rebuild = false;
  if (bt_iter_valid(remix) == false) {
    optimized_rebuild = false;
  } else {
    struct kref seg_max;
    bt_iter_kref(remix, &seg_max);

    optimized_rebuild = kref_compare(&next, &seg_max) >= 0;
 }

  // put iter1 back
  bt_iter_set_ptr(iter1, curr_ptr);
  bt_iter_fix_kv(iter1);

  // put remix_iter back
  bt_iter_set_ptr(remix, remix_ptr);
  bt_iter_fix_kv(remix);

  return optimized_rebuild;
}

  static bool
remixb2_seg_share_dbits(const struct remixb * const b, const u32 insert_at,
              const struct kref * const curr, const struct kref * const ikey)
{
  const struct mbty_iter * const iter0 = &b->iter0;
  const u32 nkeys = iter0->seg_nkeys;
  const u32 * const pkeys = iter0->pkeys.pkeys;
  const struct dkey_ref * const dkey = &(iter0->pkeys.dkey);
  debug_assert(insert_at < nkeys);
  (void)nkeys;

  const u32 lcp = kref_lcp(curr, ikey);
  const u8 mask = kref_dbit_mask(curr, ikey, lcp);
  if (mask == 0) {
    // same key
    return true;
  }
  if (lcp >= dkey->len || (dkey->ptr[lcp] & mask) == 0) {
    return false;
  }

  const u32 discard = pkey_lcp(curr, ikey, dkey);
  debug_assert(discard);
  const u32 bit_mask = (1u << (discard - 1));
  debug_assert((pkeys[insert_at] & bit_mask) != 0);
  if ((insert_at > 0) && ((pkeys[insert_at-1] & bit_mask) == 0)) {
    return false;
  }

  return true;
}

// when success, it moves iter1 one spot and sync_mp
  static bool
remixb2_build_try_insert(struct remixb * const b, struct remixmeta * const meta)
{
  b->meta.try_insert_cnt++;
  struct mbty_iter * iter0 = &b->iter0;
  struct bt_iter * const remix_iter = &(iter0->remix_iter);
  debug_assert(bt_iter_valid(remix_iter));
  for (u32 i = 0; i < iter0->nr_runs; i++)
    bt_iter_park(&(iter0->iters[i]));

  mbty_iter_sync_segment(iter0);
  mbty_iter_sync_ptrs(iter0);
  remixb2_save_ptrs(b);

  const u8 * const ranks = iter0->seg_ranks;
  const u32 nkeys = iter0->seg_nkeys;

  struct bt_iter * const iter1 = b->iters[b->run1];
  struct kref curr_ref;
  bt_iter_kref(iter1, &curr_ref);

  u32 insert_at; // const
  if (iter0->dbits) {
    mbty_iter_sync_pkeys(iter0);
    insert_at = mbty_iter_segment_seek_dbits(iter0, &curr_ref);
  } else {
    insert_at = mbty_iter_segment_seek_opt(iter0, &curr_ref);
  }

  mbty_iter_skip_dup(iter0, insert_at - iter0->seg_index);
  if (mbty_iter_valid(iter0) == false) {
    // when the merge point is the last key in this segment
    // use the previous key as the ikey
    // but we still insert at the end
    debug_assert(nkeys == insert_at);
    mbty_iter_sync_segment(iter0);
    mbty_iter_sync_ptrs(iter0);
    mbty_iter_skip_dup(iter0, insert_at - 1);
  }

  debug_assert(mbty_iter_valid(iter0));

  struct kref ikey;
  mbty_iter_kref(iter0, &ikey);

  // bool share_dbits = f
  if (b->pkf) {
    mbty_iter_sync_segment(iter0);
    // check if they share discriminative bits
    if (!remixb2_seg_share_dbits(b, insert_at, &curr_ref, &ikey)) {
      // the new dbit does not share discriminative bits
      // recover the iters
      mbty_iter_fix_ptrs(iter0);
      b->meta.try_insert_fails_dbits++;
      return false;
    }
  } else {
    mbty_iter_sync_segment(iter0);
    if (nkeys + 1 >= b->flush_thre_segment_nkeys) {
      mbty_iter_fix_ptrs(iter0);
      b->meta.try_insert_fails_split++;
      return false;
    }
  }
  b->meta.try_insert_success++;

  // save anchor
  const u32 alen = b->idx ? (kv_key_lcp(b->tmp0, b->tmp1) + 1) : 0;
  debug_assert(!alen == !b->idx);
  debug_assert(alen <= b->tmp1->klen);
  kv_dup2_key_prefix(b->tmp1, b->anchor, alen);

  mbty_iter_sync_ptrs(iter0);
  remixb2_build_save_last(b);

  u8 * vptr = kv_vptr(b->anchor);
  const u8 * const vptr0 = vptr;

  if (insert_at == nkeys) {
    struct kv * const xchg = b->tmp0;
    b->tmp0 = b->tmp1;
    b->tmp1 = xchg;
    kref_dup2_key(&curr_ref, b->tmp1);
  }

  // only insert one key
  *vptr = (u8)(nkeys + 1);
  vptr++;

  b->idx += (nkeys + 1);

  // cursor positions
  const u32 ptrs_size = sizeof(b->ptrs[0]) * b->nr_runs;
  memcpy(vptr, &b->ptrs, ptrs_size);
  vptr += ptrs_size;

  // run selectors
  const u8 * const ranks_ptr = vptr;
  memcpy(vptr, ranks, insert_at);
  vptr += insert_at;
  // check if this is changed, I am losing track of this
  const bool stale = (ikey.len == curr_ref.len) && (!memcmp(ikey.ptr, curr_ref.ptr, ikey.len));
  const bool ts = curr_ref.len == SST_VLEN_TS;
  const u16 iter1_nkeys = bt_iter_page_bthdr(iter1)->nkeys;
  const bool tail = (iter1->ptr.keyid + 1) == iter1_nkeys;
  *vptr = b->run1 | (ts ? SSTY_TOMBSTONE : 0u) | (tail ? SSTY_TAIL : 0u);
  vptr++;
  u8 * next_rank = vptr;
  const u32 nremain = nkeys - insert_at;
  memcpy(vptr, ranks + insert_at, nremain);
  vptr += nremain;
  *next_rank |= (stale ? SSTY_STALE : 0u);

  const u32 ranks_size = vptr - ranks_ptr;

  // update meta accordingly
  for (u32 i = 0; i < ranks_size; i++) {
    const u32 rankenc = ranks_ptr[i];
    remixmeta_collect(meta, rankenc);
  }

  if (b->tags) {
    mbty_iter_sync_tags(iter0);
    memcpy(vptr, iter0->seg_tags, insert_at);
    vptr += insert_at;
    const u8 new_tags = sst_tag(kv_crc32c(curr_ref.ptr, curr_ref.len));
    *vptr = new_tags;
    vptr++;
    memcpy(vptr, iter0->seg_tags + insert_at, nremain);
    vptr += nremain;
  }

  if (b->pkf) {
    debug_assert(iter0->dbits);
    const u32 * const pkeys = iter0->pkeys.pkeys;
    const struct dkey_ref * const dkey = &(iter0->pkeys.dkey);
    const u32 new_pkey = dkey_pext(&curr_ref, dkey);

    const u32 first_sz = sizeof(pkeys[0]) * insert_at;
    memcpy(vptr, pkeys, first_sz);
    vptr += first_sz;
    *(u32 *)vptr = new_pkey;
    vptr += sizeof(new_pkey);
    const u32 second_sz = sizeof(pkeys[0]) * nremain;
    memcpy(vptr, pkeys + insert_at, second_sz);
    vptr += second_sz;
    *(u8 *)vptr = dkey->len;
    vptr++;
    *(u8 *)vptr = dkey->tot1s;
    vptr++;
    memcpy(vptr, dkey->ptr, dkey->len);
    vptr += dkey->len;
  }

  b->anchor->vlen = vptr - vptr0;
  btenc_append(b->enc, b->anchor, b->anchor, false, false);
  bt_iter_skip1(remix_iter);
  if (bt_iter_valid(remix_iter)) {
    bt_iter_fix_kv(remix_iter);
    mbty_iter_sync_segment(iter0);
    mbty_iter_fix_ptrs(iter0);
  } else {
    iter0->seg_nkeys = 0;
  }
  bt_iter_skip1(iter1);
  b->meta.x_keys_cnt++;
  remixb2_sync_mp(b);
  remixb2_sync_rank(b);

  return true;
}

// it constatly moves iter1 and sync_mp
  static void
remixb2_build_scan(struct remixb * const b, struct remixmeta * const meta)
{
  b->meta.scan_cnt++;
  struct mbty_iter * iter0 = &b->iter0;
  struct mbty_iter iter0_save = *iter0;

  u32 nr_pending = 0;
  bool finish_dbits = false;

  while (remixb_valid(b)) {
    if (mbty_iter_valid(iter0) && (mbty_iter_cmp_segs(&iter0_save, iter0) != 0)) {
      break;
    }
    const u32 rankenc = remixb_rankenc(b);
    debug_assert(rankenc < SSTY_INVALID);
    debug_assert((rankenc & SSTY_RANK) < b->nr_runs);
    debug_assert(nr_pending == b->nr_pending);
    remixmeta_collect(meta, rankenc);

    if ((rankenc & SSTY_STALE) == 0) {
      if ((nr_pending >= b->flush_thre_segment_nkeys) || (finish_dbits == true)) {
        nr_pending = 0;
        const bool r = remixbm_flush(b);
        if (!r)
          debug_die();

        finish_dbits = false;
      }
    }

    // assuming the skips are operated in just one segment
    remixb2_skip1(b);
    if (b->pkf) {
      finish_dbits = pkf_check_finish(b->pkf);
    }

    nr_pending++;
  }
  // when it gets out from the loop, iter0 points to the next segment
  remixbm_flush(b);
  remixb2_sync_mp(b);
}

  static void
remixb2_report(const struct remixb * b)
{
  const struct remixb2_meta * const meta = &b->meta;
  if (meta->build_seg_cnt == 0)
    return;
  /*
  printf("%s x_nkeys: %u, nr0: %u, nr_runs: %u, nr_keys: %u\n",
      __func__, meta->x_keys_cnt, b->run0, b->nr_runs, b->idx);
  printf("seg_cnt: %u, upgrade: %u, insert: %u, scan: %u\n",
      meta->build_seg_cnt, meta->upgrade_cnt, meta->try_insert_success, meta->scan_cnt);
  printf("chk: %u, try_insert: %u, successes: %u, fails_dbits: %u fails_split: %u\n",
      meta->chkopt_cnt, meta->try_insert_cnt, meta->try_insert_success,
      meta->try_insert_fails_dbits, meta->try_insert_fails_split);
      */
}

  static u32
remix_build_b2(struct remix_build_info * const bi)
{
  struct remixb * const b = remixb2_create(bi);
  struct mbty_iter * iter0 = &b->iter0;
  struct mbty_iter * iterb = &b->iterb;
  // when entering the loop, assuming iter0 is at the beginning of a segment

  struct remixmeta meta = {};

  // iterb points to the merge point
  while (mbty_iter_valid(iterb)) {
    b->meta.build_seg_cnt++;
    // when enter, assume we are at the beginning of a segment
    // sync_rank should have been called, so tmp1 points to current (first) key
    // tmp0 points to the last key in the last segment
    mbty_iter_sync_segment(iter0);
    if (mbty_iter_cmp_segs(iter0, iterb) < 0) {
      // if the merge point is in different segment
      remixb2_build_upgrade(b, &meta);
    } else {
      debug_assert(mbty_iter_cmp_segs(iter0, iterb) == 0);
      bool fast_rebuilt = false;
      if (remixb2_build_chkopt(b)) {
        fast_rebuilt = remixb2_build_try_insert(b, &meta);
      }
      // will be skipped when try_insert succeeds
      if (fast_rebuilt == false) {
        remixb2_build_scan(b, &meta);
      }
    }
  }

  // iter0/iter1 is still valid, we have to keep building
  while (remixb2_valid(b)) {
    remixb2_build_scan(b, &meta);
  }

  const u32 pages_size = remix_finish_meta(bi, b, &meta);

  remixb2_report(b);
  remixb2_destroy(b);

  return pages_size;
}
// }}} remixb2

// {{{ remixbh
  static bool
remixbh_iter1_peek(struct remixb * b, struct kref * kref1)
{
  struct mbty_iter * const iterb = &b->iterb;
  do {
    if (b->run1 == b->nr_runs) {
      mbty_iter_park(iterb);
      // invalidate the iterator
      iterb->seg_nkeys = 0;
      // no more runs could be used
      return false;
    } else if (bt_iter_valid(b->iters[b->run1])) {
      // the run1 and iter are still valid
      break;
    }
    b->run1++;
  } while (true);
  struct bt_iter * const iter1 = b->iters[b->run1];

  // this handles the case where the keys in iterb are used up
  if (iterb->seg_nkeys == 0) {
    bt_iter_fix_kv(iter1);
    return false;
  }

  bt_iter_kref(iter1, kref1);
  return true;
}

  static bool
remixbh_iter1_valid(struct remixb * b)
{
  if (b->run1 >= b->nr_runs) {
    return false;
  }

  if (b->hist_idx >= b->hist_size) {
    return false;
  }

  return bt_iter_valid(b->iters[b->run1]);
}

// merged key
  static bool
remixbh_iter1_mgdkey(struct remixb * b)
{
  const bool is_mgdkey = ((b->merge_hist[b->hist_idx] & MITER_HIST_REP_FLAG) != 0);
  return is_mgdkey;
}

  static bool
remixbh_iter1_memkey(struct remixb * b)
{
  const u32 miter_range = b->y0->nr_runs - b->run0;
  // in history, the ranks should be only from 0 to miter_range (inclusive)
  const bool is_memkey = (b->merge_hist[b->hist_idx] == miter_range);
  return is_memkey;
}

// returns if it actually skips a key
  static bool
remixbh_iter1_skip1(struct remixb * b)
{
  debug_assert(b->hist_idx < b->hist_size);
  const bool merged_key = remixbh_iter1_mgdkey(b);
  b->hist_idx++;
  // ignoring keys that are overwritten
  if (merged_key) {
    return false;
  }
  struct bt_iter * const iter1 = b->iters[b->run1];
  bt_iter_skip1(iter1);
  b->meta.x_keys_cnt++;
  if (bt_iter_valid(iter1)) {
    return true;
  }
  b->run1++;
  if (b->run1 >= b->nr_runs) {
    return true;
  }
  bt_iter_seek_null(b->iters[b->run1]);
  return true;
}

  static bool
remixbh_iter0_iter1_same(struct remixb * b)
{
  struct mbty_iter * const iter0 = &b->iter0;
  if (mbty_iter_valid(iter0) == false) {
    return false;
  }
  if (b->hist_idx >= b->hist_size) {
    return false;
  }
  // they meet in higher rank keys, point to the same key
  const bool ret = (mbty_iter_rank(iter0) >= b->run0) && (remixbh_iter1_memkey(b) == false);
  return ret;
}

  static int
remixbh_iter0_iter1_cmp(struct remixb * b)
{
  debug_assert(remixb2_valid(b));
  struct bt_iter * const iter1 = b->iters[b->run1];
  struct mbty_iter * const iter0 = &b->iter0;
  if (remixbh_iter1_valid(b) == false) {
    // iter0 must be valid
    return -1;
  }
  // iter1 must be valid
  if (mbty_iter_valid(iter0) == false) {
    return 1;
  }
  // both are valid now
  if (remixbh_iter0_iter1_same(b)) {
    // they meet in higher rank keys, point to the same key
    return 0;
  }
  if (mbty_iter_rank(iter0) >= b->run0) {
    // move iter1
    return 1;
  }
  if (remixbh_iter1_memkey(b) == false) {
    // move iter0
    return -1;
  }
  // both keys are actually valid and could be compared
  struct kvref key0, key1;
  bt_iter_kvref(iter1, &key1);
  mbty_iter_kvref_dup(iter0, &key0);
  return kvref_kvref_compare(&key0, &key1);
}

// it moves iter1 to point to the next key that is from memtable
  static void
remixbh_iter1_seek_memkey(struct remixb * b)
{
  const u64 old_idx = b->hist_idx;
  const u64 hist_size = b->hist_size;

  for (u64 i = old_idx; i < hist_size; i++) {
    if (remixbh_iter1_memkey(b)) {
      break;
    }
    remixbh_iter1_skip1(b);
  }
}

// There could be two strategies:
// (1): key1 is already from memtable
//      The key has to be skipped by bh in skip1
//      When we use mbty_seek to find the insert point,
//      the iterb should point to a run below nr_reuse?
//      but the iterb moves in the unit of a segment?
//      x: this will lose the ptrs, block id and key id
// (2): key1 could be from both memtable and old tables,
//      we skip the segments that only contain keys from old tables.
//      In this case, we don't want to issue seek for keys from old tables
//      We cannot do upgrade as usual,
//      every segment that has old tables needs special processing.
//      even if it doesn't have old table, we need to update the bt ptr
// For both cases

// use remix and history to put iterb to the
// insert point for the keys from memtable

// if this key is from the old tables, don't issue seeks
  static void
remixbh_sync_mp(struct remixb * b)
{
  if (!remixbh_iter1_valid(b)) {
    return;
  }
  struct mbty_iter * const iterb = &b->iterb;
  // save iter1's state
  struct bt_ptr iter1_state[MSST_NR_RUNS];
  const u32 old_run1 = b->run1;
  const u64 old_idx = b->hist_idx;
  for (u32 i = b->run0; i < b->nr_runs; i++) {
    iter1_state[i] = b->iters[i]->ptr;
  }
  remixbh_iter1_seek_memkey(b);

  struct kref kref1;
  bool peek = remixbh_iter1_peek(b, &kref1);
  if (peek == true) {
    // now kref1 should be a memkey, issue a seeek
    mbty_iter_seek(iterb, &kref1);
  }

  // restore all iter1 states
  for (u32 i = b->run0; i < b->nr_runs; i++) {
    bt_iter_set_ptr(b->iters[i], iter1_state[i]);
    if (bt_iter_valid(b->iters[i]))
      bt_iter_fix_kv(b->iters[i]);
  }
  b->run1 = old_run1;
  b->hist_idx = old_idx;
}

  static bool
remixbh_valid(struct remixb * b)
{
  struct mbty_iter * const iter0 = &b->iter0;
  if (mbty_iter_valid(iter0) || remixbh_iter1_valid(b)) {
    return true;
  }
  return false;
}

  static void
remixbh_sync_rank(struct remixb * b)
{
  if (!remixbh_valid(b)) {
    b->rankenc = UINT32_MAX;
    return;
  }

  u32 rank = 0;

  struct bt_iter * const iter1 = b->iters[b->run1];
  struct mbty_iter * const iter0 = &b->iter0;
  struct kvref cref;

  struct bt_iter * iter = NULL;

  const int cmp = remixbh_iter0_iter1_cmp(b);
  if (cmp < 0) {
    mbty_iter_kvref_dup(iter0, &cref);
    rank = mbty_iter_rank(iter0);
    iter = mbty_iter_bt_iter(iter0);
  } else {
    // cmp >= 0
    // all other cases use iter1
    bt_iter_kvref(iter1, &cref);
    rank = iter1->rank;
    iter = iter1;
  }

  debug_assert((rank & SSTY_RANK) < b->nr_runs);
  const bool stale = (cref.hdr.klen == b->tmp1->klen) && (!memcmp(cref.kptr, b->tmp1->kv, b->tmp1->klen));
  const bool ts = cref.hdr.vlen == SST_VLEN_TS;
  debug_assert(iter);
  bt_iter_fix_kv(iter);
  const u16 nkeys = bt_iter_page_bthdr(iter)->nkeys;
  debug_assert(nkeys && (iter->ptr.keyid < nkeys));
  const bool tail = (iter->ptr.keyid + 1) == nkeys;
  b->rankenc = rank | (stale ? SSTY_STALE : 0u) | (ts ? SSTY_TOMBSTONE : 0u) | (tail ? SSTY_TAIL : 0u);
  if (!stale) {
    // save previous unique key in tmp0, copy the current key to tmp1
    struct kv * const xchg = b->tmp0;
    b->tmp0 = b->tmp1;
    b->tmp1 = xchg;
    kvref_dup2_key(&cref, b->tmp1);
  }
  // when entering this, iter0 points to a valid old keys on old tables
}

// there is no new keys in the segment
// - Add bt for new runs
// - Modify ranks that are higher than nr_reuse
// - Possibly removing ranks due to the merging of old tables
// it moves iter1 and iterb
  static void
remixbh_build_upgrade(struct remixb * const b, struct remixmeta * const meta)
{
  b->meta.upgrade_cnt++;
  struct mbty_iter * iter0 = &b->iter0;
  struct bt_iter * const remix_iter = &(iter0->remix_iter);
  debug_assert(bt_iter_valid(remix_iter));
  bt_iter_fix_kv(remix_iter);
  mbty_iter_sync_ptrs(iter0);

  // pointers are new
  remixb2_save_ptrs(b);
  const u32 alen = b->idx ? (kv_key_lcp(b->tmp0, b->tmp1) + 1) : 0;
  debug_assert(!alen == !b->idx);
  debug_assert(alen <= b->tmp1->klen);
  kv_dup2_key_prefix(b->tmp1, b->anchor, alen);

  remixb2_build_save_last(b); // TODO: for bh, it should not save last from old tables

  u8 * vptr = kv_vptr(b->anchor);
  u8 * const vptr0 = vptr;

  // nkeys needs to be changed
  // *vptr = (u8)nkeys;
  vptr++;

  const u32 ptrs_size = sizeof(b->ptrs[0]) * b->nr_runs;
  memcpy(vptr, &b->ptrs, ptrs_size);
  vptr += ptrs_size;

  // both need to be true or false
  // if old remix has dbits, new remix must have dbits
  // if old remix does not have dbits, new remix cannot have dbits
  debug_assert((b->pkf == NULL) == (iter0->dbits == false));

  struct kvref old_anchor;
  bt_iter_kvref(remix_iter, &old_anchor);
  const void * old_vptr = old_anchor.vptr;

  const u32 old_nkeys = iter0->seg_nkeys;
  debug_assert(old_nkeys == (*(u8 *)old_vptr));
  // nkeys
  old_vptr++;
  // ptrs (cursor offsets)
  old_vptr += (sizeof(struct bt_ptr) * iter0->nr_runs);
  // ranks (run selectors)
  const u8 * const old_ranks = old_vptr;
  old_vptr += old_nkeys;
  // tags (if any)
  const u8 * const old_tags = b->tags ? old_vptr : NULL;
  if (iter0->tags) {
    old_vptr += old_nkeys;
  }
  // pkeys
  const u32 * const old_pkeys = iter0->dbits ? old_vptr : NULL;
  if (iter0->dbits) {
    old_vptr += (sizeof(old_pkeys[0]) * old_nkeys);
  }
  // dkeys
  const u8 * const old_dkey = iter0->dbits ? old_vptr : NULL;

  u32 nkeys = 0;
  u32 * pkeys = calloc(sizeof(pkeys[0]), b->flush_thre_segment_nkeys << 1);
  for (u32 i = 0; i < old_nkeys; i++) {
    const u8 rankenc = old_ranks[i];
    const u8 rank = rankenc & SSTY_RANK;
    if (rank < b->run0) {
      *vptr = rankenc;
    } else {
      struct bt_iter * const iter1 = b->iters[b->run1];
      bt_iter_fix_kv(iter1); // TODO: we don't even need to read the key from iter1
      const u16 bt_nkeys = bt_iter_page_bthdr(iter1)->nkeys;
      const bool tail = (iter1->ptr.keyid + 1) == bt_nkeys;
      const bool merged_key = remixbh_iter1_mgdkey(b);
      debug_assert(remixbh_iter1_memkey(b) == false);
      const u8 run1 = b->run1;
      const bool skipped = remixbh_iter1_skip1(b);
      if (merged_key) {
        debug_assert(skipped == false);
        // this old version key was removed
        continue;
      } else
        debug_assert(skipped == true);
      // no stale flags because stale keys would be ignored
      *vptr = run1 | (rankenc & SSTY_TOMBSTONE) | (tail ? SSTY_TAIL : 0);
    }
    if (b->tags) {
      b->tags[nkeys] = old_tags[i];
    }
    if (b->pkf) {
      pkeys[nkeys] = old_pkeys[i];
    }
    remixmeta_collect(meta, *vptr);
    vptr++;
    nkeys++;
  }

  *vptr0 = nkeys;
  if (b->tags) {
    memcpy(vptr, b->tags, nkeys);
    vptr += nkeys;
  }

  if (b->pkf) {
    const u32 pkeys_size = nkeys * sizeof(pkeys[0]);
    memcpy(vptr, pkeys, pkeys_size);
    vptr += pkeys_size;

    const u32 dkey_length = old_anchor.hdr.vlen - (old_dkey - old_anchor.vptr);
    memcpy(vptr, old_dkey, dkey_length);
    vptr += dkey_length;
  }
  free(pkeys);
  // after run_selectors everything should be the same
  b->idx += nkeys;

  b->anchor->vlen = vptr - vptr0;
  btenc_append(b->enc, b->anchor, b->anchor, false, false);
  bt_iter_skip1(remix_iter);
  if (bt_iter_valid(remix_iter)) {
    bt_iter_fix_kv(remix_iter);
    mbty_iter_sync_segment(iter0);
    mbty_iter_fix_ptrs(iter0);
  } else {
    iter0->seg_nkeys = 0;
  }

  remixbh_sync_mp(b);
  remixbh_sync_rank(b);
}

  static struct remixb *
remixbh_create(struct remix_build_info * const bi)
{
  // TODO: this is basically the same as b2_create
  // need to review if this is necessary
  debug_assert(bi->x1);
  struct remixb * const b = calloc(1, sizeof(*b));
  if (b == NULL) {
    return NULL;
  }

  b->x1 = bi->x1;
  b->y0 = bi->y0;

  b->run0 = bi->nr_reuse;
  b->run1 = bi->nr_reuse;
  b->nr_runs = bi->x1->nr_runs;

  b->tmp0 = malloc(sizeof(*b->tmp0) + PGSZ);
  b->tmp1 = malloc(sizeof(*b->tmp1) + PGSZ);

  b->enc = btenc_create(bi->fd, SST_MAX_PAGEID);
  b->anchor = malloc(sizeof(*b->anchor) + PGSZ);
  b->ranks = calloc(1, bi->max_segment_nkeys);

  if (bi->tags) {
    b->tags = calloc(1, bi->max_segment_nkeys);
  }

  if (bi->dbits) {
    b->pkf = pkf_create();
  }

  b->merge_hist = bi->merge_hist;
  b->hist_size = bi->hist_size;

  b->flush_thre_segment_nkeys = bi->flush_thre_segment_nkeys;

  if (bi->nr_reuse) {
    debug_assert(bi->y0);
    // TODO: maybe fill these shortcuts
    // b->nkidx = mssty0->ssty->nkidx; // shortcut
    // b->ranks = mssty0->ssty->ranks; // shortcut

    mbty_iter_init(&(b->iterb), bi->y0);
    mbty_iter_seek(&(b->iterb), kref_null());
    mbty_iter_init(&(b->iter0), bi->y0);
    mbty_iter_seek(&(b->iter0), kref_null());
  }

  for (u32 i = bi->nr_reuse; i < bi->x1->nr_runs; i++) {
    b->iters[i] = bt_iter_create(&(b->x1->bts[i]));
    b->iters[i]->rank = (u8)i;
    bt_iter_seek_null(b->iters[i]);
  }

  b->currb = malloc(sizeof(*b->currb) + PGSZ);
  remixbh_sync_mp(b);

  if (remixb2_valid(b)) {
    struct mbty_iter * iter0 = &b->iter0;
    struct bt_iter * const iter1 = b->iters[b->run1];
    struct kvref cref;
    if (remixb2_iter0_iter1_cmp(b) < 0) {
      mbty_iter_kvref_dup(iter0, &cref);
    } else {
      bt_iter_kvref(iter1, &cref);
    }
    kvref_dup2_key(&cref, b->tmp1);
    b->key0 = kv_dup_key(b->tmp1);
    // make tmp1 update
    b->tmp1->klen = !b->tmp1->klen;
  }

  remixbh_sync_rank(b);

  return b;
}

  static void
remixbh_skip1(struct remixb * b)
{
  struct mbty_iter * const iter0 = &b->iter0;

  const u32 nkeys = b->nr_pending;
  if (nkeys == 0) {
    const u32 alen = b->idx ? (kv_key_lcp(b->tmp0, b->tmp1) + 1) : 0;
    debug_assert(!alen == !b->idx);
    debug_assert(alen <= b->tmp1->klen);
    kv_dup2_key_prefix(b->tmp1, b->anchor, alen);

    remixb2_save_ptrs(b);
  }

  debug_assert(b->rankenc <= UINT8_MAX);
  b->ranks[nkeys] = (u8)b->rankenc;
  if (b->tags)
    b->tags[nkeys] = sst_tag(kv_crc32c(b->tmp1->kv, b->tmp1->klen));

  // tmp1 is the current key, it is updated in remixb2_sync_rank
  if (b->pkf) {
    pkf_append(b->pkf, b->tmp1);
  }

  b->nr_pending++;

  b->idx++;
  // does a skip then assign a rank
  const int cmp = remixbh_iter0_iter1_cmp(b);
  if (cmp < 0) {
    mbty_iter_skip1_dup(iter0);
  } else if (cmp > 0) {
    remixbh_iter1_skip1(b);
  } else {
    // cmp == 0
    if (remixbh_iter0_iter1_same(b)) {
      mbty_iter_skip1_dup(iter0);
      remixbh_iter1_skip1(b);
    } else {
      // actual key equivalence
      remixbh_iter1_skip1(b);
    }
  }
  if (remixbh_iter0_iter1_same(b) && remixbh_iter1_mgdkey(b)) {
    while (true) {
      mbty_iter_skip1_dup(iter0);
      debug_assert(remixbh_iter1_mgdkey(b) == true);
      remixbh_iter1_skip1(b);
      if (remixbh_valid(b) == false)
        break;
      if (remixbh_iter0_iter1_cmp(b) != 0)
        break;
      if (remixbh_iter0_iter1_same(b) == false)
        break;
      if (remixbh_iter1_mgdkey(b) == false)
        break;
    }
  }

  remixbh_sync_mp(b);
  remixbh_sync_rank(b);
}

  static void
remixbh_build_scan(struct remixb * const b, struct remixmeta * const meta)
{
  b->meta.scan_cnt++;
  struct mbty_iter * iter0 = &b->iter0;
  struct mbty_iter iter0_save = *iter0;

  u32 nr_pending = 0;
  bool finish_dbits = false;

  while (remixb_valid(b)) {
    if (mbty_iter_valid(iter0) && (mbty_iter_cmp_segs(&iter0_save, iter0) != 0)) {
      break;
    }
    const u32 rankenc = remixb_rankenc(b);
    debug_assert(rankenc < SSTY_INVALID);
    debug_assert((rankenc & SSTY_RANK) < b->nr_runs);
    debug_assert(nr_pending == b->nr_pending);
    remixmeta_collect(meta, rankenc);

    if ((rankenc & SSTY_STALE) == 0) {
      if ((nr_pending >= b->flush_thre_segment_nkeys) || (finish_dbits == true)) {
        nr_pending = 0;
        const bool r = remixbm_flush(b);
        if (!r)
          debug_die();

        finish_dbits = false;
      }
    }

    // assuming the skips are operated in just one segment
    remixbh_skip1(b);
    if (b->pkf) {
      finish_dbits = pkf_check_finish(b->pkf);
    }

    nr_pending++;
  }
  remixbm_flush(b);
  remixbh_sync_mp(b);
}

  static u32
remix_build_hist(struct remix_build_info * const bi)
{
  debug_assert((bi->hist_size != 0) && (bi->merge_hist != NULL));
  struct remixb * const b = remixbh_create(bi);
  struct mbty_iter * iter0 = &b->iter0;
  struct mbty_iter * iterb = &b->iterb;
  // when entering the loop, assuming iter0 is at the beginning of a segment

  struct remixmeta meta = {};

  while (mbty_iter_valid(iterb) && mbty_iter_valid(iter0)) {
    b->meta.build_seg_cnt++;
    if (mbty_iter_cmp_segs(iter0, iterb) < 0) {
      remixbh_build_upgrade(b, &meta);
    } else {
      remixbh_build_scan(b, &meta);
    }
  }

  // while iter0/iter1 is still valid, keep going
  while (remixb2_valid(b)) {
    remixbh_build_scan(b, &meta);
  }

  debug_assert(b->hist_idx == b->hist_size);

  const u32 pages_size = remix_finish_meta(bi, b, &meta);

  remixb2_report(b);
  remixb2_destroy(b);

  return pages_size;
}
// }}} remixbh

// main {{{
  u32
remix_build_at(const int dfd, struct mbt * const x1,
               const u64 seq, const u32 nr_runs,
               struct mbt * const y0, const u32 nr_reuse,
               const bool gen_tags, const bool gen_dbits,
               const bool inc_rebuild, const u8 * merge_hist, const u64 hist_size)
{
  // open ssty file for output
  debug_assert(nr_runs== x1->nr_runs);
  char fn[24];
  const u64 magic = seq * 100lu + nr_runs;
  sprintf(fn, "%03lu.remix", magic);
  const int fdout = openat(dfd, fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  if (fdout < 0)
    return 0;

  struct remix_build_info bi = {.x1 = x1, .y0 = y0,
                                .tags = gen_tags, .dbits = gen_dbits,
                                .fd = fdout,
                                .flush_thre_segment_nkeys = FLUSH_THRE_SEGMENT_NKEYS,
                                .max_segment_nkeys = FLUSH_THRE_SEGMENT_NKEYS<<1,
                                .nr_reuse = nr_reuse,
                                .merge_hist = merge_hist,
                                .hist_size = hist_size, };

  debug_assert(y0 == NULL || nr_reuse <= y0->nr_runs);

  for (u32 i = 0; i < x1->nr_runs; i++) {
    struct bt * bt = &x1->bts[i];

    if (posix_fadvise(bt->fd, 0, 0, POSIX_FADV_SEQUENTIAL)) {
      logger_printf("%s fadvise failed\n", __func__);
    }

    const size_t map_size = btmeta_mmap_size(&bt->meta);
    if (posix_madvise(bt->mem, map_size, POSIX_MADV_SEQUENTIAL)) {
      logger_printf("%s fadvise failed\n", __func__);
    }
  }

  u32 r;
  if ((inc_rebuild == false) ||
      (y0 == NULL) ||
      (remix_build_overlap(x1, nr_reuse) == true) ||
      (merge_hist == NULL)) {
    r = remix_build_miter(&bi);
  } else if (nr_reuse < y0->nr_runs) {
    r = remix_build_hist(&bi);
  } else {
    r = remix_build_b2(&bi);
  }

  for (u32 i = 0; i < x1->nr_runs; i++) {
    struct bt * bt = &x1->bts[i];

    if (posix_fadvise(bt->fd, 0, 0, POSIX_FADV_RANDOM)) {
      logger_printf("%s fadvise failed\n", __func__);
    }

    const size_t map_size = btmeta_mmap_size(&bt->meta);
    if (posix_madvise(bt->mem, map_size, POSIX_MADV_RANDOM)) {
      logger_printf("%s fadvise failed\n", __func__);
    }
  }

  return r;
}

  u32
remix_build(const char * const dirname, struct mbt * const x1,
            const u64 seq, const u32 nr_runs, struct mbt * const y0,
            const u32 nr_reuse, const bool gen_tags, const bool gen_dbits,
            const bool inc_rebuild, const u8 * merge_hist, const u64 hist_size)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return 0;
  u32 ret = remix_build_at(dfd, x1, seq, nr_runs, y0, nr_reuse, gen_tags, gen_dbits,
                            inc_rebuild, merge_hist, hist_size);
  close(dfd);
  return ret;
}

  struct mbt *
remix_build_at_reuse(const int dfd, struct rcache * const rc,
    struct msstz_ytask * task, struct msstz_cfg * zcfg, u64 * ysz)
{
  struct mbt * mbt = mbtx_open_at_reuse(dfd, task->seq1, task->run1, task->y0, task->run0);
  mbty_rcache(mbt, rc);

  u32 ysize = remix_build_at(dfd, mbt, task->seq1, task->run1,
      task->y0, task->run0, zcfg->tags, zcfg->dbits, zcfg->inc_rebuild,
      task->t_build_history, task->hist_size);
  if (ysize == 0) {
    debug_die();
  }
  *ysz = ysize;

  bool ry = mbty_open_y_at(dfd, mbt);
  if (ry == false) {
    debug_die();
  }
  return mbt;
}

  void
mbty_miter_major(struct mbt * const mbty, struct miter * const miter)
{
  miter_add(miter, &kvmap_api_mbty, mbty);
}

  void
mbt_miter_partial(struct mbt * const mbt, struct miter * const miter, const u32 bestrun)
{
  const u32 nrun0 = mbt->nr_runs;
  for (u32 w = bestrun; w < nrun0; w++)
    miter_add(miter, &kvmap_api_bt, &(mbt->bts[w]));
}

  u64
mbty_comp_est_remix(const u64 nkeys, const float run)
{
  // TODO: estimate should consider whether each feature is enabled
  // use the same policy as the sst for now
  // const u64 nsecs = nkeys / FLUSH_THRE_SEGMENT_NKEYS;
  // return (sizeof(struct bt_ptr) * (u64)ceilf(run) + 16) * nsecs + nkeys * 5;
  const u64 nsecs = nkeys / 32;
  return (sizeof(struct bt_ptr) * (u64)ceilf(run) + 16) * nsecs + nkeys;
}
// }}} main

// }}} remix_build

// {{{ full index
  inline void
mbtf_rcache(struct mbt * const mbt, struct rcache * const rc)
{
  mbtx_rcache(mbt, rc);
  if (mbt->findex != NULL) {
    bt_rcache(&mbt->findex->bt, rc);
  }
}

  static struct findex *
findex_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  char fn[16];
  const u64 magic = seq * 100lu + nr_runs;
  sprintf(fn, "%03lu.findex", magic);
  const int fd = openat(dfd, fn, O_RDONLY);
  if (fd < 0)
    return NULL;

  const size_t fsize = fdsize(fd);

  u32 first_key_len, last_key_len;
  pread(fd, &first_key_len, sizeof(u32), fsize - (2 * sizeof(u32)));
  pread(fd, &last_key_len, sizeof(u32), fsize - sizeof(u32));

  const u32 first_offset =
    fsize - (first_key_len + last_key_len + (2 * sizeof(u32)));

  const u32 last_offset = fsize - (last_key_len + (2 * sizeof(u32)));

  struct kv * first_key = calloc(1, first_key_len + sizeof(*first_key));
  pread(fd, first_key->kv, first_key_len, first_offset);

  struct kv * last_key = calloc(1, last_key_len + sizeof(*last_key));
  pread(fd, last_key->kv, last_key_len, last_offset);

  first_key->klen = first_key_len;
  last_key->klen = last_key_len;

  struct btmeta meta = {};
  const u32 meta_offset = fsize -
    (sizeof(struct btmeta) + first_key_len + last_key_len + (2 * sizeof(u32)));

  struct findex * findex = malloc(sizeof(*findex));
  pread(fd, &meta, sizeof(meta), meta_offset);
  bt_init(fd, &meta, &findex->bt, false);

  findex->first_key = first_key;
  findex->last_key = last_key;

  logger_printf("%s seq %lu nr_runs %u nr_keys %u nr_pages %u\n", __func__,
      seq, nr_runs, findex->bt.meta.nr_kvs, findex->bt.meta.root);
  return findex;
}

  static void
findex_destroy(struct findex * const findex)
{
  free(findex->first_key);
  free(findex->last_key);
  bt_deinit(&findex->bt);
  free(findex);
}

 static u32
findex_build_at(const int dfd, struct mbt * const x1)
{
  char fn[24];
  const u64 magic = mbt_get_magic(x1);
  sprintf(fn, "%03lu.findex", magic);
  const int fdout = openat(dfd, fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  if (fdout < 0)
    return 0;

  // TODO: pick a max pages
  struct btenc * btenc = btenc_create(fdout, UINT32_MAX);

  struct kv * tmp0 = malloc(sizeof(*tmp0) + PGSZ);
  struct kv * tmp1 = malloc(sizeof(*tmp1) + PGSZ);

  struct miter * const miter = miter_create();
  struct bt_iter * iters[MSST_NR_RUNS];
  const u32 nr_runs = x1->nr_runs;
  for (u32 i = 0; i < nr_runs; i++) {
    iters[i] = miter_add(miter, &kvmap_api_bt, &x1->bts[i]);
  }

  struct kv * first_key = NULL;
  struct kv * last_key = NULL;
  struct kv * prev = kv_dup2(kv_null(), tmp0);

  miter_seek(miter, kref_null());
  if (miter_valid(miter)) {
    first_key = miter_peek(miter, NULL);
  }

  char findex_value[sizeof(u8) + sizeof(struct bt_ptr)];
  // [ key ] { value: [1 byte: rank] [4 bytes: bt_ptr]}

  while (miter_valid(miter)) {
    struct kv * curr = miter_peek(miter, tmp1);
    debug_assert(curr);

    // when the current key is the same as the previous key
    const bool stale = (prev != NULL) && (kv_match(prev, curr));
    // don't encode it if this is a stale key
    const u32 rank = miter_rank(miter);
    debug_assert(rank < MSST_NR_RUNS);

    struct bt_ptr ptr = iters[rank]->ptr;
    findex_value[0] = (u8)rank;
    memcpy(findex_value + 1, &ptr, sizeof(ptr));
    kv_refill_value(curr, &findex_value, sizeof(findex_value));

    const bool r = btenc_append(btenc, curr, prev, false, true);
    if (!r)
      debug_die();
    miter_skip1(miter);

    if (!stale) {
      kv_dup2_key(curr, prev);
      prev = tmp0;
    }
    last_key = prev;
  }

  struct btmeta meta = {};
  const u64 nr_pages = btenc_finish(btenc, &meta);
  const u64 pages_size = nr_pages * PGSZ;

  lseek(fdout, (off_t)pages_size, SEEK_SET);

  write(fdout, &meta, sizeof(meta));

  // debug_assert(first_key != NULL && last_key != NULL);
  u32 first_key_len = 0;
  u32 last_key_len = 0;
  if (first_key) {
    write(fdout, first_key->kv, first_key->klen);
    first_key_len = first_key->klen;
    free(first_key);
  }
  if (last_key) {
    write(fdout, last_key->kv, last_key->klen);
    last_key_len = last_key->klen;
  }

  write(fdout, &first_key_len, sizeof(first_key_len));
  write(fdout, &last_key_len, sizeof(last_key_len));

  // we don't free last_key since its in tmp0
  free(tmp0);
  free(tmp1);

  fdatasync(fdout);
  close(fdout);
  btenc_destroy(btenc);

  miter_destroy(miter);

  logger_printf("%s seq %lu nr_runs %u nr_keys %u pages %u first_key_len %u last_key_len %u\n", __func__,
      x1->seq, nr_runs, meta.nr_kvs, meta.root, first_key_len, last_key_len);

  return pages_size + sizeof(meta) + (2 * sizeof(u32)) +
              first_key_len + last_key_len;
}

  static bool
mbtx_open_f_at(const int dfd, struct mbt * const mbt)
{
  debug_assert(mbt->findex == NULL);
  struct findex * const findex =
    findex_open_at(dfd, mbt->seq, mbt->nr_runs);
  mbt->findex = findex;
  return findex != NULL;
}

  struct mbt *
findex_build_at_reuse(const int dfd, struct rcache * const rc,
    struct msstz_ytask * task, struct msstz_cfg * zcfg, u64 * ysz)
{
  (void)zcfg;
  struct mbt * mbt = mbtx_open_at_reuse(dfd, task->seq1, task->run1, task->y0, task->run0);

  mbty_rcache(mbt, rc);
  u32 size = findex_build_at(dfd, mbt);
  if (size == 0) {
    debug_die();
  }
  *ysz = size;

  if (mbtx_open_f_at(dfd, mbt) == false) {
    debug_die();
  }

  return mbt;
}

  struct mbt *
mbtf_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  struct mbt * const mbt = mbtx_open_at(dfd, seq, nr_runs);
  if (mbt == NULL)
    return NULL;

  if (mbtx_open_f_at(dfd, mbt) == false) {
    mbtx_destroy(mbt);
    return NULL;
  }

  return mbt;
}

  struct mbt *
mbtf_open(const char * const dirname, const u64 seq, const u32 nr_runs)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return NULL;

  struct mbt * const mbt = mbtf_open_at(dfd, seq, nr_runs);
  close(dfd);
  return mbt;
}

  struct mbt *
mbtf_create_at(const int dfd)
{
  struct mbt * mbt = mbtx_open_at(dfd, 0, 0);
  if (mbt == NULL) {
    return NULL;
  }

  if (!findex_build_at(dfd, mbt)) {
    mbtx_destroy(mbt);
    return NULL;
  }

  if (!mbtx_open_f_at(dfd, mbt)) {
    mbtx_destroy(mbt);
    return NULL;
  }

  return mbt;
}

  void
mbtf_destroy(struct mbt * const mbt)
{
  findex_destroy(mbt->findex);
  mbt->findex = NULL;
  mbtx_destroy(mbt);
}

  static void
mbtf_destroy_lazy(struct mbt * const mbt)
{
  findex_destroy(mbt->findex);
  mbt->findex = NULL;
  mbtx_destroy_lazy(mbt);
}

  struct kv *
mbtf_first_key(struct mbt * const mbt, struct kv * const out)
{
  debug_assert(mbt->findex);
  return kv_dup2(mbt->findex->first_key, out);
}

  struct kv *
mbtf_last_key(struct mbt * const mbt, struct kv * const out)
{
  debug_assert(mbt->findex);
  return kv_dup2(mbt->findex->last_key, out);
}

  void
mbtf_drop_lazy(struct mbt * const mbt)
{
  if (mbt->refcnt == 1) {
    mbtf_destroy_lazy(mbt);
  } else {
    mbt->refcnt--;
  }
}

  void
mbtf_drop(struct mbt * const mbt)
{
  if (mbt->refcnt == 1) {
    mbtf_destroy(mbt);
  } else {
    mbt->refcnt--;
  }
}

  void
mbtf_miter_major(struct mbt * const mbt, struct miter * const miter)
{
  miter_add(miter, &kvmap_api_mbtf, mbt);
}

struct mbtf_iter {
  struct mbt * mbt;
  struct findex * findex;
  struct bt_ptr ptr;
  u32 rank;
  u32 nr_runs;
  struct bt_iter findex_iter;
  struct bt_iter iters[MSST_NR_RUNS];
};

  struct mbtf_iter *
mbtf_iter_create(struct mbtf_ref * const ref)
{
  return (struct mbtf_iter *)ref;
}

  static struct bt_iter *
mbtf_iter_bt_iter(struct mbtf_iter * const iter)
{
  debug_assert(mbtf_iter_valid(iter));
  return &iter->iters[iter->rank];
}

  static void
mbtf_iter_sync(struct mbtf_iter * const iter)
{
  const u8 * const vptr = bt_iter_vptr(&iter->findex_iter);
  const u32 rank = vptr[0];

  iter->rank = rank;
  memcpy(&iter->ptr, vptr + 1, sizeof(iter->ptr));
  debug_assert(rank < iter->nr_runs);

  struct bt_iter * bt_iter = &iter->iters[rank];
  bt_iter_set_ptr(bt_iter, iter->ptr);
  if (bt_iter_valid(bt_iter))
    bt_iter_fix_kv(bt_iter);
}

  static struct bt_iter *
mbtf_iter_match(struct mbtf_iter * const iter, const struct kref * const key, const bool hide_ts)
{
  if (bt_iter_match(&iter->findex_iter, key) == false) {
    return NULL;
  }

  mbtf_iter_sync(iter);
  if (mbtf_iter_valid(iter) == false) {
    debug_die();
    return NULL;
  }

  struct bt_iter * bt_iter = mbtf_iter_bt_iter(iter);
  debug_assert(bt_iter_compare_kref(bt_iter, key) == 0);

  if (hide_ts && bt_iter_ts(bt_iter)) {
    return NULL;
  }

  return bt_iter;
}

  static struct kv *
mbtf_get_internal(struct mbtf_ref * const ref, const struct kref * const key, struct kv * const out, const bool hide_ts)
{
  struct mbtf_iter * const iter = (typeof(iter))ref;
  struct bt_iter * const iter1 = mbtf_iter_match(iter, key, hide_ts);
  if (iter1) {
    struct kv * const ret = bt_iter_peek(iter1, out);
    mbtf_iter_park(iter);
    return ret;
  } else {
    return NULL;
  }
}

  struct kv *
mbtf_get_ts(struct mbtf_ref * const ref, const struct kref * const key, struct kv * const out)
{
  return mbtf_get_internal(ref, key, out, true);
}

  struct kv *
mbtf_get(struct mbtf_ref * const ref, const struct kref * const key, struct kv * const out)
{
  return mbtf_get_internal(ref, key, out, false);
}

  bool
mbtf_get_value_ts(struct mbtf_ref * const ref, const struct kref * key, void * const vbuf_out, u32 * const vlen_out)
{
  struct mbtf_iter * const iter = (typeof(iter))ref;
  struct bt_iter * const iter1 = mbtf_iter_match(iter, key, true);
  if (iter1) {
    memcpy(vbuf_out, iter1->kvdata + iter1->klen, iter1->vlen);
    *vlen_out = iter1->vlen;
    mbtf_iter_park(iter);
    return true;
  } else {
    return false;
  }
}

  static bool
mbtf_probe_internal(struct mbtf_ref * const ref, const struct kref * const key, const bool hide_ts)
{
  struct mbtf_iter * const iter = (typeof(iter))ref;
  struct bt_iter * iter1 = mbtf_iter_match(iter, key, hide_ts);
  if (iter1) {
    mbtf_iter_park(iter);
    return true;
  } else {
    return false;
  }
}

  bool
mbtf_probe_ts(struct mbtf_ref * const ref, const struct kref * const key)
{
  return mbtf_probe_internal(ref, key, true);
}

  bool
mbtf_probe(struct mbtf_ref * const ref, const struct kref * const key)
{
  return mbtf_probe_internal(ref, key, false);
}

  void
mbtf_iter_seek(struct mbtf_iter * const iter, const struct kref * const key)
{
  mbtf_iter_park(iter);

  if (bt_iter_seek_le(&iter->findex_iter, key) == false)
    return;

  mbtf_iter_sync(iter);
}

  struct kv *
mbtf_iter_peek(struct mbtf_iter * const iter, struct kv * const out)
{
  if (mbtf_iter_valid(iter) == false)
    return NULL;

  struct bt_iter * const iter1 = mbtf_iter_bt_iter(iter);
  return bt_iter_peek(iter1, out);
}

  bool
mbtf_iter_kref(struct mbtf_iter * const iter, struct kref * const kref)
{
  if (mbtf_iter_valid(iter) == false)
    return false;

  struct bt_iter * const iter1 = mbtf_iter_bt_iter(iter);
  return bt_iter_kref(iter1, kref);
}

  bool
mbtf_iter_kvref(struct mbtf_iter * const iter, struct kvref * const kvref)
{
  if (mbtf_iter_valid(iter) == false)
    return false;

  struct bt_iter * const iter1 = mbtf_iter_bt_iter(iter);
  return bt_iter_kvref(iter1, kvref);
}

  u64
mbtf_iter_retain(struct mbtf_iter * const iter)
{
  debug_assert(mbtf_iter_valid(iter));
  struct bt_iter * const iter1 = mbtf_iter_bt_iter(iter);
  debug_assert(iter1->bt->rc == iter->findex->bt.rc);
  return bt_iter_retain(iter1);
}

  bool
mbtf_iter_ts(struct mbtf_iter * const iter)
{
  debug_assert(mbtf_iter_valid(iter));

  struct bt_iter * const iter1 = mbtf_iter_bt_iter(iter);
  return iter1->vlen == SST_VLEN_TS;
}

  void
mbtf_iter_skip1(struct mbtf_iter * const iter)
{
  if (mbtf_iter_valid(iter) == false)
    return;

  bt_iter_skip1(&iter->findex_iter);

  mbtf_iter_sync(iter);
}

  void
mbtf_iter_release(struct mbtf_iter * const iter, const u64 opaque)
{
  bt_page_release(iter->findex->bt.rc, (const u8 *)opaque);
}

  void
mbtf_iter_skip(struct mbtf_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (mbtf_iter_valid(iter) == false)
      return;

    mbtf_iter_skip1(iter);
  }
}

  struct kv *
mbtf_iter_next(struct mbtf_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mbtf_iter_peek(iter, out);
  mbtf_iter_skip1(iter);
  return ret;
}

  struct mbtf_iter *
mbtf_iter_new()
{
  struct mbtf_iter * const iter = malloc(sizeof(*iter));
  return iter;
}

  void
mbtf_iter_init(struct mbtf_iter * const iter, struct mbt * const mbt)
{
  debug_assert(mbt->findex);
  iter->mbt = mbt;
  struct findex * const findex = mbt->findex;
  iter->findex = findex;
  iter->nr_runs = mbt->nr_runs;
  iter->rank = UINT8_MAX;
  bt_iter_init(&iter->findex_iter, &findex->bt, UINT8_MAX);
  for (u32 i = 0; i < iter->nr_runs; i++)
    bt_iter_init(&iter->iters[i], &mbt->bts[i], (u8)i);
}

  bool
mbtf_iter_valid(const struct mbtf_iter * const iter)
{
  const bool valid = (iter->rank < iter->nr_runs);
  if (valid == false) {
    return false;
  }
  const struct bt_iter * bt_iter = &iter->iters[iter->rank];
  return bt_iter_valid(bt_iter);
}

  void
mbtf_iter_seek_null(struct mbtf_iter * const iter)
{
  mbtf_iter_park(iter);
  bt_iter_seek_null(&iter->findex_iter);
  if (bt_iter_valid(&iter->findex_iter))
    bt_iter_fix_kv(&iter->findex_iter);
  mbtf_iter_sync(iter);
}

  void
mbtf_iter_park(struct mbtf_iter * const iter)
{
  iter->rank = UINT8_MAX;
  bt_iter_park(&(iter->findex_iter));
  for (u32 i = 0; i < iter->nr_runs; i++)
    bt_iter_park(&(iter->iters[i]));
}

  void
mbtf_fprint(struct mbt * const mbt, FILE * const fout)
{
  const u32 nr_runs = mbt->nr_runs;
  fprintf(fout, "%s seq %lu nr_runs %u\n", __func__, mbt->seq, nr_runs);
  fprintf(fout, "findex bt: ");
  bt_fprint(&mbt->findex->bt, fout);
  for (u32 i = 0; i < nr_runs; i++)
    bt_fprint(&(mbt->bts[i]), fout);
}

  void
mbtf_stats(const struct mbt * const mbt, struct msst_stats * const stats)
{
  memset(stats, 0, sizeof(*stats));
  for (u32 i = 0; i < mbt->nr_runs; i++) {
    const struct bt * const bt = &(mbt->bts[i]);
    stats->data_sz += (PGSZ * bt->meta.nr_leaf);
    stats->meta_sz += sizeof(bt->meta);
    stats->totkv += bt->meta.nr_kvs;
    const struct btmeta * const meta = &bt->meta;
    stats->totsz +=
      (PGSZ * (meta->root + 1)) + meta->btbf_size + meta->blbf_size + sizeof(*meta);
  }
  stats->nr_runs = mbt->nr_runs;
  const struct findex * const findex = mbt->findex;
  stats->ssty_sz = 0;
  if (findex != NULL) {
    stats->valid = findex->bt.meta.nr_kvs;
    stats->ssty_sz += findex->bt.meta.root * PGSZ;
    stats->ssty_sz += (findex->first_key->klen + sizeof(u32));
    stats->ssty_sz += (findex->last_key->klen + sizeof(u32));
  }
}

  void
mbtf_iter_destroy(struct mbtf_iter * const iter)
{
  mbtf_iter_park(iter);
}

  struct mbtf_ref *
mbtf_ref(struct mbt * const mbt)
{
  struct mbtf_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;

  mbtf_iter_init(iter, mbt);
  return (struct mbtf_ref *)iter;
}

  struct mbt *
mbtf_unref(struct mbtf_ref * const ref)
{
  struct mbtf_iter * const iter = (typeof(iter))ref;
  struct mbt * const mbt = iter->mbt;
  mbtf_iter_park(iter);
  free(iter);
  return mbt;
}
// }}} full index

// api {{{
// a drop-in replacement of sst
const struct kvmap_api kvmap_api_bt = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)bt_get,
  .probe = (void *)bt_probe,
  .iter_create = (void *)bt_iter_create,
  .iter_seek = (void *)bt_iter_seek,
  .iter_valid = (void *)bt_iter_valid,
  .iter_peek = (void *)bt_iter_peek,
  .iter_kref = (void *)bt_iter_kref,
  .iter_kvref = (void *)bt_iter_kvref,
  .iter_retain = (void *)bt_iter_retain,
  .iter_release = (void *)bt_iter_release,
  .iter_skip1 = (void *)bt_iter_skip1,
  .iter_skip = (void *)bt_iter_skip,
  .iter_next = (void *)bt_iter_next,
  .iter_park = (void *)bt_iter_park,
  .iter_destroy = (void *)bt_iter_destroy,
  .destroy = (void *)bt_destroy,
  .fprint = (void *)bt_fprint,
};

// see everything including stale and ts
const struct kvmap_api kvmap_api_mbtx = {
  .ordered = true,
  .readonly = true,
  .unique = false,
  .get = (void *)mbtx_get,
  .probe = (void *)mbtx_probe,
  .iter_create = (void *)mbtx_iter_create,
  .iter_seek = (void *)mbtx_iter_seek,
  .iter_valid = (void *)mbtx_iter_valid,
  .iter_peek = (void *)mbtx_iter_peek,
  .iter_kref = (void *)mbtx_iter_kref,
  .iter_kvref = (void *)mbtx_iter_kvref,
  .iter_retain = (void *)mbtx_iter_retain,
  .iter_release = (void *)mbtx_iter_release,
  .iter_skip1 = (void *)mbtx_iter_skip1,
  .iter_skip = (void *)mbtx_iter_skip,
  .iter_next = (void *)mbtx_iter_next,
  .iter_park = (void *)mbtx_iter_park,
  .iter_destroy = (void *)mbtx_iter_destroy,
  .ref = (void *)mbtx_ref,
  .unref = (void *)mbtx_unref,
  .destroy = (void *)mbtx_destroy,
  .fprint = (void *)mbtx_fprint,
};

// mbty (no-suffix) iterator: hide stale version, show tombstones
// mbty_ts iterator: hide stale versions, hide tombstones
// mbty_dup iterator: show everything, including stale versions and tombstones
const struct kvmap_api kvmap_api_mbty = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)mbty_get,
  .probe = (void *)mbty_probe,
  .iter_create = (void *)mbty_iter_create,
  .iter_seek = (void *)mbty_iter_seek,
  .iter_valid = (void *)mbty_iter_valid,
  .iter_peek = (void *)mbty_iter_peek,
  .iter_kref = (void *)mbty_iter_kref,
  .iter_kvref = (void *)mbty_iter_kvref,
  .iter_retain = (void *)mbty_iter_retain,
  .iter_release = (void *)mbty_iter_release,
  .iter_skip1 = (void *)mbty_iter_skip1,
  .iter_skip = (void *)mbty_iter_skip,
  .iter_next = (void *)mbty_iter_next,
  .iter_park = (void *)mbty_iter_park,
  .iter_destroy = (void *)mbty_iter_destroy,
  .ref = (void *)mbty_ref,
  .unref = (void *)mbty_unref,
  .destroy = (void *)mbty_destroy,
  .fprint = (void *)mbty_fprint,
};

const struct kvmap_api kvmap_api_mbty_ts = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)mbty_get_ts,
  .probe = (void *)mbty_probe_ts,
  .iter_create = (void *)mbty_iter_create,
  .iter_seek = (void *)mbty_iter_seek_ts,
  .iter_valid = (void *)mbty_iter_valid,
  .iter_peek = (void *)mbty_iter_peek,
  .iter_kref = (void *)mbty_iter_kref,
  .iter_kvref = (void *)mbty_iter_kvref,
  .iter_retain = (void *)mbty_iter_retain,
  .iter_release = (void *)mbty_iter_release,
  .iter_skip1 = (void *)mbty_iter_skip1_ts,
  .iter_skip = (void *)mbty_iter_skip_ts,
  .iter_next = (void *)mbty_iter_next_ts,
  .iter_park = (void *)mbty_iter_park,
  .iter_destroy = (void *)mbty_iter_destroy,
  .ref = (void *)mbty_ref,
  .unref = (void *)mbty_unref,
  .destroy = (void *)mbty_destroy,
  .fprint = (void *)mbty_fprint,
};

const struct kvmap_api kvmap_api_mbty_dup = {
  .ordered = true,
  .readonly = true,
  .get = (void *)mbty_get,
  .probe = (void *)mbty_probe,
  .iter_create = (void *)mbty_iter_create,
  .iter_seek = (void *)mbty_iter_seek,
  .iter_valid = (void *)mbty_iter_valid,
  .iter_peek = (void *)mbty_iter_peek_dup,
  .iter_kref = (void *)mbty_iter_kref_dup,
  .iter_kvref = (void *)mbty_iter_kvref_dup,
  .iter_retain = (void *)mbty_iter_retain,
  .iter_release = (void *)mbty_iter_release,
  .iter_skip1 = (void *)mbty_iter_skip1_dup,
  .iter_skip = (void *)mbty_iter_skip_dup,
  .iter_next = (void *)mbty_iter_next_dup,
  .iter_park = (void *)mbty_iter_park,
  .iter_destroy = (void *)mbty_iter_destroy,
  .ref = (void *)mbty_ref,
  .unref = (void *)mbty_unref,
  .destroy = (void *)mbty_destroy,
  .fprint = (void *)mbty_fprint,
};

const struct kvmap_api kvmap_api_mbtf = {
  .ordered = true,
  .readonly = true,
  .get = (void *)mbtf_get,
  .probe = (void *)mbtf_probe,
  .iter_create = (void *)mbtf_iter_create,
  .iter_seek = (void *)mbtf_iter_seek,
  .iter_valid = (void *)mbtf_iter_valid,
  .iter_peek = (void *)mbtf_iter_peek,
  .iter_kref = (void *)mbtf_iter_kref,
  .iter_kvref = (void *)mbtf_iter_kvref,
  .iter_retain = (void *)mbtf_iter_retain,
  .iter_release = (void *)mbtf_iter_release,
  .iter_skip1 = (void *)mbtf_iter_skip1,
  .iter_skip = (void *)mbtf_iter_skip,
  .iter_next = (void *)mbtf_iter_next,
  .iter_park = (void *)mbtf_iter_park,
  .iter_destroy = (void *)mbtf_iter_destroy,
  .ref = (void *)mbtf_ref,
  .unref = (void *)mbtf_unref,
  .destroy = (void *)mbtf_destroy,
  .fprint = (void *)mbtf_fprint,
};

  static void *
bt_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  (void)mm;
  if (!strcmp(name, "bt")) {
    return bt_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else if (!strcmp(name, "mbtx")) {
    return mbtx_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else if ((!strcmp(name, "mbty")) || (!strcmp(name, "mbty_ts")) || (!strcmp(name, "mbty_dup"))) {
    return mbty_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else if (!strcmp(name, "mbtf")) {
    return mbtf_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else {
    return NULL;
  }
}

// alternatively, call the register function from main()
__attribute__((constructor))
  static void
bt_kvmap_api_init(void)
{
  kvmap_api_register(3, "bt", "<dirname> <seq> <run>", bt_kvmap_api_create, &kvmap_api_bt);
  kvmap_api_register(3, "mbtx", "<dirname> <seq> <nr_runs>", bt_kvmap_api_create, &kvmap_api_mbtx);
  kvmap_api_register(3, "mbty", "<dirname> <seq> <nr_runs>", bt_kvmap_api_create, &kvmap_api_mbty);
  kvmap_api_register(3, "mbty_ts", "<dirname> <seq> <nr_runs>", bt_kvmap_api_create, &kvmap_api_mbty_ts);
  kvmap_api_register(3, "mbty_dup", "<dirname> <seq> <nr_runs>", bt_kvmap_api_create, &kvmap_api_mbty_dup);
  kvmap_api_register(3, "mbtf", "<dirname> <seq> <nr_runs>", bt_kvmap_api_create, &kvmap_api_mbtf);
}
// }}} api

// vim:fdm=marker
