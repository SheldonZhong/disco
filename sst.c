/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include "lib.h"
#include "ctypes.h"
#include "kv.h"
#include <assert.h> // static_assert
#include <dirent.h> // opendir
#include <sys/uio.h> // writev
#include "sst.h"
#include "pkeys.h"

// }}} headers

// define {{{
// 4 for 16; 5 for 32; TODO: 6 for 64
#define SSTY_DBITS ((5))
#define SSTY_DIST ((1u << SSTY_DBITS))
static_assert(SSTY_DBITS >= 4 && SSTY_DBITS <= 5, "Supported SSTY_DBITS: 4 and 5; TODO: 6");
static_assert(SSTY_DBITS == 5, "Supported SSTY_DBITS: 5 because current implementation of dbits");

#if defined(__linux__)
#define SSTY_MMAP_FLAGS ((MAP_PRIVATE|MAP_POPULATE))
#define SST_OPEN_FLAGS ((O_RDONLY|O_DIRECT))
#define SSTY_OPEN_FLAGS ((O_RDONLY|O_DIRECT))
#else
#define SSTY_MMAP_FLAGS ((MAP_PRIVATE))
#define SST_OPEN_FLAGS ((O_RDONLY))
#define SSTY_OPEN_FLAGS ((O_RDONLY))
#endif

// turn on IO-optimized binary search by default; comment out to disable
#define MSSTY_SEEK_BISECT_OPT
// }}} define

// kvenc {{{
// an append-only buffer for serialization
// 2MB * 127 = 254 MB
#define KVENC_BUFSZ ((1u << 21))
#define KVENC_BUFNR ((127))
struct kvenc {
  u32 idx;
  u32 off;
  u8 * bufs[KVENC_BUFNR];
};

  static struct kvenc *
kvenc_create(void)
{
  return calloc(1, sizeof(struct kvenc));
}

// append raw data of any size
  static void
kvenc_append_raw(struct kvenc * const enc, const void * const data, const u32 size)
{
  u32 off = 0;
  u32 rem = size;
  while (rem) {
    const u32 bufidx = enc->idx;
    debug_assert(bufidx < KVENC_BUFNR);
    if (enc->bufs[bufidx] == NULL)
      enc->bufs[bufidx] = malloc(KVENC_BUFSZ);

    const u32 cpsz = (rem <= (KVENC_BUFSZ - enc->off)) ? rem : (KVENC_BUFSZ - enc->off);
    if (data)
      memcpy(enc->bufs[bufidx] + enc->off, ((u8 *)data) + off, cpsz);
    else
      memset(enc->bufs[bufidx] + enc->off, 0, cpsz);

    rem -= cpsz;
    off += cpsz;
    enc->off += cpsz;
    if (enc->off == KVENC_BUFSZ) {
      enc->idx = bufidx + 1;
      enc->off = 0;
    }
  }
}

// append 1 byte
  static void
kvenc_append_u8(struct kvenc * const enc, const u8 v)
{
  kvenc_append_raw(enc, &v, sizeof(v));
}

// append a u32 (4 bytes in little-endian order)
  static inline void
kvenc_append_u32(struct kvenc * const enc, const u32 val)
{
  kvenc_append_raw(enc, &val, sizeof(val));
}

// append a u16 (2 bytes in little-endian order)
  static inline void
kvenc_append_u16(struct kvenc * const enc, const u16 val)
{
  kvenc_append_raw(enc, &val, sizeof(val));
}

// append a place holder for u32 and return the pointer to the location
  static inline u32 *
kvenc_append_u32_backref(struct kvenc * const enc)
{
  const u32 idx = enc->idx;
  const u32 off = enc->off;
  debug_assert((off + sizeof(u32)) <= KVENC_BUFSZ);
  debug_assert((off % sizeof(u32)) == 0);
  kvenc_append_raw(enc, NULL, sizeof(u32));
  return (u32 *)(enc->bufs[idx] + off);
}

// encode a u32 value with vi128
  static inline void
kvenc_append_vi128(struct kvenc * const enc, const u32 val)
{
  u8 buf[8];
  u8 * const end = vi128_encode_u32(buf, val);
  kvenc_append_raw(enc, buf, (u32)(end - buf));
}

// move the cursor forward to the nearest aligned offset
  static inline void
kvenc_append_padding(struct kvenc * const enc, const u32 power)
{
  debug_assert(power <= 12);
  const u32 p2 = 1u << power;
  const u32 off = enc->off & (p2 - 1);
  if (off)
    kvenc_append_raw(enc, NULL, p2 - off);
}

// return the total size of the bufferred data
  static u32
kvenc_size(struct kvenc * const enc)
{
  return enc ? (KVENC_BUFSZ * enc->idx + enc->off) : 0;
}

// write everything to a file
  static ssize_t
kvenc_write(struct kvenc * const enc, const int fd)
{
  struct iovec vec[KVENC_BUFNR+1];
  const u32 nr = enc->idx;
  for (u32 i = 0; i < nr; i++) {
    vec[i].iov_base = enc->bufs[i];
    vec[i].iov_len = KVENC_BUFSZ;
  }
  vec[nr].iov_base = enc->bufs[nr];
  vec[nr].iov_len = enc->off;
  return writev(fd, vec, (int)(enc->off ? (nr + 1) : nr));
}

// reset the cursor to 0 and free all the buffers
  static void
kvenc_reset(struct kvenc * const enc)
{
  for (u32 i = 0; i < KVENC_BUFNR; i++) {
    if (enc->bufs[i])
      free(enc->bufs[i]);
    else
      break;
  }
  memset(enc, 0, sizeof(*enc));
}

  static void
kvenc_destroy(struct kvenc * const enc)
{
  const u32 nr = enc->idx;
  for (u32 i = 0; i < nr; i++)
    free(enc->bufs[i]);
  if (enc->off)
    free(enc->bufs[nr]);
  free(enc);
}
// }}} kvenc

// sst {{{
struct sst_blkmeta { // the first two bytes in each block
  u16 nkeys; // number of keys
  u16 offs[0];
};

struct sst_meta {
  u32 nblks; // == 0 for empty sst in the place of bms[0]
  u32 npages;
  u64 seq; // the original seq; a linking will generate greater seq in file name
  u32 run; // this is always valid after linking
  u32 totkv;
  u32 bmsoff;
  u32 ioffsoff;
  u32 ckeysoff;
  u32 ckeyssz;
};

struct sst {
  const struct sst_blkmeta * bms; // block metadata (2-byte each)
  u32 nblks; // number of index keys in ioffs
  u32 npages; // number of 4kB data blocks
  int fd;
  u32 refcnt; // not atomic; an sst can be referenced by multiple msst (versions of partitions)
  struct rcache * rc;
  const u32 * ioffs; // offsets of the index keys
  u8 * mem; // pointer to the mmap area
  u32 fsize;
  u32 totkv;
};

  static bool
sst_init_at(const int dfd, const u64 seq, const u32 run, struct sst * const sst)
{
  char fn[24];
  const u64 magic = seq * 100lu + run;
  sprintf(fn, "%03lu.sstx", magic);
  const int fd = openat(dfd, fn, SST_OPEN_FLAGS);
  if (fd < 0)
    return false;

  const size_t fsize = fdsize(fd);
  if (fsize == 0 || fsize >= UINT32_MAX) {
    close(fd);
    return false;
  }

  // Hugepages make replacement hard; some file systems don't support hugepages
  //MAP_HUGETLB|MAP_HUGE_2MB
  u8 * const mem = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mem == MAP_FAILED)
    return false;

  debug_assert(mem);
  sst->mem = mem;
  sst->fsize = (u32)fsize;
  const struct sst_meta * const meta = sst_meta(sst);
  debug_assert((meta->seq < seq) || ((meta->seq == seq) && (meta->run == run)));
  sst->bms = (typeof(sst->bms))(mem + meta->bmsoff);
  sst->nblks = meta->nblks;
  sst->npages = meta->npages;
  sst->fd = fd; // keep fd open
  sst->refcnt = 1;
  sst->rc = NULL;
  sst->ioffs = (typeof(sst->ioffs))(mem + meta->ioffsoff);
  sst->totkv = meta->totkv;
  //const u32 datasz = PGSZ * sst->npages;
  //madvise(mem, datasz, MADV_RANDOM);
  //pages_lock(mem + datasz, fsize - datasz); // mlock the metadata area; not necessary with ssty
  //pages_lock((void *)sst->bms, sizeof(sst->bms[0]) * meta->npages); // mlock the bms
  return true;
}

  const struct sst_meta *
sst_meta(struct sst * const sst)
{
  const struct sst_meta * const meta = (typeof(meta))(sst->mem + sst->fsize - sizeof(*meta));
  return meta;
}

  inline void
sst_rcache(struct sst * const sst, struct rcache * const rc)
{
  sst->rc = rc;
}

  static struct sst *
sst_open_at(const int dfd, const u64 seq, const u32 run)
{
  struct sst * const sst = yalloc(sizeof(*sst));
  if (sst == NULL)
    return NULL;
  if (sst_init_at(dfd, seq, run, sst)) {
    return sst;
  } else {
    free(sst);
    return NULL;
  }
}

  struct sst *
sst_open(const char * const dirname, const u64 seq, const u32 run)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return NULL;
  struct sst * const sst = sst_open_at(dfd, seq, run);
  close(dfd);
  return sst;
}

  static inline u32
k128_search_le(const u8 * const base, const u32 * const ioffs, const struct kref * const key, u32 l, u32 r)
{
  while ((l + 1) < r) {
    const u32 m = (l + r) >> 1;
    const int cmp = kref_k128_compare(key, base + ioffs[m]);
    if (cmp < 0) // search-key < [m]
      r = m;
    else if (cmp > 0) // search-key > [m]
      l = m;
    else
      return m;
  }
  return l;
}

  static u16
sst_search_pageid(struct sst * const map, const struct kref * const key)
{
  const u32 ikeyid = k128_search_le(map->mem + sizeof(u16), map->ioffs, key, 0, map->nblks);
  const u16 pageid = *(const u16 *)(map->mem + map->ioffs[ikeyid]);
  return pageid;
}

// access data blocks from here
  static inline const u8 *
sst_blk_acquire(const struct sst * const map, const u32 pageid)
{
  if (map->rc) {
    const u8 * const ptr = rcache_acquire(map->rc, map->fd, pageid);
    debug_assert(ptr);
    return ptr;
  } else {
    return map->mem + (PGSZ * pageid);
  }
}

  static inline u64
sst_blk_retain(struct rcache * const rc, const u8 * blk)
{
  debug_assert(blk && (((u64)blk) & 0xffflu) == 0);
  if (rc)
    rcache_retain(rc, blk);
  return (u64)blk;
}

  static inline void
sst_blk_release(struct rcache * const rc, const u8 * blk)
{
  debug_assert(blk && (((u64)blk) & 0xffflu) == 0);
  if (rc)
    rcache_release(rc, blk);
}

// the highest bit is set if there is a match
// return 0 to nkeys (low bits)
  static u32
sst_search_block_ge(const u8 * const blk, const struct kref * const key)
{
  const struct sst_blkmeta * const bm = (typeof(bm))blk;
  u32 l = 0;
  u32 r = ((struct sst_blkmeta *)blk)->nkeys; // blkmeta.nkeys
  while (l < r) {
    const u32 m = (l + r) >> 1;
    const int cmp = kref_kv128_compare(key, blk + bm->offs[m]);
    if (cmp < 0)
      r = m;
    else if (cmp > 0)
      l = m + 1;
    else
      return m | (1u << 31); // match
  }
  return l;
}

  static inline const u8 *
sst_blk_get_kvptr(const u8 * const blk, const u32 id)
{
  const struct sst_blkmeta * const bm = (typeof(bm))blk;
  debug_assert(id < bm->nkeys);
  return blk + bm->offs[id];
}

  struct kv *
sst_get(struct sst * const map, const struct kref * const key, struct kv * const out)
{
  const u16 pageid = sst_search_pageid(map, key);

  // search in the block
  const u8 * const blk = sst_blk_acquire(map, pageid);
  const u32 r = sst_search_block_ge(blk, key);
  if ((r >> 31) == 0) { // not found
    sst_blk_release(map->rc, blk);
    return NULL;
  }

  // found
  const u8 * ptr = sst_blk_get_kvptr(blk, r & 0xffffu);
  u32 klen, vlen;
  ptr = vi128_decode_u32(ptr, &klen);
  ptr = vi128_decode_u32(ptr, &vlen);

  const u32 vlen1 = vlen & SST_VLEN_MASK;
  const u32 kvlen = klen + vlen1;
  struct kv * const ret = out ? out : malloc(sizeof(*ret) + kvlen);
  ret->klen = klen;
  ret->vlen = vlen;
  memcpy(ret->kv, ptr, kvlen);
  sst_blk_release(map->rc, blk);
  return ret;
}

  bool
sst_probe(struct sst * const map, const struct kref * const key)
{
  const u16 pageid = sst_search_pageid(map, key);

  // search in the block
  const u8 * const blk = sst_blk_acquire(map, pageid);
  const u32 r = sst_search_block_ge(blk, key);
  sst_blk_release(map->rc, blk);
  return (r >> 31);
}

  struct kv *
sst_first_key(const struct sst * const map, struct kv * const out)
{
  if (map->npages == 0)
    return NULL;

  const u8 * const blk = sst_blk_acquire(map, 0);
  const u8 * ptr = sst_blk_get_kvptr(blk, 0);
  u32 klen, vlen;
  ptr = vi128_decode_u32(ptr, &klen);
  ptr = vi128_decode_u32(ptr, &vlen);
  struct kv * const ret = out ? out : malloc(sizeof(*ret) + klen);
  ret->klen = klen;
  ret->vlen = 0;
  memcpy(ret->kv, ptr, klen);
  sst_blk_release(map->rc, blk);
  return ret;
}

  struct kv *
sst_last_key(const struct sst * const map, struct kv * const out)
{
  if (map->npages == 0)
    return NULL;

  const u8 * const blk = sst_blk_acquire(map, map->npages-1);
  const struct sst_blkmeta * const bm = (typeof(bm))blk;
  const u8 * ptr = sst_blk_get_kvptr(blk, bm->nkeys-1);
  u32 klen, vlen;
  ptr = vi128_decode_u32(ptr, &klen);
  ptr = vi128_decode_u32(ptr, &vlen);
  struct kv * const ret = out ? out : malloc(sizeof(*ret) + klen);
  ret->klen = klen;
  ret->vlen = 0;
  memcpy(ret->kv, ptr, klen);
  sst_blk_release(map->rc, blk);
  return ret;
}

  static void
sst_deinit(struct sst * const map)
{
  if (map->refcnt == 1) {
    debug_assert(map->mem);
    munmap((void *)map->mem, map->fsize);
    if (map->rc)
      rcache_close(map->rc, map->fd);
    else
      close(map->fd);
  } else {
    map->refcnt--;
  }
}

  static void
sst_deinit_lazy(struct sst * const map)
{
  if (map->refcnt == 1) {
    debug_assert(map->mem);
    munmap((void *)map->mem, map->fsize);
    if (map->rc)
      rcache_close_lazy(map->rc, map->fd);
    else
      close(map->fd);
  } else {
    map->refcnt--;
  }
}

  void
sst_destroy(struct sst * const map)
{
  sst_deinit(map);
  free(map);
}

  void
sst_fprint(struct sst * const map, FILE * const out)
{
  fprintf(out, "%s totkv %u nblks %u npages %u filesz %u\n",
      __func__, map->totkv, map->nblks, map->npages, map->fsize);
}
// }}} sst

// sst_build {{{
// at most 1xklen=0+253xklen=1 key 4-byte each
#define SST_BUILD_MAX_KPB ((621)) // maximum possible keys per block
#define SST_BUILD_METASZ ((sizeof(u16) * SST_BUILD_MAX_KPB * 2))
#define SST_BUILD_BUFSZ ((SST_BUILD_METASZ + SST_MAX_BLKSZ))
#define SST_BUILD_NVEC ((16))

// from k0 (inclusive) to kz (exclusive)
// warning: all iters in miter must handle the tombstone (vlen >= SST_VLEN_TS)
// return the output file size (in bytes)
  u64
sst_build_at(const int dfd, struct miter * const miter,
    const struct t_build_cfg * const cfg,
    const struct kv * const k0, const struct kv * const kz)
{
  char fn[24];
  const u64 magic = cfg->seq * 100lu + cfg->run;
  sprintf(fn, "%03lu.sstx", magic);
  const int fdout = openat(dfd, fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  if (fdout < 0)
    return 0;

  struct kv * const tmp0 = malloc(sizeof(*tmp0) + SST_MAX_BLKSZ);
  kv_refill(tmp0, "", 0, "", 0);
  struct kv * const tmp1 = malloc(sizeof(*tmp0) + SST_MAX_BLKSZ);

  // kv encoding buffers
  struct iovec vecs[SST_BUILD_NVEC];
  u8 * const databufs = malloc(SST_BUILD_BUFSZ * SST_BUILD_NVEC); // kv blocks
  u16 * mbuf = (u16 *)databufs;
  u8 * kvbuf = ((u8 *)mbuf) + SST_BUILD_METASZ;
  u8 * kvcsr = kvbuf;
  u32 vi = 0;

  // max number of 4kB data blocks
  const u32 tgtblksz = PGSZ;
  debug_assert(cfg->max_pages && (cfg->max_pages <= SST_MAX_PAGEID));
  struct sst_blkmeta * const bms = calloc(1, sizeof(bms[0]) * (cfg->max_pages + 1));
  u32 keyid = 0; // number of keys in current block
  u32 pageid = 0;
  u32 totkv = 0;
  // at most 65536 ikeys
  u32 * const ioffs = malloc(sizeof(ioffs[0]) * (1lu << 16)); // offsets of ikeys

  struct kvenc * const aenc = kvenc_create();
  struct kvenc * const kenc = kvenc_create();
  u32 nblks = 0;

  if (k0)
    miter_kv_seek(miter, k0);

  do {
    // key in tmp1
    struct kv * curr = miter_peek(miter, tmp1);

    // if del is true then skip all tombstones and stale keys
    if (cfg->del) {
      while (curr && (curr->vlen == SST_VLEN_TS)) {
        miter_skip_unique(miter);
        curr = miter_peek(miter, tmp1);
      }
    }

    // check for termination
    if (curr && kz && (kv_compare(curr, kz) >= 0))
      curr = NULL;

    const size_t est1 = curr ? ((u32)sst_kv_vi128_estimate(curr) + sizeof(u16)) : 0;
    if (est1 > SST_MAX_KVSZ) {
      fprintf(stderr, "WARNING: skip very long kv: size=%zu\n", est1);
      miter_skip_unique(miter);
      continue;
    }
    // estimate the sizes if curr is added to the current block
    const u32 metasz = sizeof(u16) * (keyid + 1);
    const u32 datasz = (u32)(kvcsr - kvbuf);
    const u32 totsz = metasz + datasz;
    const u32 esttot = totsz + (u32)est1;
    // close and write current block if:
    //     no more new data: curr == NULL
    // or: the new keys is not the first key AND total size is more than one page
    if (curr == NULL || (keyid && (esttot > tgtblksz))) {
      if (keyid == 0)
        break;

      debug_assert(keyid <= SST_BUILD_MAX_KPB);
      // blksize: whole pages
      const u32 blksize = (u32)bits_round_up(totsz, PGBITS);
      // encode the metadata right before the kvbuf
      struct sst_blkmeta * const bm = (typeof(bm))(kvbuf - metasz);
      bm->nkeys = (u16)keyid; // u32 to u16
      bms[pageid].nkeys = bm->nkeys; // a separate copy
      for (u32 i = 0; i < keyid; i++)
        bm->offs[i] = mbuf[i] + (u16)metasz;

      memset(kvcsr, 0, blksize - totsz); // zero-padding

      struct iovec * const vec = &vecs[vi];
      vec->iov_base = bm;
      vec->iov_len = blksize;
      vi++;
      if (vi == SST_BUILD_NVEC) {
        writev(fdout, vecs, (int)vi); // ignore I/O errors
        vi = 0;
      }
      mbuf = (u16 *)(databufs + (SST_BUILD_BUFSZ * vi));
      kvbuf = ((u8 *)mbuf) + SST_BUILD_METASZ;
      kvcsr = kvbuf;
      keyid = 0;
      pageid++;
      // stop processing the next block; break the do-while loop
      if ((curr == NULL) || (pageid >= cfg->max_pages))
        break;
    }

    // the beginning of a block: build anchor key for every head key of block
    if (keyid == 0) {
      ioffs[nblks] = kvenc_size(aenc);
      // block id
      debug_assert(pageid <= SST_MAX_PAGEID);
      kvenc_append_u16(aenc, (u16)pageid);
      // anchor key
      const u32 alen = tmp0->klen ? (kv_key_lcp(tmp0, curr)+1) : 0;
      debug_assert(alen <= curr->klen);
      // encode index key
      kvenc_append_vi128(aenc, alen);
      kvenc_append_raw(aenc, curr->kv, alen);
      nblks++;
    }

    // append kv to data block
    mbuf[keyid++] = (u16)(kvcsr - kvbuf);
    kvcsr = sst_kv_vi128_encode(kvcsr, curr);
    totkv++;
    // copy keys for faster remix building
    if (cfg->ckeys) {
      const u32 lcp = kv_key_lcp(curr, tmp0);
      const u32 slen = curr->klen - lcp;
      kvenc_append_vi128(kenc, lcp); // prefix length
      kvenc_append_vi128(kenc, slen); // suffix length
      kvenc_append_u8(kenc, curr->vlen == SST_VLEN_TS ? 1 : 0);
      kvenc_append_raw(kenc, curr->kv + lcp, slen);
    }
    // remember last key in tmp0
    kv_dup2_key(curr, tmp0);
    miter_skip_unique(miter);
  } while (true);

  if (vi)
    writev(fdout, vecs, (int)vi); // ignore I/O errors

  debug_assert(nblks == pageid && pageid <= cfg->max_pages);
  // place bms immediately after data blocks
  const u32 bmsoff = PGSZ * pageid;
  const u32 bmssz = sizeof(bms[0]) * pageid;
  // now all data blocks have been written; write one big index block
  // calculate index-key offsets
  const u32 ikeysoff = bmsoff + bmssz; // index keys
  for (u64 i = 0; i < nblks; i++)
    ioffs[i] += ikeysoff;
  // write: index keys; all index-key offsets; # of index-keys
  kvenc_append_padding(aenc, 4);
  kvenc_append_padding(kenc, 4);
  const u32 ikeyssz = kvenc_size(aenc);
  const u32 ioffsoff = ikeysoff + ikeyssz;
  const u32 ioffssz = sizeof(ioffs[0]) * nblks;
  const u32 ckeysoff = ioffsoff + ioffssz;
  const u32 ckeyssz = kvenc_size(kenc);

  // metadata
  debug_assert(nblks == pageid);
  struct sst_meta endmeta = {.nblks = nblks, .npages = pageid, .seq = cfg->seq, .run = cfg->run, .totkv = totkv,
    .bmsoff = bmsoff, .ioffsoff = ioffsoff, .ckeysoff = ckeysoff, .ckeyssz = ckeyssz, };
  const u32 endsz = sizeof(endmeta);
  const u64 totsz = ckeysoff + ckeyssz + endsz;

  // sst file layout:
  // 0: data blocks 4kB x pageid     +bmsoff==blkssz
  // bmsoff: blockmetas (bms)        +bmssz[0]
  // ikeysoff: index keys (ikeys)    +ikeyssz[1]
  // ioffsoff: index offsets (ioffs) +ioffssz[2]
  // ?:      endmeta                 +endsz[3]
  // totsz is file size

  //fprintf(stderr, "%s totkv %u nblks %u npages %u bmssz %u ikeyssz %u ioffssz %u\n",
  //    __func__, totkv, nblks, pageid, bmssz, ikeyssz, ioffssz);

  const ssize_t nwbms = write(fdout, bms, bmssz);
  const ssize_t nwanc = kvenc_write(aenc, fdout);
  const ssize_t nwiof = write(fdout, ioffs, ioffssz);
  const ssize_t nwcpy = kvenc_write(kenc, fdout);
  const ssize_t nwmeta = write(fdout, &endmeta, endsz);
  const bool wok = (bmssz + ikeyssz + ioffssz + ckeyssz + endsz) == (nwbms + nwanc + nwiof + nwcpy + nwmeta);

  // done
  fsync(fdout);
  close(fdout);
  free(tmp0);
  free(tmp1);
  free(databufs);
  free(bms);
  free(ioffs);
  kvenc_destroy(aenc);
  kvenc_destroy(kenc);
  return wok ? totsz : 0;
}

  u64
sst_build(const char * const dirname, struct miter * const miter,
    const u64 seq, const u32 run, const u16 max_pages,
    const bool del, const bool ckeys,
    const bool bloom, const bool leaf_bloom,
    const struct kv * const k0, const struct kv * const kz)
{
  (void)leaf_bloom;
  (void)bloom;
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return 0;

  const struct t_build_cfg cfg = {.seq = seq, .run = run,
    .max_pages = max_pages, .del = del, .ckeys = ckeys};
  const u64 ret = sst_build_at(dfd, miter, &cfg, k0, kz);
  close(dfd);
  return ret;
}
// }}} sst_build

// sst_iter {{{
struct sst_ptr {
  u16 pageid; // xth 4kb-block in the table
  u16 keyid; // xth key in the block // MAX == invalid
};

struct sst_iter { // 32 bytes
  struct sst * sst;
  u8 rank; // pure rank value < nr_runs
  u8 padding;
  u16 npages; // valid: pageid < npages
  struct sst_ptr ptr;
  u32 klen;
  u32 vlen;
  const u8 * kvdata;
};

  static int
sst_iter_compare(struct sst_iter * const i1, struct sst_iter * const i2)
{
  debug_assert(i1->ptr.keyid != UINT16_MAX);
  debug_assert(i2->ptr.keyid != UINT16_MAX);
  const u32 len = i1->klen < i2->klen ? i1->klen : i2->klen;
  const int cmp = memcmp(i1->kvdata, i2->kvdata, len);
  return cmp ? cmp : (((int)i1->klen) - ((int)i2->klen));
}

// i1 must be valid
// key can be NULL
  static int
sst_iter_compare_kref(struct sst_iter * const iter, const struct kref * const key)
{
  debug_assert(iter->ptr.keyid != UINT16_MAX);
  debug_assert(key);
  const u32 len = (iter->klen < key->len) ? iter->klen : key->len;
  const int cmp = memcmp(iter->kvdata, key->ptr, len);
  if (cmp != 0) {
    return cmp;
  } else {
    return ((int)iter->klen) - ((int)key->len);
  }
}

  static inline bool
sst_iter_match_kref(const struct sst_iter * const i1, const struct kref * const key)
{
  debug_assert(i1->ptr.keyid != UINT16_MAX);
  return (i1->klen == key->len) && (!memcmp(i1->kvdata, key->ptr, i1->klen));
}

  static inline const u8 *
sst_iter_blk_addr(struct sst_iter * const iter)
{
  debug_assert(iter->kvdata);
  const u64 addr = ((u64)iter->kvdata) >> PGBITS << PGBITS;
  return (const u8 *)addr;
}

  static inline void
sst_iter_blk_release(struct sst_iter * const iter)
{
  if (iter->kvdata) {
    // get page address
    const u8 * const blk = sst_iter_blk_addr(iter);
    sst_blk_release(iter->sst->rc, blk);
    iter->kvdata = NULL;
  }
}

// blk has been acquired by the caller; now iter owns it
  static void
sst_iter_fix_kv_blk(struct sst_iter * const iter, const u8 * const blk)
{
  const u8 * ptr = sst_blk_get_kvptr(blk, iter->ptr.keyid);
  ptr = vi128_decode_u32(ptr, &iter->klen);
  iter->kvdata = vi128_decode_u32(ptr, &iter->vlen);
}

  static void
sst_iter_fix_kv_reuse(struct sst_iter * const iter)
{
  // reuse the kvdata and keyid
  debug_assert(iter->kvdata);
  const u8 * const blk = sst_iter_blk_addr(iter);
  sst_iter_fix_kv_blk(iter, blk);
}

// make kvdata current with the iter; acquire blk
// also used by mssty
  static void
sst_iter_fix_kv(struct sst_iter * const iter)
{
  // don't fix if invalid or already has the ->kvdata
  if ((!sst_iter_valid(iter)) || iter->kvdata)
    return;

  const u8 * blk = sst_blk_acquire(iter->sst, iter->ptr.pageid);
  sst_iter_fix_kv_blk(iter, blk);
}

// points to the first key; invalid for empty sst
  static inline void
sst_iter_init(struct sst_iter * const iter, struct sst * const sst, const u8 rank)
{
  debug_assert(rank < MSST_NR_RUNS);
  debug_assert(sst->npages < UINT16_MAX);
  iter->sst = sst;
  iter->rank = rank;
  iter->npages = (u16)sst->npages;
  iter->ptr.pageid = iter->npages;
  iter->ptr.keyid = UINT16_MAX;
  // klen, vlen are ignored
  iter->kvdata = NULL;
}

  struct sst_iter *
sst_iter_create(struct sst * const sst)
{
  struct sst_iter * const iter = calloc(1, sizeof(*iter));
  if (iter == NULL)
    return NULL;
  sst_iter_init(iter, sst, 0);
  return iter;
}

  void
sst_iter_seek(struct sst_iter * const iter, const struct kref * const key)
{
  sst_iter_blk_release(iter);
  struct sst * const sst = iter->sst;

  // first, find the block
  iter->ptr.pageid = sst_search_pageid(sst, key);
  if (iter->ptr.pageid < iter->npages) {
    // second, find search in the block
    const u8 * const blk = sst_blk_acquire(sst, iter->ptr.pageid);
    iter->ptr.keyid = (u16)sst_search_block_ge(blk, key); // ignoring the high bits

    const struct sst_blkmeta * const bm = (typeof(bm))blk;
    debug_assert(iter->ptr.keyid <= bm->nkeys);
    if (iter->ptr.keyid < bm->nkeys) { // seek to kv in the same page
      sst_iter_fix_kv_blk(iter, blk);
    } else { // seek to the next page or EOF
      sst_blk_release(sst->rc, blk);
      iter->ptr.pageid++;
      iter->ptr.keyid = iter->ptr.pageid < iter->npages ? 0 : UINT16_MAX;
    }
  } else {
    // empty sst: keyid should always == MAX
    debug_assert(iter->ptr.keyid == UINT16_MAX);
  }
}

  inline void
sst_iter_seek_null(struct sst_iter * const iter)
{
  sst_iter_blk_release(iter);

  iter->ptr.pageid = 0;
  iter->ptr.keyid = iter->npages ? 0 : UINT16_MAX;
}

  inline bool
sst_iter_valid(struct sst_iter * const iter)
{
  return iter->ptr.keyid != UINT16_MAX;
}

// test if iter points to a tombstone
  inline bool
sst_iter_ts(struct sst_iter * const iter)
{
  sst_iter_fix_kv(iter);
  return iter->vlen == SST_VLEN_TS;
}

  struct kv *
sst_iter_peek(struct sst_iter * const iter, struct kv * const out)
{
  if (!sst_iter_valid(iter))
    return NULL;

  sst_iter_fix_kv(iter);

  const u32 vlen1 = iter->vlen & SST_VLEN_MASK;
  const u32 kvlen = iter->klen + vlen1;
  struct kv * const ret = out ? out : malloc(sizeof(*ret) + kvlen);
  ret->klen = iter->klen;
  ret->vlen = iter->vlen;
  memcpy(ret->kv, iter->kvdata, kvlen);
  return ret;
}

  bool
sst_iter_kref(struct sst_iter * const iter, struct kref * const kref)
{
  if (!sst_iter_valid(iter))
    return false;

  sst_iter_fix_kv(iter);
  kref_ref_raw(kref, iter->kvdata, iter->klen); // no hash32
  return true;
}

  bool
sst_iter_kvref(struct sst_iter * const iter, struct kvref * const kvref)
{
  if (!sst_iter_valid(iter))
    return false;

  sst_iter_fix_kv(iter);
  kvref->hdr.klen = iter->klen;
  kvref->hdr.vlen = iter->vlen;
  kvref->hdr.hash = 0;
  kvref->kptr = iter->kvdata;
  kvref->vptr = iter->kvdata + iter->klen;
  return true;
}

  inline u64
sst_iter_retain(struct sst_iter * const iter)
{
  return sst_blk_retain(iter->sst->rc, sst_iter_blk_addr(iter));
}

  inline void
sst_iter_release(struct sst_iter * const iter, const u64 opaque)
{
  sst_blk_release(iter->sst->rc, (const u8 *)opaque);
}

  void
sst_iter_skip1(struct sst_iter * const iter)
{
  debug_assert(sst_iter_valid(iter));
  struct sst_ptr * const pptr = &iter->ptr;

  pptr->keyid++;
  if (pptr->keyid == iter->sst->bms[pptr->pageid].nkeys) {
    sst_iter_park(iter); // discard iter->kvdata
    pptr->pageid++;
    if (pptr->pageid >= iter->npages) {
      pptr->keyid = UINT16_MAX;
      return; // invalid
    }
    pptr->keyid = 0;
  }

  if (iter->kvdata)
    sst_iter_fix_kv_reuse(iter);
}

// skip using the given blkmeta[]
  void
sst_iter_skip(struct sst_iter * const iter, const u32 nr)
{
  debug_assert(sst_iter_valid(iter));
  const struct sst_blkmeta * const bms = iter->sst->bms;
  struct sst_ptr * const pptr = &iter->ptr;

  u32 todo = nr;
  do {
    const u32 ncap = bms[pptr->pageid].nkeys - pptr->keyid;
    if (todo < ncap) {
      pptr->keyid += (u16)todo;
      if (iter->kvdata)
        sst_iter_fix_kv_reuse(iter);
      return; // done
    }
    sst_iter_park(iter); // discard iter->kvdata
    pptr->pageid++;
    if (pptr->pageid >= iter->npages) {
      pptr->keyid = UINT16_MAX;
      return; // invalid
    }
    pptr->keyid = 0;
    todo -= ncap;
  } while (todo);
}

  struct kv *
sst_iter_next(struct sst_iter * const iter, struct kv * const out)
{
  struct kv * const ret = sst_iter_peek(iter, out);
  if (sst_iter_valid(iter))
    sst_iter_skip1(iter);
  return ret;
}

  void
sst_iter_park(struct sst_iter * const iter)
{
  sst_iter_blk_release(iter);
}

  void
sst_iter_destroy(struct sst_iter * const iter)
{
  sst_iter_park(iter);
  free(iter);
}

  void
sst_dump(struct sst * const sst, const char * const fn)
{
  const int fd = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  debug_assert(fd >= 0);
  struct sst_iter iter;
  sst_iter_init(&iter, sst, 0);
  sst_iter_seek_null(&iter);
  struct kvref kvref;
  u32 n = 0;
  dprintf(fd, "npages %u totkv %u\n", sst->npages, sst->totkv);
  while (sst_iter_kvref(&iter, &kvref)) {
    dprintf(fd, "%6u b %6u k %6u %.*s (%u,%u)\n",
        n, iter.ptr.pageid, iter.ptr.keyid, iter.klen, iter.kvdata, iter.klen, iter.vlen);
    sst_iter_skip1(&iter);
    n++;
  }
  fsync(fd);
  close(fd);
}
// }}} sst_iter

// msstx {{{
struct msst {
  u64 seq;
  u32 nr_runs;
  u32 refcnt; // not atomic: -- in msstz_gc(); ++ in append-to-v; no race condition
  struct ssty * ssty; // ssty makes it mssty
  struct rcache * rc;
  struct sst ssts[MSST_NR_RUNS];
};

struct msstx_iter {
  struct msst * msst;
  u32 nr_runs;
  // minheap
  struct sst_iter * mh[MSST_NR_RUNS+1];
  struct sst_iter iters[MSST_NR_RUNS];
};

  struct msst *
msstx_open_at_reuse(const int dfd, const u64 seq, const u32 nr_runs, struct msst * const msst0, const u32 nrun0)
{
  if (nr_runs > MSST_NR_RUNS)
    return NULL;
  struct msst * const msst = calloc(1, sizeof(*msst));
  if (msst == NULL)
    return NULL;

  debug_assert(nrun0 <= nr_runs);
  for (u32 i = 0; i < nrun0; i++) {
    debug_assert(msst0->ssts[i].refcnt == 1);
    msst->ssts[i] = msst0->ssts[i];
    // only increment the old's refcnt
    msst0->ssts[i].refcnt++;
  }

  for (u32 i = nrun0; i < nr_runs; i++) {
    if (!sst_init_at(dfd, seq, i, &(msst->ssts[i]))) {
      // error
      for (u64 j = 0; j < i; j++)
        sst_deinit(&(msst->ssts[j]));

      free(msst);
      return NULL;
    }
  }
  msst->refcnt = 0; // deliberate, msstv owns refcnt
  msst->seq = seq;
  msst->nr_runs = nr_runs;
  return msst;
}

  struct msst *
msstx_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  return msstx_open_at_reuse(dfd, seq, nr_runs, NULL, 0);
}

  inline struct msst *
msstx_open(const char * const dirname, const u64 seq, const u32 nr_runs)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return NULL;
  struct msst * const msst = msstx_open_at_reuse(dfd, seq, nr_runs, NULL, 0);
  close(dfd);
  return msst;
}

  inline void
msst_rcache(struct msst * const msst, struct rcache * const rc)
{
  msst->rc = rc;
  for (u32 i = 0; i < msst->nr_runs; i++)
    sst_rcache(&(msst->ssts[i]), rc);
}

  inline void
msst_add_refcnt(struct msst * const msst)
{
  msst->refcnt++;
}

  void
msstx_destroy(struct msst * const msst)
{
  debug_assert(msst->ssty == NULL);
  for (u32 i = 0; i < msst->nr_runs; i++)
    sst_deinit(&(msst->ssts[i]));
  free(msst);
}

  struct msstx_iter *
msstx_iter_create(struct msst * const msst)
{
  struct msstx_iter * const iter = calloc(1, sizeof(*iter));
  if (iter == NULL)
    return NULL;

  iter->msst = msst;
  iter->nr_runs = msst->nr_runs;
  for (u32 i = 0; i < msst->nr_runs; i++) {
    sst_iter_init(&(iter->iters[i]), &(msst->ssts[i]), (u8)i);
    iter->mh[i+1] = &(iter->iters[i]);
  }
  return iter;
}

  struct kv *
msstx_get(struct msst * const msst, const struct kref * const key, struct kv * const out)
{
  for (u32 i = msst->nr_runs-1; i < msst->nr_runs; i--) {
    struct kv * const ret = sst_get(&(msst->ssts[i]), key, out);
    if (ret)
      return ret;
  }
  return NULL;
}

  bool
msstx_probe(struct msst * const msst, const struct kref * const key)
{
  for (u32 i = msst->nr_runs-1; i < msst->nr_runs; i--)
    if (sst_probe(&(msst->ssts[i]), key))
      return true;
  return false;
}

// mh {{{
  static void
msstx_mh_swap(struct msstx_iter * const iter, const u32 cidx)
{
  debug_assert(cidx > 1);
  struct sst_iter * const tmp = iter->mh[cidx];
  iter->mh[cidx] = iter->mh[cidx>>1];
  iter->mh[cidx>>1] = tmp;
}

  static bool
msstx_mh_should_swap(struct sst_iter * const sp, struct sst_iter * const sc)
{
  debug_assert(sp != sc);
  debug_assert(sp->rank != sc->rank);
  if (!sst_iter_valid(sp))
    return true;
  if (!sst_iter_valid(sc))
    return false;

  const int c = sst_iter_compare(sp, sc);
  if (c > 0)
    return true;
  else if (c < 0)
    return false;
  return sp->rank < sc->rank; // high rank == high priority
}

  static void
msstx_mh_uphead(struct msstx_iter * const iter, u32 idx)
{
  while (idx > 1) {
    struct sst_iter * const sp = iter->mh[idx >> 1];
    struct sst_iter * const sc = iter->mh[idx];
    if (!sst_iter_valid(sc))
      return;
    if (msstx_mh_should_swap(sp, sc))
      msstx_mh_swap(iter, idx);
    else
      return;
    idx >>= 1;
  }
}

  static void
msstx_mh_downheap(struct msstx_iter * const iter, u32 idx)
{
  const u32 nr_runs = iter->nr_runs;
  while ((idx<<1) <= nr_runs) {
    struct sst_iter * sl = iter->mh[idx<<1];
    u32 idxs = idx << 1;
    if ((idx<<1) < nr_runs) { // has sr
      struct sst_iter * sr = iter->mh[(idx<<1) + 1];
      if (msstx_mh_should_swap(sl, sr))
        idxs++;
    }

    if (msstx_mh_should_swap(iter->mh[idx], iter->mh[idxs]))
      msstx_mh_swap(iter, idxs);
    else
      return;
    idx = idxs;
  }
}
// }}} mh

  bool
msstx_iter_valid(struct msstx_iter * const iter)
{
  return iter->nr_runs && sst_iter_valid(iter->mh[1]);
}

  static inline bool
msstx_iter_valid_1(struct msstx_iter * const iter)
{
  return iter->nr_runs != 0;
}

  void
msstx_iter_seek(struct msstx_iter * const iter, const struct kref * const key)
{
  const u32 nr_runs = iter->nr_runs;
  for (u32 i = 1; i <= nr_runs; i++) {
    struct sst_iter * const iter1 = iter->mh[i];
    sst_iter_seek(iter1, key);
    if (sst_iter_valid(iter1))
      sst_iter_fix_kv(iter1);
  }
  for (u32 i = 2; i <= nr_runs; i++)
    msstx_mh_uphead(iter, i);
}

  void
msstx_iter_seek_null(struct msstx_iter * const iter)
{
  const u32 nr_runs = iter->nr_runs;
  for (u32 i = 1; i <= nr_runs; i++) {
    struct sst_iter * const iter1 = iter->mh[i];
    sst_iter_seek_null(iter1);
    if (sst_iter_valid(iter1))
      sst_iter_fix_kv(iter1);
  }
  for (u32 i = 2; i <= nr_runs; i++)
    msstx_mh_uphead(iter, i);
}

  struct kv *
msstx_iter_peek(struct msstx_iter * const iter, struct kv * const out)
{
  if (!msstx_iter_valid_1(iter))
    return NULL;
  return sst_iter_peek(iter->mh[1], out);
}

  bool
msstx_iter_kref(struct msstx_iter * const iter, struct kref * const kref)
{
  if (!msstx_iter_valid_1(iter))
    return false;

  return sst_iter_kref(iter->mh[1], kref);
}

  bool
msstx_iter_kvref(struct msstx_iter * const iter, struct kvref * const kvref)
{
  if (!msstx_iter_valid_1(iter))
    return false;

  return sst_iter_kvref(iter->mh[1], kvref);
}

  inline u64
msstx_iter_retain(struct msstx_iter * const iter)
{
  return sst_iter_retain(iter->mh[1]);
}

  inline void
msstx_iter_release(struct msstx_iter * const iter, const u64 opaque)
{
  // all should use the same rcache
  sst_blk_release(iter->msst->rc, (const u8 *)opaque);
}

  void
msstx_iter_skip1(struct msstx_iter * const iter)
{
  if (!msstx_iter_valid(iter))
    return;
  struct sst_iter * const iter1 = iter->mh[1];
  sst_iter_skip1(iter1);
  if (sst_iter_valid(iter1))
    sst_iter_fix_kv(iter1);
  msstx_mh_downheap(iter, 1);
}

  void
msstx_iter_skip(struct msstx_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!msstx_iter_valid(iter))
      return;
    struct sst_iter * const iter1 = iter->mh[1];
    sst_iter_skip1(iter1);
    if (sst_iter_valid(iter1))
      sst_iter_fix_kv(iter1);
    msstx_mh_downheap(iter, 1);
  }
}

  struct kv *
msstx_iter_next(struct msstx_iter * const iter, struct kv * const out)
{
  struct kv * const ret = msstx_iter_peek(iter, out);
  msstx_iter_skip1(iter);
  return ret;
}

  void
msstx_iter_park(struct msstx_iter * const iter)
{
  const u32 nr_runs = iter->nr_runs;
  for (u32 i = 0; i < nr_runs; i++)
    sst_iter_park(&(iter->iters[i]));
}

  void
msstx_iter_destroy(struct msstx_iter * const iter)
{
  msstx_iter_park(iter);
  free(iter);
}
// }}} msstx

// ssty {{{
struct ssty_meta {
  u32 nr_runs; // 0 to MSST_NR_RUNS
  u32 nkidx; // size of the ranks array
  u32 tags_off; // (optional) hash tag array if not zero
  u32 ptrs_off; // cursor offsets
  u32 inr1; // number of L1 index keys; number of blocks; <= 4KB blocks
  u32 ioffs1_off;
  u32 inr2; // number of L2 index keys (much smaller)
  u32 ioffs2_off;

  u32 totkv; // total number, including stale keys and tombstones
  u32 totsz; // sum of all sstx file's sizes (NOTE: totsz < 4GB)
  u32 valid; // number of valid keys (excluding stale keys and tombstones)
  u32 uniqx[MSST_NR_RUNS+1];
  u64 magic;
};

struct ssty {
  union {
    u8 * mem; // and the array
    const u8 * ranks;
  };
  size_t size; // ssty file size
  u32 nr_runs;
  u32 nkidx; // number of entries (including placeholders)
  u32 inr1; // meta->inr1
  u32 inr2; // meta->inr2
  const struct sst_ptr * ptrs; // array of seek pointers
  u32 ioffs1_off; // meta->ioffs1_off
  u32 ioffs2_off; // meta->ioffs2_off
  const u8 * tags; // (optional) 16-bit non-zero hash tags
  const struct ssty_meta * meta;
};

  static struct ssty *
ssty_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  char fn[16];
  const u64 magic = seq * 100lu + nr_runs;
  sprintf(fn, "%03lu.ssty", magic);
  const int fd = openat(dfd, fn, SSTY_OPEN_FLAGS);
  if (fd < 0)
    return NULL;
  struct stat st;

  if (fstat(fd, &st) != 0) {
    close(fd);
    return NULL;
  }

  const u64 fsize = (u64)st.st_size;
  debug_assert(fsize < UINT32_MAX);
  u8 * const mem = mmap(NULL, fsize, PROT_READ, SSTY_MMAP_FLAGS, fd, 0);
  close(fd); // will only use the mapped memory
  if (mem == MAP_FAILED)
    return NULL;

  debug_assert(mem);
  struct ssty * const ssty = calloc(1, sizeof(*ssty));

  ssty->mem = mem;
  ssty->size = fsize;
  //pages_lock(mem, fsize);
  const struct ssty_meta * const meta = (typeof(meta))(mem + fsize - sizeof(*meta));
  ssty->nr_runs = meta->nr_runs;
  ssty->nkidx = meta->nkidx;
  ssty->ptrs = (struct sst_ptr *)(mem + meta->ptrs_off); // size0+size1
  ssty->inr1 = meta->inr1; // nsecs
  ssty->ioffs1_off = meta->ioffs1_off; // ioffsoff
  ssty->inr2 = meta->inr2; // ipages
  ssty->ioffs2_off = meta->ioffs2_off; // ioffsoff2
  ssty->tags = meta->tags_off ? (typeof(ssty->tags))(mem + meta->tags_off) : NULL;
  ssty->meta = meta;
  debug_assert(ssty->meta->magic == magic);
  return ssty;
}

  void
ssty_destroy(struct ssty * const ssty)
{
  debug_assert(ssty);
  munmap((void *)ssty->mem, ssty->size);
  free(ssty);
}

  void
ssty_dump(struct ssty * const ssty, const char * const filename)
{
  FILE * const fout = fopen(filename, "w");
  u32 totkv = 0;
  for (u32 i = 0; i < ssty->nkidx; i++) {
    fprintf(fout, " %02hhx", ssty->ranks[i]);
    if (ssty->ranks[i] != SSTY_INVALID) {
      totkv++;
    }
    if ((i % SSTY_DIST) == (SSTY_DIST - 1))
      fprintf(fout, "\n");
  }
  fprintf(fout, "totkv %u nkidx %u\n", totkv, ssty->nkidx);
  fclose(fout);
}

  u32
msst_nruns(const struct msst * const msst)
{
  return msst->nr_runs;
}

  u32
msst_accu_nkv_at(const struct msst * const msst, const u32 i)
{
  if (msst->ssty) {
    return msst->ssty->meta->uniqx[i];
  }
  const u32 nruns = msst->nr_runs;
  u32 uniqx = 0;
  for (u32 j = nruns - 1; j >= i && j < nruns; j--) {
    uniqx += msst->ssts[j].totkv;
  }
  return uniqx;
}

  u32
msst_nkv_at(const struct msst * const msst, const u32 i)
{
  if (i >= msst->nr_runs) {
    return 0;
  }
  return msst->ssts[i].totkv;
}

  u32
msst_nr_pages_at(const struct msst * const msst, const u32 i)
{
  if (i >= msst->nr_runs) {
    return 0;
  }
  return msst->ssts[i].npages;
}

  void
msst_stats(const struct msst * const msst, struct msst_stats * const stats)
{
  memset(stats, 0, sizeof(*stats));
  for (u32 j = 0; j < msst->nr_runs; j++) {
    const struct sst * const sst = &(msst->ssts[j]);
    stats->data_sz += (PGSZ * sst->npages);
    const u32 msz = sst->fsize - (PGSZ * sst->npages);
    debug_assert(msz <= sst->fsize);
    stats->meta_sz += msz;
    stats->totkv += sst->totkv;
    stats->totsz += sst->fsize;
  }
  stats->nr_runs = msst->nr_runs;
  const struct ssty * const ssty = msst->ssty;
  if (ssty != NULL) {
    debug_assert(ssty->nr_runs == msst->nr_runs);
    debug_assert(stats->totsz == ssty->meta->totsz);
    stats->ssty_sz = ssty->size;
    stats->valid = ssty->meta->valid;
  }
}

  void
ssty_fprint(struct ssty * const ssty, FILE * const fout)
{
  const double bpk = (double)(ssty->size << 3) / (double)ssty->meta->totkv;
  fprintf(fout, "%s magic %lu nr_runs %u nkidx %u inr1 %u inr2 %u filesz %zu tags %c bits/key %.1lf\n",
      __func__, ssty->meta->magic, ssty->nr_runs, ssty->nkidx,
      ssty->inr1, ssty->inr2, ssty->size, ssty->tags ? 'y' : 'n', bpk);
}

  static inline u32
ssty_search_index(const struct ssty * const ssty, const struct kref * const key)
{
  // use two-level index
  // i2: the first 8 bytes are two u32 for [start, end) of i1 (plr)
  const u32 * const ioffs2 = (const u32 *)(ssty->mem + ssty->ioffs2_off);
  const u32 sidx2 = k128_search_le(ssty->mem + sizeof(u32) + sizeof(u32), ioffs2, key, 0, ssty->inr2);
  const u32 * const plr = (typeof(plr))(ssty->mem + ioffs2[sidx2]);
  const u32 * const ioffs1 = (const u32 *)(ssty->mem + ssty->ioffs1_off);
  const u32 sidx = k128_search_le(ssty->mem, ioffs1, key, plr[0], plr[1]);
  return sidx;
}

  static u32
ssty_ranks_match_mask(const u8 * const ranks, const u8 rank)
{
#if defined(__x86_64__)

#if SSTY_DBITS == 5
#if defined(__AVX2__)
  const m256 maskv = _mm256_set1_epi8(SSTY_RANK);
  const m256 rankv = _mm256_set1_epi8((char)rank);
  const m256 tmpv = _mm256_and_si256(_mm256_load_si256((const void *)ranks), maskv);
  return (u32)_mm256_movemask_epi8(_mm256_cmpeq_epi8(tmpv, rankv));
#else // No __AVX2__, use SSE 4.2
  const m128 maskv = _mm_set1_epi8(SSTY_RANK);
  const m128 rankv = _mm_set1_epi8((char)rank);
  const m128 tmpvlo = _mm_and_si128(_mm_load_si128((const void *)ranks), maskv);
  const m128 tmpvhi = _mm_and_si128(_mm_load_si128((const void *)(ranks + sizeof(m128))), maskv);
  const u32 masklo = m128_movemask_u8(_mm_cmpeq_epi8(tmpvlo, rankv));
  const u32 maskhi = m128_movemask_u8(_mm_cmpeq_epi8(tmpvhi, rankv));
  return (maskhi << sizeof(m128)) | masklo;
#endif // __AVX2__
#elif SSTY_DBITS == 4
  const m128 maskv = _mm_set1_epi8(SSTY_RANK);
  const m128 rankv = _mm_set1_epi8((char)rank);
  const m128 tmpv = _mm_and_si128(_mm_load_si128((const void *)ranks), maskv);
  return (u32)_mm_movemask_epi8(_mm_cmpeq_epi8(tmpv, rankv));
#endif // SSTY_DBITS

#elif defined(__aarch64__)
  const m128 maskv = vdupq_n_u8(SSTY_RANK);
  const m128 rankv = vdupq_n_u8(rank);
#if SSTY_DBITS == 5
  const m128 cmplo = vceqq_u8(vandq_u8(vld1q_u8(ranks), maskv), rankv); // cmpeq => 0xff or 0x00
  const m128 cmphi = vceqq_u8(vandq_u8(vld1q_u8(ranks + sizeof(m128)), maskv), rankv); // cmpeq => 0xff or 0x00
  const u32 masklo = m128_movemask_u8(cmplo);
  const u32 maskhi = m128_movemask_u8(cmphi);
  return (maskhi << sizeof(m128)) | masklo;
#elif SSTY_DBITS == 4
  const m128 cmp = vceqq_u8(vandq_u8(vld1q_u8(ranks), maskv), rankv); // cmpeq => 0xff or 0x00
  return m128_movemask_u8(cmp);
#endif // SSTY_DBITS

#endif // __x86_64__
}

  static u32
ssty_ranks_count(const u8 * const ranks, const u32 nr, const u8 rank)
{
  const u32 mask = ssty_ranks_match_mask(ranks, rank) & (((u32)(1lu << nr)) - 1u);
  return (u32)__builtin_popcount(mask);
}

// find the matching tags and filter out stale keys
  static u32
ssty_tags_match_mask(const u8 * const tags, const u8 * const ranks, const u8 tag)
{
#if defined(__x86_64__)

#if SSTY_DBITS == 5
#if defined(__AVX2__)
  // stale -> 0xFF
  const m256 maskv = _mm256_cmpgt_epi8(_mm256_setzero_si256(), _mm256_load_si256((const void *)ranks));
  // match -> 0xFF
  const m256 matchv = _mm256_cmpeq_epi8(_mm256_load_si256((const void *)tags), _mm256_set1_epi8((char)tag));
  // (not stale) && match -> 0xFF -> bit
  return (u32)_mm256_movemask_epi8(_mm256_andnot_si256(maskv, matchv));
#else // No __AVX2__, use SSE 4.2
  const m128 zerov = _mm_setzero_si128();
  const m128 maskvlo = _mm_cmpgt_epi8(zerov, _mm_load_si128((const void *)ranks));
  const m128 maskvhi = _mm_cmpgt_epi8(zerov, _mm_load_si128((const void *)(ranks + sizeof(m128))));
  const m128 tagv = _mm_set1_epi8((char)tag);
  const m128 matchvlo = _mm_cmpeq_epi8(_mm_load_si128((const void *)tags), tagv);
  const m128 matchvhi = _mm_cmpeq_epi8(_mm_load_si128((const void *)(tags + sizeof(m128))), tagv);
  const u32 masklo = m128_movemask_u8(_mm_andnot_si128(maskvlo, matchvlo));
  const u32 maskhi = m128_movemask_u8(_mm_andnot_si128(maskvhi, matchvhi));
  return (maskhi << sizeof(m128)) | masklo;
#endif // __AVX2__
#elif SSTY_DBITS == 4
  // stale -> 0xFF
  const m128 maskv = _mm_cmpgt_epi8(_mm_setzero_si128(), _mm_load_si128((const void *)ranks));
  const m128 matchv = _mm_cmpeq_epi8(_mm_load_si128((const void *)tags), _mm_set1_epi8((char)tag));
  return (u32)_mm_movemask_epi8(_mm_andnot_si128(maskv, matchv));
#endif // SSTY_DBITS

#elif defined(__aarch64__)
  const m128 stalev = vdupq_n_u8(SSTY_STALE);
  const m128 tagv = vdupq_n_u8(tag);
#if SSTY_DBITS == 5
  const m128 maskvlo = vcltq_u8(vld1q_u8(ranks), stalev);
  const m128 maskvhi = vcltq_u8(vld1q_u8(ranks + sizeof(m128)), stalev);
  const m128 matchvlo = vceqq_u8(vld1q_u8(tags), tagv);
  const m128 matchvhi = vceqq_u8(vld1q_u8(tags + sizeof(m128)), tagv);
  const u32 masklo = m128_movemask_u8(vandq_u8(maskvlo, matchvlo));
  const u32 maskhi = m128_movemask_u8(vandq_u8(maskvhi, matchvhi));
  return (maskhi << sizeof(m128)) | masklo;
#elif SSTY_DBITS == 4
  const m128 maskv = vcltq_u8(vld1q_u8(ranks), stalev);
  const m128 matchv = vceqq_u8(vld1q_u8(tags), tagv);
  return m128_movemask_u8(vandq_u8(maskv, matchv));
#endif // SSTY_DBITS

#endif // __x86_64__
}
// }}} ssty

// mssty {{{
struct mssty_iter {
  // ssty status
  u32 kidx; // invalid if >= ssty->nkidx
  u32 valid_bm;
  const struct sst_ptr * seek_ptrs;
  struct msst * msst;
  struct ssty * ssty;
  // iters
  struct sst_iter iters[MSST_NR_RUNS];
};

// misc {{{
  struct msst *
mssty_create_at(const int dfd)
{
  struct msst * msst = msstx_open_at(dfd, 0, 0);
  if (msst == NULL) {
    return NULL;
  }

  if (!ssty_build_at(dfd, msst, 0, 0, NULL, 0, false, false, false, NULL, 0)) {
    msstx_destroy(msst);
    return NULL;
  }

  if (!mssty_open_y_at(dfd, msst)) {
    msstx_destroy(msst);
    return NULL;
  }

  return msst;
}

  bool
mssty_open_y_at(const int dfd, struct msst * const msst)
{
  debug_assert(msst->ssty == NULL);
  struct ssty * const ssty = ssty_open_at(dfd, msst->seq, msst->nr_runs);
  msst->ssty = ssty;
  return ssty != NULL;
}


// naming convention example: seq=123, nr_runs=8:
// dir/12300.sstx, dir/12301.sstx, ..., dir/12307.sstx, dir/12308.ssty
  struct msst *
mssty_open_at(const int dfd, const u64 seq, const u32 nr_runs)
{
  struct msst * const msst = msstx_open_at(dfd, seq, nr_runs);
  if (msst == NULL)
    return NULL;

  if (!mssty_open_y_at(dfd, msst)) {
    msstx_destroy(msst);
    return NULL;
  }

  return msst;
}

  struct msst *
mssty_open(const char * const dirname, const u64 seq, const u32 nr_runs)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return NULL;

  struct msst * const msst = mssty_open_at(dfd, seq, nr_runs);
  close(dfd);
  return msst;
}

  static void
mssty_destroy_lazy(struct msst * const msst)
{
  ssty_destroy(msst->ssty);
  for (u32 i = 0; i < msst->nr_runs; i++)
    sst_deinit_lazy(&(msst->ssts[i]));
  free(msst);
}

// used only in msstv
  void
mssty_drop_lazy(struct msst * const msst)
{
  if (msst->refcnt == 1) {
    mssty_destroy_lazy(msst);
  } else {
    msst->refcnt--;
  }
}

  void
mssty_destroy(struct msst * const msst)
{
  ssty_destroy(msst->ssty);
  msst->ssty = NULL;
  msstx_destroy(msst);
}

// used only in msstv
  void
mssty_drop(struct msst * const msst)
{
  if (msst->refcnt == 1) {
    mssty_destroy(msst);
  } else {
    msst->refcnt--;
  }
}
  u64
mssty_get_magic(const struct msst * const msst)
{
  return msst->ssty->meta->magic;
}

  void
mssty_fprint(struct msst * const msst, FILE * const fout)
{
  const u32 nr_runs = msst->nr_runs;
  fprintf(fout, "%s nr_runs %u\n", __func__, nr_runs);
  ssty_fprint(msst->ssty, fout);
  for (u32 i = 0; i < nr_runs; i++)
    sst_fprint(&(msst->ssts[i]), fout);
}

  struct mssty_iter *
mssty_iter_create(struct mssty_ref * const ref)
{
  // ref is already an iter
  return (struct mssty_iter *)ref;
}

  struct mssty_iter *
mssty_iter_new()
{
  struct mssty_iter * const iter = malloc(sizeof(*iter));
  return iter;
}
// }}} misc

// helpers {{{
  void
mssty_iter_init(struct mssty_iter * const iter, struct msst * const msst)
{
  iter->msst = msst;
  iter->ssty = msst->ssty;
  iter->valid_bm = 0;
  const u32 nr_runs = iter->ssty->nr_runs;
  for (u32 i = 0; i < nr_runs; i++)
    sst_iter_init(&(iter->iters[i]), &(msst->ssts[i]), (u8)i);
}

  void
mssty_iter_park(struct mssty_iter * const iter)
{
  u32 bits = iter->valid_bm;
  while (bits) {
    const u32 i = (u32)__builtin_ctz(bits);
    sst_iter_park(&(iter->iters[i]));
    bits ^= (1u << i);
  }
}

// internal: invalidate the iter and set a new ptr
  static inline void
mssty_iter_set_ptr(struct sst_iter * const iter, const struct sst_ptr ptr)
{
  sst_iter_park(iter);
  iter->ptr = ptr;
}

  static void
mssty_iter_fix_rank(struct mssty_iter * const iter, const u8 rank)
{
  debug_assert(rank < MSST_NR_RUNS);
  if (((1u << rank) & iter->valid_bm) == 0) {
    mssty_iter_set_ptr(&(iter->iters[rank]), iter->seek_ptrs[rank]);
    iter->valid_bm |= (1u << rank);
  }
}

  void
mssty_iter_seek_null(struct mssty_iter * const iter)
{
  mssty_iter_park(iter);
  iter->valid_bm = 0;
  iter->kidx = 0;
  struct ssty * const ssty = iter->ssty;
  iter->seek_ptrs = ssty->ptrs;
  if (ssty->nkidx)
    mssty_iter_fix_rank(iter, ssty->ranks[0] & SSTY_RANK);
}

  struct mssty_ref *
mssty_ref(struct msst * const msst)
{
  struct mssty_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;

  mssty_iter_init(iter, msst);
  iter->kidx = iter->ssty->nkidx; // invalid
  return (struct mssty_ref *)iter;
}

  struct msst *
mssty_unref(struct mssty_ref * const ref)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  struct msst * const msst = iter->msst;
  mssty_iter_park(iter);
  free(iter);
  return msst;
}

// skip sst_iter without accessing bms
  static void
mssty_sst_iter_skip(struct sst_iter * const iter, const u8 * const ranks, const u32 nr)
{
  struct sst_ptr * const pptr = &iter->ptr;

  u32 todo = nr;
  u32 i = 0;
  while (todo) {
    const u8 rankenc = ranks[i];
    if ((rankenc & SSTY_RANK) == iter->rank) {
      if (rankenc & SSTY_TAIL) {
        sst_iter_park(iter); // discard iter->kvdata
        pptr->pageid++;
        pptr->keyid = 0;
      } else {
        pptr->keyid++;
        if (iter->kvdata)
          sst_iter_fix_kv_reuse(iter);
      }
      todo--;
    }
    i++;
  }

  if (pptr->pageid >= iter->npages)
    pptr->keyid = UINT16_MAX;
}

// skip with rankenc without accessing bms
  static void
mssty_sst_iter_skip1(struct sst_iter * const iter, const u8 rankenc)
{
  debug_assert((rankenc & SSTY_RANK) == iter->rank);
  struct sst_ptr * const pptr = &iter->ptr;

  if (rankenc & SSTY_TAIL) {
    sst_iter_park(iter); // discard iter->kvdata
    pptr->pageid++;
    pptr->keyid = 0;
  } else {
    pptr->keyid++;
    if (iter->kvdata)
      sst_iter_fix_kv_reuse(iter);
  }

  if (pptr->pageid >= iter->npages)
    pptr->keyid = UINT16_MAX;
}

// to randomly access a sst_iter in a segment
  static struct sst_iter *
mssty_iter_access(struct mssty_iter * const iter, const u8 * const ranks, const u32 i)
{
  const u8 rank = ranks[i] & SSTY_RANK;
  struct sst_iter * const iter1 = &(iter->iters[rank]);
  debug_assert(iter1->rank == rank);
  mssty_iter_set_ptr(iter1, iter->seek_ptrs[rank]);
  const u32 nskip = ssty_ranks_count(ranks, i, rank);
  mssty_sst_iter_skip(iter1, ranks, nskip);
  debug_assert(sst_iter_valid(iter1));
  sst_iter_fix_kv(iter1);
  return iter1;
}

  inline bool
mssty_iter_valid(struct mssty_iter * const iter)
{
  return iter->kidx < iter->ssty->nkidx;
}

// internal: skip the sst_iter at rank (< nr_runs)
  static inline void
mssty_iter_skip1_rank(struct mssty_iter * const iter, const u8 rank)
{
  debug_assert(rank < MSST_NR_RUNS);
  debug_assert((iter->ssty->ranks[iter->kidx] & SSTY_RANK) == rank);
  struct sst_iter * const iter1 = &iter->iters[rank];
  mssty_sst_iter_skip1(iter1, iter->ssty->ranks[iter->kidx]);

  // if the key (at kidx) before the skip is the tail, then the key after the skip will have keyid == 0
  debug_assert((!sst_iter_valid(iter1)) || (iter1->ptr.keyid == 0) == ((iter->ssty->ranks[iter->kidx] & SSTY_TAIL) != 0));
}

// does not check iter_valid
  void
mssty_iter_skip1(struct mssty_iter * const iter)
{
  debug_assert(mssty_iter_valid(iter));
  struct ssty * const ssty = iter->ssty;
  const u8 * const ranks = ssty->ranks;
  u8 rank = ranks[iter->kidx] & SSTY_RANK;

  mssty_iter_skip1_rank(iter, rank);
  iter->kidx++;

  while (ranks[iter->kidx] & SSTY_STALE) { // stop when kidx >= nkidx
    rank = ranks[iter->kidx] & SSTY_RANK;
    if (rank < ssty->nr_runs) { // not gap
      mssty_iter_fix_rank(iter, rank);
      mssty_iter_skip1_rank(iter, rank);
    }
    iter->kidx++;
  }

  if (mssty_iter_valid(iter)) {
    rank = ranks[iter->kidx] & SSTY_RANK;
    debug_assert(rank < ssty->nr_runs);
    mssty_iter_fix_rank(iter, rank);
  }
}
// }}} helpers

// seek {{{
  static u32
mssty_iter_seek_bisect(struct mssty_iter * const iter, const struct kref * const key, const u32 aidx, u32 l, u32 r)
{
  // notes from ssty_build:
  // gaps are marked SSTY_INVALID; end of array is marked nr_runs
  debug_assert(r <= SSTY_DIST);
  const u32 r0 = r;
  struct ssty * const ssty = iter->ssty;
  const u8 * const ranks = ssty->ranks + aidx;

  // l may point to a stale key when performing forward searching
  // search-key > key-at-l; it's safe to move forward
  while (ranks[l] & SSTY_STALE)
    l++;

  // skip stale slots and placeholders
  // no underflow because the first key of each group is not stale
  while (r && (ranks[r-1] & SSTY_STALE))
    r--;

  while (l < r) {
#ifdef MSSTY_SEEK_BISECT_OPT
    const u8 rankx = ranks[(l+r)>>1] & SSTY_RANK; // pick up a rank randomly
    struct sst_iter * const iterx = &(iter->iters[rankx]);
    mssty_iter_set_ptr(iterx, iter->seek_ptrs[rankx]);
    debug_assert(sst_iter_valid(iterx));
    // scan from l to r; skip 0 to l
    // use 1lu << r to avoid undefined behavior of left-shift by 32
    const u32 mask0 = ssty_ranks_match_mask(ranks, rankx) & (((u32)(1lu << r)) - 1u);
    debug_assert(l < SSTY_DIST);
    const u32 low = (1u << l) - 1u;
    const u32 nskip0 = (u32)__builtin_popcount(mask0 & low);
    if (nskip0)
      mssty_sst_iter_skip(iterx, ranks, nskip0);
    u32 mask = mask0 & (~low); // bits between l and r
    debug_assert(mask); // have at least one bit
    do { // scan one by one
      sst_iter_fix_kv(iterx);
      const int cmp = sst_iter_compare_kref(iterx, key);
      const u32 m = (u32)__builtin_ctz(mask);
      debug_assert((ranks[m] & SSTY_RANK) == rankx);
      debug_assert(m < r);
      if (cmp < 0) { // shrink forward
        mssty_sst_iter_skip1(iterx, ranks[m]);
        l = m + 1;
      } else if (cmp > 0) { // shrink backward
        r = m;
        break;
      } else { // match; must point to the non-stale version
        l = m;
        while (ranks[l] & SSTY_STALE)
          l--;
        r = m;
        break;
      }
      mask &= (mask - 1);
    } while (mask);
    sst_iter_park(iterx);
    // l may point to a stale key when performing forward searching
    // search-key > key-at-l; it's safe to move forward
    while ((l < r0) && (ranks[l] & SSTY_STALE))
      l++;
    // skip stale slots and placeholders
    // no underflow because the first key of each group is not stale
    while (r && (ranks[r-1] & SSTY_STALE))
      r--;
#else // MSSTY_SEEK_BISECT_OPT
    u32 m = (l + r) >> 1;
    // skip stale keys and move left; always compare with non-stale key
    while (ranks[m] & SSTY_STALE)
      m--;

    // compare
    debug_assert(l <= m && m < r);
    debug_assert((ranks[m] & SSTY_STALE) == 0);
    struct sst_iter * const iterm = mssty_iter_access(iter, ranks, m);
    const int cmp = sst_iter_compare_kref(iterm, key);
    sst_iter_park(iterm);

    if (cmp < 0) { // shrink forward
      l = m + 1;
      // skip stale keys
      while ((l < r0) && (ranks[l] & SSTY_STALE))
        l++;
    } else if (cmp > 0) { // shrink backward
      r = m;
    } else { // cmp == 0; done
      l = m;
      r = m;
    }
#endif // MSSTY_SEEK_BISECT_OPT
  }
  return l;
}

// perform seek in the group of kidx0 (group_id = kidx0 / dist)
// kidx0 may point to a stale key
// bisect between kidx0 and the last element
  static void
mssty_iter_seek_local(struct mssty_iter * const iter, const struct kref * const key, const u32 kidx0)
{
  debug_assert(iter->valid_bm == 0);
  // first key's index of the target group
  struct ssty * const ssty = iter->ssty;
  const u32 aidx = kidx0 >> SSTY_DBITS << SSTY_DBITS;
  // <= dist
  const u32 l0 = kidx0 - aidx;
  const u32 r0 = (aidx + SSTY_DIST) > ssty->nkidx ? (ssty->nkidx - aidx) : SSTY_DIST;
  const u32 goff = mssty_iter_seek_bisect(iter, key, aidx, l0, r0);

  debug_assert(iter->valid_bm == 0);
  // skip keys
  if (goff) {
    if (goff < SSTY_DIST) {
      const u8 * const ranks = ssty->ranks + aidx;
      for (u8 i = 0; i < ssty->nr_runs; i++) {
        const u32 nskip = ssty_ranks_count(ranks, goff, i);
        if (nskip) {
          mssty_iter_fix_rank(iter, i);
          mssty_sst_iter_skip(&iter->iters[i], ranks, nskip);
        }
      }
    } else { // shortcut to the next group
      debug_assert(goff == SSTY_DIST);
      iter->seek_ptrs += ssty->nr_runs;
    }
  } // else: goff == 0; do nothing
  iter->kidx = aidx + goff;
  // the current key must be the one unless >= nkidx
  if (unlikely(iter->kidx >= ssty->nkidx))
    return;

  const u8 rank = ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  debug_assert(rank < ssty->nr_runs);
  mssty_iter_fix_rank(iter, rank);
}

  void
mssty_iter_seek(struct mssty_iter * const iter, const struct kref * const key)
{
  struct ssty * const ssty = iter->ssty;
  mssty_iter_park(iter);
  iter->valid_bm = 0;
  const u32 sidx = ssty_search_index(ssty, key);
  if (unlikely(sidx >= ssty->inr1)) { // invalid
    iter->kidx = ssty->nkidx;
    return;
  }
  iter->seek_ptrs = &(ssty->ptrs[sidx * ssty->nr_runs]);
  const u32 kidx0 = sidx << SSTY_DBITS;
  mssty_iter_seek_local(iter, key, kidx0);
}
// }}} seek

// seek-near {{{
  static u32
mssty_iter_seek_index_near(struct ssty * const ssty, const struct kref * const key, u32 l)
{
  while ((l < ssty->nkidx) && (ssty->ranks[l] & SSTY_STALE))
    l++;
  if (l == ssty->nkidx)
    return l;

  // linear scan
  const u32 * const ioffs = (const u32 *)(ssty->mem + ssty->ioffs1_off);
  u32 g = l >> SSTY_DBITS;
  u32 r = (g + 1) << SSTY_DBITS;
  while (r < ssty->nkidx) {
    const int cmp = kref_k128_compare(key, ssty->mem + ioffs[g + 1]);
    if (cmp < 0) {
      break;
    } else {
      g++;
      l = r;
      r += SSTY_DIST;
    }
  }
  debug_assert(l < ssty->nkidx);
  return l;
}

  static void
mssty_iter_seek_local_near(struct mssty_iter * const iter, const struct kref * const key, const u32 l)
{
  struct ssty * const ssty = iter->ssty;
  // now search in l's group; l must be a non-stale key
  const u32 g = l >> SSTY_DBITS;
  if (g == (iter->kidx >> SSTY_DBITS)) { // stay in the same group; reuse the valid iter
    while (iter->kidx < l)
      mssty_iter_skip1(iter);
    debug_assert(iter->kidx == l);
  } else { // switch group
    debug_assert((l & (SSTY_DIST-1)) == 0);
    mssty_iter_park(iter);
    iter->valid_bm = 0;
    iter->seek_ptrs = &(ssty->ptrs[(l >> SSTY_DBITS) * ssty->nr_runs]);
    iter->kidx = l;
  }

  do {
    const u8 rank = ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
    debug_assert(rank < ssty->nr_runs);
    mssty_iter_fix_rank(iter, rank);
    struct sst_iter * const iter1 = &(iter->iters[rank]);
    sst_iter_fix_kv(iter1);
    if (sst_iter_compare_kref(iter1, key) >= 0)
      return;
    mssty_iter_skip1(iter);
  } while (mssty_iter_valid(iter));
}

// the target key must >= the current key under the iter
// the current iter can point to a stale key or deleted key
  void
mssty_iter_seek_near(struct mssty_iter * const iter, const struct kref * const key, const bool bsearch_keys)
{
  debug_assert(mssty_iter_valid(iter));
  struct ssty * const ssty = iter->ssty;

  // first test if key < iter
  const u8 * const ranks = ssty->ranks;
  const u8 rank0 = ranks[iter->kidx];
  struct sst_iter * const iter0 = &(iter->iters[rank0 & SSTY_RANK]);
  sst_iter_fix_kv(iter0);
  // return without any change
  if (sst_iter_compare_kref(iter0, key) >= 0)
    return;

  // seek_index does not affect the iter
  const u32 l = mssty_iter_seek_index_near(ssty, key, iter->kidx+1);
  if (l == ssty->nkidx) { // invalid
    mssty_iter_park(iter);
    iter->kidx = ssty->nkidx;
    return;
  }

  if (bsearch_keys) { // reset iter and use seek_local
    mssty_iter_park(iter);
    iter->valid_bm = 0;
    iter->seek_ptrs = &(ssty->ptrs[(l >> SSTY_DBITS) * ssty->nr_runs]);
    mssty_iter_seek_local(iter, key, l);
  } else { // linear scan using the valid iter
    mssty_iter_seek_local_near(iter, key, l);
  }
}
// }}} seek-near

// iter {{{
// peek non-stale keys
  struct kv *
mssty_iter_peek(struct mssty_iter * const iter, struct kv * const out)
{
  if (!mssty_iter_valid(iter))
    return NULL;
  const u8 rank = iter->ssty->ranks[iter->kidx]; // rank starts with 0
  debug_assert((rank & SSTY_STALE) == 0);
  return sst_iter_peek(&(iter->iters[rank & SSTY_RANK]), out);
}

// kvref non-stale keys
  bool
mssty_iter_kref(struct mssty_iter * const iter, struct kref * const kref)
{
  if (!mssty_iter_valid(iter))
    return false;

  const u8 rank = iter->ssty->ranks[iter->kidx]; // rank starts with 0
  debug_assert((rank & SSTY_STALE) == 0);
  return sst_iter_kref(&(iter->iters[rank & SSTY_RANK]), kref);
}

// kvref non-stale keys
  bool
mssty_iter_kvref(struct mssty_iter * const iter, struct kvref * const kvref)
{
  if (!mssty_iter_valid(iter))
    return false;

  const u8 rank = iter->ssty->ranks[iter->kidx]; // rank starts with 0
  debug_assert((rank & SSTY_STALE) == 0);
  return sst_iter_kvref(&(iter->iters[rank & SSTY_RANK]), kvref);
}

  inline u64
mssty_iter_retain(struct mssty_iter * const iter)
{
  const u8 rank = iter->ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  return sst_iter_retain(&(iter->iters[rank]));
}

  inline void
mssty_iter_release(struct mssty_iter * const iter, const u64 opaque)
{
  sst_blk_release(iter->msst->rc, (const u8 *)opaque);
}

// non-stale keys
  void
mssty_iter_skip(struct mssty_iter * const iter, const u32 nr)
{
  if (!mssty_iter_valid(iter))
    return;
  struct ssty * const ssty = iter->ssty;
  const u8 * const ranks = ssty->ranks;
  u8 rank = ranks[iter->kidx] & SSTY_RANK;
  debug_assert(rank < ssty->nr_runs);

  for (u32 i = 0; i < nr; i++) {
    mssty_iter_skip1_rank(iter, rank);
    iter->kidx++;

    // skip stale keys or gaps
    while (ranks[iter->kidx] & SSTY_STALE) { // stop when kidx >= nkidx
      rank = ranks[iter->kidx] & SSTY_RANK;
      if (rank < ssty->nr_runs) { // not gap
        mssty_iter_fix_rank(iter, rank);
        mssty_iter_skip1_rank(iter, rank);
      }
      iter->kidx++;
    }
    if (!mssty_iter_valid(iter))
      return;
    // still valid
    rank = ranks[iter->kidx] & SSTY_RANK;
    debug_assert(rank < ssty->nr_runs);
    mssty_iter_fix_rank(iter, rank);
  }
}

  struct kv *
mssty_iter_next(struct mssty_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mssty_iter_peek(iter, out);
  if (mssty_iter_valid(iter))
    mssty_iter_skip1(iter);
  return ret;
}

  void
mssty_iter_destroy(struct mssty_iter * const iter)
{
  mssty_iter_park(iter);
}
// }}} iter

// ts {{{
// ts iter: ignore a key if its newest version is a tombstone
  bool
mssty_iter_ts(struct mssty_iter * const iter)
{
  return (iter->ssty->ranks[iter->kidx] & SSTY_TOMBSTONE) != 0;
}

// hide tomestones
  void
mssty_iter_seek_ts(struct mssty_iter * const iter, const struct kref * const key)
{
  mssty_iter_seek(iter, key);
  while (mssty_iter_valid(iter) && mssty_iter_ts(iter))
    mssty_iter_skip1(iter);
}

  void
mssty_iter_skip1_ts(struct mssty_iter * const iter)
{
  if (!mssty_iter_valid(iter))
    return;
  mssty_iter_skip1(iter);
  while (mssty_iter_valid(iter) && mssty_iter_ts(iter))
    mssty_iter_skip1(iter);
}

// skip nr valid keys (tomestones are transparent)
  void
mssty_iter_skip_ts(struct mssty_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!mssty_iter_valid(iter))
      return;
    mssty_iter_skip1(iter);
    while (mssty_iter_valid(iter) && mssty_iter_ts(iter))
      mssty_iter_skip1(iter);
  }
}

  struct kv *
mssty_iter_next_ts(struct mssty_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mssty_iter_peek(iter, out);
  mssty_iter_skip1_ts(iter);
  return ret;
}
// }}} ts

// dup {{{
// _dup iterator: return all versions, including old keys and tombstones
  struct kv *
mssty_iter_peek_dup(struct mssty_iter * const iter, struct kv * const out)
{
  if (!mssty_iter_valid(iter))
    return NULL;
  const u8 rank = iter->ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  debug_assert(rank < iter->ssty->nr_runs);
  return sst_iter_peek(&(iter->iters[rank]), out);
}

  void
mssty_iter_skip1_dup(struct mssty_iter * const iter)
{
  if (!mssty_iter_valid(iter))
    return;
  struct ssty * const ssty = iter->ssty;
  const u8 * const ranks = ssty->ranks;
  u8 rank = ranks[iter->kidx] & SSTY_RANK;
  debug_assert(rank < ssty->nr_runs);

  mssty_iter_skip1_rank(iter, rank);
  iter->kidx++;

  // skip gaps
  while (ranks[iter->kidx] == SSTY_INVALID)
    iter->kidx++;

  if (!mssty_iter_valid(iter))
    return;

  // still valid
  rank = ranks[iter->kidx] & SSTY_RANK;
  mssty_iter_fix_rank(iter, rank);
}

  void
mssty_iter_skip_dup(struct mssty_iter * const iter, const u32 nr)
{
  if (!mssty_iter_valid(iter))
    return;
  struct ssty * const ssty = iter->ssty;
  const u8 * const ranks = ssty->ranks;
  u8 rank = ranks[iter->kidx] & SSTY_RANK;
  debug_assert(rank < ssty->nr_runs);

  for (u32 i = 0; i < nr; i++) {
    mssty_iter_skip1_rank(iter, rank);
    iter->kidx++;

    // skip gaps
    while (ranks[iter->kidx] == SSTY_INVALID)
      iter->kidx++;

    if (!mssty_iter_valid(iter))
      return;

    // still valid
    rank = ranks[iter->kidx] & SSTY_RANK;
    mssty_iter_fix_rank(iter, rank);
  }
}

  struct kv *
mssty_iter_next_dup(struct mssty_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mssty_iter_peek_dup(iter, out);
  mssty_iter_skip1_dup(iter);
  return ret;
}

  bool
mssty_iter_kref_dup(struct mssty_iter * const iter, struct kref * const kref)
{
  if (!mssty_iter_valid(iter))
    return false;

  const u8 rank = iter->ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  return sst_iter_kref(&(iter->iters[rank]), kref);
}

  bool
mssty_iter_kvref_dup(struct mssty_iter * const iter, struct kvref * const kvref)
{
  if (!mssty_iter_valid(iter))
    return false;

  const u8 rank = iter->ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  return sst_iter_kvref(&(iter->iters[rank]), kvref);
}
// }}} dup

// point {{{
// return the internal sst_iter if there is a match
// when hide_ts == true, return NULL when the matching kv is a ts
// when a non-NULL sst_iter is returned, the caller must park it after use
  static struct sst_iter *
mssty_iter_match(struct mssty_iter * const iter, const struct kref * const key, const bool hide_ts)
{
  struct ssty * const ssty = iter->ssty;
  mssty_iter_park(iter);
  iter->valid_bm = 0;
  const u32 sidx = ssty_search_index(ssty, key);
  if (unlikely(sidx >= ssty->inr1)) { // invalid
    iter->kidx = ssty->nkidx;
    return NULL;
  }

  iter->seek_ptrs = &(ssty->ptrs[sidx * ssty->nr_runs]);

  // local
  const u32 aidx = sidx << SSTY_DBITS;
  const u8 * const ranks = ssty->ranks + aidx;
  const u32 rmax0 = ssty->nkidx - aidx;
  const u32 rmax = rmax0 < SSTY_DIST ? rmax0 : SSTY_DIST;

  if (ssty->tags) {
    const u8 * const tags = ssty->tags + aidx;
    u32 mask = ssty_tags_match_mask(tags, ranks, sst_tag(key->hash32));
    while (mask) {
      const u32 i = (u32)__builtin_ctz(mask);
      debug_assert((ranks[i] & SSTY_STALE) == 0);

      // overflow
      if (i >= rmax)
        return NULL;

      if ((!hide_ts) || ((ranks[i] & SSTY_TOMBSTONE) == 0)) {
        struct sst_iter * const iter1 = mssty_iter_access(iter, ranks, i);
        if (sst_iter_match_kref(iter1, key)) // the caller must park the iterx later
          return iter1;

        sst_iter_park(iter1);
      }
      mask &= (mask - 1);
    }
  } else {
    const u32 r0 = (aidx + SSTY_DIST) > ssty->nkidx ? (ssty->nkidx - aidx) : SSTY_DIST;
    const u32 i = mssty_iter_seek_bisect(iter, key, aidx, 0, r0);

    // no match
    if (i >= rmax)
      return NULL;

    debug_assert((ranks[i] & SSTY_STALE) == 0);
    if ((!hide_ts) || ((ranks[i] & SSTY_TOMBSTONE) == 0)) {
      struct sst_iter * const iter1 = mssty_iter_access(iter, ranks, i);
      if (sst_iter_match_kref(iter1, key)) // the caller must park the iterx later
        return iter1;

      sst_iter_park(iter1);
    }
  }
  return NULL;
}

  static struct kv *
mssty_get_internal(struct mssty_ref * const ref, const struct kref * const key, struct kv * const out, const bool hide_ts)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  struct sst_iter * const iter1 = mssty_iter_match(iter, key, hide_ts);
  if (iter1) {
    struct kv * const ret = sst_iter_peek(iter1, out);
    sst_iter_park(iter1);
    return ret;
  } else {
    return NULL;
  }
}

  static bool
mssty_probe_internal(struct mssty_ref * const ref, const struct kref * const key, const bool hide_ts)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  struct sst_iter * const iter1 = mssty_iter_match(iter, key, hide_ts);
  if (iter1) {
    sst_iter_park(iter1);
    return true;
  } else {
    return false;
  }
}

// mssty_get can return tombstone
  struct kv *
mssty_get(struct mssty_ref * const ref, const struct kref * const key, struct kv * const out)
{
  return mssty_get_internal(ref, key, out, false);
}

// mssty_probe can return tombstone
  bool
mssty_probe(struct mssty_ref * const ref, const struct kref * const key)
{
  return mssty_probe_internal(ref, key, false);
}

// return NULL for tomestone
  struct kv *
mssty_get_ts(struct mssty_ref * const ref, const struct kref * const key, struct kv * const out)
{
  return mssty_get_internal(ref, key, out, true);
}

// return false for tomestone
  bool
mssty_probe_ts(struct mssty_ref * const ref, const struct kref * const key)
{
  return mssty_probe_internal(ref, key, true);
}

// return false for tomestone
  bool
mssty_get_value_ts(struct mssty_ref * const ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  struct sst_iter * const iter1 = mssty_iter_match(iter, key, true);
  if (iter1) {
    memcpy(vbuf_out, iter1->kvdata + iter1->klen, iter1->vlen);
    *vlen_out = iter1->vlen;
    sst_iter_park(iter1);
    return true;
  } else {
    return false;
  }
}

  struct kv *
mssty_first_key(const struct msst * const msst, struct kv * const out)
{
  if (msst->ssty->nkidx == 0)
    return NULL;

  const u8 rank = msst->ssty->ranks[0] & SSTY_RANK;
  const struct sst * const sst = &(msst->ssts[rank]);
  return sst_first_key(sst, out);
}

  struct kv *
mssty_last_key(const struct msst * const msst, struct kv * const out)
{
  const u32 nkidx = msst->ssty->nkidx;
  if (nkidx == 0)
    return NULL;

  const u8 rank = msst->ssty->ranks[nkidx-1] & SSTY_RANK;
  const struct sst * const sst = &(msst->ssts[rank]);
  return sst_last_key(sst, out);
}
// }}} point

// dump {{{
  void
mssty_dump(struct msst * const msst, const char * const fn)
{
  const int fd = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  debug_assert(fd >= 0);
  void * const ref = mssty_ref(msst);
  struct mssty_iter * const iter = mssty_iter_create(ref);
  struct ssty * const ssty = msst->ssty;
  const struct ssty_meta * const meta = ssty->meta;
  dprintf(fd, "mssty seq%lu nr_runs %u nkidx %u inr1 %u inr2 %u valid %u uniqx ",
      msst->seq, ssty->nr_runs, ssty->nkidx, ssty->inr1, ssty->inr2, meta->valid);
  for (u32 i = 0; i < ssty->nr_runs; i++)
    dprintf(fd, "%u%c", meta->uniqx[i], (i == (ssty->nr_runs-1)) ? '\n' : ' ');

  // print i2 keys
  const u32 n2 = ssty->inr2;
  const u32 * const ioffs2 = (const u32 *)(ssty->mem + ssty->ioffs2_off);
  for (u32 i = 0; i < n2; i++) {
    const u32 ioff2 = ioffs2[i];
    const u32 * const e2 = (typeof(e2))(ssty->mem + ioff2);
    const u8 * const a2 = (typeof(a2))(ssty->mem + ioff2 + sizeof(u32) + sizeof(u32));
    u32 klen = 0;
    const u8 * const keyptr = vi128_decode_u32(a2, &klen);
    dprintf(fd, "i2 %6u  %6u %6u %.*s (%u)\n", i, e2[0], e2[1], klen, keyptr, klen);
  }

  struct kvref kvref;
  u32 n = 0;
  mssty_iter_seek_null(iter);
  while (mssty_iter_kvref_dup(iter, &kvref)) { // dump all the keys
    const u8 rank = ssty->ranks[iter->kidx];
    const bool stale = (rank & SSTY_STALE) != 0;
    const bool ts = (rank & SSTY_TOMBSTONE) != 0; // first X: ssty says it's a TS
    const bool ts2 = (kvref.hdr.vlen & SST_VLEN_TS) != 0; // second X: the KV is really a TS
    debug_assert(ts == ts2);
    // count kidx(anchor) !DD rank key
    dprintf(fd, "%7u %7u%c %c%c%c%x %.*s (%u,%u)\n", n, iter->kidx, (iter->kidx % SSTY_DIST) ? ' ' : '*',
        stale ? '!' : ' ', ts ? 'X' : ' ', ts2 ? 'X' : ' ', rank & SSTY_RANK,
        kvref.hdr.klen, kvref.kptr, kvref.hdr.klen, kvref.hdr.vlen & SST_VLEN_MASK);
    mssty_iter_skip1_dup(iter);
    n++;
  }
  mssty_iter_destroy(iter);
  mssty_unref(ref);
  fsync(fd);
  close(fd);
}
// }}} dump

// }}} mssty

// ssty_build {{{

// bi {{{
struct ssty_build_info {
  struct msst * x1; // input: target tables
  struct msst * y0; // input: the old mssty or NULL

  // allocated by the main function; filled by the sort function
  u8 * ranks; // output: run selectors
  struct sst_ptr * ptrs; // output: cursor positions
  struct kv ** anchors; // output: anchors
  u8 * tags; // output: hash tags

  int dfd; // input
  u32 run0;  // input: number of ssts to reuse in y0
  u32 nkidx; // output: maximum key index
  u32 nsecs; // output: number of groups
  u32 valid; // output: number of valid keys
  u32 uniqx[MSST_NR_RUNS]; // output: uniq non-stale keys at each level
};

// number of bytes read
static __thread u64 ssty_build_ckeys_reads = 0;
// }}} bi

// sstc_iter {{{
struct sstc_iter { // sstc_iter can be read as a sst_iter
  struct sst_iter iter;
  u8 * rawbuffer;
  u8 * buffer; // rawbuffer + 8
  size_t bufsz;
  const u8 * cptr;
  const u8 * ckeysptr;
};

  static void
sstc_sync_kv(struct sstc_iter * const iter)
{
  const u8 * ptr = iter->cptr;
  u32 plen = 0, slen = 0;
  ptr = vi128_decode_u32(ptr, &plen);
  ptr = vi128_decode_u32(ptr, &slen);
  const bool ts = *ptr++;
  if ((plen + slen + sizeof(u64)) > iter->bufsz) {
    iter->bufsz = bits_p2_up_u32(plen + slen + 256);
    iter->rawbuffer = realloc(iter->rawbuffer, iter->bufsz);
    iter->buffer = iter->rawbuffer + sizeof(u64);
    debug_assert(iter->rawbuffer);
  }
  memcpy(iter->buffer + plen, ptr, slen);

  iter->cptr = ptr + slen;

  struct sst_iter * const iter0 = &iter->iter;
  iter0->klen = plen + slen;
  iter0->vlen = ts ? SST_VLEN_TS : 0;
  iter0->kvdata = iter->buffer;
}

  static inline void
sstc_iter_init(struct sstc_iter * const iter, struct sst * const sst, const u8 rank)
{
  sst_iter_init(&iter->iter, sst, rank);
  const struct sst_meta * const meta = sst_meta(sst);

  if (sst->npages && meta->ckeyssz) {
    iter->bufsz = 256; // buffer size
    iter->rawbuffer = malloc(iter->bufsz);
    iter->buffer = iter->rawbuffer + sizeof(u64);

    const u8 * const ckeys = sst->mem + meta->ckeysoff;
    iter->ckeysptr = ckeys;
    posix_madvise((void *)ckeys, meta->ckeyssz, POSIX_MADV_WILLNEED);
    iter->cptr = ckeys;

    struct sst_iter * const iter0 = &iter->iter;
    iter0->ptr.pageid = 0;
    iter0->ptr.keyid = 0;

    sstc_sync_kv(iter);
  }
}

  static struct sstc_iter *
sstc_iter_create(struct sst * const sst)
{
  struct sstc_iter * const iter = calloc(1, sizeof(*iter));
  if (iter == NULL)
    return NULL;
  sstc_iter_init(iter, sst, 0);
  return iter;
}

  static inline bool
sstc_iter_valid(struct sstc_iter * const iter)
{
  return sst_iter_valid(&iter->iter);
}

  static inline void
sstc_iter_seek(struct sstc_iter * const iter, const struct kref * const key)
{
  debug_assert(key == NULL || key == kref_null());
  (void)iter;
  (void)key;
}

  static inline void
sstc_iter_skip1(struct sstc_iter * const iter)
{
  struct sst_iter * const iter0 = &iter->iter;
  iter0->kvdata = NULL; // it points to the sstc buffer; just set to NULL
  sst_iter_skip1(iter0);
  if (sst_iter_valid(iter0))
    sstc_sync_kv(iter);
}

  static void
sstc_iter_skip(struct sstc_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++)
    sstc_iter_skip1(iter);
}

  static bool
sstc_iter_kref(struct sstc_iter * const iter, struct kref * const kref)
{
  if (!sstc_iter_valid(iter))
    return false;

  kref_ref_raw(kref, iter->buffer, iter->iter.klen); // no hash32
  return true;
}

  static bool
sstc_iter_kvref(struct sstc_iter * const iter, struct kvref * const kvref)
{
  if (!sstc_iter_valid(iter))
    return false;

  struct sst_iter * const iter0 = &iter->iter;
  kvref->hdr.klen = iter0->klen;
  kvref->hdr.vlen = iter0->vlen;
  kvref->hdr.hash = 0;
  kvref->kptr = iter->buffer;
  kvref->vptr = NULL; // no value
  return true;
}

  static bool
sstc_iter_ts(struct sstc_iter * const iter)
{
  return sstc_iter_valid(iter) && (iter->iter.vlen == SST_VLEN_TS);
}

  static int
sstc_iter_compare(struct sstc_iter * const iter1, struct sstc_iter * const iter2)
{
  debug_assert(sstc_iter_valid(iter1) && sstc_iter_valid(iter2));
  // both are valid
  struct kref kref1, kref2;
  kref_ref_raw(&kref1, iter1->buffer, iter1->iter.klen); // no hash32
  kref_ref_raw(&kref2, iter2->buffer, iter2->iter.klen); // no hash32
  return kref_compare(&kref1, &kref2);
}

  static void
sstc_iter_destroy(struct sstc_iter * const iter)
{
  if (iter->ckeysptr) {
    const u32 ckeyssz = sst_meta(iter->iter.sst)->ckeyssz;
    debug_assert(ckeyssz);
    posix_madvise((void *)iter->ckeysptr, ckeyssz, POSIX_MADV_DONTNEED);
  }

  free(iter->rawbuffer);
  free(iter);
}

static const struct kvmap_api kvmap_api_sstc = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .iter_create = (void *)sstc_iter_create,
  .iter_seek = (void *)sstc_iter_seek,
  .iter_valid = (void *)sstc_iter_valid,
  .iter_kref = (void *)sstc_iter_kref,
  .iter_kvref = (void *)sstc_iter_kvref,
  .iter_skip1 = (void *)sstc_iter_skip1,
  .iter_skip = (void *)sstc_iter_skip,
  .iter_destroy = (void *)sstc_iter_destroy,
};

  static bool
msstb_use_ckeys(struct msst * const msstx1)
{
  bool use_ckeys = true;
  u64 ckeys_size = 0;
  for (u32 i = 0; i < msstx1->nr_runs; i++) {
    const struct sst_meta * const meta = sst_meta(&(msstx1->ssts[i]));
    if ((meta->totkv != 0) && (meta->ckeyssz == 0)) {
      use_ckeys = false;
      break;
    }
    ckeys_size += meta->ckeyssz;
  }
  if (use_ckeys)
    ssty_build_ckeys_reads += ckeys_size;
  return use_ckeys;
}
// }}} sstc_iter

// msstb {{{

// msstb: a special kind of iterator structure for building ssty (REMIX)
// There are three instances of msstb
// A msstz-compaction always write new tables sequentially (a sorted view),
// and the existing data are already sorted (another sorted view).
// both msstb2 and msstbc perform a two-way merge between the old and new data.
// msstb2 uses the key-value data. It uses binary searches to find merge points.
// msstbc uses the ckeys to perform a regular two-way merge.
// msstbc is the most (I/O) efficient.

// If the input data does not qualify for a two-way merge, msstbm should be used.
// msstbm can be used to create ssty (REMIX) for any kind of inputs (e.g., overlapping).
// msstbm uses miter to perform multi-way merge.
// msstbm automatically uses ckeys if every input table contains ckeys.
// A rough comparison of speed: fast | msstbc > msstbm+ckeys <?> msstb2 > msstbm | slow

struct msstb {
  u32 rankenc; // the current rankenc (rank and flags)
  u32 idx; // index on the full sorted view
  u32 nr_runs; // the target nr_runs
  u32 run0; // <= y0->nr_runs, the tables to reuse in the new ssty
  u32 run1; // iters[run1] is the current sst iter; valid if run1 < nr_runs
  u32 nkidx; // a copy of y0->ssty->nkidx
  u32 kidx0; // index on ranks (of y0) for bc

  bool bsearch_anchors; // binary search anchors vs. linear scan anchors
  bool bsearch_keys; // binary search keys vs. linear scan keys in a group
  bool dup;   // the new key == old key; msstb2_sync1 can set dup to true
  bool stale;   // the old key should be set as stale

  const u8 * ranks; // shortcut to y0->ssty->ranks

  struct msst * x1; // the input msstx
  struct msst * y0; // the old mssty
  const u8 * tags0; // y0->ssty->tags
  struct miter * miter;

  struct kv * tmp0; // for bc
  struct kv * tmp1; // for bc
  struct sst_iter older;
  struct sst_iter newer;

  // iterb will be moved ahead of iter0 (iterb >= iter0)
  // then iter0 will be used to encode the old kvs until they meet again
  struct mssty_iter iterb; // for binary search only
  struct mssty_iter iter0; // for linear iteration and encoding
  union {
    struct sst_iter * iters[MSST_NR_RUNS]; // for new tables
    struct sstc_iter * citers[MSST_NR_RUNS]; // for bc
  };
};

struct msstb_api {
  struct msstb * (*create)  (struct msst * const msstx1, struct msst * const mssty0, const u32 run0);
  void (*ptrs)              (struct msstb * const b, struct sst_ptr * const ptrs_out); // dump cursor offsets
  struct kv * (*anchor)     (struct msstb * const b); // create anchor key
  u8 (*tag)                 (struct msstb * const b); // calculate a 8-bit tag (the lowest 8-bits of crc32c)
  void (*skip1)             (struct msstb * const b);
  void (*destroy)           (struct msstb * const b);
};

  static inline bool
msstb_valid(struct msstb * const b)
{
  return b->rankenc != UINT32_MAX;
}

  static inline u32
msstb_rankenc(struct msstb * const b)
{
  return b->rankenc;
}
// }}} msstb

// msstbm {{{
  static void
msstbm_sync_rank(struct msstb * const b)
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
  const struct sst_iter * const iter = b->iters[rank];
  const u16 nkeys = iter->sst->bms[iter->ptr.pageid].nkeys;
  debug_assert(nkeys && (iter->ptr.keyid < nkeys));
  const bool tail = (iter->ptr.keyid + 1) == nkeys;
  b->rankenc = rank | (stale ? SSTY_STALE : 0u) | (ts ? SSTY_TOMBSTONE : 0u) | (tail ? SSTY_TAIL : 0u);

  if (!stale) {
    struct kv * const xchg = b->tmp0;
    b->tmp0 = b->tmp1;
    b->tmp1 = xchg;
    kvref_dup2_key(&cref, b->tmp1);
  }
}

  static struct kv *
msstbm_anchor(struct msstb * const b)
{
  const u32 alen = b->idx ? (kv_key_lcp(b->tmp0, b->tmp1)+1) : 0;
  debug_assert(alen <= b->tmp1->klen);
  struct kv * const anchor = kv_create(b->tmp1->kv, alen, NULL, 0); // key only
  return anchor;
}

  static u8
msstbm_tag(struct msstb * const b)
{
  // no extra I/O for accessing the key
  struct kv * const curr = b->tmp1;
  return sst_tag(kv_crc32c(curr->kv, curr->klen));
}

  static void
msstbm_ptrs(struct msstb * const b, struct sst_ptr * const ptrs)
{
  for (u32 i = 0; i < b->nr_runs; i++)
    ptrs[i] = b->iters[i]->ptr;
}

  static void
msstbm_skip1(struct msstb * const b)
{
  miter_skip1(b->miter);
  b->idx++;
  msstbm_sync_rank(b);
}

  static struct msstb *
msstbm_create(struct msst * const msstx1, struct msst * const mssty0, const u32 run0)
{
  (void)mssty0;
  (void)run0;
  struct msstb * const b = calloc(1, sizeof(*b));
  b->nr_runs = msstx1->nr_runs;
  b->idx = 0;
  b->tmp0 = malloc(sizeof(*b->tmp0) + SST_MAX_KVSZ);
  b->tmp1 = malloc(sizeof(*b->tmp1) + SST_MAX_KVSZ);
  const bool use_ckeys = msstb_use_ckeys(msstx1);
  const struct kvmap_api * const api_build = use_ckeys ? &kvmap_api_sstc : &kvmap_api_sst;
  struct miter * const miter = miter_create();
  b->miter = miter;
  for (u32 i = 0; i < b->nr_runs; i++)
    b->iters[i] = miter_add(miter, api_build, &msstx1->ssts[i]);

  miter_seek(miter, kref_null());
  if (miter_valid(miter)) {
    struct kvref kvref;
    miter_kvref(miter, &kvref);
    kvref_dup2_key(&kvref, b->tmp1);
    b->tmp1->klen = !b->tmp1->klen; // let the first stale == false
  }
  msstbm_sync_rank(b);
  return b;
}

  static void
msstbm_destroy(struct msstb * const b)
{
  free(b->tmp0);
  free(b->tmp1);
  miter_destroy(b->miter);
  free(b);
}

static const struct msstb_api msstb_api_miter = {
  .create = msstbm_create,
  .ptrs = msstbm_ptrs,
  .anchor = msstbm_anchor,
  .tag = msstbm_tag,
  .skip1 = msstbm_skip1,
  .destroy = msstbm_destroy,
};
// }}} msstbm

// msstb2 {{{
  static void
msstb2_iter(struct msstb * const b, const u8 rank, struct sst_iter * const out)
{
  debug_assert(rank < b->nr_runs);
  struct sst_iter * const iter = (rank < b->run0) ? &(b->iter0.iters[rank]) : b->iters[rank];
  debug_assert(iter->rank == rank);
  out->sst = iter->sst;
  out->rank = rank;
  out->ptr = iter->ptr;
  // klen and vlen are ignored
  out->kvdata = NULL;
}

  static void
msstb2_sync_rank(struct msstb * const b)
{
  const bool valid = (b->iter0.kidx < b->nkidx) || (b->run1 < b->nr_runs);
  if (!valid) {
    b->rankenc = UINT32_MAX;
    return;
  }

  if (b->iter0.kidx < b->iterb.kidx) { // use the old
    b->rankenc = b->ranks[b->iter0.kidx] | (b->stale ? SSTY_STALE : 0); // only need to check STALE
  } else { // use the new
    debug_assert(b->iter0.kidx == b->iterb.kidx);
    const struct sst_iter * const iter = b->iters[b->run1];
    const bool ts = iter->vlen == SST_VLEN_TS;
    const u16 nkeys = iter->sst->bms[iter->ptr.pageid].nkeys;
    debug_assert(nkeys && (iter->ptr.keyid < nkeys));
    const bool tail = (iter->ptr.keyid + 1) == nkeys;
    b->rankenc = b->run1 | (ts ? SSTY_TOMBSTONE : 0u) | (tail ? SSTY_TAIL : 0u);
  }

  if ((b->rankenc & SSTY_STALE) == 0) {
    b->older = b->newer;
    msstb2_iter(b, b->rankenc & SSTY_RANK, &b->newer);
  }
}

// update iterb to mark the merge point for the current sst_iter
  static void
msstb2_sync_mp(struct msstb * const b)
{
  struct mssty_iter * const iterb = &(b->iterb);
  do {
    if (b->run1 == b->nr_runs) {
      mssty_iter_park(iterb); // no longer needed
      iterb->kidx = b->nkidx;
      return;
    } else if (sst_iter_valid(b->iters[b->run1])) {
      // use this run1 and iter1
      break;
    }
    b->run1++;
  } while (true);
  struct sst_iter * const iter1 = b->iters[b->run1];

  if (iterb->kidx == b->nkidx) { // !mssty_iter_valid(iterb)
    sst_iter_fix_kv(iter1); // msstb2_sync_rank needs the vlen
    return;
  }
  // seek on iterb; now iter1 is valid
  struct kref kref1;
  sst_iter_kref(iter1, &kref1);
  // let iterb point to the merge point
  mssty_iter_seek_near(iterb, &kref1, b->bsearch_keys);

  // skip placeholders and high-rank keys
  // not end and
  // invalid ranks (since the ranks must be smaller than run0 in y0)
  while ((iterb->kidx < b->nkidx) && ((b->ranks[iterb->kidx] & SSTY_RANK) >= b->run0))
    mssty_iter_skip1_dup(iterb);

  struct kref kref0; // the current
  if (mssty_iter_kref_dup(iterb, &kref0)) // mssty_iter is also valid
    b->dup = kref_match(&kref1, &kref0); // may find a dup
}

  static struct kv *
msstb2_anchor(struct msstb * const b)
{
  struct kref tmp0 = {};
  struct kref tmp1 = {};
  sst_iter_kref(&b->older, &tmp0);
  sst_iter_kref(&b->newer, &tmp1);
  const u32 alen = b->idx ? (kref_lcp(&tmp0, &tmp1)+1) : 0;
  debug_assert(alen <= tmp1.len);
  struct kv * const anchor = kv_create(tmp1.ptr, alen, NULL, 0); // key only
  sst_iter_park(&b->older);
  sst_iter_park(&b->newer);
  return anchor;
}

// used when (ckeys == false && tags == true)
// The current implementation will have to read every key
// This configuration is obsolete and should not be used
// TODO: can be improved by reading u8 tags from y0
  static u8
msstb2_tag(struct msstb * const b)
{
  if (b->tags0 && ((b->rankenc & SSTY_RANK) < b->run0)) // tags0 && lo
    return b->tags0[b->iter0.kidx];

  struct kref curr = {};
  sst_iter_kref(&b->newer, &curr);
  const u32 hash32 = kv_crc32c(curr.ptr, curr.len);
  sst_iter_park(&b->newer);
  return sst_tag(hash32);
}

  static void
msstb2_ptrs(struct msstb * const b, struct sst_ptr * const ptrs)
{
  struct mssty_iter * const iter0 = &(b->iter0);
  for (u32 i = 0; i < b->run0; i++)
    ptrs[i] = iter0->iters[i].ptr;

  for (u32 i = b->run0; i < b->nr_runs; i++)
    ptrs[i] = b->iters[i]->ptr;
}

  static void
msstb2_skip1(struct msstb * const b)
{
  b->idx++;
  if (b->iter0.kidx < b->iterb.kidx) { // skip an old key
    b->stale = false; // stale is one shot only
    do {
      mssty_iter_skip1_dup(&(b->iter0));
    } while ((b->iter0.kidx < b->nkidx) && ((b->ranks[b->iter0.kidx] & SSTY_RANK) >= b->run0));
    debug_assert(b->iter0.kidx <= b->iterb.kidx);
  } else { // skip a new key
    debug_assert(b->iter0.kidx == b->iterb.kidx);
    sst_iter_skip1(b->iters[b->run1]);
    b->stale = b->dup; // force the next key to be stale
    b->dup = false; // dup is one shot only
    msstb2_sync_mp(b); // update iterb (and run1)
  }
  msstb2_sync_rank(b);
}

  static struct msstb *
msstb2_create_common(struct msst * const msstx1, struct msst * const mssty0, const u32 run0)
{
  debug_assert(msstx1);
  struct msstb * const b = calloc(1, sizeof(*b));
  if (!b)
    return NULL;

  b->x1 = msstx1;
  b->y0 = mssty0;
  b->tags0 = mssty0 ? mssty0->ssty->tags : NULL;
  b->run0 = run0;
  b->run1 = run0; // new tables start with run0
  b->nr_runs = msstx1->nr_runs; // the target nr_runs
  b->newer.ptr.keyid = UINT16_MAX;

  if (run0) {
    debug_assert(mssty0);
    b->nkidx = mssty0->ssty->nkidx; // shortcut
    b->ranks = mssty0->ssty->ranks; // shortcut
  }
  return b;
}

  static struct msstb *
msstb2_create(struct msst * const msstx1, struct msst * const mssty0, const u32 run0)
{
  struct msstb * const b = msstb2_create_common(msstx1, mssty0, run0);
  if (run0) {
    mssty_iter_init(&(b->iterb), mssty0);
    mssty_iter_seek_null(&(b->iterb));
    mssty_iter_init(&(b->iter0), mssty0);
    mssty_iter_seek_null(&(b->iter0));
    for (u8 i = 0; i < run0; i++)
      mssty_iter_fix_rank(&(b->iter0), i);

    // skip the first a few stale keys
    while ((b->iter0.kidx < b->nkidx) && ((b->ranks[b->iter0.kidx] & SSTY_RANK) >= b->run0))
      mssty_iter_skip1_dup(&(b->iter0));
  }

  u32 newcnt = 0;
  for (u32 i = run0; i < b->nr_runs; i++) {
    b->iters[i] = sst_iter_create(&(msstx1->ssts[i]));
    b->iters[i]->rank = (u8)i;
    sst_iter_seek_null(b->iters[i]);
    newcnt += msstx1->ssts[i].totkv;
  }

  // size ratio between the old and new sorted views; old:new, 1 <= ratio
  const u32 ratio = (newcnt && (newcnt < b->nkidx)) ? (b->nkidx / newcnt) : 1;
  // compensate the linear search for locality and efficiency
  b->bsearch_keys = ratio > (SSTY_DBITS + run0);

  msstb2_sync_mp(b);
  debug_assert(b->iter0.kidx <= b->iterb.kidx);
  msstb2_sync_rank(b);
  return b;
}

  static void
msstb2_destroy(struct msstb * const b)
{
  mssty_iter_park(&(b->iterb));
  mssty_iter_park(&(b->iter0));
  for (u32 i = b->run0; i < b->nr_runs; i++)
    sst_iter_destroy(b->iters[i]);
  free(b);
}

static const struct msstb_api msstb_api_b2 = {
  .create = msstb2_create,
  .ptrs = msstb2_ptrs,
  .anchor = msstb2_anchor,
  .tag = msstb2_tag,
  .skip1 = msstb2_skip1,
  .destroy = msstb2_destroy,
};
// }}} msstb2

// msstbc {{{
  static void
msstbc_ptrs(struct msstb * const b, struct sst_ptr * const ptrs)
{
  for (u32 i = 0; i < b->nr_runs; i++)
    ptrs[i] = b->citers[i]->iter.ptr;
}

  static void
msstbc_sync_lo(struct msstb * const b)
{
  while ((b->kidx0 < b->nkidx) && ((b->ranks[b->kidx0] & SSTY_RANK) >= b->run0))
    b->kidx0++;
}

  static void
msstbc_sync_hi(struct msstb * const b)
{
  while ((b->run1 < b->nr_runs) && (!sstc_iter_valid(b->citers[b->run1])))
    b->run1++;
}

  static void
msstbc_sync_rank(struct msstb * const b)
{
  const bool validlo = b->kidx0 < b->nkidx;
  const bool validhi = b->run1 < b->nr_runs;

  // RANK & STALE
  if (validlo) {
    const u8 loenc = b->ranks[b->kidx0];
    const u8 lorank = loenc & SSTY_RANK;
    debug_assert(lorank < b->run0);
    const int cmp = validhi ? sstc_iter_compare(b->citers[lorank], b->citers[b->run1]) : -1;
    if (cmp < 0) { // use lo
      b->rankenc = loenc; // keep TOMBSTONE, STALE, and TAIL
      if (b->stale)
        b->rankenc |= SSTY_STALE;
    } else { // use hi
      b->rankenc = b->run1;
      debug_assert(b->stale == false);
    }
    b->stale = cmp == 0;
  } else { // validlo == false
    if (validhi) { // use hi
      b->rankenc = b->run1;
    } else { // stop
      b->rankenc = UINT32_MAX;
      return;
    }
  }

  // from new runs: TOMBSTONE & TAIL
  const u32 rank = b->rankenc & SSTY_RANK;
  struct sstc_iter * const citer = b->citers[rank];
  if (rank >= b->run0) { // new key: never STALE; can have TOMBSTONE or TAIL
    if (sstc_iter_ts(citer))
      b->rankenc |= SSTY_TOMBSTONE;

    struct sst_iter * const iter = &citer->iter;
    const u16 nkeys = iter->sst->bms[iter->ptr.pageid].nkeys;
    debug_assert(nkeys && (iter->ptr.keyid < nkeys));
    const bool tail = (iter->ptr.keyid + 1) == nkeys;
    if (tail)
      b->rankenc |= SSTY_TAIL;
  }

  // update tmp1 as the last valid key
  if ((b->rankenc & SSTY_STALE) == 0) {
    struct kv * const xchg = b->tmp0;
    b->tmp0 = b->tmp1;
    b->tmp1 = xchg;
    struct kref cref;
    if (sstc_iter_kref(citer, &cref)) {
      b->tmp1->klen = cref.len;
      memcpy(b->tmp1->kv, cref.ptr, cref.len); // hash is ignored
    } else {
      debug_die();
    }
  }
}

  static u8
msstbc_tag(struct msstb * const b)
{
  if (b->tags0 && ((b->rankenc & SSTY_RANK) < b->run0)) // tags0 && lo
    return b->tags0[b->kidx0];

  // no extra I/O for accessing the key
  struct kv * const curr = b->tmp1;
  return sst_tag(kv_crc32c(curr->kv, curr->klen));
}

  static void
msstbc_skip1(struct msstb * const b)
{
  const u8 rank = b->rankenc & SSTY_RANK;
  sstc_iter_skip1(b->citers[rank]);
  b->idx++;
  if (rank < b->run0) { // lo
    b->kidx0++;
    msstbc_sync_lo(b);
  } else {
    msstbc_sync_hi(b);
  }
  msstbc_sync_rank(b);
}

  static struct msstb *
msstbc_create(struct msst * const msstx1, struct msst * const mssty0, const u32 run0)
{
  struct msstb * const b = msstb2_create_common(msstx1, mssty0, run0);

  b->tmp0 = malloc(sizeof(*b->tmp0) + SST_MAX_KVSZ);
  b->tmp1 = malloc(sizeof(*b->tmp1) + SST_MAX_KVSZ);

  for (u32 i = 0; i < b->nr_runs; i++) {
    b->citers[i] = sstc_iter_create(&(msstx1->ssts[i]));
    b->citers[i]->iter.rank = (u8)i;
  }
  msstbc_sync_lo(b);
  msstbc_sync_hi(b);
  msstbc_sync_rank(b);
  return b;
}

  static void
msstbc_destroy(struct msstb * const b)
{
  free(b->tmp0);
  free(b->tmp1);
  for (u32 i = 0; i < b->nr_runs; i++)
    sstc_iter_destroy(b->citers[i]);
  free(b);
}

static const struct msstb_api msstb_api_bc = {
  .create = msstbc_create,
  .ptrs = msstbc_ptrs,
  .anchor = msstbm_anchor, // reuse msstbm_anchor
  .tag = msstbc_tag,
  .skip1 = msstbc_skip1,
  .destroy = msstbc_destroy,
};
// }}} msstbc

// sort {{{
// check if tables at run0 to nr_runs overlap
  static const struct msstb_api *
ssty_build_api(struct msst * const msstx1, const u32 run0)
{
  const u32 nr_runs = msstx1->nr_runs;
  struct kv * const last = malloc(sizeof(*last) + SST_MAX_KVSZ);
  struct kv * const tmp = malloc(sizeof(*last) + SST_MAX_KVSZ);
  last->klen = UINT32_MAX;
  bool overlap = false;
  for (u32 i = run0; i < nr_runs; i++) {
    if (msstx1->ssts[i].totkv == 0)
      continue;

    struct kv * const first = sst_first_key(&(msstx1->ssts[i]), tmp);
    if ((last->klen != UINT32_MAX) && (kv_compare(last, first) >= 0)) {
      overlap = true;
      break;
    }
    sst_last_key(&(msstx1->ssts[i]), last);
  }

  free(last);
  free(tmp);
  if (overlap) {
    return &msstb_api_miter;
  } else if (msstb_use_ckeys(msstx1)) {
    return &msstb_api_bc;
  } else {
    return &msstb_api_b2;
  }
}

  static void
ssty_build_sort_msstb(struct ssty_build_info * const bi)
{
  const struct msstb_api * const api = ssty_build_api(bi->x1, bi->run0);
  struct msstb * const b = api->create(bi->x1, bi->y0, bi->run0);
  if (!b)
    debug_die();

  const u32 nr_runs = bi->x1->nr_runs;
  u8 * const ranks = bi->ranks;
  u8 * const tags = bi->tags;

  struct sst_ptr * ptrs = bi->ptrs;

  u32 kidx0 = 0; // id of the first key of multiple identical keys (<= kidx1)
  u32 kidx1 = 0; // the current key
  u32 valid = 0; // number of unique and valid keys (unique_keys - tombstones)
  u32 aidx = 0; // the next anchor's index; generate anchor key when kidx0 == aidx

  while (msstb_valid(b)) {
    const u32 rankenc = msstb_rankenc(b);
    debug_assert(rankenc < SSTY_INVALID);
    debug_assert((rankenc & SSTY_RANK) < nr_runs);

    if ((rankenc & SSTY_STALE) == 0) { // not a stale key
      api->ptrs(b, ptrs); // save ptrs of every newest version
      kidx0 = kidx1;
      bi->uniqx[rankenc & SSTY_RANK]++;
      if ((rankenc & SSTY_TOMBSTONE) == 0)
        valid++;
    } else if ((kidx0 ^ kidx1) >> SSTY_DBITS) { // crossing boundary
      const u32 gap = kidx1 - kidx0;
      memmove(&(ranks[kidx1]), &(ranks[kidx0]), gap); // move forward
      memset(&(ranks[kidx0]), SSTY_INVALID, gap); // fill with INVALID
      if (tags)
        memmove(&(tags[kidx1]), &(tags[kidx0]), gap); // move forward

      kidx0 += gap;
      kidx1 += gap;
    }

    if (kidx0 == aidx) { // generate anchors
      bi->anchors[aidx >> SSTY_DBITS] = api->anchor(b);
      aidx += SSTY_DIST;
      ptrs += nr_runs; // ptrs accepted
    }
    ranks[kidx1] = (u8)rankenc;
    if (tags)
      tags[kidx1] = api->tag(b);
    api->skip1(b);
    kidx1++;
  }
  api->destroy(b);

  // metadata
  bi->nkidx = kidx1;
  bi->nsecs = (kidx1 + SSTY_DIST - 1) >> SSTY_DBITS;
  bi->valid = valid;
}
// }}} sort

// main {{{
// layout
// +---------------------------+ <-- 0
// | ranks (ranks_sz)          |
// +---------------------------+ <-- tags_off
// | tags (tags_sz)            | * OPTIONAL
// +---------------------------+ <-- ptrs_off
// | ptrs (ptrs_sz)            |
// +---------------------------+ <-- anchors_off
// | anchors (anchors_sz)      |
// +---------------------------+ <-- ioffs1_off
// | aoffs (aoffs_sz)          |  anchors' offsets, L1 index offsets
// +---------------------------+ <-- ikeys2_off
// | ikeys2 (ikeys2_sz)        |  L2 anchor keys
// +---------------------------+ <-- aoffs2_off
// | ioffs2 (ioffs2_sz)        |  L2 index offsets
// +---------------------------+ <-- meta_off
// | meta (meta_sz)            |
// +---------------------------+
// y0 and run0 are optional
  u32
ssty_build_at(const int dfd, struct msst * const msstx1,
    const u64 seq, const u32 nr_runs, struct msst * const mssty0, const u32 run0,
    const bool gen_tags, const bool gen_dbits, const bool inc_rebuild,
    const u8 * merge_hist, u64 hist_size)
{
  (void)gen_dbits;
  (void)inc_rebuild;
  (void)merge_hist;
  (void)hist_size;
  // open ssty file for output
  debug_assert(nr_runs == msstx1->nr_runs);
  char fn[24];
  const u64 magic = seq * 100lu + nr_runs;
  sprintf(fn, "%03lu.ssty", magic);
  const int fdout = openat(dfd, fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  if (fdout < 0)
    return 0;

  u32 totkv = 0;
  size_t totsz = 0;
  for (u32 i = 0; i < nr_runs; i++) {
    totkv += msstx1->ssts[i].totkv;
    totsz += msstx1->ssts[i].fsize;
  }
  debug_assert(totsz <= UINT32_MAX);

  const u32 maxkidx = (totkv + SSTY_DIST) * 2; // large enough
  const u32 maxsecs = maxkidx >> SSTY_DBITS;
  u8 * const ranks = malloc(maxkidx + 128); // double size is enough
  struct sst_ptr * const ptrs = malloc(sizeof(*ptrs) * (maxsecs * nr_runs + MSST_NR_RUNS + 8));
  struct kv ** const anchors = malloc(sizeof(*anchors) * maxsecs);
  debug_assert(ranks && ptrs && anchors);

  // double size is enough
  u8 * const tags = gen_tags ? malloc((maxkidx + 128) * sizeof(tags[0])) : NULL;
  debug_assert(tags || (!gen_tags));

  struct ssty_build_info bi = {.x1 = msstx1, .y0 = mssty0,
    .ranks = ranks, .ptrs = ptrs, .anchors = anchors, .tags = tags,
    .dfd = dfd, .run0 = run0};

  ssty_build_sort_msstb(&bi);
  debug_assert(bi.nkidx <= maxkidx);
  debug_assert(bi.nsecs <= maxsecs);
  const u32 nkidx = bi.nkidx;
  const u32 nsecs = bi.nsecs;
  // write ranks // x16 for simd in seek_local
  const u32 ranks_sz = (u32)bits_round_up(sizeof(u8) * nkidx + 1, SSTY_DBITS);
  // pad with nr_runs (at least 1 byte, up to 16)
  memset(&ranks[nkidx], (int)nr_runs, sizeof(ranks[0]) * SSTY_DIST);
  write(fdout, ranks, ranks_sz);
  free(ranks);

  // assuming ranks are 1 byte
  const u32 tags_sz = tags ? (ranks_sz * sizeof(tags[0])) : 0;
  const u32 tags_off = tags ? ranks_sz: 0;
  if (tags) {
    memset(&tags[nkidx], 0, sizeof(tags[0]) * SSTY_DIST); // pad with 0
    write(fdout, tags, tags_sz);
    free(tags);
  }

  // write level indicators and seek ptrs
  const u32 ptrs_off = ranks_sz + tags_sz;
  const u32 ptrs_sz = (u32)(sizeof(struct sst_ptr) * nsecs * nr_runs);
  write(fdout, ptrs, ptrs_sz);
  free(ptrs);

  // gen anchors
  const u32 anchors_off = ptrs_off + ptrs_sz;
  u32 * const aoffs = malloc(sizeof(*aoffs) * nsecs);
  struct kvenc * const aenc = kvenc_create();
  for (u64 i = 0; i < nsecs; i++) {
    const u32 ioff = anchors_off + kvenc_size(aenc);
    aoffs[i] = ioff;
    const u32 klen = anchors[i]->klen;
    const u32 est = vi128_estimate_u32(klen) + klen;
    const u32 rem = PGSZ - (ioff % PGSZ);
    if (est > rem) {
      kvenc_append_raw(aenc, NULL, rem); // append zeroes
      aoffs[i] += rem;
      debug_assert((aoffs[i] % PGSZ) == 0);
    }
    kvenc_append_vi128(aenc, klen);
    kvenc_append_raw(aenc, anchors[i]->kv, klen);
  }
  kvenc_append_padding(aenc, 2); // x4 for readable hex dump
  const u32 anchors_sz = kvenc_size(aenc);
  kvenc_write(aenc, fdout);
  kvenc_reset(aenc);

  const u32 aoffs_off = anchors_off + anchors_sz;
  const u32 aoffs_sz = sizeof(*aoffs) * nsecs;
  write(fdout, aoffs, aoffs_sz);

  // ikeys2
  const u32 ikeys2_off = aoffs_off + aoffs_sz;
  const u32 pga = nsecs ? (aoffs[0] / PGSZ) : 0; // first pageno of index blocks
  const u32 pgz = nsecs ? (aoffs[nsecs-1] / PGSZ) : 0; // last pageno of index blocks
  const u32 ipages = nsecs ? (pgz - pga + 1) : 0; // totol number of pages of index blocks
  u32 * const ioffs2 = malloc(sizeof(*ioffs2) * ipages);

  u32 i1 = 0;
  u32 * pend2 = NULL;
  for (u32 i = 0; i < ipages; i++) {
    // search for the first anchor key in the block
    while ((aoffs[i1] / PGSZ) != (pga + i))
      i1++;
    if (pend2)
      *pend2 = i1;

    const u32 ioff2 = ikeys2_off + kvenc_size(aenc);
    ioffs2[i] = ioff2; // offset of this entry
    kvenc_append_u32(aenc, i1);
    pend2 = kvenc_append_u32_backref(aenc);
    struct kv * const anchor = anchors[i1];
    kvenc_append_vi128(aenc, anchor->klen);
    kvenc_append_raw(aenc, anchor->kv, anchor->klen);
    kvenc_append_padding(aenc, 2); // x4 for readable hex dump
    i1++;
  }
  if (pend2)
    *pend2 = nsecs;

  free(aoffs);
  for (u64 i = 0; i < nsecs; i++)
    free(anchors[i]);
  free(anchors);

  const u32 ikeys2_sz = kvenc_size(aenc);
  kvenc_write(aenc, fdout);
  kvenc_destroy(aenc);

  const u32 ioffs2_off = ikeys2_off + ikeys2_sz;
  const u32 ioffs2_sz = sizeof(*ioffs2) * ipages;
  write(fdout, ioffs2, ioffs2_sz);
  free(ioffs2);

  const u32 meta_off = ioffs2_off + ioffs2_sz;

  // ssty metadata
  struct ssty_meta meta = {
    .nr_runs = nr_runs, .nkidx = nkidx, .tags_off = tags_off, .ptrs_off = ptrs_off,
    .inr1 = nsecs, .ioffs1_off = aoffs_off, .inr2 = ipages, .ioffs2_off = ioffs2_off,
    .totkv = totkv, .totsz = (u32)totsz, .valid = bi.valid, .magic = magic,};

  // in the ssty file, each uniqx[i] is the number of unique keys at [i:n] levels if they are merged
  u32 uniq = 0;
  for (u32 i = nr_runs-1; i < nr_runs; i--) {
    uniq += bi.uniqx[i];
    meta.uniqx[i] = uniq;
  }
  const bool succ = write(fdout, &meta, sizeof(meta)) == sizeof(meta);
  const u32 fsize = meta_off + (u32)sizeof(meta);
  debug_assert(fsize < UINT32_MAX);

  // done
  fsync(fdout);
  close(fdout);
  return succ ? fsize : 0;
}

  u32
ssty_build(const char * const dirname, struct msst * const msstx1,
    const u64 seq, const u32 nr_runs, struct msst * const mssty0, const u32 run0, const bool tags, const bool dbits)
{
  const int dfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dfd < 0)
    return 0;
  const u32 ret = ssty_build_at(dfd, msstx1, seq, nr_runs, mssty0, run0, tags, dbits, false, NULL, 0);
  close(dfd);
  return ret;
}

  struct msst *
ssty_build_at_reuse(const int dfd, struct rcache * const rc,
    struct msstz_ytask * task, struct msstz_cfg * zcfg, u64 * ysz)
{
  struct msst * msst = msstx_open_at_reuse(dfd, task->seq1,
      task->run1, task->y0, task->run0);
  msst_rcache(msst, rc);

  u32 ysize = ssty_build_at(dfd, msst, task->seq1, task->run1, task->y0,
      task->run0, zcfg->tags, zcfg->dbits, zcfg->inc_rebuild,
      task->t_build_history, task->hist_size);
  if (ysize == 0) {
    debug_die();
  }
  *ysz = ysize;

  bool ry = mssty_open_y_at(dfd, msst);
  if (ry == false) {
    debug_die();
  }
  return msst;
}

  void
mssty_miter_major(struct msst * const msst, struct miter * const miter)
{
  miter_add(miter, &kvmap_api_mssty, msst);
}

  void
mssty_miter_partial(struct msst * const msst, struct miter * const miter, const u32 bestrun)
{
  const u32 nrun0 = msst->nr_runs;
  for (u32 w = bestrun; w < nrun0; w++)
    miter_add(miter, &kvmap_api_sst, &(msst->ssts[w]));
}

  u64
mssty_comp_est_ssty(const u64 nkeys, const float run)
{
  const u64 nsecs = nkeys / SSTY_DIST;
  return (sizeof(struct sst_ptr) * (u64)ceilf(run) + 16) * nsecs + nkeys;
}
// }}} main

// }}} ssty_build

// api {{{
//
// *sst* TOMESTONES
// regular functions: iter/get/probe
//   tompstones are treated as regular keys
//   they are always visible with iterators
//   this behavior is required by a few internal functions
//
// _ts functions:
//   tomestones are not visible to caller
const struct kvmap_api kvmap_api_sst = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)sst_get,
  .probe = (void *)sst_probe,
  .iter_create = (void *)sst_iter_create,
  .iter_seek = (void *)sst_iter_seek,
  .iter_valid = (void *)sst_iter_valid,
  .iter_peek = (void *)sst_iter_peek,
  .iter_kref = (void *)sst_iter_kref,
  .iter_kvref = (void *)sst_iter_kvref,
  .iter_retain = (void *)sst_iter_retain,
  .iter_release = (void *)sst_iter_release,
  .iter_skip1 = (void *)sst_iter_skip1,
  .iter_skip = (void *)sst_iter_skip,
  .iter_next = (void *)sst_iter_next,
  .iter_park = (void *)sst_iter_park,
  .iter_destroy = (void *)sst_iter_destroy,
  .destroy = (void *)sst_destroy,
  .fprint = (void *)sst_fprint,
};

const struct kvmap_api kvmap_api_msstx = {
  .ordered = true,
  .readonly = true,
  .unique = false,
  .get = (void *)msstx_get,
  .probe = (void *)msstx_probe,
  .iter_create = (void *)msstx_iter_create,
  .iter_seek = (void *)msstx_iter_seek,
  .iter_valid = (void *)msstx_iter_valid,
  .iter_peek = (void *)msstx_iter_peek,
  .iter_kref = (void *)msstx_iter_kref,
  .iter_kvref = (void *)msstx_iter_kvref,
  .iter_retain = (void *)msstx_iter_retain,
  .iter_release = (void *)msstx_iter_release,
  .iter_skip1 = (void *)msstx_iter_skip1,
  .iter_skip = (void *)msstx_iter_skip,
  .iter_next = (void *)msstx_iter_next,
  .iter_park = (void *)msstx_iter_park,
  .iter_destroy = (void *)msstx_iter_destroy,
  .destroy = (void *)msstx_destroy,
};

const struct kvmap_api kvmap_api_mssty = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)mssty_get,
  .probe = (void *)mssty_probe,
  .iter_create = (void *)mssty_iter_create,
  .iter_seek = (void *)mssty_iter_seek,
  .iter_valid = (void *)mssty_iter_valid,
  .iter_peek = (void *)mssty_iter_peek,
  .iter_kref = (void *)mssty_iter_kref,
  .iter_kvref = (void *)mssty_iter_kvref,
  .iter_retain = (void *)mssty_iter_retain,
  .iter_release = (void *)mssty_iter_release,
  .iter_skip1 = (void *)mssty_iter_skip1,
  .iter_skip = (void *)mssty_iter_skip,
  .iter_next = (void *)mssty_iter_next,
  .iter_park = (void *)mssty_iter_park,
  .iter_destroy = (void *)mssty_iter_destroy,
  .ref = (void *)mssty_ref,
  .unref = (void *)mssty_unref,
  .destroy = (void *)mssty_destroy,
  .fprint = (void *)mssty_fprint,
};

const struct kvmap_api kvmap_api_mssty_ts = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)mssty_get_ts,
  .probe = (void *)mssty_probe_ts,
  .iter_create = (void *)mssty_iter_create,
  .iter_seek = (void *)mssty_iter_seek_ts,
  .iter_valid = (void *)mssty_iter_valid,
  .iter_peek = (void *)mssty_iter_peek,
  .iter_kref = (void *)mssty_iter_kref,
  .iter_kvref = (void *)mssty_iter_kvref,
  .iter_retain = (void *)mssty_iter_retain,
  .iter_release = (void *)mssty_iter_release,
  .iter_skip1 = (void *)mssty_iter_skip1_ts,
  .iter_skip = (void *)mssty_iter_skip_ts,
  .iter_next = (void *)mssty_iter_next_ts,
  .iter_park = (void *)mssty_iter_park,
  .iter_destroy = (void *)mssty_iter_destroy,
  .ref = (void *)mssty_ref,
  .unref = (void *)mssty_unref,
  .destroy = (void *)mssty_destroy,
  .fprint = (void *)mssty_fprint,
};

const struct kvmap_api kvmap_api_mssty_dup = {
  .ordered = true,
  .readonly = true,
  .get = (void *)mssty_get,
  .probe = (void *)mssty_probe,
  .iter_create = (void *)mssty_iter_create,
  .iter_seek = (void *)mssty_iter_seek,
  .iter_valid = (void *)mssty_iter_valid,
  .iter_peek = (void *)mssty_iter_peek_dup,
  .iter_kref = (void *)mssty_iter_kref_dup,
  .iter_kvref = (void *)mssty_iter_kvref_dup,
  .iter_retain = (void *)mssty_iter_retain,
  .iter_release = (void *)mssty_iter_release,
  .iter_skip1 = (void *)mssty_iter_skip1_dup,
  .iter_skip = (void *)mssty_iter_skip_dup,
  .iter_next = (void *)mssty_iter_next_dup,
  .iter_park = (void *)mssty_iter_park,
  .iter_destroy = (void *)mssty_iter_destroy,
  .ref = (void *)mssty_ref,
  .unref = (void *)mssty_unref,
  .destroy = (void *)mssty_destroy,
  .fprint = (void *)mssty_fprint,
};

  static void *
sst_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  (void)mm;
  if (!strcmp(name, "sst")) {
    return sst_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else if (!strcmp(name, "msstx")) {
    return msstx_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else if ((!strcmp(name, "mssty")) || (!strcmp(name, "mssty_ts")) || (!strcmp(name, "mssty_dup"))) {
    return mssty_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else {
    return NULL;
  }
}

// alternatively, call the register function from main()
__attribute__((constructor))
  static void
sst_kvmap_api_init(void)
{
  kvmap_api_register(3, "sst", "<dirname> <seq> <run>", sst_kvmap_api_create, &kvmap_api_sst);
  kvmap_api_register(3, "msstx", "<dirname> <seq> <nr_runs>", sst_kvmap_api_create, &kvmap_api_msstx);
  kvmap_api_register(3, "mssty", "<dirname> <seq> <nr_runs>", sst_kvmap_api_create, &kvmap_api_mssty);
  kvmap_api_register(3, "mssty_ts", "<dirname> <seq> <nr_runs>", sst_kvmap_api_create, &kvmap_api_mssty_ts);
  kvmap_api_register(3, "mssty_dup", "<dirname> <seq> <nr_runs>", sst_kvmap_api_create, &kvmap_api_mssty_dup);
}
// }}} api

// vim:fdm=marker
