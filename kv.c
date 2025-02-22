/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include <assert.h> // static_assert
#include <ctype.h>
#include "lib.h"
#include "ctypes.h"
#include "kv.h"
// }}} headers

// crc32c {{{
  inline u32
kv_crc32c(const void * const ptr, u32 len)
{
  return crc32c_inc((const u8 *)ptr, len, KV_CRC32C_SEED);
}

  inline u64
kv_crc32c_extend(const u32 lo)
{
  const u64 hi = (u64)(~lo);
  return (hi << 32) | ((u64)lo);
}
// }}} crc32c

// kv {{{

// size {{{
  inline size_t
kv_size(const struct kv * const kv)
{
  return sizeof(*kv) + kv->klen + kv->vlen;
}

  inline size_t
kv_size_align(const struct kv * const kv, const u64 align)
{
  debug_assert(align && ((align & (align - 1)) == 0));
  return (sizeof(*kv) + kv->klen + kv->vlen + (align - 1)) & (~(align - 1));
}

  inline size_t
key_size(const struct kv *const key)
{
  return sizeof(*key) + key->klen;
}

  inline size_t
key_size_align(const struct kv *const key, const u64 align)
{
  debug_assert(align && ((align & (align - 1)) == 0));
  return (sizeof(*key) + key->klen + (align - 1)) & (~(align - 1));
}
// }}} size

// construct {{{
  inline void
kv_update_hash(struct kv * const kv)
{
  const u32 lo = kv_crc32c((const void *)kv->kv, kv->klen);
  kv->hash = kv_crc32c_extend(lo);
}

  inline u64
byte_hash64(const u8 * const byte, const size_t len)
{
  const u32 lo = kv_crc32c((const void *)byte, len);
  const u64 hash = kv_crc32c_extend(lo);
  const u64 hash64 = mhash64(hash);
  return hash64;
}

  inline u64
kv_hash64(const struct kv * const kv)
{
  return byte_hash64(kv->kv, kv->klen);
}

  inline void
kv_refill_value(struct kv * const kv, const void * const value, const u32 vlen)
{
  debug_assert((vlen == 0) || value);
  memcpy(&(kv->kv[kv->klen]), value, vlen);
  kv->vlen = vlen;
}

  inline void
kv_refill(struct kv * const kv, const void * const key, const u32 klen,
    const void * const value, const u32 vlen)
{
  debug_assert(kv);
  kv->klen = klen;
  memcpy(&(kv->kv[0]), key, klen);
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_str(struct kv * const kv, const char * const key,
    const void * const value, const u32 vlen)
{
  kv_refill(kv, key, (u32)strlen(key), value, vlen);
}

  inline void
kv_refill_str_str(struct kv * const kv, const char * const key,
    const char * const value)
{
  kv_refill(kv, key, (u32)strlen(key), value, (u32)strlen(value));
}

// the u64 key is filled in big-endian byte order for correct ordering
  inline void
kv_refill_u64(struct kv * const kv, const u64 key, const void * const value, const u32 vlen)
{
  kv->klen = sizeof(u64);
  *(u64 *)(kv->kv) = __builtin_bswap64(key); // bswap on little endian
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_hex32(struct kv * const kv, const u32 hex, const void * const value, const u32 vlen)
{
  kv->klen = 8;
  strhex_32(kv->kv, hex);
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_hex64(struct kv * const kv, const u64 hex, const void * const value, const u32 vlen)
{
  kv->klen = 16;
  strhex_64(kv->kv, hex);
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_hex64_klen(struct kv * const kv, const u64 hex,
    const u32 klen, const void * const value, const u32 vlen)
{
  if (klen > 16) {
    kv->klen = klen;
    memset(kv->kv, '!', klen - 16);
    strhex_64(kv->kv + klen - 16, hex);
  } else {
    strhex_64(kv->kv, hex);
    kv->klen = 16;
  }
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_kref(struct kv * const kv, const struct kref * const kref)
{
  kv->klen = kref->len;
  kv->vlen = 0;
  kv->hash = kv_crc32c_extend(kref->hash32);
  memmove(kv->kv, kref->ptr, kref->len);
}

  inline void
kv_refill_kref_v(struct kv * const kv, const struct kref * const kref,
    const void * const value, const u32 vlen)
{
  kv->klen = kref->len;
  kv->vlen = vlen;
  kv->hash = kv_crc32c_extend(kref->hash32);
  memmove(kv->kv, kref->ptr, kref->len);
  memcpy(kv->kv + kv->klen, value, vlen);
}

  inline void
kv_refill_kvref(struct kv * const kv, const struct kvref * const kvref)
{
  kv->klen = kvref->hdr.klen;
  kv->vlen = kvref->hdr.vlen;
  kv->hash = kv_crc32c_extend(kvref->hdr.hashlo);
  memmove(kv->kv, kvref->kptr, kv->klen);
  memmove(kv->kv + kv->klen, kvref->vptr, kv->vlen);
}

  inline struct kref
kv_kref(const struct kv * const key)
{
  return (struct kref){.ptr = key->kv, .len = key->klen, .hash32 = key->hashlo};
}

  inline struct kv *
kv_create(const void * const key, const u32 klen, const void * const value, const u32 vlen)
{
  struct kv * const kv = malloc(sizeof(*kv) + klen + vlen);
  if (kv)
    kv_refill(kv, key, klen, value, vlen);
  return kv;
}

  inline struct kv *
kv_create_str(const char * const key, const void * const value, const u32 vlen)
{
  return kv_create(key, (u32)strlen(key), value, vlen);
}

  inline struct kv *
kv_create_str_str(const char * const key, const char * const value)
{
  return kv_create(key, (u32)strlen(key), value, (u32)strlen(value));
}

  inline struct kv *
kv_create_kref(const struct kref * const kref, const void * const value, const u32 vlen)
{
  return kv_create(kref->ptr, kref->len, value, vlen);
}

static struct kv __kv_null = {};

__attribute__((constructor))
  static void
kv_null_init(void)
{
  kv_update_hash(&__kv_null);
}

  inline const struct kv *
kv_null(void)
{
  return &__kv_null;
}
// }}} construct

// dup {{{
  inline struct kv *
kv_dup(const struct kv * const kv)
{
  if (kv == NULL)
    return NULL;

  const size_t sz = kv_size(kv);
  struct kv * const new = malloc(sz);
  if (new)
    memcpy(new, kv, sz);
  return new;
}

  inline struct kv *
kv_dup_key(const struct kv * const kv)
{
  if (kv == NULL)
    return NULL;

  const size_t sz = key_size(kv);
  struct kv * const new = malloc(sz);
  if (new) {
    memcpy(new, kv, sz);
    new->vlen = 0;
  }
  return new;
}

  inline struct kv *
kv_dup_key_prefix_extra(const struct kv * const kv, const u32 plen, const u32 extra)
{
  if (kv == NULL)
    return NULL;

  const size_t sz = key_size(kv);
  struct kv * const new = malloc(sz + extra);
  if (new) {
    new->klen = plen;
    memcpy(new->kv, kv->kv, plen);
    new->vlen = 0;
    kv_update_hash(new);
  }
  return new;
}

  inline struct kv *
kv_dup2(const struct kv * const from, struct kv * const to)
{
  if (from == NULL)
    return NULL;
  const size_t sz = kv_size(from);
  struct kv * const new = to ? to : malloc(sz);
  if (new)
    memcpy(new, from, sz);
  return new;
}

  inline struct kv *
kv_dup2_key(const struct kv * const from, struct kv * const to)
{
  if (from == NULL)
    return NULL;
  const size_t sz = key_size(from);
  struct kv * const new = to ? to : malloc(sz);
  if (new) {
    memcpy(new, from, sz);
    new->vlen = 0;
  }
  return new;
}

  inline struct kv *
kref_dup2_key(const struct kref * const from, struct kv * const to)
{
  if (from == NULL)
    return NULL;
  const size_t sz = sizeof(*to) + from->len;
  struct kv * const new = to ? to : malloc(sz);
  if (new) {
    new->klen = from->len;
    memcpy(new->kv, from->ptr, new->klen);
    new->vlen = 0;
    kv_update_hash(new);
  }
  return new;
}

  inline struct kv *
kv_dup2_key_prefix(const struct kv * const from, struct kv * const to, const u32 plen)
{
  if (from == NULL)
    return NULL;
  debug_assert(plen <= from->klen);
  const size_t sz = sizeof(*from) + plen;
  struct kv * const new = to ? to : malloc(sz);
  if (new) {
    new->klen = plen;
    memcpy(new->kv, from->kv, plen);
    new->vlen = 0;
    kv_update_hash(new);
  }
  return new;
}
// }}} dup

// compare {{{
  static inline int
klen_compare(const u32 len1, const u32 len2)
{
  if (len1 < len2)
    return -1;
  else if (len1 > len2)
    return 1;
  else
    return 0;
}

// compare whether the two keys are identical
// optimistic: do not check hash
  inline bool
kv_match(const struct kv * const key1, const struct kv * const key2)
{
  //cpu_prefetch0(((u8 *)key2) + 64);
  //return (key1->hash == key2->hash)
  //  && (key1->klen == key2->klen)
  //  && (!memcmp(key1->kv, key2->kv, key1->klen));
  return (key1->klen == key2->klen) && (!memcmp(key1->kv, key2->kv, key1->klen));
}

// compare whether the two keys are identical
// check hash first
// pessimistic: return false quickly if their hashes mismatch
  inline bool
kv_match_hash(const struct kv * const key1, const struct kv * const key2)
{
  return (key1->hash == key2->hash)
    && (key1->klen == key2->klen)
    && (!memcmp(key1->kv, key2->kv, key1->klen));
}

  inline bool
kv_match_full(const struct kv * const kv1, const struct kv * const kv2)
{
  return (kv1->kvlen == kv2->kvlen)
    && (!memcmp(kv1, kv2, sizeof(*kv1) + kv1->klen + kv1->vlen));
}

  bool
kv_match_kv128(const struct kv * const sk, const u8 * const kv128)
{
  debug_assert(sk);
  debug_assert(kv128);

  u32 klen128 = 0;
  u32 vlen128 = 0;
  const u8 * const pdata = vi128_decode_u32(vi128_decode_u32(kv128, &klen128), &vlen128);
  (void)vlen128;
  return (sk->klen == klen128) && (!memcmp(sk->kv, pdata, klen128));
}

  inline int
kv_compare(const struct kv * const kv1, const struct kv * const kv2)
{
  const u32 len = kv1->klen < kv2->klen ? kv1->klen : kv2->klen;
  const int cmp = memcmp(kv1->kv, kv2->kv, (size_t)len);
  return cmp ? cmp : klen_compare(kv1->klen, kv2->klen);
}

// for qsort and bsearch
  static int
kv_compare_ptrs(const void * const p1, const void * const p2)
{
  const struct kv * const * const pp1 = (typeof(pp1))p1;
  const struct kv * const * const pp2 = (typeof(pp2))p2;
  return kv_compare(*pp1, *pp2);
}

  int
kv_k128_compare(const struct kv * const sk, const u8 * const k128)
{
  debug_assert(sk);
  const u32 klen1 = sk->klen;
  u32 klen2 = 0;
  const u8 * const ptr2 = vi128_decode_u32(k128, &klen2);
  debug_assert(ptr2);
  const u32 len = (klen1 < klen2) ? klen1 : klen2;
  const int cmp = memcmp(sk->kv, ptr2, len);
  return cmp ? cmp : klen_compare(klen1, klen2);
}

  int
kv_kv128_compare(const struct kv * const sk, const u8 * const kv128)
{
  debug_assert(sk);
  const u32 klen1 = sk->klen;
  u32 klen2 = 0;
  u32 vlen2 = 0;
  const u8 * const ptr2 = vi128_decode_u32(vi128_decode_u32(kv128, &klen2), &vlen2);
  const u32 len = (klen1 < klen2) ? klen1 : klen2;
  const int cmp = memcmp(sk->kv, ptr2, len);
  return cmp ? cmp : klen_compare(klen1, klen2);
}

  inline void
kv_qsort(struct kv ** const kvs, const size_t nr)
{
  qsort(kvs, nr, sizeof(kvs[0]), kv_compare_ptrs);
}

// return the length of longest common prefix of the two keys
  inline u32
kv_key_lcp(const struct kv * const key1, const struct kv * const key2)
{
  const u32 max = (key1->klen < key2->klen) ? key1->klen : key2->klen;
  return memlcp(key1->kv, key2->kv, max);
}

// return the length of longest common prefix of the two keys with a known lcp0
  inline u32
kv_key_lcp_skip(const struct kv * const key1, const struct kv * const key2, const u32 lcp0)
{
  const u32 max = (key1->klen < key2->klen) ? key1->klen : key2->klen;
  debug_assert(max >= lcp0);
  return lcp0 + memlcp(key1->kv+lcp0, key2->kv+lcp0, max-lcp0);
}
// }}}

// psort {{{
  static inline void
kv_psort_exchange(struct kv ** const kvs, const u64 i, const u64 j)
{
  if (i != j) {
    struct kv * const tmp = kvs[i];
    kvs[i] = kvs[j];
    kvs[j] = tmp;
  }
}

  static u64
kv_psort_partition(struct kv ** const kvs, const u64 lo, const u64 hi)
{
  if (lo >= hi)
    return lo;

  const u64 p = (lo+hi) >> 1;
  kv_psort_exchange(kvs, lo, p);
  u64 i = lo;
  u64 j = hi + 1;
  do {
    while (kv_compare(kvs[++i], kvs[lo]) < 0 && i < hi);
    while (kv_compare(kvs[--j], kvs[lo]) > 0);
    if (i >= j)
      break;
    kv_psort_exchange(kvs, i, j);
  } while (true);
  kv_psort_exchange(kvs, lo, j);
  return j;
}

  static void
kv_psort_rec(struct kv ** const kvs, const u64 lo, const u64 hi, const u64 tlo, const u64 thi)
{
  if (lo >= hi)
    return;
  const u64 c = kv_psort_partition(kvs, lo, hi);

  if (c > tlo) // go left
    kv_psort_rec(kvs, lo, c-1, tlo, thi);

  if (c < thi) // go right
    kv_psort_rec(kvs, c+1, hi, tlo, thi);
}

  inline void
kv_psort(struct kv ** const kvs, const u64 nr, const u64 tlo, const u64 thi)
{
  debug_assert(tlo <= thi);
  debug_assert(thi < nr);
  kv_psort_rec(kvs, 0, nr-1, tlo, thi);
}
// }}} psort

// ptr {{{
  inline void *
kv_vptr(struct kv * const kv)
{
  return (void *)(&(kv->kv[kv->klen]));
}

  inline void *
kv_kptr(struct kv * const kv)
{
  return (void *)(&(kv->kv[0]));
}

  inline const void *
kv_vptr_c(const struct kv * const kv)
{
  return (const void *)(&(kv->kv[kv->klen]));
}

  inline const void *
kv_kptr_c(const struct kv * const kv)
{
  return (const void *)(&(kv->kv[0]));
}
// }}} ptr

// print {{{
// cmd "KV" K and V can be 's': string, 'x': hex, 'd': dec, or else for not printing.
// n for newline after kv
  void
kv_print(const struct kv * const kv, const char * const cmd, FILE * const out)
{
  debug_assert(cmd);
  const u32 klen = kv->klen;
  fprintf(out, "#%016lx k[%3u]", kv->hash, klen);

  switch(cmd[0]) {
  case 's': fprintf(out, " %.*s", klen, kv->kv); break;
  case 'x': str_print_hex(out, kv->kv, klen); break;
  case 'd': str_print_dec(out, kv->kv, klen); break;
  default: break;
  }

  const u32 vlen = kv->vlen;
  switch (cmd[1]) {
  case 's': fprintf(out, "  v[%4u] %.*s", vlen, vlen, kv->kv+klen); break;
  case 'x': fprintf(out, "  v[%4u]", vlen); str_print_hex(out, kv->kv+klen, vlen); break;
  case 'd': fprintf(out, "  v[%4u]", vlen); str_print_dec(out, kv->kv+klen, vlen); break;
  default: break;
  }
  if (strchr(cmd, 'n'))
    fprintf(out, "\n");
}
// }}} print

// mm {{{
  struct kv *
kvmap_mm_in_noop(struct kv * const kv, void * const priv)
{
  (void)priv;
  return kv;
}

// copy-out
  struct kv *
kvmap_mm_out_noop(struct kv * const kv, struct kv * const out)
{
  (void)out;
  return kv;
}

  void
kvmap_mm_free_noop(struct kv * const kv, void * const priv)
{
  (void)kv;
  (void)priv;
}

// copy-in
  struct kv *
kvmap_mm_in_dup(struct kv * const kv, void * const priv)
{
  (void)priv;
  return kv_dup(kv);
}

// copy-out
  struct kv *
kvmap_mm_out_dup(struct kv * const kv, struct kv * const out)
{
  return kv_dup2(kv, out);
}

  void
kvmap_mm_free_free(struct kv * const kv, void * const priv)
{
  (void)priv;
  free(kv);
}

const struct kvmap_mm kvmap_mm_dup = {
  .in = kvmap_mm_in_dup,
  .out = kvmap_mm_out_dup,
  .free = kvmap_mm_free_free,
  .priv = NULL,
};

const struct kvmap_mm kvmap_mm_ndf = {
  .in = kvmap_mm_in_noop,
  .out = kvmap_mm_out_dup,
  .free = kvmap_mm_free_free,
  .priv = NULL,
};

// }}} mm

// kref {{{
  inline void
kref_ref_raw(struct kref * const kref, const u8 * const ptr, const u32 len)
{
  kref->ptr = ptr;
  kref->len = len;
  kref->hash32 = 0;
}

  inline void
kref_ref_hash32(struct kref * const kref, const u8 * const ptr, const u32 len)
{
  kref->ptr = ptr;
  kref->len = len;
  kref->hash32 = kv_crc32c(ptr, len);
}

  inline u64
kref_hash64(const struct kref * const kref)
{
  const u32 lo = kv_crc32c(kref->ptr, kref->len);
  const u64 hash = kv_crc32c_extend(lo);
  const u64 hash64 = mhash64(hash);
  return hash64;
}

  inline void
kref_update_hash32(struct kref * const kref)
{
  kref->hash32 = kv_crc32c(kref->ptr, kref->len);
}

  inline void
kref_ref_kv(struct kref * const kref, const struct kv * const kv)
{
  kref->ptr = kv->kv;
  kref->len = kv->klen;
  kref->hash32 = kv->hashlo;
}

  inline void
kref_ref_kv_hash32(struct kref * const kref, const struct kv * const kv)
{
  kref->ptr = kv->kv;
  kref->len = kv->klen;
  kref->hash32 = kv_crc32c(kv->kv, kv->klen);
}

  inline bool
kref_match(const struct kref * const k1, const struct kref * const k2)
{
  return (k1->len == k2->len) && (!memcmp(k1->ptr, k2->ptr, k1->len));
}

// match a kref and a key
  inline bool
kref_kv_match(const struct kref * const kref, const struct kv * const k)
{
  return (kref->len == k->klen) && (!memcmp(kref->ptr, k->kv, kref->len));
}

  inline bool
kref_kvref_match(const struct kref * const kref, const struct kvref * const kvref)
{
  return (kref->len == kvref->hdr.klen) && (!memcmp(kref->ptr, kvref->kptr, kref->len));
}

  inline int
kref_compare(const struct kref * const kref1, const struct kref * const kref2)
{
  const u32 len = kref1->len < kref2->len ? kref1->len : kref2->len;
  const int cmp = memcmp(kref1->ptr, kref2->ptr, (size_t)len);
  return cmp ? cmp : klen_compare(kref1->len, kref2->len);
}

// compare a kref and a key
  inline int
kref_kv_compare(const struct kref * const kref, const struct kv * const k)
{
  debug_assert(kref);
  debug_assert(k);
  const u32 len = kref->len < k->klen ? kref->len : k->klen;
  const int cmp = memcmp(kref->ptr, k->kv, (size_t)len);
  return cmp ? cmp : klen_compare(kref->len, k->klen);
}

  inline int
kref_kvref_compare(const struct kref * const kref, const struct kvref * const kvref)
{
  const u32 len = kref->len < kvref->hdr.klen ? kref->len : kvref->hdr.klen;
  const int cmp = memcmp(kref->ptr, kvref->kptr, (size_t)len);
  return cmp ? cmp : klen_compare(kref->len, kvref->hdr.klen);
}

  inline u32
kref_lcp(const struct kref * const k1, const struct kref * const k2)
{
  const u32 max = (k1->len < k2->len) ? k1->len : k2->len;
  return memlcp(k1->ptr, k2->ptr, max);
}

  inline u32
kref_kv_lcp(const struct kref * const kref, const struct kv * const kv)
{
  const u32 max = (kref->len < kv->klen) ? kref->len : kv->klen;
  return memlcp(kref->ptr, kv->kv, max);
}

// klen, key, ...
  inline int
kref_k128_compare(const struct kref * const sk, const u8 * const k128)
{
  debug_assert(sk);
  const u32 klen1 = sk->len;
  u32 klen2 = 0;
  const u8 * const ptr2 = vi128_decode_u32(k128, &klen2);
  debug_assert(ptr2);
  const u32 len = (klen1 < klen2) ? klen1 : klen2;
  const int cmp = memcmp(sk->ptr, ptr2, len);
  return cmp ? cmp : klen_compare(klen1, klen2);
}

// klen, vlen, key, ...
  inline int
kref_kv128_compare(const struct kref * const sk, const u8 * const kv128)
{
  debug_assert(sk);
  const u32 klen1 = sk->len;
  u32 klen2 = 0;
  u32 vlen2 = 0;
  const u8 * const ptr2 = vi128_decode_u32(vi128_decode_u32(kv128, &klen2), &vlen2);
  const u32 len = (klen1 < klen2) ? klen1 : klen2;
  const int cmp = memcmp(sk->ptr, ptr2, len);
  return cmp ? cmp : klen_compare(klen1, klen2);
}

static struct kref __kref_null = {.hash32 = KV_CRC32C_SEED};

  inline const struct kref *
kref_null(void)
{
  return &__kref_null;
}
// }}} kref

// kvref {{{
  inline void
kvref_ref_kv(struct kvref * const ref, struct kv * const kv)
{
  ref->kptr = kv->kv;
  ref->vptr = kv->kv + kv->klen;
  ref->hdr = *kv;
}

  struct kv *
kvref_dup2_kv(struct kvref * const ref, struct kv * const to)
{
  if (ref == NULL)
    return NULL;
  const size_t sz = sizeof(*to) + ref->hdr.klen + ref->hdr.vlen;
  struct kv * const new = to ? to : malloc(sz);
  if (new == NULL)
    return NULL;

  *new = ref->hdr;
  memcpy(new->kv, ref->kptr, new->klen);
  memcpy(new->kv + new->klen, ref->vptr, new->vlen);
  return new;
}

  struct kv *
kvref_dup2_key(struct kvref * const ref, struct kv * const to)
{
  if (ref == NULL)
    return NULL;
  const size_t sz = sizeof(*to) + ref->hdr.klen;
  struct kv * const new = to ? to : malloc(sz);
  if (new == NULL)
    return NULL;

  *new = ref->hdr;
  memcpy(new->kv, ref->kptr, new->klen);
  return new;
}

  int
kvref_kvref_compare(const struct kvref * const a, const struct kvref * const b)
{
  const u32 len = a->hdr.klen < b->hdr.klen ? a->hdr.klen : b->hdr.klen;
  const int cmp = memcmp(a->kptr, b->kptr, (size_t)len);
  return cmp ? cmp : klen_compare(a->hdr.klen, b->hdr.klen);
}

  int
kvref_kv_compare(const struct kvref * const ref, const struct kv * const kv)
{
  const u32 len = ref->hdr.klen < kv->klen ? ref->hdr.klen : kv->klen;
  const int cmp = memcmp(ref->kptr, kv->kv, (size_t)len);
  return cmp ? cmp : klen_compare(ref->hdr.klen, kv->klen);
}
// }}} kvref

// kv128 {{{
// estimate the encoded size
  inline size_t
kv128_estimate_kv(const struct kv * const kv)
{
  return vi128_estimate_u32(kv->klen) + vi128_estimate_u32(kv->vlen) + kv->klen + kv->vlen;
}

// create a kv128 from kv
  u8 *
kv128_encode_kv(const struct kv * const kv, u8 * const out, size_t * const pesize)
{
  u8 * const ptr = out ? out : malloc(kv128_estimate_kv(kv));
  if (!ptr)
    return NULL;

  u8 * const pdata = vi128_encode_u32(vi128_encode_u32(ptr, kv->klen), kv->vlen);
  memcpy(pdata, kv->kv, kv->klen + kv->vlen);

  if (pesize)
    *pesize = (size_t)(pdata - ptr) + kv->klen + kv->vlen;
  return ptr; // return the head of the encoded kv128
}

// dup kv128 to a kv
  struct kv *
kv128_decode_kv(const u8 * const ptr, struct kv * const out, size_t * const pesize)
{
  u32 klen, vlen;
  const u8 * const pdata = vi128_decode_u32(vi128_decode_u32(ptr, &klen), &vlen);
  struct kv * const ret = out ? out : malloc(sizeof(struct kv) + klen + vlen);
  if (ret)
    kv_refill(ret, pdata, klen, pdata + klen, vlen);

  if (pesize)
    *pesize = (size_t)(pdata - ptr) + klen + vlen;
  return ret; // return the kv
}

  void
kv128_decode_kvref(const u8 * const ptr, struct kvref * const kvref)
{
  kvref->kptr = vi128_decode_u32(vi128_decode_u32(ptr, &kvref->hdr.klen), &kvref->hdr.vlen);
  kvref->vptr = kvref->kptr + kvref->hdr.klen;
}

  inline size_t
kv128_size(const u8 * const ptr)
{
  u32 klen, vlen;
  const u8 * const pdata = vi128_decode_u32(vi128_decode_u32(ptr, &klen), &vlen);
  return ((size_t)(pdata - ptr)) + klen + vlen;
}
// }}} kv128

// }}} kv

// kvmap {{{

// registry {{{
// increase MAX if need more
#define KVMAP_API_MAX ((32))
static struct kvmap_api_reg kvmap_api_regs[KVMAP_API_MAX];
static u64 kvmap_api_regs_nr = 0;

  void
kvmap_api_register(const int nargs, const char * const name, const char * const args_msg,
    void * (*create)(const char *, const struct kvmap_mm *, char **), const struct kvmap_api * const api)
{
  if (kvmap_api_regs_nr < KVMAP_API_MAX) {
    kvmap_api_regs[kvmap_api_regs_nr].nargs = nargs;
    kvmap_api_regs[kvmap_api_regs_nr].name = name;
    kvmap_api_regs[kvmap_api_regs_nr].args_msg = args_msg;
    kvmap_api_regs[kvmap_api_regs_nr].create = create;
    kvmap_api_regs[kvmap_api_regs_nr].api = api;
    kvmap_api_regs_nr++;
  } else {
    fprintf(stderr, "%s failed to register [%s]\n", __func__, name);
  }
}
  void
kvmap_api_helper_message(void)
{
  fprintf(stderr, "%s Usage: api <map-type> <param1> ...\n", __func__);
  for (u64 i = 0; i < kvmap_api_regs_nr; i++) {
    fprintf(stderr, "%s example: api %s %s\n", __func__,
        kvmap_api_regs[i].name, kvmap_api_regs[i].args_msg);
  }
}

  int
kvmap_api_helper(int argc, char ** const argv, const struct kvmap_mm * const mm,
    const struct kvmap_api ** const api_out, void ** const map_out)
{
  // "api" "name" "arg1", ...
  if (argc < 2 || strcmp(argv[0], "api") != 0)
    return -1;

  for (u64 i = 0; i < kvmap_api_regs_nr; i++) {
    const struct kvmap_api_reg * const reg = &kvmap_api_regs[i];
    if (0 != strcmp(argv[1], reg->name))
      continue;

    if ((argc - 2) < reg->nargs)
      return -1;

    void * const map = reg->create(argv[1], mm, argv + 2); // skip "api" "name"
    if (map) {
      *api_out = reg->api;
      *map_out = map;
      return 2 + reg->nargs;
    } else {
      return -1;
    }
  }

  // no match
  return -1;
}
// }}} registry

// misc {{{
  void
kvmap_inp_steal_kv(struct kv * const kv, void * const priv)
{
  // steal the kv pointer out so we don't need a dangerous get_key_interanl()
  if (priv)
    *(struct kv **)priv = kv;
}

  inline void *
kvmap_ref(const struct kvmap_api * const api, void * const map)
{
  return api->ref ? api->ref(map) : map;
}

// return the original map pointer; usually unused by caller
  inline void *
kvmap_unref(const struct kvmap_api * const api, void * const ref)
{
  return api->unref ? api->unref(ref) : ref;
}
// }}} misc

// kvmap_kv_op {{{
  inline struct kv *
kvmap_kv_get(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, struct kv * const out)
{
  const struct kref kref = kv_kref(key);
  return api->get(ref, &kref, out);
}

  inline bool
kvmap_kv_probe(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key)
{
  const struct kref kref = kv_kref(key);
  return api->probe(ref, &kref);
}

  inline bool
kvmap_kv_put(const struct kvmap_api * const api, void * const ref,
    struct kv * const kv)
{
  return api->put(ref, kv);
}

  inline bool
kvmap_kv_del(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key)
{
  const struct kref kref = kv_kref(key);
  return api->del(ref, &kref);
}

  inline bool
kvmap_kv_inpr(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, kv_inp_func uf, void * const priv)
{
  const struct kref kref = kv_kref(key);
  return api->inpr(ref, &kref, uf, priv);
}

  inline bool
kvmap_kv_inpw(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, kv_inp_func uf, void * const priv)
{
  const struct kref kref = kv_kref(key);
  return api->inpw(ref, &kref, uf, priv);
}

  inline bool
kvmap_kv_merge(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, kv_merge_func uf, void * const priv)
{
  const struct kref kref = kv_kref(key);
  return api->merge(ref, &kref, uf, priv);
}

  inline u64
kvmap_kv_delr(const struct kvmap_api * const api, void * const ref,
    const struct kv * const start, const struct kv * const end)
{
  const struct kref kref0 = kv_kref(start);
  if (end) {
    const struct kref krefz = kv_kref(end);
    return api->delr(ref, &kref0, &krefz);
  } else {
    return api->delr(ref, &kref0, NULL);
  }
}

  inline void
kvmap_kv_iter_seek(const struct kvmap_api * const api, void * const iter,
    const struct kv * const key)
{
  const struct kref kref = kv_kref(key);
  api->iter_seek(iter, &kref);
}
// }}} kvmap_kv_op

// kvmap_raw_op {{{
  inline struct kv *
kvmap_raw_get(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr, struct kv * const out)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->get(ref, &kref, out);
}

  inline bool
kvmap_raw_probe(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->probe(ref, &kref);
}

  inline bool
kvmap_raw_del(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->del(ref, &kref);
}

  inline bool
kvmap_raw_inpr(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr, kv_inp_func uf, void * const priv)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->inpr(ref, &kref, uf, priv);
}

  inline bool
kvmap_raw_inpw(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr, kv_inp_func uf, void * const priv)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->inpw(ref, &kref, uf, priv);
}

  inline void
kvmap_raw_iter_seek(const struct kvmap_api * const api, void * const iter,
    const u32 len, const u8 * const ptr)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  api->iter_seek(iter, &kref);
}
// }}}} kvmap_raw_op

// dump {{{
  u64
kvmap_dump_keys(const struct kvmap_api * const api, void * const map, const int fd)
{
  void * const ref = kvmap_ref(api, map);
  void * const iter = api->iter_create(ref);
  api->iter_seek(iter, kref_null());
  u64 i = 0;
  while (api->iter_valid(iter)) {
    struct kvref kvref;
    api->iter_kvref(iter, &kvref);
    dprintf(fd, "%010lu [%3u] %.*s [%u]\n", i, kvref.hdr.klen, kvref.hdr.klen, kvref.kptr, kvref.hdr.vlen);
    i++;
    api->iter_skip1(iter);
  }
  api->iter_destroy(iter);
  kvmap_unref(api, ref);
  return i;
}
// }}} dump

// kv64 {{{
struct kv64 { // internal only
  struct kv kv;
  u64 key_be; // must be in big endian
  u64 value;
};

  inline bool
kvmap_kv64_get(const struct kvmap_api * const api, void * const ref,
    const u64 key, u64 * const out)
{
  struct kv64 keybuf, kvout;
  struct kref kref;
  keybuf.key_be = __builtin_bswap64(key);
  kref_ref_hash32(&kref, keybuf.kv.kv, sizeof(keybuf.key_be));
  struct kv * const ret = api->get(ref, &kref, &kvout.kv);
  if (ret) {
    *out = kvout.value;
    return true;
  } else {
    return false;
  }
}

  inline bool
kvmap_kv64_probe(const struct kvmap_api * const api, void * const ref,
    const u64 key)
{
  struct kv64 keybuf;
  struct kref kref;
  keybuf.key_be = __builtin_bswap64(key);
  kref_ref_hash32(&kref, keybuf.kv.kv, sizeof(keybuf.key_be));
  return api->probe(ref, &kref);
}

  inline bool
kvmap_kv64_put(const struct kvmap_api * const api, void * const ref,
    const u64 key, const u64 value)
{
  struct kv64 kv;
  kv.key_be = __builtin_bswap64(key);
  kv.value = value;
  kv.kv.klen = sizeof(key);
  kv.kv.vlen = sizeof(value);
  if (api->hashkey)
    kv_update_hash(&kv.kv);

  return api->put(ref, &kv.kv);
}

  inline bool
kvmap_kv64_del(const struct kvmap_api * const api, void * const ref,
    const u64 key)
{
  struct kv64 keybuf;
  struct kref kref;
  keybuf.key_be = __builtin_bswap64(key);
  kref_ref_hash32(&kref, keybuf.kv.kv, sizeof(keybuf.key_be));
  return api->del(ref, &kref);
}

  inline void
kvmap_kv64_iter_seek(const struct kvmap_api * const api, void * const iter,
    const u64 key)
{
  struct kv64 keybuf;
  struct kref kref;
  keybuf.key_be = __builtin_bswap64(key);
  kref_ref_hash32(&kref, keybuf.kv.kv, sizeof(keybuf.key_be));
  api->iter_seek(iter, &kref);
}

  inline bool
kvmap_kv64_iter_peek(const struct kvmap_api * const api, void * const iter,
    u64 * const key_out, u64 * const value_out)
{
  struct kv64 kvout;
  struct kv * const ret = api->iter_peek(iter, &kvout.kv);
  if (key_out)
    *key_out = __builtin_bswap64(kvout.key_be); // to LE
  if (value_out)
    *value_out = kvout.value;
  return ret != NULL;
}
// }}} kv64

// }}} kvmap

// miter {{{
struct miter_stream { // minheap
  struct kref kref;
  const struct kvmap_api * api;
  void * ref;
  void * iter;
  u32 rank; // rank of this stream
  bool private_ref;
  bool private_iter;
};

// merging iterator
#define MITER_MAX_STREAMS ((18))
struct miter {
  u32 nway;
  u32 parked; // 0/1
  struct kref kref0;
  void * ptr0; // buffer for copying the last key during skip_unique
  size_t len0; // allocation size of ptr0
  u8 * merge_hist;
  u32 hist_size;
  u32 hist_index;
  bool recording;
  // mh[0] is used for saving the last stream for skip_unique
  struct miter_stream * mh[1+MITER_MAX_STREAMS];
};

//
//       [X]
//      |    |
//    [2X]  [2X+1]

  struct miter *
miter_create(void)
{
  struct miter * const miter = calloc(1, sizeof(*miter));
  return miter;
}

// swap child (cidx) with its parent
  static inline void
miter_swap(struct miter * const miter, const u32 cidx)
{
  debug_assert(cidx > 1);
  struct miter_stream * const tmp = miter->mh[cidx];
  miter->mh[cidx] = miter->mh[cidx>>1];
  miter->mh[cidx>>1] = tmp;
}

// NOTE: stream with equal kvs: inserted last will be first out
  static bool
miter_should_swap(struct miter_stream * const sp, struct miter_stream * const sc)
{
  if (sp->kref.ptr == NULL)
    return true;
  if (sc->kref.ptr == NULL)
    return false;

  const int c = kref_compare(&sp->kref, &sc->kref);
  if (c > 0)
    return true;
  else if (c < 0)
    return false;
  return sp->rank < sc->rank; // high rank == high priority
}

// call upheap when a key may move up
  static void
miter_upheap(struct miter * const miter, u32 idx)
{
  while (idx > 1) {
    struct miter_stream * sp = miter->mh[idx>>1];
    struct miter_stream * sc = miter->mh[idx];
    if (sc->kref.ptr == NULL)
      return; // +inf
    if (miter_should_swap(sp, sc))
      miter_swap(miter, idx);
    else
      return;
    idx >>= 1;
  }
}

  static void
miter_downheap(struct miter * const miter, u32 idx)
{
  while ((idx<<1) <= miter->nway) {
    struct miter_stream * sl = miter->mh[idx<<1];
    u32 idxs = idx << 1;
    if ((idx<<1) < miter->nway) { // has sr
      struct miter_stream * sr = miter->mh[(idx<<1) + 1];
      if (miter_should_swap(sl, sr))
        idxs++;
    }

    if (miter_should_swap(miter->mh[idx], miter->mh[idxs]))
      miter_swap(miter, idxs);
    else
      return;
    idx = idxs;
  }
}

  static void
miter_stream_fix(struct miter_stream * const s)
{
  const bool r = s->api->iter_kref(s->iter, &s->kref);
  if (!r)
    s->kref.ptr = NULL;
}

  static void
miter_stream_skip(struct miter_stream * const s)
{
  s->api->iter_skip1(s->iter);
  miter_stream_fix(s);
}

  static bool
miter_stream_add(struct miter * const miter, const struct kvmap_api * const api,
    void * const ref, void * const iter, const bool private_ref, const bool private_iter)
{
  const u32 way = miter->nway + 1;

  if (miter->mh[way] == NULL)
    miter->mh[way] = malloc(sizeof(struct miter_stream));

  struct miter_stream * const s = miter->mh[way];
  if (s == NULL)
    return false;

  s->kref.ptr = NULL;
  s->iter = iter;
  s->ref = ref;
  s->api = api;
  s->rank = miter->nway; // rank starts with 0
  s->private_ref = private_ref;
  s->private_iter = private_iter;
  miter->nway = way; // +1
  return true;
}

  bool
miter_add_iter(struct miter * const miter, const struct kvmap_api * const api, void * const ref, void * const iter)
{
  if (miter->nway >= MITER_MAX_STREAMS)
    return NULL;

  return miter_stream_add(miter, api, ref, iter, false, false);
}

  void *
miter_add_ref(struct miter * const miter, const struct kvmap_api * const api, void * const ref)
{
  if (miter->nway >= MITER_MAX_STREAMS)
    return NULL;

  void * const iter = api->iter_create(ref);
  if (iter == NULL)
    return NULL;

  const bool r = miter_stream_add(miter, api, ref, iter, false, true);
  if (!r) {
    api->iter_destroy(iter);
    return NULL;
  }
  return iter;
}

// add lower-level stream first, and then moving up
// add(s1); add(s2);
// if two keys in s1 and s2 are equal, the key in s2 will be poped out first
// return the iter created for map; caller should not edit iter while miter is active
  void *
miter_add(struct miter * const miter, const struct kvmap_api * const api, void * const map)
{
  if (miter->nway >= MITER_MAX_STREAMS)
    return NULL;

  void * const ref = kvmap_ref(api, map);
  if (ref == NULL)
    return NULL;

  void * const iter = api->iter_create(ref);
  if (iter == NULL) {
    kvmap_unref(api, ref);
    return NULL;
  }

  const bool r = miter_stream_add(miter, api, ref, iter, true, true);
  if (!r) {
    api->iter_destroy(iter);
    kvmap_unref(api, ref);
    return NULL;
  }
  return iter;
}

  u32
miter_rank(struct miter * const miter)
{
  if (!miter_valid(miter))
    return UINT32_MAX;
  return miter->mh[1]->rank;
}

  static void
miter_resume(struct miter * const miter)
{
  if (miter->parked) {
    miter->parked = 0;
    for (u32 i = 1; i <= miter->nway; i++) {
      struct miter_stream * const s = miter->mh[i];
      if (s->api->refpark)
        s->api->resume(s->ref);
    }
  }
}

  void
miter_seek(struct miter * const miter, const struct kref * const key)
{
  miter_resume(miter);
  for (u32 i = 1; i <= miter->nway; i++) {
    struct miter_stream * const s = miter->mh[i];
    s->api->iter_seek(s->iter, key);
    miter_stream_fix(s);
  }
  for (u32 i = 2; i <= miter->nway; i++)
    miter_upheap(miter, i);
}

  void
miter_kv_seek(struct miter * const miter, const struct kv * const key)
{
  const struct kref s = kv_kref(key);
  miter_seek(miter, &s);
}

  bool
miter_valid(struct miter * const miter)
{
  return miter->nway && miter->mh[1]->kref.ptr;
}

  static bool
miter_valid_1(struct miter * const miter)
{
  return miter->nway != 0;
}

  struct kv *
miter_peek(struct miter * const miter, struct kv * const out)
{
  if (!miter_valid_1(miter))
    return NULL;

  struct miter_stream * const s = miter->mh[1];
  return s->api->iter_peek(s->iter, out);
}

  bool
miter_kref(struct miter * const miter, struct kref * const kref)
{
  if (!miter_valid_1(miter))
    return false;

  struct miter_stream * const s = miter->mh[1];
  return s->api->iter_kref(s->iter, kref);
}

  bool
miter_kvref(struct miter * const miter, struct kvref * const kvref)
{
  if (!miter_valid_1(miter))
    return false;

  struct miter_stream * const s = miter->mh[1];
  return s->api->iter_kvref(s->iter, kvref);
}

  void
miter_skip1(struct miter * const miter)
{
  if (!miter_valid(miter)) {
    return;
  }
  if (miter->recording) {
    u8 * hist = miter->merge_hist;
    if (miter->hist_index >= miter->hist_size) {
      miter->hist_size <<= 1;
      miter->merge_hist = realloc(miter->merge_hist, miter->hist_size);
      hist = miter->merge_hist;
    }
    const u8 rank = miter_rank(miter);
    hist[miter->hist_index++] = rank;
  }
  miter_stream_skip(miter->mh[1]);
  miter_downheap(miter, 1);
}

// nobody uses this function
  void
miter_skip(struct miter * const miter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!miter_valid(miter))
      return;
    miter_stream_skip(miter->mh[1]);
    miter_downheap(miter, 1);
  }
}

  struct kv *
miter_next(struct miter * const miter, struct kv * const out)
{
  if (!miter_valid_1(miter))
    return NULL;
  struct kv * const ret = miter_peek(miter, out);
  miter_skip1(miter);
  return ret;
}

  static u64
miter_retain_key0(struct miter * const miter)
{
  struct miter_stream * const s0 = miter->mh[1];
  const struct kvmap_api * const api0 = s0->api;
  if (api0->iter_retain) { // no copy
    miter->kref0 = s0->kref;
    miter->mh[0] = s0;
    return api0->iter_retain(s0->iter);
  } else {
    struct kref * const kref = &s0->kref;
    if (unlikely(kref->len > miter->len0)) {
      const size_t len1 = miter->len0 + PGSZ;
      miter->ptr0 = realloc(miter->ptr0, len1);
      miter->len0 = len1;
      debug_assert(miter->ptr0);
    }

    miter->kref0.len = kref->len;
    miter->kref0.hash32 = kref->hash32;
    miter->kref0.ptr = miter->ptr0;
    memcpy(miter->ptr0, kref->ptr, kref->len);
    miter->mh[0] = NULL;
    return 0;
  }
}

  static void
miter_release_key0(struct miter * const miter, const u64 opaque)
{
  struct miter_stream * const s0 = miter->mh[0];
  if (s0) {
    const struct kvmap_api * const api0 = s0->api;
    if (api0->iter_release)
      api0->iter_release(s0->iter, opaque);
  }
}

  void
miter_skip_unique(struct miter * const miter)
{
  if (!miter_valid(miter))
    return;

  const u64 opaque = miter_retain_key0(miter); // save the current key to kref0
  struct miter_stream * const s0 = miter->mh[1];
  const bool unique0 = s0->api->unique;
  u8 flag = 0;
  do {
    miter_skip1(miter);
    if (miter->recording) {
      // don't set the flag for the first key
      miter->merge_hist[miter->hist_index-1] |= flag;
    }
    if (!miter_valid(miter))
      break;
    // try to avoid cmp with unique stream
    if (unique0 && (miter->mh[1] == s0))
      break;
    if (kref_compare(&miter->kref0, &(miter->mh[1]->kref)) != 0) {
      break;
    }
    flag |= MITER_HIST_REP_FLAG;
  } while (true);
  miter_release_key0(miter, opaque);
}

  struct kv *
miter_next_unique(struct miter * const miter, struct kv * const out)
{
  if (!miter_valid(miter))
    return NULL;
  struct kv * const ret = miter_peek(miter, out);
  miter_skip_unique(miter);
  return ret;
}

  void
miter_park(struct miter * const miter)
{
  for (u32 i = 1; i <= miter->nway; i++) {
    struct miter_stream * const s = miter->mh[i];
    // park the iter
    if (s->api->iter_park)
      s->api->iter_park(s->iter);
    s->kref.ptr = NULL;
    // park ref
    if (s->api->refpark) {
      s->api->park(s->ref);
      miter->parked = 1;
    }
  }
}

  void
miter_start_recording(struct miter * const miter)
{
  u8 * hist = miter->merge_hist;
  if (hist == NULL) {
    miter->hist_size = 1024;
    hist = malloc(1024);
  }
  miter->hist_index = 0;
  memset(hist, 0, miter->hist_size);
  miter->merge_hist = hist;
  miter->recording = true;
}

  void
miter_stop_recording(struct miter * const miter, u8 ** history, u64 * hist_size)
{
  *history = miter->merge_hist;
  *hist_size = miter->hist_index;
  miter->recording = false;
}

  void
miter_clean(struct miter * const miter)
{
  miter_resume(miter); // resume refs if parked
  for (u32 i = 1; i <= miter->nway; i++) {
    struct miter_stream * const s = miter->mh[i];
    const struct kvmap_api * const api = s->api;
    if (s->private_iter)
      api->iter_destroy(s->iter);
    if (s->private_ref)
      kvmap_unref(api, s->ref);
  }
  miter->nway = 0;
}

  void
miter_destroy(struct miter * const miter)
{
  miter_clean(miter);
  for (u32 i = 1; i <= MITER_MAX_STREAMS; i++) {
    if (miter->mh[i]) {
      free(miter->mh[i]);
      miter->mh[i] = NULL;
    } else {
      break;
    }
  }
  if (miter->ptr0)
    free(miter->ptr0);
  if (miter->merge_hist) {
    free(miter->merge_hist);
  }
  free(miter);
}
// }}} miter

// kvload {{{
// for loading real traces

u64 kvnr = 0;
struct kv ** kvss = NULL;
static u64 kvss_memsz = 0;
u32 kvmaxklen = 0;

  static bool
load_mmapkv(const char * const fn)
{
#if defined(MMAPKVDIO)
  const int flags = O_RDONLY | O_DIRECT;
#else
  const int flags = O_RDONLY;
#endif
  const int fd0 = open(fn, flags);
  const int fd = (fd0 >= 0) ? fd0 : open(fn, O_RDONLY); // no DIRECT_IO
  if (fd < 0)
    return false;

  struct stat st = {};
  fstat(fd, &st);
  const size_t filesz = (size_t)st.st_size;

  const u64 mapsize = filesz + (1lu << 24); // +16MB for value
  u64 mapsize_out = 0;
  u8 * const mem = pages_alloc_best(mapsize, true, &mapsize_out);
  if (mem == NULL) {
    fprintf(stderr, "%s alloc failed\n", __func__);
    close(fd);
    return false;
  }
  fprintf(stderr, "%s %lu (MB)\n", __func__, mapsize >> 20);
  size_t todo = filesz;
  size_t off = 0;
  do {
    ssize_t n = read(fd, mem + off, todo);
    if (n <= 0) {
      pages_unmap(mem, mapsize);
      close(fd);
      return false;
    }
    debug_assert((size_t)n <= todo);
    off += (size_t)n;
    todo -= (size_t)n;
  } while (todo);
  close(fd);
  u64 * const offs = (typeof(offs))mem;
  kvnr = (offs[0]) / sizeof(offs); // # of offs
  kvss = (typeof(kvss))mem;
  kvss_memsz = mapsize_out;
  kvmaxklen = 0;
  // restore kvss ptrs and find maxklen
  for (u64 i = 0; i < kvnr; i++) {
    kvss[i] = (struct kv *)(mem + offs[i]);
    if (kvmaxklen < kvss[i]->klen)
      kvmaxklen = kvss[i]->klen;
  }

  bool recomp = false;
  for (u64 i = 0; i < 1000; i++) { // randomly check some hash
    struct kv * const chk = kvss[random_u64() % kvnr];
    const u64 h0 = chk->hash;
    kv_update_hash(chk);
    const u64 h1 = chk->hash;
    if (h0 != h1) {
      recomp = true;
      break;
    }
  }
  if (recomp) {
    fprintf(stderr, "generating all kv->hash\n");
    for (u64 i = 0; i < kvnr; i++)
      kv_update_hash(kvss[i]);
  }
  fprintf(stderr, "%s filesz %zu nr %lu kvmaxklen %u\n",
      __func__, filesz, kvnr, kvmaxklen);
  return true;
}

  static bool
load_genkv(const char * const fn)
{
  FILE * const fin = fopen(fn, "r");
  if (fin == NULL)
    return false;

  char * buf = NULL;
  size_t bufsize = 0;
  u64 nr = 0;
  u32 klen = 0;
  u32 minb = '0'; // printable
  // line 1: nr klen [minb]
  if (getline(&buf, &bufsize, fin) <= 0 || sscanf(buf, "%lu%u%u", &nr, &klen, &minb) < 2)
    goto fail_cfg;

  kvmaxklen = klen;
  // get full size
  u32 * const ranges = malloc(klen * sizeof(u64));
  if (!ranges)
    goto fail_cfg;

  for (u32 i = 0; i < klen; i++)
    ranges[i] = 1;
  // line 2+: key-offset nr-tokens
  u32 koff, ntok;
  while (getline(&buf, &bufsize, fin) > 0 && sscanf(buf, "%u%u", &koff, &ntok) == 2) {
    if (koff >= klen || (minb + ntok) > UINT8_MAX)
      goto fail_cfg2;
    ranges[koff] = ntok;
  }

  // 8b aligned
  const u64 unit = bits_round_up(sizeof(struct kv) + klen, 3);
  const u64 basesize = (unit + sizeof(struct kv *)) * nr;
  const u64 mapsize = basesize + (1lu << 24); // +16MB for the last value
  fprintf(stderr, "%s %lu MB\n", __func__, mapsize >> 20);
  u64 mapsize_out = 0;
  u8 * ptr = pages_alloc_best(mapsize, true, &mapsize_out);
  if (!ptr)
    goto fail_cfg2;

  free(buf);
  fclose(fin);

  kvnr = nr;
  kvss = (typeof(kvss))ptr;
  kvss_memsz = mapsize_out;

  ptr += (sizeof(struct kv *) * nr); // skip kvss
  for (u64 i = 0; i < nr; i++) { // link kvss
    struct kv * const kv = (typeof(kv))ptr;
    kv->klen = klen;
    kv->vlen = 0;
    memset(kv->kv, (int)minb, klen);
    u64 v = i;
    for (u32 k = klen-1; k<klen; k--) {
      const u32 r = ranges[k];
      if (r > 1) {
        kv->kv[k] = (u8)((v % r) + minb);
        v /= r;
      }
    }
    kv_update_hash(kv);
    kvss[i] = kv;
    ptr += unit;
  }
  free(ranges);

  // clean up
  return true;
fail_cfg2:
  free(ranges);
fail_cfg:
  free(buf);
  fclose(fin);
  return false;
}

  static bool
load_txtkv(const char * const fn)
{
  FILE * const f = fopen(fn, "r");
  if (!f)
    return false;

  char * buf = NULL;
  size_t sz = 0;
  u64 n = 0;
  u64 totsz = 1lu << 24;
  do {
    ssize_t lsz = getline(&buf, &sz, f);
    if (lsz <= 0)
      break;
    if (isspace(buf[lsz-1]))
      lsz--;
    totsz += (sizeof(void *) + sizeof(struct kv) + bits_round_up((u64)lsz, 3));
    n++;
  } while (true);

  if (!n)
    goto fail_1;

  kvss = pages_alloc_best(totsz, true, &kvss_memsz);
  if (!kvss)
    goto fail_1;

  rewind(f);
  const u64 nkeys = n;
  u8 * iter = ((u8 *)kvss) + (nkeys * sizeof(void *));
  n = 0;
  kvmaxklen = 0;
  do {
    ssize_t lsz = getline(&buf, &sz, f);
    if (lsz <= 0)
      break;
    debug_assert(n < nkeys);
    if (isspace(buf[lsz-1]))
      lsz--;
    struct kv * const kv = (typeof(kv))iter;
    debug_assert(lsz < UINT32_MAX);
    const u32 klen = (u32)(u64)lsz;
    kv->klen = klen;
    if (kvmaxklen < klen)
      kvmaxklen = klen;
    memcpy(kv->kv, buf, kv->klen);
    kv_update_hash(kv);
    kvss[n] = kv;
    iter += (sizeof(struct kv) + bits_round_up((u64)lsz, 3));
    n++;
  } while (true);
  debug_assert(n == nkeys);
  kvnr = n;
  fclose(f);
  free(buf);
  return true;

fail_1:
  fclose(f);
  free(buf);
  return false;
}

  bool
kv_load(const char * const fn)
{
  // clean up before loading
  if (kvss)
    kvloader_destroy();

  if (isatty(fileno(stderr)))
    fprintf(stderr, "%s " TERMCLR(35) "%s" TERMCLR(0) "\n", __func__, fn);
  else
    fprintf(stderr, "%s %s\n", __func__, fn);

  const char * p = strrchr(fn, '.');
  if (p == NULL)
    return false;
  p++;
  if (strcmp(p, "mmapkv") == 0)
    return load_mmapkv(fn);
  else if (strcmp(p, "genkv") == 0)
    return load_genkv(fn);
  else
    return load_txtkv(fn);
}

  static void *
kv_load_worker(void * const ptr)
{
  if (false == kv_load((const char *)ptr))
    fprintf(stderr, "load failed\n");

  return NULL;
}

  bool
kv_load_cpu(const char * const fn, const u32 cpu)
{
  pthread_t pt_pp;
  const double t0 = time_sec();
  thread_create_at(cpu, &pt_pp, kv_load_worker, (void *)fn);
  pthread_join(pt_pp, NULL);
  const double dt = time_diff_sec(t0);
  fprintf(stderr, "kvload: dt %.2lfs\n", dt);
  return kvss != NULL;
}

  bool
kv_gen_strhex64(const u64 nr, struct rgen * const gen)
{
  if (kvss)
    kvloader_destroy();

  const u64 kvsz = sizeof(struct kv) + 16; // 64-bit hex value string
  const u64 memsz = (kvsz + sizeof(void *)) * nr + (1lu << 24);
  kvnr = nr;

  kvss = pages_alloc_best(memsz + 65536, true, &kvss_memsz);
  if (!kvss)
    return false;

  u8 * base = ((u8 *)kvss) + (sizeof(void *) * nr);
  kvmaxklen = 16;
  for (u64 i = 0; i < nr; i++) {
    struct kv * const kv = (typeof(kvss[i]))base;
    const u64 r = rgen_next(gen);
    strhex_64(kv->kv, r);
    kv->klen = 16;
    kv_update_hash(kv);
    kvss[i] = kv;
    base += kvsz;
  }
  return true;
}

  void
kvloader_destroy(void)
{
  if (kvss) {
    pages_unmap(kvss, kvss_memsz);
    kvss = NULL;
    kvnr = 0;
  }
}
// }}} kvload

// vim:fdm=marker
