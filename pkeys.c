#define _GNU_SOURCE

// headers {{{
#include "lib.h"
#include "kv.h"
#include "pkeys.h"

// }}} headers

#define DKEY_BUFF_SZ ((4096))

struct pkf {
  struct kv ** kv_buff;
  u32 * lcps;
  u8 * masks;
  u8 * dkey_ptr;
  u32 * pkeys_ptr;
  u32 buff_sz;
  u32 nr;
  u32 max;
};

// pkeys factory {{{
  static u64
pext_u64(u64 src, u64 mask)
{
#if defined(__BMI2__)
  return (u64)(_pext_u64(src, mask));
#else
  u64 res = 0;
  for (u64 bp = 1; mask != 0; bp += bp) {
    if (src & mask & -mask) {
      res |= bp;
    }
    mask &= (mask - 1);
  }
  return res;
#endif
}

  static u32
pext_u32(u32 src, u32 mask)
{
#if defined(__BMI2__)
  return (u32)(_pext_u32(src, mask));
#else
  u32 res = 0;
  for (u32 bp = 1; mask != 0; bp += bp) {
    if (src & mask & -mask) {
      res |= bp;
    }
    mask &= (mask - 1);
  }
  return res;
#endif
}

  struct pkf *
pkf_create()
{
  struct pkf * pkf = calloc(1, sizeof(*pkf));
  pkf->buff_sz = 64;
  pkf->kv_buff = malloc(pkf->buff_sz * sizeof(pkf->kv_buff[0]));
  pkf->lcps = malloc(pkf->buff_sz * sizeof(pkf->lcps[0]));
  pkf->masks = malloc(pkf->buff_sz * sizeof(pkf->masks[0]));
  pkf->pkeys_ptr = malloc(pkf->buff_sz * sizeof(pkf->pkeys_ptr[0]));

  pkf->dkey_ptr = calloc(1, DKEY_BUFF_SZ);
  return pkf;
}

  void
pkf_destroy(struct pkf * pkf)
{
  pkf_clear(pkf);
  free(pkf->kv_buff);
  free(pkf->lcps);
  free(pkf->masks);
  free(pkf->dkey_ptr);
  free(pkf->pkeys_ptr);
  free(pkf);
}

// ordering guarantees
  static u8
mem_dbit_mask(const u8 * const mem1, const u8 * const mem2,
              const u32 l1, const u32 l2, const u32 lcp)
{
  const u32 max = (l1< l2) ? l1 : l2;
  if (lcp == max) {
    // key1 is the prefix of key2 ordering guarantee
    debug_assert(max == l1);
    if (max == l2) {
      // if they are the same
      return 0;
    }
    const u8 char2 = mem2[lcp];
    debug_assert(char2 != 0);
    return bits_p2_down_u32(char2);
  }
  // lcp < max
  const u8 char1 = mem1[lcp];
  const u8 char2 = mem2[lcp];
  const u8 x = char1 ^ char2;
  return bits_p2_down_u32(x);
}

// copy from whp.c
  static u8
kv_key_dbit_mask(const struct kv * const key1, const struct kv * const key2, const u32 lcp)
{
  return mem_dbit_mask(key1->kv, key2->kv, key1->klen, key2->klen, lcp);
}

  u8
kref_dbit_mask(const struct kref * const key0, const struct kref * const key1, const u32 lcp)
{
  return mem_dbit_mask(key0->ptr, key1->ptr, key0->len, key1->len, lcp);
}

// the key in the argument is allocated
  void
pkf_append(struct pkf * f, const struct kv * key_in)
{
  struct kv * key = kv_dup_key(key_in);
  const u32 nr = f->nr;
  if (nr >= f->buff_sz) {
    f->buff_sz <<= 1;
    f->kv_buff = realloc(f->kv_buff, f->buff_sz * sizeof(f->kv_buff[0]));
    f->lcps = realloc(f->lcps, f->buff_sz * sizeof(f->lcps[0]));
    f->masks = realloc(f->masks, f->buff_sz * sizeof(f->masks[0]));
    f->pkeys_ptr = realloc(f->pkeys_ptr, f->buff_sz * sizeof(f->pkeys_ptr[0]));
  }

  u32 * lcps = f->lcps;
  u8 * masks = f->masks;
  struct kv ** const kv_buff = f->kv_buff;
  debug_assert(nr < f->buff_sz);
  kv_buff[nr] = key;
  f->nr++;

  // if there was already one key before this insert
  if (nr > 0) {
    debug_assert(kv_compare(key, kv_buff[nr-1]) >= 0);
    const struct kv * const key0 = kv_buff[nr-1];
    const u32 lcp = kv_key_lcp(key0, key);
    if ((key0->klen == key->klen) && (lcp == key0->klen)) {
      lcps[nr-1] = 0;
      masks[nr-1] = 0;
      return;
    }
    u8 mask = kv_key_dbit_mask(key0, key, lcp);
    lcps[nr-1] = lcp;
    masks[nr-1] = mask;
    if (lcp >= f->max) {
      f->max = bits_round_up(lcp+1, 3);
    }
    f->dkey_ptr[lcp] |= mask;
  }
}

// return true
// if appending one more key is going to result in overflow of dbits
  bool
pkf_check_finish(struct pkf * f)
{
  /*
  if (f->nr < 32) {
    return false;
  }
  */
  const u32 max = f->max;

  u8 * dkey = f->dkey_ptr;

  u32 tot1s = 0;

  for (u32 i = 0; i < max; i++) {
    tot1s += __builtin_popcount(dkey[i]);
  }

  return tot1s >= 32;
}

// copied from whp.c
// TODO: maybe we can try with shorter dkeys?
  static u64
mem_pext1(const u8 * mem, const u32 len, const u8 * dkey, u32 dkey_len, u32 tot1s)
{
  const u32 max = len < dkey_len ? len : dkey_len;

  const u32 max64 = max & (~7u);
  u32 clen = 0;
  u64 ret = 0;
  int tshift = 0;
  while (clen < max64) {
    const u64 v = *(const u64 *)(mem+clen);
    const u64 m = *(const u64 *)(dkey+clen);
    const u64 v1 = __builtin_bswap64(v);
    const u64 m1 = __builtin_bswap64(m);
    const u64 t = pext_u64(v1, m1);
    int shift = __builtin_popcountl(m);
    tshift += shift;
    ret <<= shift;
    ret |= t;

    clen += sizeof(u64);
  }

  // see if add one u32 is effective
  if ((clen + sizeof(u32)) <= max) {
    const u32 v = *(const u32 *)(mem+clen);
    const u32 m = *(const u32 *)(dkey+clen);
    const u32 v1 = __builtin_bswap32(v);
    const u32 m1 = __builtin_bswap32(m);
    const u32 t = pext_u32(v1, m1);
    int shift = __builtin_popcount(m);
    tshift += shift;
    ret <<= shift;
    ret |= t;
    clen += sizeof(u32);
  }

  u32 v = 0;
  u32 m = 0;
  while (clen < max) {
    v |= mem[clen];
    m |= dkey[clen];
    v <<= 8;
    m <<= 8;
    clen++;
  }
  const u32 t = pext_u32(v, m);
  int shift = __builtin_popcount(m);
  tshift += shift;
  ret <<= shift;
  ret |= t;

  ret <<= (tot1s - tshift);
  return ret;
}

  static u64
mem_pext0(const u8 * mem, const u32 len,
          const u8 * mask, const u32 mask_len)
{
  u64 kvp = 0;
  u64 mkp = 0;
  u64 ret = 0;

  int tot_shift = 0;
  for (u32 i = 0; i < mask_len; i++) {
    const u8 cmask = mask[i];
    if (cmask) {
      u8 kbyte = 0;
      if (i < len)
        kbyte = mem[i];

      kvp <<= 8;
      kvp |= kbyte;

      mkp <<= 8;
      mkp |= cmask;

      if (mkp & 0xFF00000000000000) {
        u64 t = pext_u64(kvp, mkp);
        int shift = __builtin_popcountll(mkp);
        tot_shift += shift;
        ret <<= shift;
        ret |= t;
        kvp = 0;
        mkp = 0;
      }
    }
  }

  if (mkp) {
    u64 t = pext_u64(kvp, mkp);
    int shift = __builtin_popcountll(mkp);
    tot_shift += shift;
    ret  <<= shift;
    ret |= t;
  }

  if (tot_shift > 64) {
    debug_die();
  }

  return ret;
}

  u32
dkey_pext(const struct kref * const key, const struct dkey_ref * const dkey)
{
  u32 pkey = mem_pext0(key->ptr, key->len, dkey->ptr, dkey->len);
  return pkey;
}

  static u64
kv_pext(const struct kv * kv, const u8 * mask, u32 len, u32 tot1s)
{
  const u64 ret = mem_pext1(kv->kv, kv->klen, mask, len, tot1s);
  debug_assert(ret == mem_pext0(kv->kv, kv->klen, mask, len));
  return ret;
}

  u32
pkf_build(struct pkf * f, struct pkeys_ref * pkeys_out, struct dkey_ref * dkey_out)
{
  const u32 nr = f->nr;
  debug_assert((nr > 0) && (nr <= f->buff_sz));
  struct kv * const * kv_buff = f->kv_buff;
  const u32 max = f->max;

  u8 * dkey = f->dkey_ptr;

  const u32 dkey_len = max;
  u32 tot1s = 0;

  for (u32 i = 0; i < max; i++) {
    tot1s += __builtin_popcount(dkey[i]);
  }

  debug_assert(tot1s <= nr);

  u32 * pkeys = f->pkeys_ptr;
  pkeys_out->len = nr * sizeof(pkeys[0]);
  pkeys_out->ptr = pkeys;

  for (u32 i = 0; i < nr; i++) {
    const struct kv * const key = kv_buff[i];
    const u32 pkey = kv_pext(key, dkey, dkey_len, tot1s);
    pkeys[i] = pkey;
  }

  debug_assert(dkey_out != NULL);
  dkey_out->len = dkey_len;
  dkey_out->tot1s = tot1s;
  dkey_out->ptr = dkey;

  return nr;
}

  void
pkf_clear(struct pkf * f)
{
  for (u32 i = 0; i < f->nr; i++) {
    free(f->kv_buff[i]);
    f->kv_buff[i] = NULL;
  }
  f->nr = 0;
  f->max = bits_round_up(1, 3);
  memset(f->dkey_ptr, 0, DKEY_BUFF_SZ);
}
// }}} pkeys factory

  void
pkeys_deserialize(struct pkeys * pkeys, const u32 nkeys, const u8 * const mem)
{
  pkeys->pkeys = (void *)mem;
  const u8 * dkey_ptr = mem + (nkeys * sizeof(pkeys->pkeys[0]));
  pkeys->dkey.len = dkey_ptr[0];
  pkeys->dkey.tot1s = dkey_ptr[1];
  pkeys->dkey.ptr = dkey_ptr + 2;
}

  void
pkeys_dprintf(const struct pkeys * pkeys, const int fd, const u32 nkeys)
{
  dprintf(fd, "dkey len: %u, tot1s: %u\n", pkeys->dkey.len, pkeys->dkey.tot1s);
  for (u32 i = 0; i < nkeys; i++) {
    dprintf(fd, "%x", pkeys->pkeys[i]);
    if (i < (nkeys-1)) {
      dprintf(fd, ",");
    } else {
      dprintf(fd, "\n");
    }
  }
}

// read utilities {{{
  u32
pkey_lcp(const struct kref * const key0, const struct kref * const key1,
          const struct dkey_ref * const dkey)
{
  const u32 dkey_len = dkey->len;
  u32 matched = 0;
  const u32 max = (key0->len < key1->len) ? key0->len : key1->len;
  const u32 max_len = max < dkey_len ? max : dkey_len;
  const u32 tot1s = dkey->tot1s;

  for (u32 i = 0; i < max_len; i++) {
    const u8 m = dkey->ptr[i];
    u8 b1 = key0->ptr[i];
    u8 b2 = key1->ptr[i];

    const u8 x = b1 ^ b2;
    if (x) {
      const u8 lz = __builtin_clz(x) - 24;
      const u8 mask = (1 << (8-lz)) - 1;
      matched += __builtin_popcount(m & (~mask));

      // number of bits that will be discarded
      const u32 discard = tot1s - matched;
      return discard;
    }

    matched += __builtin_popcount(m);
  }

  const struct kref * key = key0->len < key1->len ? key1 : key0;
  // enter this loop only if max_len < dkey_len
  // which implies max < dkey_len
  // which implies the shortest among key0 and key1 is smaller than dkey_len
  // or key0 and key1 could be equal and they are smaller than dkey_len
  // and the key here is the longer key among key0 and key1
  // we actually access beyound the bound of key
  // we will stop only when the byte is not zero, or we reach the end of dkey
  for (u32 i = max_len; i < dkey_len; i++) {
    const u8 m = dkey->ptr[i];

    if (i < key->len) {
      const u8 x = key->ptr[i];
      if (x) {
        const u8 lz = __builtin_clz(x) - 24;
        const u8 mask = (1 << (8-lz)) - 1;
        matched += __builtin_popcount(m & (~mask));

        // number of bits that will be discarded
        const u32 discard = tot1s - matched;
        return discard;
      }
    }
    matched += __builtin_popcount(m);
  }

  return tot1s - matched;
}

  u32
pkeys_search(const u32 * const pkeys, const u32 target, u32 lo, u32 hi)
{
#pragma nounroll
  while (lo < hi) {
    u32 mid = (lo + hi) >> 1;
    if (target <= pkeys[mid])
      hi = mid;
    else
      lo = mid + 1;
  }

  return lo;
}

  u32
pkeys_match(const struct pkeys * const pkeys, const struct kref * const key, const u32 lo, const u32 hi)
{
  const u32 target = dkey_pext(key, &pkeys->dkey);
  const u32 pos = pkeys_search(pkeys->pkeys, target, lo, hi);
  if (pos == hi) {
    // out of bound, invalid, not found
    return hi;
  }

  if (pkeys->pkeys[pos] == target) {
    return pos;
  }

  // there is no equal pkey, return invalid
  return hi;
}

  static u32
pkeys_lpm(const u32 * const pkeys, const u32 target, const u32 lo, const u32 hi)
{
  const u32 pos = pkeys_search(pkeys, target, lo, hi);
  if (pos == hi) {
    return hi-1;
  }

  if (pos > lo) {
    u32 prev = pkeys[pos-1];
    u32 curr = pkeys[pos];
    u32 mc = __builtin_clz(target ^ curr);
    u32 mp = __builtin_clz(target ^ prev);
    return mc > mp ? pos : pos-1;
  }

  return pos;
}

  static u64
pkey_lower(u64 pkey, u32 discard)
{
  const u64 bit = 1lu << (discard);
  if (pkey < bit) {
    return 0;
  }
  u64 ret = pkey & (~(bit-1));
  return ret;
}

  static u64
pkey_higher(u64 pkey, u32 discard)
{
  const u64 bit = 1lu << (discard);
  debug_assert(pkey + bit > pkey);
  u64 ret = pkey + bit;
  ret &= (~(bit-1));
  return ret;
}

  u32
pkeys_find(const struct pkeys * pkeys, const struct kref * const key, const u32 l, const u32 r)
{
  const u32 pkey = dkey_pext(key, &pkeys->dkey);
  u32 pkey_pos = pkeys_lpm(pkeys->pkeys, pkey, l, r);
  return pkey_pos;
}

  u32
pkeys_correct(const struct pkeys * pkeys, const u32 pos,
          const struct kref * const key, const struct kref * const curr,
          u32 l, u32 r)
{
  const u32 pkey = dkey_pext(key, &pkeys->dkey);
  const u32 len = key->len < curr->len ? key->len : curr->len;
  int cmp = memcmp(key->ptr, curr->ptr, (size_t)len);
  const u32 discard = pkey_lcp(key, curr, &pkeys->dkey);

  if (!cmp) {
    if (key->len <= curr->len) {
      return pos;
    }
    // prefix match, but user key is longer than the current key
    cmp = 1;
  }

  if (discard == 0) {
    if (cmp < 0) {
      return pos;
    }
    return pos + 1;
  }

  u32 pkey1 = 0;
  if (cmp > 0) {
    l = pos;
    const u64 res = pkey_higher(pkey, discard);
    pkey1 = (res > UINT32_MAX) ? UINT32_MAX : res;
  } else {
    r = pos;
    if (r == 0)
      return 0;
    const u64 res = pkey_lower(pkey, discard);
    pkey1 = res;
  }
  u32 bs_pos = pkeys_search(pkeys->pkeys, pkey1, l, r);
  return bs_pos;
}
// }}} read utilities

// vim:fdm=marker
