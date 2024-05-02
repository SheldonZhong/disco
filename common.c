#define _GNU_SOURCE

#include "common.h"

const struct msstz_cfg msstz_cfg_default = {
  .major_switch = 2,
  .major_trigger = 8,
  .estimate_safe = 14,
  .max_pages = 20400, // maximum number of pages in a run
  .pages_accept = 5000, // tune with max_pages
  .ckeys = true,
  .tags = true,
  .bt_bloom = false,
  .leaf_bloom = false,
  .dbits = true,
  .inc_rebuild = true,
};

// mm {{{
  struct kv *
kvmap_mm_in_ts(struct kv * const kv, void * const priv)
{
  (void)priv;
  if (kv == NULL)
    return NULL;

  const size_t sz = sst_kv_size(kv);
  struct kv * const new = malloc(sz);
  if (new)
    memcpy(new, kv, sz);
  return new;
}

  struct kv *
kvmap_mm_out_ts(struct kv * const kv, struct kv * const out)
{
  if (kv == NULL)
    return NULL;
  const size_t sz = sst_kv_size(kv);
  struct kv * const new = out ? out : malloc(sz);
  if (new)
    memcpy(new, kv, sz);
  return new;
}

// for memtable
const struct kvmap_mm kvmap_mm_ts = {
  .in = kvmap_mm_in_ts,
  .out = kvmap_mm_out_ts,
  .free = kvmap_mm_free_free,
  .priv = NULL,
};
// }}} mm

  u8
sst_tag(const u32 hash32)
{
  return (u8)hash32;
}

  inline size_t
sst_kv_vi128_estimate(const struct kv * const kv)
{
  return vi128_estimate_u32(kv->klen) + vi128_estimate_u32(kv->vlen) + kv->klen + (kv->vlen & SST_VLEN_MASK);
}

  u8 *
sst_kv_vi128_encode(u8 * ptr, const struct kv * const kv)
{
  ptr = vi128_encode_u32(ptr, kv->klen);
  ptr = vi128_encode_u32(ptr, kv->vlen);
  const u32 kvlen = kv->klen + (kv->vlen & SST_VLEN_MASK);
  memcpy(ptr, kv->kv, kvlen);
  return ptr + kvlen;
}

  inline size_t
sst_kv_size(const struct kv * const kv)
{
  return sizeof(*kv) + kv->klen + (kv->vlen & SST_VLEN_MASK);
}

  struct kv *
sst_kv_vi128_decode(const u8 * ptr, struct kv * const out)
{
  u32 klen, vlen;
  const u8 * const kvptr = vi128_decode_u32(vi128_decode_u32(ptr, &klen), &vlen);
  const u32 kvlen = klen + (vlen & SST_VLEN_MASK);
  struct kv * const ret = out ? out : malloc(sizeof(struct kv) + kvlen);
  ret->klen = klen;
  ret->vlen = vlen;
  memcpy(ret->kv, kvptr, kvlen);
  return ret;
}

  struct kv *
sst_kvref_dup2_kv(const struct kvref * const kvref, struct kv * const out)
{
  debug_assert(kvref->kptr + kvref->hdr.klen == kvref->vptr);
  const size_t sz = sst_kv_size(&kvref->hdr);
  struct kv * const new = out ? out : malloc(sz);
  if (new) {
    *new = kvref->hdr;
    memcpy(new->kv, kvref->kptr, new->klen);
    memcpy(new->kv + new->klen, kvref->vptr, new->vlen & SST_VLEN_MASK);
  }
  return new;
}
