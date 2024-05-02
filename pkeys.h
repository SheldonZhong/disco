#pragma once

#include "lib.h"

struct dkey_ref {
  const u8 * ptr;
  u32 len;
  u32 tot1s;
};

struct pkeys_ref {
  const u32 * ptr;
  u32 len;
};

struct pkf;

struct pkf * pkf_create();

void pkf_append(struct pkf * f, const struct kv * key);

bool pkf_check_finish(struct pkf * f);

u32 pkf_build(struct pkf * f, struct pkeys_ref * pkeys, struct dkey_ref * dkey);

void pkf_clear(struct pkf * f);

void pkf_destroy(struct pkf * pkf);

u32 dkey_pext(const struct kref * const key, const struct dkey_ref * const dkey);

struct pkeys {
  const u32 * pkeys;
  struct dkey_ref dkey;
};

void pkeys_dprintf(const struct pkeys * pkeys, const int fd, const u32 nkeys);

void pkeys_deserialize(struct pkeys * pkeys, const u32 nkeys, const u8 * mem);

u32 pkeys_find(const struct pkeys * const pkeys, const struct kref * const key,
              const u32 l, const u32 r);

u32 pkeys_correct(const struct pkeys * pkeys, const u32 pos,
              const struct kref * const key, const struct kref * const curr,
              u32 l, u32 r);

u32 pkey_lcp(const struct kref * const key0, const struct kref * const key1,
          const struct dkey_ref * const dkey);

u32 pkeys_match(const struct pkeys * const pkeys, const struct kref * const key, const u32 lo, const u32 hi);

u32 pkeys_search(const u32 * const pkeys, const u32 target, u32 lo, u32 hi);

u8 kref_dbit_mask(const struct kref * const key0, const struct kref * const key1, const u32 lcp);
